/// SRTLA sender – wire-compatible with BELABOX srtla2, with faithful
/// per-sequence-number in-flight tracking like srtla_send.c.
///
/// Every outgoing SRT data packet's sequence number is logged together with
/// the link it was sent on. Incoming acknowledgements then adjust exactly
/// the right link:
///   - SRTLA ACK (0x9100): lists individual seqs received by srtla_rec
///   - SRT ACK  (0x8002): cumulative "everything below N arrived"
///   - SRT NAK  (0x8003): loss list → shrink the window of the responsible
///     link, biasing traffic towards healthier links
///
/// This per-seq accounting is what makes srtla's load balancing stable;
/// naive round-robin between links with very different RTTs causes packet
/// reordering, NAK storms and finally a broken SRT connection.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use rand::RngCore;

// ─── SRTLA packet types (big-endian u16 at offset 0) ─────────────────────────
pub const SRTLA_TYPE_KEEPALIVE: u16 = 0x9000;
pub const SRTLA_TYPE_ACK:       u16 = 0x9100;
pub const SRTLA_TYPE_REG1:      u16 = 0x9200;
pub const SRTLA_TYPE_REG2:      u16 = 0x9201;
pub const SRTLA_TYPE_REG3:      u16 = 0x9202;
pub const SRTLA_TYPE_REG_ERR:   u16 = 0x9210;
pub const SRTLA_TYPE_REG_NGP:   u16 = 0x9211;
pub const SRTLA_TYPE_REG_NAK:   u16 = 0x9212;

// SRT control types (u16 at offset 0)
pub const SRT_TYPE_ACK: u16 = 0x8002;
pub const SRT_TYPE_NAK: u16 = 0x8003;

pub const SRTLA_ID_LEN: usize = 256;
pub const REG2_LEN: usize = 2 + SRTLA_ID_LEN;

pub const KEEPALIVE_INTERVAL_MS: u64 = 1_000;
pub const REG_TIMEOUT_MS:        u64 = 3_000;
pub const LINK_TIMEOUT_MS:       u64 = 6_000;
pub const REG_ERR_BACKOFF_MS:    u64 = 5_000;

// Window management — values follow srtla_send.c proportions
pub const WINDOW_MIN:  u32 = 20;
pub const WINDOW_INIT: u32 = 200;
pub const WINDOW_MAX:  u32 = 600;
pub const WINDOW_INCR: u32 = 1;     // per ACK event
/// Packet-log entries older than this are considered lost in transit and
/// purged, releasing in-flight accounting.
pub const PKT_LOG_TIMEOUT_MS: u64 = 2_000;
pub const PKT_LOG_MAX: usize = 32_768;

// ─── Per-link quality gating ──────────────────────────────────────────────────
// Window shrink/grow already biases traffic towards the healthier link, but
// only gradually — a link that starts NAK'ing heavily still gets picked
// proportionally to whatever window it has left, which keeps feeding it
// packets that are likely to be lost too. This adds a faster, relative signal
// on top: each link's NAK/sent ratio is compared against the *best* active
// link's ratio every tick, and a link doing meaningfully worse gets its
// selection weight cut hard and fast, recovering gradually once it's back in
// line with its peers. Relative (not an absolute NAK threshold) because this
// bond's healthy-state NAK/sent baseline varies a lot with network conditions
// — an absolute cutoff would either never fire or fire constantly.
pub const QUALITY_EVAL_INTERVAL_MS: u64 = 1_000;
/// Minimum packets sent on a link this interval before its ratio is trusted —
/// below this, a couple of unlucky losses would look like a huge ratio.
pub const QUALITY_MIN_SAMPLE: u64 = 10;
/// A link is "meaningfully worse" than the best link this interval if its
/// ratio exceeds the best ratio by this multiple...
pub const QUALITY_BAD_MULTIPLE: f64 = 2.0;
/// ...AND by at least this absolute margin, so noise on an already-tiny best
/// ratio doesn't trip the gate.
pub const QUALITY_BAD_FLOOR: f64 = 0.05;
// Bumped MIN from 0.05 and softened PENALTY from 0.7: the original values
// crushed a "relatively worse" link down to a ~5% trickle within ~9 bad
// intervals — effectively failover, not bonding. A link that's merely worse
// (not actually broken) should still carry a real parallel share; genuine
// collapse is still caught independently by the TS-side dropRatio brake.
pub const QUALITY_PENALTY: f64 = 0.85;    // multiplicative cut per bad interval
pub const QUALITY_MIN: f64 = 0.35;        // soft gate, keeps a real parallel share
pub const QUALITY_RECOVERY_PER_TICK: f64 = 0.05;

fn pkt_type(buf: &[u8]) -> Option<u16> {
    if buf.len() >= 2 {
        Some(u16::from_be_bytes([buf[0], buf[1]]))
    } else {
        None
    }
}

/// True if `a` is (cyclically) newer-or-equal than `b` in 31-bit seq space.
fn seq_lt(a: u32, b: u32) -> bool {
    // a < b, accounting for wrap-around
    let diff = b.wrapping_sub(a) & 0x7FFF_FFFF;
    diff != 0 && diff < 0x4000_0000
}

// ─── Group / link state ──────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GroupState {
    Unregistered,
    Reg1Sent,
    Registered,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LinkState {
    Idle,
    Reg2Sent,
    Active,
    Down,
}

pub struct Link {
    pub socket:            UdpSocket,
    pub local_addr:        SocketAddr,
    pub remote_addr:       SocketAddr,
    pub state:             LinkState,
    pub in_flight:         u32,
    pub window:            u32,
    /// EWMA round-trip time, in ms: send timestamp (from `pkt_log`) to the
    /// arrival of an ACK/cumulative-ACK confirming that sequence number.
    /// 0.0 = no sample yet.
    pub rtt_ms:            f64,
    /// Selection-weight multiplier in (0.0, 1.0], see `Bond::update_link_quality`.
    pub quality:           f64,
    pub nak_count:         u64,
    pub sent_count:        u64,
    q_prev_nak:            u64,
    q_prev_sent:           u64,
    pub last_keepalive_tx: Instant,
    pub last_rx:           Instant,
    pub last_sent:         Instant,
    pub last_reg_sent:     Instant,
}

impl Link {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_nonblocking(true)?;
        let now = Instant::now();
        Ok(Link {
            socket,
            local_addr,
            remote_addr,
            state: LinkState::Idle,
            in_flight: 0,
            window: WINDOW_INIT,
            rtt_ms: 0.0,
            quality: 1.0,
            nak_count: 0,
            sent_count: 0,
            q_prev_nak: 0,
            q_prev_sent: 0,
            last_keepalive_tx: now,
            last_rx: now,
            last_sent: now,
            last_reg_sent: now - Duration::from_secs(10),
        })
    }

    fn send_typed(&self, t: u16, payload: &[u8]) -> std::io::Result<usize> {
        let mut buf = Vec::with_capacity(2 + payload.len());
        buf.extend_from_slice(&t.to_be_bytes());
        buf.extend_from_slice(payload);
        self.socket.send_to(&buf, self.remote_addr)
    }

    pub fn send_reg1(&mut self, id: &[u8; SRTLA_ID_LEN]) -> std::io::Result<()> {
        self.send_typed(SRTLA_TYPE_REG1, id)?;
        self.last_reg_sent = Instant::now();
        Ok(())
    }

    pub fn send_reg2(&mut self, id: &[u8; SRTLA_ID_LEN]) -> std::io::Result<()> {
        self.send_typed(SRTLA_TYPE_REG2, id)?;
        self.state = LinkState::Reg2Sent;
        self.last_reg_sent = Instant::now();
        Ok(())
    }

    pub fn send_keepalive(&mut self) -> std::io::Result<()> {
        self.send_typed(SRTLA_TYPE_KEEPALIVE, &[])?;
        self.last_keepalive_tx = Instant::now();
        Ok(())
    }

    pub fn grow_window(&mut self) {
        if self.state == LinkState::Active {
            self.window = (self.window + WINDOW_INCR).min(WINDOW_MAX);
        }
    }

    pub fn shrink_window(&mut self) {
        self.window = (self.window * 95 / 100).max(WINDOW_MIN);
    }

    /// EWMA-smooth a fresh RTT sample (ms). First sample seeds the average
    /// directly rather than smoothing from 0, so a single slow start doesn't
    /// take many rounds to "catch up".
    pub fn sample_rtt(&mut self, ms: f64) {
        if ms <= 0.0 || !ms.is_finite() {
            return;
        }
        self.rtt_ms = if self.rtt_ms <= 0.0 { ms } else { self.rtt_ms * 0.9 + ms * 0.1 };
    }

    pub fn has_capacity(&self) -> bool {
        self.state == LinkState::Active && self.in_flight < self.window
    }

    /// Linear free-window headroom. The previous quadratic score
    /// (window² / in_flight) starved the slower link: once one link won a
    /// few rounds in a row, its window kept growing, its score skyrocketed,
    /// and the other link never got picked. Linear "free slots" mirrors
    /// what srtla_send.c does and produces a much more even split.
    ///
    /// `quality` (see `Bond::update_link_quality`) folds in on top of that:
    /// window-based headroom reacts over several round trips, quality reacts
    /// within one eval tick to a link doing relatively worse than its peers.
    pub fn score(&self) -> i64 {
        let headroom = self.window as i64 - self.in_flight as i64;
        (headroom as f64 * self.quality).round() as i64
    }
}

// ─── Bond ─────────────────────────────────────────────────────────────────────
pub struct Bond {
    pub links: Vec<Link>,
    pub group_state: GroupState,
    pub group_id: [u8; SRTLA_ID_LEN],
    pub last_reg1: Instant,
    pub backoff_until: Option<Instant>,
    /// SRT seq → (link index, send time). The heart of the load balancer.
    pkt_log: HashMap<u32, (usize, Instant)>,
    pkt_order: VecDeque<u32>,
    last_stats: Instant,
    last_quality_eval: Instant,
    stat_sent: u64,
    stat_returned: u64,
    stat_overflow: u64,
    stat_dropped: u64,
    stat_nak: u64,
    rr_counter: u32,
}

impl Bond {
    pub fn new() -> Self {
        let mut id = [0u8; SRTLA_ID_LEN];
        rand::thread_rng().fill_bytes(&mut id[..SRTLA_ID_LEN / 2]);
        let mut rr_seed = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut rr_seed);
        Bond {
            links: Vec::new(),
            group_state: GroupState::Unregistered,
            group_id: id,
            last_reg1: Instant::now() - Duration::from_secs(10),
            backoff_until: None,
            pkt_log: HashMap::new(),
            pkt_order: VecDeque::new(),
            last_stats: Instant::now(),
            last_quality_eval: Instant::now(),
            stat_sent: 0,
            stat_returned: 0,
            stat_overflow: 0,
            stat_dropped: 0,
            stat_nak: 0,
            rr_counter: u32::from_le_bytes(rr_seed),
        }
    }

    pub fn add_link(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> std::io::Result<()> {
        self.links.push(Link::new(local_addr, remote_addr)?);
        Ok(())
    }

    fn reset_group(&mut self) {
        rand::thread_rng().fill_bytes(&mut self.group_id[..SRTLA_ID_LEN / 2]);
        self.group_id[SRTLA_ID_LEN / 2..].fill(0);
        self.group_state = GroupState::Unregistered;
        self.pkt_log.clear();
        self.pkt_order.clear();
        for l in &mut self.links {
            l.state = LinkState::Idle;
            l.in_flight = 0;
            l.window = WINDOW_INIT;
            l.rtt_ms = 0.0;
            l.quality = 1.0;
            l.nak_count = 0;
            l.sent_count = 0;
            l.q_prev_nak = 0;
            l.q_prev_sent = 0;
        }
    }

    /// Compares each active link's NAK/sent ratio this interval against the
    /// *best* active link's ratio and penalizes ones doing meaningfully
    /// worse — see the QUALITY_* constants for why this is relative rather
    /// than an absolute threshold.
    pub fn update_link_quality(&mut self, now: Instant) {
        if now.duration_since(self.last_quality_eval) < Duration::from_millis(QUALITY_EVAL_INTERVAL_MS) {
            return;
        }
        self.last_quality_eval = now;

        let mut ratios: Vec<Option<f64>> = Vec::with_capacity(self.links.len());
        for l in &mut self.links {
            let delta_sent = l.sent_count.saturating_sub(l.q_prev_sent);
            let delta_nak  = l.nak_count.saturating_sub(l.q_prev_nak);
            l.q_prev_sent = l.sent_count;
            l.q_prev_nak  = l.nak_count;
            ratios.push(if l.state == LinkState::Active && delta_sent >= QUALITY_MIN_SAMPLE {
                Some(delta_nak as f64 / delta_sent as f64)
            } else {
                None
            });
        }

        let best_ratio = ratios.iter().flatten().cloned().fold(f64::INFINITY, f64::min);
        if !best_ratio.is_finite() {
            return; // no active link had enough traffic this interval to judge
        }

        for (l, ratio) in self.links.iter_mut().zip(ratios) {
            match ratio {
                Some(r) if r > best_ratio * QUALITY_BAD_MULTIPLE + QUALITY_BAD_FLOOR => {
                    l.quality = (l.quality * QUALITY_PENALTY).max(QUALITY_MIN);
                }
                _ => {
                    // In line with (or better than) peers, or too idle to judge this
                    // interval — recover. Idle links recovering is fine: has_capacity()
                    // already gates whether they're picked at all.
                    l.quality = (l.quality + QUALITY_RECOVERY_PER_TICK).min(1.0);
                }
            }
        }
    }

    // ── packet-log helpers ────────────────────────────────────────────────
    fn log_sent(&mut self, seq: u32, link_idx: usize) {
        if let Some((old_idx, _)) = self.pkt_log.insert(seq, (link_idx, Instant::now())) {
            // Retransmission of a still-logged seq on (possibly) another link
            self.links[old_idx].in_flight = self.links[old_idx].in_flight.saturating_sub(1);
        } else {
            self.pkt_order.push_back(seq);
        }
        self.links[link_idx].in_flight += 1;

        while self.pkt_order.len() > PKT_LOG_MAX {
            if let Some(old) = self.pkt_order.pop_front() {
                if let Some((idx, _)) = self.pkt_log.remove(&old) {
                    self.links[idx].in_flight =
                        self.links[idx].in_flight.saturating_sub(1);
                }
            }
        }
    }

    /// Per-sequence ACK from SRTLA receiver.
    /// in_flight is decremented on the link that sent the packet,
    /// but window growth is credited to the link that delivered the ACK
    /// – healthier return paths deserve more trust. This matches srtla_send.c
    /// and is essential when the server's reverse path doesn't mirror our
    /// forward path (which is the rule, not the exception).
    fn ack_seq(&mut self, seq: u32, recv_link: usize) {
        if let Some((idx, sent_at)) = self.pkt_log.remove(&seq) {
            self.links[idx].in_flight = self.links[idx].in_flight.saturating_sub(1);
            self.links[idx].sample_rtt(sent_at.elapsed().as_secs_f64() * 1000.0);
        }
        self.links[recv_link].grow_window();
    }

    /// Cumulative SRT ACK: everything strictly below `upto` arrived.
    /// Grows the receive link's window once per ACK event.
    fn ack_below(&mut self, upto: u32, recv_link: usize) {
        let mut credited: Vec<(usize, Instant)> = Vec::new();
        self.pkt_log.retain(|&seq, &mut (idx, sent_at)| {
            if seq_lt(seq, upto) {
                credited.push((idx, sent_at));
                false
            } else {
                true
            }
        });
        for (idx, sent_at) in credited {
            self.links[idx].in_flight = self.links[idx].in_flight.saturating_sub(1);
            self.links[idx].sample_rtt(sent_at.elapsed().as_secs_f64() * 1000.0);
        }
        self.links[recv_link].grow_window();
    }

    fn nak_seq(&mut self, seq: u32) {
        self.stat_nak += 1;
        if let Some(&(idx, _)) = self.pkt_log.get(&seq) {
            self.links[idx].shrink_window();
            self.links[idx].nak_count += 1;
        }
    }

    fn purge_stale_log(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_millis(PKT_LOG_TIMEOUT_MS);
        let mut released: Vec<usize> = Vec::new();
        self.pkt_log.retain(|_, &mut (idx, t)| {
            if now.duration_since(t) > timeout {
                released.push(idx);
                false
            } else {
                true
            }
        });
        for idx in released {
            self.links[idx].in_flight = self.links[idx].in_flight.saturating_sub(1);
        }
    }

    // ── receive path ──────────────────────────────────────────────────────
    /// Poll all link sockets. Handles SRTLA control internally; returns SRT
    /// return traffic to forward back to the local SRT caller.
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let mut buf = [0u8; 2048];
        let mut return_traffic = Vec::new();
        let mut got_group_reg2 = false;
        let mut got_ngp = false;
        let mut got_nak = false;
        let mut got_err = false;

        for i in 0..self.links.len() {
            loop {
                let res = self.links[i].socket.recv_from(&mut buf);
                match res {
                    Ok((n, _)) if n >= 2 => {
                        self.links[i].last_rx = Instant::now();
                        let pkt_owned = buf[..n].to_vec();
                        let pkt = pkt_owned.as_slice();
                        match pkt_type(pkt) {
                            Some(SRTLA_TYPE_REG2) if n >= REG2_LEN => {
                                if pkt[2..2 + SRTLA_ID_LEN / 2]
                                    == self.group_id[..SRTLA_ID_LEN / 2]
                                {
                                    self.group_id
                                        .copy_from_slice(&pkt[2..2 + SRTLA_ID_LEN]);
                                    got_group_reg2 = true;
                                    gst::info!(CAT, "Group registered (REG2 received)");
                                }
                            }
                            Some(SRTLA_TYPE_REG3) => {
                                if self.links[i].state != LinkState::Active {
                                    gst::info!(
                                        CAT, "Link {} active (REG3)",
                                        self.links[i].local_addr
                                    );
                                }
                                self.links[i].state = LinkState::Active;
                            }
                            Some(SRTLA_TYPE_KEEPALIVE) => {}
                            Some(SRTLA_TYPE_ACK) => {
                                // 4-byte header, then u32 seq numbers
                                let mut off = 4;
                                while off + 4 <= n {
                                    let seq = u32::from_be_bytes([
                                        pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3],
                                    ]) & 0x7FFF_FFFF;
                                    self.ack_seq(seq, i);
                                    off += 4;
                                }
                            }
                            Some(SRTLA_TYPE_REG_NGP) => got_ngp = true,
                            Some(SRTLA_TYPE_REG_NAK) => got_nak = true,
                            Some(SRTLA_TYPE_REG_ERR) => got_err = true,
                            Some(t) => {
                                // SRT traffic → reverse path + bookkeeping
                                self.stat_returned += 1;
                                if t == SRT_TYPE_ACK && n >= 20 {
                                    // SRT ACK CIF: last acked seq + 1 at offset 16
                                    let upto = u32::from_be_bytes([
                                        pkt[16], pkt[17], pkt[18], pkt[19],
                                    ]) & 0x7FFF_FFFF;
                                    self.ack_below(upto, i);
                                } else if t == SRT_TYPE_NAK && n >= 20 {
                                    // SRT NAK CIF: loss list of u32s from offset 16.
                                    // Top bit set = range start, next u32 = range end.
                                    let mut off = 16;
                                    while off + 4 <= n {
                                        let v = u32::from_be_bytes([
                                            pkt[off], pkt[off + 1],
                                            pkt[off + 2], pkt[off + 3],
                                        ]);
                                        if v & 0x8000_0000 != 0 && off + 8 <= n {
                                            let start = v & 0x7FFF_FFFF;
                                            let end = u32::from_be_bytes([
                                                pkt[off + 4], pkt[off + 5],
                                                pkt[off + 6], pkt[off + 7],
                                            ]) & 0x7FFF_FFFF;
                                            let mut s = start;
                                            let mut guard = 0;
                                            loop {
                                                self.nak_seq(s);
                                                if s == end || guard > 4096 {
                                                    break;
                                                }
                                                s = (s + 1) & 0x7FFF_FFFF;
                                                guard += 1;
                                            }
                                            off += 8;
                                        } else {
                                            self.nak_seq(v & 0x7FFF_FFFF);
                                            off += 4;
                                        }
                                    }
                                }
                                return_traffic.push(pkt_owned);
                            }
                            None => {}
                        }
                    }
                    _ => break,
                }
            }
        }

        if got_group_reg2 && self.group_state != GroupState::Registered {
            self.group_state = GroupState::Registered;
            let id = self.group_id;
            for link in &mut self.links {
                let _ = link.send_reg2(&id);
            }
        }
        if got_ngp {
            gst::warning!(CAT, "REG_NGP: invalid group ID, re-registering");
            self.reset_group();
        }
        if got_err {
            gst::warning!(CAT, "REG_ERR: backing off {}ms", REG_ERR_BACKOFF_MS);
            self.backoff_until =
                Some(Instant::now() + Duration::from_millis(REG_ERR_BACKOFF_MS));
        }
        if got_nak {
            gst::error!(CAT, "REG_NAK: registration refused, giving up");
            self.group_state = GroupState::Refused;
        }

        return_traffic
    }

    // ── maintenance ───────────────────────────────────────────────────────
    pub fn tick(&mut self) {
        let now = Instant::now();

        self.purge_stale_log();
        self.update_link_quality(now);

        if now.duration_since(self.last_stats) > Duration::from_secs(3) {
            self.last_stats = now;
            gst::info!(
                CAT,
                "stats: sent={} returned={} naks={} overflow={} dropped={} log={}",
                self.stat_sent, self.stat_returned, self.stat_nak,
                self.stat_overflow, self.stat_dropped, self.pkt_log.len()
            );
            for l in &self.links {
                gst::info!(
                    CAT,
                    "  link {}: state={:?} window={} in_flight={} rtt_ms={:.1} quality={:.2}",
                    l.local_addr, l.state, l.window, l.in_flight, l.rtt_ms, l.quality
                );
            }
        }

        if let Some(t) = self.backoff_until {
            if now < t {
                return;
            }
            self.backoff_until = None;
        }

        match self.group_state {
            GroupState::Refused => {}
            GroupState::Unregistered | GroupState::Reg1Sent => {
                if now.duration_since(self.last_reg1)
                    > Duration::from_millis(REG_TIMEOUT_MS)
                {
                    let id = self.group_id;
                    if let Some(link) = self.links.first_mut() {
                        if link.send_reg1(&id).is_ok() {
                            gst::debug!(CAT, "REG1 sent on {}", link.local_addr);
                            self.group_state = GroupState::Reg1Sent;
                            self.last_reg1 = now;
                        }
                    }
                }
            }
            GroupState::Registered => {
                let id = self.group_id;
                for link in &mut self.links {
                    match link.state {
                        LinkState::Idle | LinkState::Down => {
                            let _ = link.send_reg2(&id);
                        }
                        LinkState::Reg2Sent => {
                            if now.duration_since(link.last_reg_sent)
                                > Duration::from_millis(REG_TIMEOUT_MS)
                            {
                                let _ = link.send_reg2(&id);
                            }
                        }
                        LinkState::Active => {
                            if now.duration_since(link.last_keepalive_tx)
                                > Duration::from_millis(KEEPALIVE_INTERVAL_MS)
                            {
                                let _ = link.send_keepalive();
                            }
                            if now.duration_since(link.last_rx)
                                > Duration::from_millis(LINK_TIMEOUT_MS)
                            {
                                gst::warning!(CAT, "Link {} timed out", link.local_addr);
                                link.state = LinkState::Down;
                                link.in_flight = 0;
                                link.window = WINDOW_INIT;
                                link.quality = 1.0;
                            }
                        }
                    }
                }
            }
        }
    }

    // ── send path ─────────────────────────────────────────────────────────
    /// Stochastic weighted link selection. Greedy "always pick the best link"
    /// produces bursty oscillation: a slight transient advantage of one link
    /// makes the scheduler send dozens of consecutive packets there, causing
    /// reordering at the receiver and NAK storms.
    ///
    /// We instead pick proportionally to the free-window headroom of each
    /// link – every active link with capacity has a chance to be chosen on
    /// every packet. This produces smoothly interleaved traffic, which is
    /// what srtla_send does and what SRT's reordering needs.
    pub fn pick_link(&mut self) -> Option<usize> {
        let weights: Vec<i64> = self
            .links
            .iter()
            .map(|l| if l.has_capacity() { l.score().max(1) } else { 0 })
            .collect();
        let total: i64 = weights.iter().sum();
        if total <= 0 {
            return None;
        }
        // Deterministic pseudo-random: cycle a counter and modulo by total.
        // This avoids the cost of a real RNG per packet while still
        // interleaving links proportionally.
        self.rr_counter = self.rr_counter.wrapping_add(2654435761); // golden-ratio hash
        let pick = (self.rr_counter as i64).rem_euclid(total);
        let mut acc: i64 = 0;
        for (i, w) in weights.iter().enumerate() {
            acc += *w;
            if pick < acc {
                return Some(i);
            }
        }
        None
    }

    pub fn send(&mut self, data: &[u8]) -> bool {
        let Some(idx) = self.pick_link() else {
            self.stat_dropped += 1;
            return false;
        };
        let _ = self.links[idx].socket.send_to(data, self.links[idx].remote_addr);
        self.links[idx].last_sent = Instant::now();
        self.links[idx].sent_count += 1;
        self.stat_sent += 1;

        // Log SRT data packets (bit 31 of first u32 clear) for per-link
        // in-flight accounting.
        if data.len() >= 16 && data[0] & 0x80 == 0 {
            let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]])
                & 0x7FFF_FFFF;
            self.log_sent(seq, idx);
        }
        true
    }

    pub fn active_count(&self) -> usize {
        self.links.iter().filter(|l| l.state == LinkState::Active).count()
    }

    /// Snapshot of aggregate + per-link bond stats as a GstStructure, for
    /// external consumers (e.g. the "stats" element property) to read.
    /// Per-link details are packed as a hand-rolled JSON array string rather
    /// than a nested GstStructure array, since addresses/debug-formatted
    /// states never contain characters needing escaping.
    pub fn stats_structure(&self) -> gst::Structure {
        let links_json = {
            let parts: Vec<String> = self
                .links
                .iter()
                .map(|l| {
                    format!(
                        r#"{{"address":"{}","state":"{:?}","window":{},"in_flight":{},"rtt_ms":{:.1},"quality":{:.2}}}"#,
                        l.local_addr, l.state, l.window, l.in_flight, l.rtt_ms, l.quality
                    )
                })
                .collect();
            format!("[{}]", parts.join(","))
        };

        // Aggregate RTT: the fastest currently-active path, mirroring
        // belacoder's `rttMin` baseline — the healthiest link sets the floor
        // that increases are judged against.
        let rtt_ms_agg = self
            .links
            .iter()
            .filter(|l| l.state == LinkState::Active && l.rtt_ms > 0.0)
            .map(|l| l.rtt_ms)
            .fold(f64::INFINITY, f64::min);
        let rtt_ms_agg = if rtt_ms_agg.is_finite() { rtt_ms_agg } else { 0.0 };

        gst::Structure::builder("stats")
            .field("sent", self.stat_sent)
            .field("returned", self.stat_returned)
            .field("overflow", self.stat_overflow)
            .field("dropped", self.stat_dropped)
            .field("naks", self.stat_nak)
            .field("rtt-ms", rtt_ms_agg)
            .field("links-json", links_json)
            .build()
    }
}

use once_cell::sync::Lazy;
pub static CAT: Lazy<gst::DebugCategory> = Lazy::new(|| {
    gst::DebugCategory::new(
        "srtlasink",
        gst::DebugColorFlags::empty(),
        Some("SRTLA Sink"),
    )
});
