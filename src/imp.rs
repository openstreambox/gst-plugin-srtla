/// gst-plugin-srtla – srtlasink as a GstBin
///
/// The element wraps an internal `srtsink` (from gst-plugins-bad) and a
/// SRTLA bonding proxy. Externally it looks like a single sink:
///
///   ┌─────────────────── srtlasink (GstBin) ───────────────────┐
///   │  ghost "sink" → [srtsink → srt://127.0.0.1:<ephemeral>]  │
///   │                        │ SRT/UDP loopback                │
///   │                  [bond proxy thread]                     │
///   │                   ├── link 10.203.90.145 ──► receiver    │
///   │                   └── link 192.168.178.161 ► receiver    │
///   └───────────────────────────────────────────────────────────┘
///
/// Pipeline example:
///   ... ! mpegtsmux ! srtlasink host=example.com port=5000 \
///         streamid=publish/live/feed1 latency=2000 \
///         local-addrs="10.0.0.2,192.168.1.2"

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use glib::prelude::*;
use glib::subclass::prelude::*;
use gst::prelude::*;
use gst::subclass::prelude::*;
use once_cell::sync::Lazy;

use crate::srtla::{Bond, CAT};

// ─── Defaults ─────────────────────────────────────────────────────────────────
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u32 = 5000;
const DEFAULT_LOCAL_ADDRS: &str = "";
const DEFAULT_LATENCY: u32 = 2000;
const DEFAULT_STREAMID: &str = "";
const DEFAULT_PASSPHRASE: &str = "";

#[derive(Debug, Clone)]
struct Settings {
    host: String,
    port: u32,
    local_addrs: String,
    latency: u32,
    streamid: String,
    passphrase: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            host: DEFAULT_HOST.into(),
            port: DEFAULT_PORT,
            local_addrs: DEFAULT_LOCAL_ADDRS.into(),
            latency: DEFAULT_LATENCY,
            streamid: DEFAULT_STREAMID.into(),
            passphrase: DEFAULT_PASSPHRASE.into(),
        }
    }
}

struct State {
    stop_flag: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Default)]
pub struct SrtlaSink {
    settings: Mutex<Settings>,
    state: Mutex<Option<State>>,
    srtsink: Mutex<Option<gst::Element>>,
    bond: Mutex<Option<Arc<Mutex<Bond>>>>,
}

#[glib::object_subclass]
impl ObjectSubclass for SrtlaSink {
    const NAME: &'static str = "GstSrtlaSink";
    type Type = super::SrtlaSink;
    type ParentType = gst::Bin;
}

impl ObjectImpl for SrtlaSink {
    fn constructed(&self) {
        self.parent_constructed();
        let obj = self.obj();

        // Internal SRT caller – does all SRT protocol work for us.
        let srtsink = gst::ElementFactory::make("srtsink")
            .name("srtla-internal-srtsink")
            .build()
            .expect("srtsink element not found – install gst-plugins-bad");
        srtsink.set_property("wait-for-connection", false);

        obj.add(&srtsink).unwrap();

        // Expose srtsink's sink pad as our own ghost "sink" pad.
        let target = srtsink.static_pad("sink").unwrap();
        let ghost = gst::GhostPad::builder_with_target(&target)
            .unwrap()
            .name("sink")
            .build();
        obj.add_pad(&ghost).unwrap();

        obj.set_element_flags(gst::ElementFlags::SINK);

        *self.srtsink.lock().unwrap() = Some(srtsink);
    }

    fn properties() -> &'static [glib::ParamSpec] {
        static PROPS: Lazy<Vec<glib::ParamSpec>> = Lazy::new(|| {
            vec![
                glib::ParamSpecString::builder("host")
                    .nick("Host")
                    .blurb("SRTLA receiver hostname or IP address")
                    .default_value(Some(DEFAULT_HOST))
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("port")
                    .nick("Port")
                    .blurb("SRTLA receiver UDP port")
                    .minimum(1)
                    .maximum(65535)
                    .default_value(DEFAULT_PORT)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("local-addrs")
                    .nick("Local addresses")
                    .blurb("Comma-separated local IPs to bond (empty = default route)")
                    .default_value(Some(DEFAULT_LOCAL_ADDRS))
                    .mutable_ready()
                    .build(),
                glib::ParamSpecUInt::builder("latency")
                    .nick("Latency")
                    .blurb("SRT latency in milliseconds")
                    .minimum(20)
                    .maximum(60_000)
                    .default_value(DEFAULT_LATENCY)
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("streamid")
                    .nick("Stream ID")
                    .blurb("SRT stream ID, e.g. publish/live/feed1")
                    .default_value(Some(DEFAULT_STREAMID))
                    .mutable_ready()
                    .build(),
                glib::ParamSpecString::builder("passphrase")
                    .nick("Passphrase")
                    .blurb("SRT encryption passphrase (empty = no encryption)")
                    .default_value(Some(DEFAULT_PASSPHRASE))
                    .mutable_ready()
                    .build(),
                glib::ParamSpecBoxed::builder::<gst::Structure>("stats")
                    .nick("Bond Statistics")
                    .blurb("Current SRTLA bond statistics (aggregate + per-link) as a GstStructure")
                    .read_only()
                    .build(),
            ]
        });
        PROPS.as_ref()
    }

    fn set_property(&self, _id: usize, value: &glib::Value, pspec: &glib::ParamSpec) {
        let mut s = self.settings.lock().unwrap();
        match pspec.name() {
            "host" => s.host = value.get().unwrap(),
            "port" => s.port = value.get().unwrap(),
            "local-addrs" => s.local_addrs = value.get().unwrap(),
            "latency" => s.latency = value.get().unwrap(),
            "streamid" => s.streamid = value.get().unwrap(),
            "passphrase" => s.passphrase = value.get().unwrap(),
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
        if pspec.name() == "stats" {
            let bond_guard = self.bond.lock().unwrap();
            let structure = match bond_guard.as_ref() {
                Some(bond) => bond.lock().unwrap().stats_structure(),
                None => gst::Structure::builder("stats")
                    .field("sent", 0u64)
                    .field("returned", 0u64)
                    .field("overflow", 0u64)
                    .field("dropped", 0u64)
                    .field("naks", 0u64)
                    .field("rtt-ms", 0.0f64)
                    .field("links-json", "[]")
                    .build(),
            };
            return structure.to_value();
        }

        let s = self.settings.lock().unwrap();
        match pspec.name() {
            "host" => s.host.to_value(),
            "port" => s.port.to_value(),
            "local-addrs" => s.local_addrs.to_value(),
            "latency" => s.latency.to_value(),
            "streamid" => s.streamid.to_value(),
            "passphrase" => s.passphrase.to_value(),
            _ => unimplemented!(),
        }
    }
}

impl GstObjectImpl for SrtlaSink {}

impl ElementImpl for SrtlaSink {
    fn metadata() -> Option<&'static gst::subclass::ElementMetadata> {
        static META: Lazy<gst::subclass::ElementMetadata> = Lazy::new(|| {
            gst::subclass::ElementMetadata::new(
                "SRTLA Sink",
                "Sink/Network",
                "Sends an SRT stream over SRTLA (link bonding)",
                "Alexander Kettner <alexander@arv-live.de>",
            )
        });
        Some(&*META)
    }

    fn pad_templates() -> &'static [gst::PadTemplate] {
        static TEMPLATES: Lazy<Vec<gst::PadTemplate>> = Lazy::new(|| {
            let caps = gst::Caps::new_any();
            vec![gst::PadTemplate::new(
                "sink",
                gst::PadDirection::Sink,
                gst::PadPresence::Always,
                &caps,
            )
            .unwrap()]
        });
        TEMPLATES.as_ref()
    }

    fn change_state(
        &self,
        transition: gst::StateChange,
    ) -> Result<gst::StateChangeSuccess, gst::StateChangeError> {
        if transition == gst::StateChange::NullToReady {
            self.start_bond().map_err(|e| {
                gst::element_imp_error!(
                    self,
                    gst::ResourceError::OpenWrite,
                    ["Failed to start SRTLA bond: {}", e]
                );
                gst::StateChangeError
            })?;
        }

        let res = self.parent_change_state(transition)?;

        if transition == gst::StateChange::ReadyToNull {
            self.stop_bond();
        }
        Ok(res)
    }
}

impl BinImpl for SrtlaSink {}

impl SrtlaSink {
    fn start_bond(&self) -> Result<(), String> {
        let settings = self.settings.lock().unwrap().clone();

        gst::info!(
            CAT, imp = self,
            "Starting SRTLA bond → {}:{}", settings.host, settings.port
        );

        // Resolve remote
        let remote_str = format!("{}:{}", settings.host, settings.port);
        let remote_addr: SocketAddr = remote_str
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {}: {}", remote_str, e))?
            .next()
            .ok_or_else(|| format!("no addresses for {}", remote_str))?;

        // Parse local addresses
        let local_addrs: Vec<SocketAddr> = if settings.local_addrs.trim().is_empty() {
            vec!["0.0.0.0:0".parse().unwrap()]
        } else {
            settings
                .local_addrs
                .split(',')
                .map(|s| {
                    let s = s.trim();
                    let with_port =
                        if s.contains(':') { s.to_string() } else { format!("{}:0", s) };
                    with_port
                        .parse::<SocketAddr>()
                        .map_err(|e| format!("invalid local address '{}': {}", with_port, e))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        gst::info!(CAT, imp = self, "Bonding {} link(s)", local_addrs.len());

        let mut bond = Bond::new();
        for la in local_addrs {
            bond.add_link(la, remote_addr)
                .map_err(|e| format!("cannot bind {}: {}", la, e))?;
            gst::debug!(CAT, imp = self, "Link added: {} → {}", la, remote_addr);
        }
        bond.tick(); // send REG1 immediately

        // Local proxy on an ephemeral loopback port
        let proxy_sock = UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| format!("cannot bind proxy socket: {}", e))?;
        proxy_sock
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let proxy_port = proxy_sock.local_addr().unwrap().port();

        // Point the internal srtsink at the proxy
        let mut uri = format!(
            "srt://127.0.0.1:{}?mode=caller&latency={}",
            proxy_port, settings.latency
        );
        if !settings.streamid.is_empty() {
            uri.push_str(&format!("&streamid={}", settings.streamid));
        }
        if !settings.passphrase.is_empty() {
            uri.push_str(&format!("&passphrase={}", settings.passphrase));
        }
        gst::info!(CAT, imp = self, "Internal SRT URI: {}", uri);

        let srtsink_guard = self.srtsink.lock().unwrap();
        let srtsink = srtsink_guard.as_ref().ok_or("internal srtsink missing")?;
        srtsink.set_property("uri", &uri);
        drop(srtsink_guard);

        // Worker thread: maintenance, proxy forwarding, reverse path
        let bond = Arc::new(Mutex::new(bond));
        *self.bond.lock().unwrap() = Some(Arc::clone(&bond));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker = {
            let bond = Arc::clone(&bond);
            let stop = Arc::clone(&stop_flag);
            std::thread::Builder::new()
                .name("srtla-worker".into())
                .spawn(move || {
                    let mut caller_addr: Option<SocketAddr> = None;
                    let mut buf = [0u8; 2048];

                    while !stop.load(Ordering::Relaxed) {
                        // Maintenance + collect SRT return traffic
                        let return_traffic = {
                            let mut b = bond.lock().unwrap();
                            b.tick();
                            b.poll()
                        };

                        // Reverse path → local SRT caller
                        if let Some(addr) = caller_addr {
                            for pkt in &return_traffic {
                                let _ = proxy_sock.send_to(pkt, addr);
                            }
                        }

                        // Forward path: local SRT caller → bond
                        for _ in 0..256 {
                            match proxy_sock.recv_from(&mut buf) {
                                Ok((n, from)) => {
                                    caller_addr = Some(from);
                                    let mut b = bond.lock().unwrap();
                                    b.send(&buf[..n]);
                                }
                                Err(_) => break, // timeout / would-block
                            }
                        }
                    }
                })
                .map_err(|e| format!("cannot spawn worker: {}", e))?
        };

        *self.state.lock().unwrap() = Some(State {
            stop_flag,
            worker: Some(worker),
        });
        Ok(())
    }

    fn stop_bond(&self) {
        gst::info!(CAT, imp = self, "Stopping SRTLA bond");
        if let Some(mut s) = self.state.lock().unwrap().take() {
            s.stop_flag.store(true, Ordering::Relaxed);
            if let Some(h) = s.worker.take() {
                let _ = h.join();
            }
        }
        *self.bond.lock().unwrap() = None;
    }
}
