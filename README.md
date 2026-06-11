# gst-plugin-srtla

GStreamer SRTLA Sink Plugin in Rust – for link bonding on devices like the Radxa Rock 5B+.

The plugin presents itself as a single GStreamer sink element (`srtlasink`)
that internally wraps an `srtsink` and an SRTLA bonding proxy. Plug it in,
configure your local link IPs, and you have multi-WAN SRT streaming.

## Architecture

```
┌─────────────────── srtlasink (GstBin) ───────────────────┐
│  ghost "sink" → [srtsink → srt://127.0.0.1:<ephemeral>]  │
│                        │ SRT/UDP loopback                │
│                  [bond proxy thread]                     │
│                   ├── link 10.x.x.x (LTE)  ──► receiver  │
│                   └── link 192.168.x.x (DSL) ► receiver  │
└───────────────────────────────────────────────────────────┘
```

## Building

```bash
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev pkg-config
cargo build --release
```

## Permanent installation

```bash
# System-wide
sudo cp target/release/libgstsrtla.so \
  /usr/lib/aarch64-linux-gnu/gstreamer-1.0/
rm -rf ~/.cache/gstreamer-1.0/
sudo rm -rf /root/.cache/gstreamer-1.0/

# Verify
gst-inspect-1.0 srtlasink
```

## Properties

| Property | Type | Default | Description |
|---|---|---|---|
| `host` | string | 127.0.0.1 | SRTLA receiver hostname/IP |
| `port` | uint | 5000 | SRTLA receiver UDP port |
| `local-addrs` | string | "" | Comma-separated local IPs to bond |
| `latency` | uint | 2000 | SRT latency (ms) |
| `streamid` | string | "" | SRT stream ID (e.g. `publish/live/feed1`) |
| `passphrase` | string | "" | SRT encryption passphrase |

## Example pipeline (Rock 5B+ with hardware H.265)

```bash
GST_DEBUG=srtlasink:4 gst-launch-1.0 -e \
  v4l2src device=/dev/video0 ! \
  queue ! \
  mpph265enc zero-copy-pkt=0 qp-max=51 gop=120 \
    bps=6000000 bps-max=6500000 rc-mode=cbr ! \
  h265parse config-interval=-1 ! \
  queue ! mux. \
  alsasrc device=hw:CARD=rockchiphdmiin ! \
  audioconvert ! voaacenc bitrate=128000 ! aacparse ! \
  queue ! mux. \
  mpegtsmux name=mux alignment=7 ! \
  tsparse set-timestamps=true ! \
  srtlasink host=your-server.example.com port=5000 \
    streamid=publish/live/feed1 latency=2500 \
    local-addrs="10.0.0.2,192.168.1.2"
```

**Important pipeline notes:**

- `mpegtsmux alignment=7` packs 7 TS packets (= 1316 bytes) per buffer,
  matching the SRT MTU.
- `tsparse set-timestamps=true` is **essential** – without it, the internal
  `srtsink` drops PAT/PMT header buffers and the receiver can't decode.

## Multi-WAN policy routing (Linux)

Binding a socket to a local IP does **not** force traffic through that
interface on Linux – the routing table decides. Set up separate routing
tables per link:

## Diagnostics

With `GST_DEBUG=srtlasink:4`, the bond logs per-link statistics every 3 seconds:


Healthy bond:
- `sent` close to (encoder bitrate × interval) / 1316 bytes
- `returned` continuously growing (SRT ACKs from server)
- `naks` low (< 100 per interval after warmup)
- `dropped` zero after warmup
- Both link windows in similar range, both `in_flight` non-zero

## Protocol

The plugin implements the BELABOX srtla2 wire format on the sender side:

| Type | Code | Direction | Payload |
|---|---|---|---|
| KEEPALIVE | 0x9000 | both | empty, every 1s |
| ACK | 0x9100 | receiver→sender | 4-byte header + u32 SRT seq list |
| REG1 | 0x9200 | sender→receiver | 256-byte ID (half random) |
| REG2 | 0x9201 | both | 256-byte completed ID |
| REG3 | 0x9202 | receiver→sender | empty, confirms link |
| REG_ERR | 0x9210 | receiver→sender | back off and retry |
| REG_NGP | 0x9211 | receiver→sender | invalid group ID |
| REG_NAK | 0x9212 | receiver→sender | registration refused |

Load balancing uses per-sequence-number tracking (every outgoing SRT seq is
logged with the link that carried it) plus weighted round robin across all
links proportional to free window headroom. SRT ACKs from the server grow
the window of the *receiving* link (not the sending link) – this matches
`srtla_send.c` and is essential when the server's reverse path doesn't
mirror the forward path.

## License

MIT

## Author

Alexander Kettner <alexander@arv-live.de>
[ARV-Live](https://github.com/ARV-Live)
