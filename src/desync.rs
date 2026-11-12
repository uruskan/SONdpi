//! Desync strategies.
//!
//! Pure logic: given one outbound TCP packet that starts a TLS ClientHello or an HTTP request,
//! produce the packets to send instead (fakes first, then the real data in fragments).
//!
//! # Spec strings
//!
//! A [`Strategy`] round-trips through a compact, comma-separated `key=value` string. Keys may
//! appear in any order; omitted keys take the [`Default`] value; unknown or repeated keys are
//! an error; whitespace around items is ignored. [`Strategy::to_spec`] always writes every key
//! in the order below.
//!
//! | key      | values | meaning |
//! |----------|--------|---------|
//! | `fake`   | `none`, or one or more of `ttl`, `badsum`, `badseq` joined by `+` | how the fake request is kept away from the server: TTL that expires before the server, a wrong TCP checksum, a sequence number (and ack) in the past |
//! | `ttl`    | `N` (1-255) or `auto:SUB:MIN:MAX` (`auto` alone = `auto:4:3:12`) | TTL of TTL-fooled fakes: fixed, or `clamp(hops - SUB, MIN, MAX)` from the server's hop distance |
//! | `sni`    | host name (letters, digits, `.`, `-`, `_`; 1-253 bytes) | SNI / Host carried by the fake |
//! | `repeat` | 1-16 | copies of the fake |
//! | `split`  | `none`, `sni`, `sni-mid`, or a byte offset 1-65535 | where the real payload is cut: not at all, at the start of the SNI / Host value, in the middle of it, or at a fixed offset |
//! | `order`  | `in`, `reverse` | send the real fragments in order or the second part first |
//! | `http`   | `0`, `1` | whether plain HTTP requests are handled (TLS always is) |
//!
//! Default (the configuration measured to work on the test line):
//! `fake=ttl,ttl=auto:4:3:12,sni=www.google.com,repeat=1,split=sni-mid,order=reverse,http=1`.
//!
//! # Fake TTL safety
//!
//! A fake that reaches the server breaks the connection. So when the server's hop distance
//! is known, every TTL-fooled fake is capped at `hops - 1` (one hop of margin for asymmetric
//! paths), fixed policy included; with `auto` and an unknown hop distance no TTL-only fake is
//! sent (a fake that is also `badsum`/`badseq` is still sent, with the original TTL, because
//! the server discards it anyway). See [`Strategy::fake_ttl`].

use std::fmt::Write as _;
use std::ops::Range;

use crate::packet::{Packet, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
use crate::tls;

/// WinDivert filter sub-expression matching the outbound TCP packets `apply` cares about
/// (payload starts a TLS ClientHello or an HTTP request). The engine wraps it with direction,
/// loopback and address conditions.
///
/// WinDivert 2.x semantics relied on: `tcp.Payload[i]` / `tcp.Payload16[i]` /
/// `tcp.Payload32[i]` are the i-th 8/16/32-bit *word* of the payload (word index, not byte
/// index) read in network byte order, and a test whose index is out of bounds fails, so short
/// payloads never match. Constants are decimal to avoid any doubt about hex literal syntax.
///
/// - TLS: byte 0 = 22 (handshake), byte 1 = 3, byte 2 <= 4, byte 5 = 1 (ClientHello).
/// - HTTP: the payload starts with `GET `, `POST `, `HEAD `, `PUT `, `DELETE `, `OPTIONS `,
///   `PATCH ` or `CONNECT ` (32-bit words below are those ASCII bytes big-endian; the unit
///   tests recompute every number from the method names).
pub const FILTER: &str = "(tcp.Payload[0] == 22 and tcp.Payload[1] == 3 and tcp.Payload[2] <= 4 and tcp.Payload[5] == 1) or \
tcp.Payload32[0] == 1195725856 or \
(tcp.Payload32[0] == 1347375956 and tcp.Payload[4] == 32) or \
(tcp.Payload32[0] == 1212498244 and tcp.Payload[4] == 32) or \
tcp.Payload32[0] == 1347769376 or \
(tcp.Payload32[0] == 1145392197 and tcp.Payload16[2] == 21573 and tcp.Payload[6] == 32) or \
(tcp.Payload32[0] == 1330664521 and tcp.Payload32[1] == 1330533152) or \
(tcp.Payload32[0] == 1346458691 and tcp.Payload16[2] == 18464) or \
(tcp.Payload32[0] == 1129270862 and tcp.Payload32[1] == 1162040352)";

/// HTTP request methods recognised by [`FILTER`] and [`parse_http_request`], each followed by
/// a space.
pub const HTTP_METHODS: [&str; 8] = ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "];

/// How the fake request is kept from being accepted by the server. Flags combine; all false
/// means no fake is sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fooling {
    /// TTL / hop limit from the [`TtlPolicy`], so the fake expires after the DPI but before the
    /// server. The method measured to work.
    pub ttl: bool,
    /// Deliberately wrong TCP checksum.
    pub bad_checksum: bool,
    /// Sequence number 10000 and ack number 66000 in the past.
    pub bad_seq: bool,
}

impl Fooling {
    pub const NONE: Fooling = Fooling { ttl: false, bad_checksum: false, bad_seq: false };
    pub const TTL: Fooling = Fooling { ttl: true, bad_checksum: false, bad_seq: false };

    /// True when a fake is sent at all.
    pub fn any(&self) -> bool {
        self.ttl || self.bad_checksum || self.bad_seq
    }
}

/// TTL of TTL-fooled fakes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TtlPolicy {
    /// Always this value (still capped below the server when its distance is known).
    Fixed(u8),
    /// `clamp(hops - sub, min, max)` from the server's hop distance; no TTL-only fake when the
    /// distance is unknown.
    Auto { sub: u8, min: u8, max: u8 },
}

/// Where the real payload is cut in two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SplitPos {
    /// Not cut (only `max_payload` may still segment it).
    None,
    /// At this payload offset (no cut when the payload is not longer than that).
    Offset(u16),
    /// At the first byte of the SNI / Host value.
    SniStart,
    /// In the middle of the SNI / Host value, so neither part holds the whole name.
    SniMid,
}

/// Order of the two real parts on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Order {
    InOrder,
    /// Second part first, then the first part.
    Reversed,
}

/// Offset used for `sni` / `sni-mid` when the name is not inside this segment (or too short).
pub const FALLBACK_SPLIT: usize = 2;

/// How far `bad_seq` moves the fake's sequence and acknowledgment numbers into the past.
pub const BAD_SEQ_DELTA: u32 = 10_000;
pub const BAD_ACK_DELTA: u32 = 66_000;

/// A complete description of how to desync one request. Round-trips through a spec string so
/// it can be passed on the command line, stored in the registry and shown in the tray.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Strategy {
    /// Fake packet fooling; [`Fooling::NONE`] = split only.
    pub fake: Fooling,
    /// TTL of fakes when `fake.ttl` is on.
    pub ttl: TtlPolicy,
    /// Host name carried by the fake (TLS SNI or HTTP Host).
    pub fake_host: String,
    /// Copies of the fake (1-16).
    pub repeat: u8,
    /// Where the real payload is cut.
    pub split: SplitPos,
    /// Order of the real parts.
    pub order: Order,
    /// Handle plain HTTP requests too.
    pub http: bool,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy {
            fake: Fooling::TTL,
            ttl: TtlPolicy::Auto { sub: 4, min: 3, max: 12 },
            fake_host: "www.google.com".to_string(),
            repeat: 1,
            split: SplitPos::SniMid,
            order: Order::Reversed,
            http: true,
        }
    }
}

fn parse_u8(v: &str, what: &str) -> Result<u8, String> {
    v.parse::<u8>().map_err(|_| format!("{what}: '{v}' is not a number 0-255"))
}

fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

impl Strategy {
    /// Parse a spec string (grammar in the module docs). The empty string is the default.
    pub fn from_spec(spec: &str) -> Result<Strategy, String> {
        let mut s = Strategy::default();
        let mut seen: Vec<&str> = Vec::new();
        for item in spec.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let (k, v) = item.split_once('=').ok_or_else(|| format!("'{item}' is not key=value"))?;
            let (k, v) = (k.trim(), v.trim());
            if seen.contains(&k) {
                return Err(format!("key '{k}' given twice"));
            }
            match k {
                "fake" => {
                    s.fake = Fooling::NONE;
                    if v != "none" {
                        for f in v.split('+') {
                            match f.trim() {
                                "ttl" => s.fake.ttl = true,
                                "badsum" => s.fake.bad_checksum = true,
                                "badseq" => s.fake.bad_seq = true,
                                o => return Err(format!("fake: unknown method '{o}' (ttl, badsum, badseq, none)")),
                            }
                        }
                    }
                }
                "ttl" => {
                    s.ttl = if v == "auto" {
                        TtlPolicy::Auto { sub: 4, min: 3, max: 12 }
                    } else if let Some(rest) = v.strip_prefix("auto:") {
                        let parts: Vec<&str> = rest.split(':').collect();
                        if parts.len() != 3 {
                            return Err(format!("ttl: '{v}' is not auto:SUB:MIN:MAX"));
                        }
                        let sub = parse_u8(parts[0], "ttl sub")?;
                        let min = parse_u8(parts[1], "ttl min")?;
                        let max = parse_u8(parts[2], "ttl max")?;
                        if min == 0 || max < min {
                            return Err(format!("ttl: need 1 <= MIN <= MAX in '{v}'"));
                        }
                        TtlPolicy::Auto { sub, min, max }
                    } else {
                        let n = parse_u8(v, "ttl")?;
                        if n == 0 {
                            return Err("ttl: 0 is not a usable TTL".into());
                        }
                        TtlPolicy::Fixed(n)
                    }
                }
                "sni" => {
                    if !valid_host(v) {
                        return Err(format!("sni: '{v}' is not a host name"));
                    }
                    s.fake_host = v.to_string();
                }
                "repeat" => {
                    let n = parse_u8(v, "repeat")?;
                    if !(1..=16).contains(&n) {
                        return Err(format!("repeat: {n} is outside 1-16"));
                    }
                    s.repeat = n;
                }
                "split" => {
                    s.split = match v {
                        "none" => SplitPos::None,
                        "sni" => SplitPos::SniStart,
                        "sni-mid" => SplitPos::SniMid,
                        n => match n.parse::<u16>() {
                            Ok(n) if n > 0 => SplitPos::Offset(n),
                            _ => return Err(format!("split: '{v}' (none, sni, sni-mid or offset 1-65535)")),
                        },
                    }
                }
                "order" => {
                    s.order = match v {
                        "in" => Order::InOrder,
                        "reverse" => Order::Reversed,
                        _ => return Err(format!("order: '{v}' (in, reverse)")),
                    }
                }
                "http" => {
                    s.http = match v {
                        "0" => false,
                        "1" => true,
                        _ => return Err(format!("http: '{v}' (0, 1)")),
                    }
                }
                _ => return Err(format!("unknown key '{k}'")),
            }
            seen.push(k);
        }
        Ok(s)
    }

    /// Canonical spec string with every key.
    pub fn to_spec(&self) -> String {
        let mut out = String::from("fake=");
        if self.fake.any() {
            let mut m = Vec::new();
            if self.fake.ttl {
                m.push("ttl");
            }
            if self.fake.bad_checksum {
                m.push("badsum");
            }
            if self.fake.bad_seq {
                m.push("badseq");
            }
            out.push_str(&m.join("+"));
        } else {
            out.push_str("none");
        }
        match self.ttl {
            TtlPolicy::Fixed(n) => {
                let _ = write!(out, ",ttl={n}");
            }
            TtlPolicy::Auto { sub, min, max } => {
                let _ = write!(out, ",ttl=auto:{sub}:{min}:{max}");
            }
        }
        let _ = write!(out, ",sni={},repeat={},split=", self.fake_host, self.repeat);
        match self.split {
            SplitPos::None => out.push_str("none"),
            SplitPos::Offset(n) => {
                let _ = write!(out, "{n}");
            }
            SplitPos::SniStart => out.push_str("sni"),
            SplitPos::SniMid => out.push_str("sni-mid"),
        }
        out.push_str(match self.order {
            Order::InOrder => ",order=in",
            Order::Reversed => ",order=reverse",
        });
        out.push_str(if self.http { ",http=1" } else { ",http=0" });
        out
    }

    /// Strategies worth trying during calibration, most likely to work first. The first entry
    /// is [`Strategy::default`]; there are no duplicates.
    pub fn candidates() -> Vec<Strategy> {
        let d = Strategy::default();
        let with = |f: &dyn Fn(&mut Strategy)| {
            let mut s = d.clone();
            f(&mut s);
            s
        };
        let badsum = Fooling { ttl: false, bad_checksum: true, bad_seq: false };
        let badseq = Fooling { ttl: false, bad_checksum: false, bad_seq: true };
        vec![
            d.clone(),
            // TTL policy
            with(&|s| s.ttl = TtlPolicy::Fixed(8)),
            with(&|s| s.ttl = TtlPolicy::Fixed(10)),
            with(&|s| s.ttl = TtlPolicy::Fixed(12)),
            with(&|s| s.ttl = TtlPolicy::Auto { sub: 2, min: 3, max: 16 }),
            with(&|s| s.ttl = TtlPolicy::Auto { sub: 6, min: 3, max: 12 }),
            with(&|s| s.ttl = TtlPolicy::Fixed(6)),
            // order, split point, repeat
            with(&|s| s.order = Order::InOrder),
            with(&|s| s.split = SplitPos::SniStart),
            with(&|s| s.split = SplitPos::Offset(2)),
            with(&|s| s.split = SplitPos::None),
            with(&|s| s.repeat = 2),
            with(&|s| {
                s.ttl = TtlPolicy::Fixed(8);
                s.repeat = 3;
            }),
            // other fooling modes and combinations
            with(&|s| s.fake.bad_checksum = true),
            with(&|s| s.fake.bad_seq = true),
            with(&|s| s.fake = badsum),
            with(&|s| s.fake = badseq),
            with(&|s| s.fake = Fooling { ttl: false, bad_checksum: true, bad_seq: true }),
            with(&|s| {
                s.fake = badsum;
                s.split = SplitPos::Offset(2);
                s.order = Order::InOrder;
            }),
            // split only
            with(&|s| s.fake = Fooling::NONE),
            with(&|s| {
                s.fake = Fooling::NONE;
                s.order = Order::InOrder;
            }),
            with(&|s| {
                s.fake = Fooling::NONE;
                s.split = SplitPos::Offset(2);
                s.order = Order::InOrder;
            }),
        ]
    }

    /// TTL for this strategy's TTL-fooled fakes on a flow, or `None` when no safe value
    /// exists (auto policy with unknown hop distance, or a server 1 hop away). When the hop
    /// distance is known the result is capped at `hops - 1`.
    pub fn fake_ttl(&self, hint: &FlowHint) -> Option<u8> {
        let hops = hint.server_ttl.and_then(hops_from_ttl);
        let t = match self.ttl {
            TtlPolicy::Fixed(n) => n,
            TtlPolicy::Auto { sub, min, max } => {
                let h = hops?;
                h.saturating_sub(sub).clamp(min, max)
            }
        };
        let t = match hops {
            Some(h) => t.min(h - 1),
            None => t,
        };
        if t == 0 {
            None
        } else {
            Some(t)
        }
    }

    /// TTL each fake is sent with (`Some(original)` when TTL fooling is off), or `None` when
    /// no fake is sent on this flow.
    fn fake_send_ttl(&self, hint: &FlowHint, original: u8) -> Option<u8> {
        if !self.fake.any() {
            return None;
        }
        if !self.fake.ttl {
            return Some(original);
        }
        match self.fake_ttl(hint) {
            Some(t) => Some(t),
            // Without a safe TTL, only a fake the server discards anyway may go out.
            None if self.fake.bad_checksum || self.fake.bad_seq => Some(original),
            None => None,
        }
    }
}

/// Per-connection facts the engine learned before the request was sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowHint {
    /// TTL / hop limit observed on the server's SYN-ACK, when the engine saw it.
    pub server_ttl: Option<u8>,
    /// Largest TCP payload one produced packet may carry (the path MSS), when known. Captured
    /// packets can be larger than this when segmentation offload is on.
    pub max_payload: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Send the packet unchanged.
    Pass,
    /// Drop the packet and send these instead, in order. Checksums are already fixed.
    Replace(Vec<Packet>),
}

/// An HTTP/1.x request found at the start of a TCP payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// Byte range of the Host header value (trimmed) inside the payload, when the header line
    /// is completely inside this payload.
    pub host: Option<Range<usize>>,
}

/// `Some` when `payload` starts with one of [`HTTP_METHODS`].
pub fn parse_http_request(payload: &[u8]) -> Option<HttpRequest> {
    if !HTTP_METHODS.iter().any(|m| payload.starts_with(m.as_bytes())) {
        return None;
    }
    let mut host = None;
    // Skip the request line, then walk complete header lines.
    let mut pos = find_crlf(payload, 0).map(|i| i + 2);
    while let Some(start) = pos {
        let Some(end) = find_crlf(payload, start) else { break };
        let line = &payload[start..end];
        if line.is_empty() {
            break;
        }
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let mut a = start + 5;
            let mut b = end;
            while a < b && (payload[a] == b' ' || payload[a] == b'\t') {
                a += 1;
            }
            while b > a && (payload[b - 1] == b' ' || payload[b - 1] == b'\t') {
                b -= 1;
            }
            if a < b {
                host = Some(a..b);
            }
            break;
        }
        pos = Some(end + 2);
    }
    Some(HttpRequest { host })
}

fn find_crlf(p: &[u8], from: usize) -> Option<usize> {
    p.get(from..)?.windows(2).position(|w| w == b"\r\n").map(|i| i + from)
}

/// Seed for the fake ClientHello, derived from the flow (FNV-1a over addresses, ports, seq).
fn flow_seed(pkt: &Packet) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: &[u8]| {
        for &x in b {
            h ^= x as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for ip in [pkt.src_ip(), pkt.dst_ip()] {
        match ip {
            std::net::IpAddr::V4(a) => eat(&a.octets()),
            std::net::IpAddr::V6(a) => eat(&a.octets()),
        }
    }
    eat(&pkt.src_port().to_be_bytes());
    eat(&pkt.dst_port().to_be_bytes());
    eat(&pkt.seq().to_be_bytes());
    h
}

/// Flip the stored TCP checksum so it is certainly wrong. `pkt` must be TCP with fixed
/// checksums.
fn corrupt_tcp_checksum(pkt: Packet) -> Packet {
    let l4 = pkt.len() - pkt.payload_len() - 20 - pkt.tcp_options().len();
    let mut d = pkt.clone().into_bytes();
    d[l4 + 16] ^= 0xff;
    d[l4 + 17] ^= 0xff;
    Packet::parse(d).unwrap_or(pkt)
}

/// Decide what to do with one outbound TCP packet.
pub fn apply(strategy: &Strategy, pkt: &Packet, hint: &FlowHint) -> Verdict {
    if !pkt.is_tcp() || pkt.payload_len() == 0 || pkt.tcp_flags() & (TCP_SYN | TCP_RST) != 0 {
        return Verdict::Pass;
    }
    let pl = pkt.payload();
    let (is_tls, name) = if let Some(ch) = tls::parse_client_hello(pl) {
        (true, ch.sni)
    } else if strategy.http {
        match parse_http_request(pl) {
            Some(r) => (false, r.host),
            None => return Verdict::Pass,
        }
    } else {
        return Verdict::Pass;
    };
    let max = match hint.max_payload {
        Some(m) if m > 0 => m as usize,
        _ => usize::MAX,
    };

    let mut out = Vec::new();

    // Fakes.
    if let Some(ttl) = strategy.fake_send_ttl(hint, pkt.ttl()) {
        let mut body = if is_tls {
            tls::build_client_hello(&strategy.fake_host, flow_seed(pkt))
        } else {
            format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", strategy.fake_host).into_bytes()
        };
        body.truncate(max);
        let mut f = pkt.with_payload(&body, 0);
        f.set_tcp_flags(pkt.tcp_flags() & !TCP_FIN);
        if strategy.fake.ttl {
            f.set_ttl(ttl);
        }
        if strategy.fake.bad_seq {
            f.set_seq(pkt.seq().wrapping_sub(BAD_SEQ_DELTA));
            f.set_ack(pkt.ack().wrapping_sub(BAD_ACK_DELTA));
        }
        f.fix_checksums();
        if strategy.fake.bad_checksum {
            f = corrupt_tcp_checksum(f);
        }
        for _ in 0..strategy.repeat.max(1) {
            out.push(f.clone());
        }
    }

    // Real payload: two parts at the split point, each segmented to `max`.
    let len = pl.len();
    let at = match strategy.split {
        SplitPos::None => None,
        SplitPos::Offset(n) => Some(n as usize),
        SplitPos::SniStart => Some(name.map(|r| r.start).unwrap_or(FALLBACK_SPLIT)),
        SplitPos::SniMid => Some(match name {
            Some(r) if r.len() >= 2 => r.start + r.len() / 2,
            _ => FALLBACK_SPLIT,
        }),
    }
    .filter(|&a| a > 0 && a < len);
    let mut parts: Vec<Range<usize>> = Vec::with_capacity(2);
    match at {
        Some(a) => parts.extend([0..a, a..len]),
        None => parts.push(0..len),
    }
    if strategy.order == Order::Reversed {
        parts.reverse();
    }
    let mut real = 0;
    for part in parts {
        let mut s = part.start;
        while s < part.end {
            let e = part.end.min(s.saturating_add(max));
            let mut p = pkt.with_payload(&pl[s..e], s as u32);
            if e != len {
                p.set_tcp_flags(pkt.tcp_flags() & !(TCP_PSH | TCP_FIN));
            }
            p.fix_checksums();
            out.push(p);
            real += 1;
            s = e;
        }
    }
    if out.len() == 1 && real == 1 {
        // Nothing changed.
        return Verdict::Pass;
    }
    Verdict::Replace(out)
}

/// Hop distance of a peer estimated from the TTL its packet arrived with (initial TTL assumed
/// to be 64, 128 or 255). `None` when no sensible estimate exists.
pub fn hops_from_ttl(observed_ttl: u8) -> Option<u8> {
    let initial: u16 = match observed_ttl {
        0 => return None,
        1..=64 => 64,
        65..=128 => 128,
        _ => 255,
    };
    let hops = initial - observed_ttl as u16;
    if hops == 0 || hops > 40 {
        None
    } else {
        Some(hops as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::testutil::{tcp4, tcp6, udp};
    use crate::packet::TCP_ACK;
    use std::net::Ipv6Addr;

    // ---- a tiny evaluator for the subset of the WinDivert filter language FILTER uses ----

    fn eval_filter(f: &str, payload: &[u8]) -> bool {
        let spaced = f.replace('(', " ( ").replace(')', " ) ");
        let toks: Vec<&str> = spaced.split_whitespace().collect();
        let mut i = 0;
        let r = or_expr(&toks, &mut i, payload);
        assert_eq!(i, toks.len(), "filter fully consumed");
        r
    }
    fn or_expr(t: &[&str], i: &mut usize, p: &[u8]) -> bool {
        let mut v = and_expr(t, i, p);
        while t.get(*i) == Some(&"or") {
            *i += 1;
            v |= and_expr(t, i, p);
        }
        v
    }
    fn and_expr(t: &[&str], i: &mut usize, p: &[u8]) -> bool {
        let mut v = atom(t, i, p);
        while t.get(*i) == Some(&"and") {
            *i += 1;
            v &= atom(t, i, p);
        }
        v
    }
    fn atom(t: &[&str], i: &mut usize, p: &[u8]) -> bool {
        if t[*i] == "(" {
            *i += 1;
            let v = or_expr(t, i, p);
            assert_eq!(t[*i], ")");
            *i += 1;
            return v;
        }
        let (field, op, val) = (t[*i], t[*i + 1], t[*i + 2].parse::<u64>().expect("decimal constant"));
        *i += 3;
        let (name, idx) = field.split_once('[').unwrap();
        let idx: usize = idx.trim_end_matches(']').parse().unwrap();
        let width = match name {
            "tcp.Payload" => 1,
            "tcp.Payload16" => 2,
            "tcp.Payload32" => 4,
            _ => panic!("unexpected field {name}"),
        };
        let off = idx * width; // word index
        let Some(bytes) = p.get(off..off + width) else { return false }; // out of bounds fails
        let w = bytes.iter().fold(0u64, |a, &b| (a << 8) | b as u64); // network byte order
        match op {
            "==" => w == val,
            "<=" => w <= val,
            _ => panic!("unexpected op {op}"),
        }
    }

    #[test]
    fn filter_constants_match_method_names() {
        for m in HTTP_METHODS {
            let b = m.as_bytes();
            let w0 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            assert!(FILTER.contains(&format!("tcp.Payload32[0] == {w0}")), "{m}");
            if b.len() == 5 {
                assert!(FILTER.contains(&format!("tcp.Payload32[0] == {w0} and tcp.Payload[4] == 32")), "{m}");
            } else if b.len() == 6 {
                let w = u16::from_be_bytes([b[4], b[5]]);
                assert!(FILTER.contains(&format!("tcp.Payload32[0] == {w0} and tcp.Payload16[2] == {w})")), "{m}");
            } else if b.len() == 7 {
                let w = u16::from_be_bytes([b[4], b[5]]);
                assert!(FILTER.contains(&format!("tcp.Payload32[0] == {w0} and tcp.Payload16[2] == {w} and tcp.Payload[6] == 32")), "{m}");
            } else if b.len() == 8 {
                let w = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                assert!(FILTER.contains(&format!("tcp.Payload32[1] == {w}")), "{m}");
            }
        }
        assert!(!FILTER.contains("Port"), "port independent");
    }

    #[test]
    fn filter_agrees_with_apply_detection() {
        let mut inputs: Vec<Vec<u8>> = vec![
            tls::build_client_hello("discord.com", 1),
            tls::build_client_hello("discord.com", 1)[..6].to_vec(),
            tls::build_client_hello("discord.com", 1)[..5].to_vec(),
            vec![0x16, 0x03, 0x04, 0, 0, 1],
            vec![0x16, 0x03, 0x05, 0, 0, 1],
            vec![0x16, 0x03, 0x03, 0, 0, 2],
            vec![0x17, 0x03, 0x03, 0, 0x20, 1],
            b"HTTP/1.1 200 OK\r\n".to_vec(),
            b"GETX / HTTP/1.1\r\n".to_vec(),
            b"POSTX".to_vec(),
            b"DELETEX".to_vec(),
            b"OPTIONSX".to_vec(),
            b"PATCHX".to_vec(),
            b"CONNECTX".to_vec(),
            b"GET".to_vec(),
            vec![],
        ];
        for m in HTTP_METHODS {
            inputs.push(format!("{m}/ HTTP/1.1\r\nHost: a.b\r\n\r\n").into_bytes());
            inputs.push(m.as_bytes().to_vec());
            inputs.push(m.as_bytes()[..m.len() - 1].to_vec());
        }
        let mut x: u64 = 7;
        for _ in 0..5000 {
            let mut v = Vec::new();
            for _ in 0..(x % 12) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                v.push((x >> 56) as u8);
            }
            if x.is_multiple_of(3) && v.len() >= 6 {
                v[0] = 0x16;
                v[1] = 3;
            }
            inputs.push(v);
        }
        for p in inputs {
            let want = tls::parse_client_hello(&p).is_some() || parse_http_request(&p).is_some();
            assert_eq!(eval_filter(FILTER, &p), want, "{:?}", String::from_utf8_lossy(&p));
        }
    }

    // ---- spec ----

    #[test]
    fn default_spec_string() {
        let d = Strategy::default();
        assert_eq!(d.to_spec(), "fake=ttl,ttl=auto:4:3:12,sni=www.google.com,repeat=1,split=sni-mid,order=reverse,http=1");
        assert_eq!(Strategy::from_spec("").unwrap(), d);
        assert_eq!(Strategy::from_spec(" ttl = 8 , ").unwrap().ttl, TtlPolicy::Fixed(8));
        assert_eq!(Strategy::from_spec("ttl=auto").unwrap().ttl, d.ttl);
        let s = Strategy::from_spec("fake=badseq+ttl+badsum,split=40,order=in,http=0,repeat=16,sni=example.org").unwrap();
        assert_eq!(s.fake, Fooling { ttl: true, bad_checksum: true, bad_seq: true });
        assert_eq!(s.split, SplitPos::Offset(40));
        assert_eq!(Strategy::from_spec(&s.to_spec()).unwrap(), s);
    }

    #[test]
    fn spec_errors() {
        for bad in [
            "foo=1",
            "fake=ttl,fake=none",
            "fake=magic",
            "ttl=0",
            "ttl=300",
            "ttl=auto:4:3",
            "ttl=auto:4:12:3",
            "ttl=auto:4:0:3",
            "sni=",
            "sni=a b",
            "repeat=0",
            "repeat=17",
            "split=0",
            "split=middle",
            "order=up",
            "http=yes",
            "novalue",
        ] {
            assert!(Strategy::from_spec(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn candidates_round_trip_and_are_unique() {
        let c = Strategy::candidates();
        assert_eq!(c[0], Strategy::default());
        assert!(c.len() <= 24);
        for (i, s) in c.iter().enumerate() {
            assert_eq!(Strategy::from_spec(&s.to_spec()).unwrap(), *s, "{}", s.to_spec());
            for t in &c[i + 1..] {
                assert_ne!(s, t, "duplicate {}", s.to_spec());
            }
        }
        assert!(c.iter().any(|s| !s.fake.any()), "split-only present");
        assert!(c.iter().any(|s| s.fake.bad_checksum && !s.fake.ttl));
        assert!(c.iter().any(|s| s.fake.bad_seq && !s.fake.ttl));
    }

    // ---- TTL ----

    #[test]
    fn hops_estimate() {
        assert_eq!(hops_from_ttl(43), Some(21));
        assert_eq!(hops_from_ttl(46), Some(18));
        assert_eq!(hops_from_ttl(64), None);
        assert_eq!(hops_from_ttl(0), None);
        assert_eq!(hops_from_ttl(1), None); // 63 hops
        assert_eq!(hops_from_ttl(110), Some(18));
        assert_eq!(hops_from_ttl(128), None);
        assert_eq!(hops_from_ttl(240), Some(15));
        assert_eq!(hops_from_ttl(255), None);
        assert_eq!(hops_from_ttl(80), None); // 48 hops from 128
    }

    #[test]
    fn fake_ttl_policy() {
        let d = Strategy::default();
        let h = |t| FlowHint { server_ttl: Some(t), max_payload: None };
        assert_eq!(d.fake_ttl(&h(43)), Some(12)); // 21 - 4 = 17 -> 12
        assert_eq!(d.fake_ttl(&h(54)), Some(6)); // 10 - 4
        assert_eq!(d.fake_ttl(&h(58)), Some(3)); // 6 - 4 = 2 -> 3
        assert_eq!(d.fake_ttl(&h(61)), Some(2)); // 3 hops: capped at 2
        assert_eq!(d.fake_ttl(&h(63)), None); // 1 hop
        assert_eq!(d.fake_ttl(&FlowHint::default()), None);
        let f = Strategy { ttl: TtlPolicy::Fixed(10), ..d.clone() };
        assert_eq!(f.fake_ttl(&FlowHint::default()), Some(10));
        assert_eq!(f.fake_ttl(&h(43)), Some(10));
        assert_eq!(f.fake_ttl(&h(56)), Some(7)); // 8 hops
    }

    // ---- apply ----

    const HOST: &str = "discord.com";

    fn tls_payloads() -> Vec<Vec<u8>> {
        let full = tls::build_client_hello(HOST, 99);
        let mut big = tls::build_client_hello(&"z".repeat(250), 5);
        big.extend(std::iter::repeat_n(0xee, 1000)); // stray trailing bytes beyond the record
        vec![full.clone(), full[..60].to_vec(), big]
    }

    fn http_payload() -> Vec<u8> {
        format!("GET /path HTTP/1.1\r\nUser-Agent: x\r\nhost:  {HOST} \r\nAccept: */*\r\n\r\n").into_bytes()
    }

    fn packets(payload: &[u8]) -> Vec<Packet> {
        let s: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let d: Ipv6Addr = "2001:db8::2".parse().unwrap();
        vec![
            tcp4([10, 0, 0, 2], 50000, [1, 2, 3, 4], 443, 0xffff_ff00, 777, TCP_PSH | TCP_ACK, payload),
            tcp6(s, 50001, d, 8443, 12345, 999, TCP_PSH | TCP_ACK, payload),
        ]
    }

    fn hints() -> Vec<FlowHint> {
        let mut v = Vec::new();
        for t in [None, Some(43), Some(110), Some(62)] {
            for m in [None, Some(1460), Some(100), Some(7), Some(1)] {
                v.push(FlowHint { server_ttl: t, max_payload: m });
            }
        }
        v
    }

    fn check(s: &Strategy, pkt: &Packet, hint: &FlowHint, name: Option<&[u8]>) {
        let ctx = format!("{} v6={} {:?}", s.to_spec(), pkt.is_ipv6(), hint);
        let pl = pkt.payload();
        let fakes_expected = match s.fake_send_ttl(hint, pkt.ttl()) {
            Some(_) => s.repeat as usize,
            None => 0,
        };
        let out = match apply(s, pkt, hint) {
            Verdict::Replace(v) => v,
            Verdict::Pass => {
                assert_eq!(fakes_expected, 0, "{ctx}");
                assert!(hint.max_payload.is_none_or(|m| pl.len() <= m as usize), "{ctx}");
                vec![pkt.clone()]
            }
        };
        let max = hint.max_payload.map_or(usize::MAX, |m| m as usize);
        for p in &out {
            let re = Packet::parse(p.as_bytes().to_vec()).expect("lengths consistent");
            assert_eq!(re.payload(), p.payload(), "{ctx}");
            assert!(p.payload_len() <= max, "{ctx}: max_payload");
            assert_eq!((p.src(), p.dst()), (pkt.src(), pkt.dst()), "{ctx}");
            assert_eq!(p.tcp_options(), pkt.tcp_options(), "{ctx}");
        }
        assert!(out.len() > fakes_expected, "{ctx}");
        let (fakes, real) = out.split_at(fakes_expected);
        for f in fakes {
            assert_eq!(f.l4_checksum_ok(), !s.fake.bad_checksum, "{ctx}");
            let want_ttl = if s.fake.ttl { s.fake_ttl(hint).unwrap_or(pkt.ttl()) } else { pkt.ttl() };
            assert_eq!(f.ttl(), want_ttl, "{ctx}");
            if s.fake.ttl && s.fake_ttl(hint).is_some() {
                if let Some(h) = hint.server_ttl.and_then(hops_from_ttl) {
                    assert!(f.ttl() < h, "{ctx}: fake would reach the server");
                }
            }
            if s.fake.bad_seq {
                assert_eq!(f.seq(), pkt.seq().wrapping_sub(BAD_SEQ_DELTA), "{ctx}");
                assert_eq!(f.ack(), pkt.ack().wrapping_sub(BAD_ACK_DELTA), "{ctx}");
            } else {
                assert_eq!((f.seq(), f.ack()), (pkt.seq(), pkt.ack()), "{ctx}");
            }
            assert!(f.payload() != pl, "{ctx}");
            let fh = s.fake_host.as_bytes();
            assert!(f.payload().windows(fh.len()).any(|w| w == fh) || f.payload_len() < 300, "{ctx}: fake host");
        }
        // Real fragments: reassemble by sequence number.
        let mut buf = vec![None; pl.len()];
        for p in real {
            assert!(p.l4_checksum_ok(), "{ctx}");
            assert_eq!(p.ttl(), pkt.ttl(), "{ctx}");
            assert_eq!(p.ack(), pkt.ack(), "{ctx}");
            let off = p.seq().wrapping_sub(pkt.seq()) as usize;
            assert!(off + p.payload_len() <= pl.len(), "{ctx}");
            for (i, &b) in p.payload().iter().enumerate() {
                assert!(buf[off + i].is_none(), "{ctx}: overlap");
                buf[off + i] = Some(b);
            }
            let last = off + p.payload_len() == pl.len();
            let want = if last { pkt.tcp_flags() } else { pkt.tcp_flags() & !(TCP_PSH | TCP_FIN) };
            assert_eq!(p.tcp_flags(), want, "{ctx}");
            if s.split == SplitPos::SniMid {
                if let Some(n) = name {
                    assert!(!p.payload().windows(n.len()).any(|w| w == n), "{ctx}: whole name in one fragment");
                }
            }
        }
        let got: Vec<u8> = buf.into_iter().map(|b| b.expect("every byte carried")).collect();
        assert_eq!(got, pl, "{ctx}");
        // Order: reversed means the first real fragment is not the start (when split).
        if real.len() > 1 && s.split != SplitPos::None && max >= pl.len() {
            let first_off = real[0].seq().wrapping_sub(pkt.seq());
            assert_eq!(first_off != 0, s.order == Order::Reversed, "{ctx}");
        }
    }

    #[test]
    fn every_candidate_on_tls_and_http() {
        let mut cands = Strategy::candidates();
        cands.push(Strategy::from_spec("fake=ttl+badsum+badseq,ttl=3,repeat=4,split=500").unwrap());
        cands.push(Strategy::from_spec("fake=none,split=none").unwrap());
        for s in &cands {
            for pl in tls_payloads() {
                let name = tls::parse_client_hello(&pl).unwrap().sni.map(|r| pl[r].to_vec());
                for pkt in packets(&pl) {
                    for h in hints() {
                        check(s, &pkt, &h, name.as_deref());
                    }
                }
            }
            let pl = http_payload();
            for pkt in packets(&pl) {
                for h in hints() {
                    check(s, &pkt, &h, Some(HOST.as_bytes()));
                }
            }
        }
    }

    #[test]
    fn default_on_measured_line() {
        // SYN-ACK TTL 44 -> 20 hops -> fake TTL 12; one fake, then the second half first.
        let pl = tls::build_client_hello(HOST, 1);
        let pkt = &packets(&pl)[0];
        let hint = FlowHint { server_ttl: Some(44), max_payload: Some(1460) };
        let Verdict::Replace(v) = apply(&Strategy::default(), pkt, &hint) else { panic!() };
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].ttl(), 12);
        assert!(v[0].l4_checksum_ok());
        let fake = tls::parse_client_hello(v[0].payload()).unwrap().sni.unwrap();
        assert_eq!(&v[0].payload()[fake], b"www.google.com");
        let sni = tls::parse_client_hello(&pl).unwrap().sni.unwrap();
        let mid = sni.start + sni.len() / 2;
        assert_eq!(v[1].seq(), pkt.seq().wrapping_add(mid as u32));
        assert_eq!(v[2].seq(), pkt.seq());
        assert_eq!(v[2].payload_len(), mid);
    }

    #[test]
    fn unknown_hops_auto_sends_no_ttl_fake() {
        let pl = tls::build_client_hello(HOST, 1);
        let pkt = &packets(&pl)[0];
        let Verdict::Replace(v) = apply(&Strategy::default(), pkt, &FlowHint::default()) else { panic!() };
        assert_eq!(v.len(), 2, "split only");
        assert!(v.iter().all(|p| p.ttl() == pkt.ttl()));
    }

    #[test]
    fn http_path() {
        let pl = http_payload();
        let r = parse_http_request(&pl).unwrap().host.unwrap();
        assert_eq!(&pl[r], HOST.as_bytes());
        let pkt = &packets(&pl)[0];
        let hint = FlowHint { server_ttl: Some(44), max_payload: None };
        let Verdict::Replace(v) = apply(&Strategy::default(), pkt, &hint) else { panic!() };
        assert!(v[0].payload().starts_with(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"));
        let off = Strategy { http: false, ..Strategy::default() };
        assert_eq!(apply(&off, pkt, &hint), Verdict::Pass);
        // Host line cut off by the segment end: no name, fallback split.
        let cut = b"POST /x HTTP/1.1\r\nHost: disc";
        assert_eq!(parse_http_request(cut), Some(HttpRequest { host: None }));
        assert_eq!(parse_http_request(b"GET / HTTP/1.1\r\n\r\nHost: a\r\n"), Some(HttpRequest { host: None }));
        assert_eq!(parse_http_request(b"get / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn non_requests_pass() {
        let s = Strategy::default();
        let h = FlowHint { server_ttl: Some(44), max_payload: None };
        let appdata = [0x17u8, 0x03, 0x03, 0x00, 0x10, 1, 2, 3];
        for pl in [&appdata[..], b"", b"HTTP/1.1 200 OK\r\n\r\n", &[0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00]] {
            for p in packets(pl) {
                assert_eq!(apply(&s, &p, &h), Verdict::Pass);
            }
        }
        let hello = tls::build_client_hello(HOST, 1);
        let syn = tcp4([10, 0, 0, 2], 1, [1, 2, 3, 4], 443, 0, 0, TCP_SYN, &hello);
        assert_eq!(apply(&s, &syn, &h), Verdict::Pass);
        let u = udp("10.0.0.2:5000".parse().unwrap(), "1.2.3.4:443".parse().unwrap(), &hello);
        assert_eq!(apply(&s, &u, &h), Verdict::Pass);
        let ack_only = tcp4([10, 0, 0, 2], 1, [1, 2, 3, 4], 443, 0, 0, TCP_ACK, b"");
        assert_eq!(apply(&s, &ack_only, &h), Verdict::Pass);
    }

    #[test]
    fn random_payloads_never_panic() {
        let s = Strategy::default();
        let mut x: u64 = 1;
        for i in 0..3000 {
            let mut v = Vec::new();
            for _ in 0..(x % 300) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                v.push((x >> 56) as u8);
            }
            if i % 2 == 0 && v.len() >= 6 {
                v[..6].copy_from_slice(&[0x16, 3, 1, 0x02, 0x00, 1]);
            }
            for p in packets(&v) {
                let _ = apply(&s, &p, &FlowHint { server_ttl: Some(44), max_payload: Some(50) });
            }
        }
    }
}
