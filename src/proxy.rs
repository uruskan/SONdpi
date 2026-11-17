//! Local proxy: the macOS front end of the engine.
//!
//! Without a packet driver the engine cannot touch other programs' packets, so on macOS the
//! system proxy setting points browsers and other proxy-aware programs at this proxy (through
//! a PAC script it serves itself). For every connection it
//!
//! 1. resolves the host name over DoH ([`crate::resolve`]), never through the system resolver
//!    whose answers the ISP rewrites;
//! 2. dials with [`crate::dial`], which re-dials an unanswered SYN from a fresh source port;
//! 3. re-frames the client's first TLS record (the ClientHello) as two records cut in the
//!    middle of the server name and writes them as two TCP segments, or cuts a plain HTTP
//!    request in the middle of its Host value. Measured on the line in CLAUDE.md: the DPI
//!    does not reassemble TLS records, while plain TCP segmentation alone draws its RST.
//!
//! Protocols: HTTP `CONNECT`, absolute-form HTTP requests (forwarded with
//! `Connection: close`, so a kept-alive client connection cannot carry a request for another
//! host to the wrong server), SOCKS5 `CONNECT` (no authentication), and `GET /proxy.pac`.
//!
//! Nothing here panics on client or server input; anything not understood is relayed
//! unchanged or refused.

use crate::dial::{self, DialConfig};
use crate::resolve::Resolver;
use crate::tls;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Largest HTTP request head or SOCKS5 request accepted from a client.
pub const MAX_HEAD: usize = 16 * 1024;

/// Path of the PAC script served to the system proxy setting.
pub const PAC_PATH: &str = "/proxy.pac";

/// Where a client wants to go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    /// Parse `host`, `host:port`, `1.2.3.4:port`, `[v6]` or `[v6]:port`. A bare IPv6 address
    /// without brackets is accepted only without a port.
    pub fn parse_authority(s: &str, default_port: u16) -> Option<Target> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (h, after) = rest.split_once(']')?;
            let port = match after {
                "" => default_port,
                p => p.strip_prefix(':')?.parse().ok()?,
            };
            (Host::Ip(IpAddr::V6(h.parse().ok()?)), port)
        } else if s.matches(':').count() > 1 {
            (Host::Ip(IpAddr::V6(s.parse().ok()?)), default_port)
        } else {
            let (h, port) = match s.split_once(':') {
                Some((h, p)) => (h, p.parse().ok()?),
                None => (s, default_port),
            };
            (host_from_str(h)?, port)
        };
        (port != 0).then_some(Target { host, port })
    }
}

/// An IP literal, or a syntactically valid host name (lower-cased, trailing dot removed).
fn host_from_str(h: &str) -> Option<Host> {
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Some(Host::Ip(ip));
    }
    let h = h.strip_suffix('.').unwrap_or(h);
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63)
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    ok.then(|| Host::Name(h.to_ascii_lowercase()))
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Host::Name(n) => write!(f, "{n}:{}", self.port),
            Host::Ip(IpAddr::V6(a)) => write!(f, "[{a}]:{}", self.port),
            Host::Ip(a) => write!(f, "{a}:{}", self.port),
        }
    }
}

/// What an HTTP client asked the proxy for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpAsk {
    /// `CONNECT host:port`: open a tunnel.
    Tunnel(Target),
    /// Absolute-form request: send `head` (already rewritten to origin form, with
    /// `Connection: close`) to `target`, then relay.
    Forward { target: Target, head: Vec<u8> },
    /// Origin-form request addressed to the proxy itself.
    Local { method: String, path: String },
}

/// Parse an HTTP request head at the start of `buf`.
///
/// `Ok(None)`: the head is not complete yet. `Ok(Some((ask, n)))`: the head is `buf[..n]`
/// (bytes after it belong to the request body). `Err`: refuse with 400.
pub fn parse_http(buf: &[u8]) -> Result<Option<(HttpAsk, usize)>, &'static str> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= MAX_HEAD { Err("request head too large") } else { Ok(None) };
    };
    let n = end + 4;
    if n > MAX_HEAD {
        return Err("request head too large");
    }
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(uri), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err("malformed request line");
    };
    if !version.starts_with("HTTP/1.") || method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err("malformed request line");
    }
    let headers: Vec<(&str, &str)> = lines
        .map(|l| l.split_once(':').map(|(k, v)| (k.trim(), v.trim())).ok_or("malformed header"))
        .collect::<Result<_, _>>()?;

    if method == "CONNECT" {
        let t = Target::parse_authority(uri, 443).ok_or("bad CONNECT target")?;
        return Ok(Some((HttpAsk::Tunnel(t), n)));
    }
    if uri.starts_with('/') {
        return Ok(Some((HttpAsk::Local { method: method.to_string(), path: uri.to_string() }, n)));
    }
    let rest = uri.strip_prefix("http://").or_else(|| uri.strip_prefix("HTTP://")).ok_or("unsupported request target")?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        return Err("credentials in request target");
    }
    let target = Target::parse_authority(authority, 80).ok_or("bad request target")?;

    // Hop-by-hop headers, including those the client names in Connection (RFC 9110 7.6.1).
    let mut hop: Vec<String> = ["proxy-connection", "proxy-authorization", "connection", "keep-alive", "upgrade", "te"]
        .iter()
        .map(|h| h.to_string())
        .collect();
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("proxy-connection") {
            hop.extend(v.split(',').map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()));
        }
    }
    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for (k, v) in &headers {
        let drop = hop.iter().any(|d| k.eq_ignore_ascii_case(d));
        if drop {
            continue;
        }
        has_host |= k.eq_ignore_ascii_case("host");
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    Ok(Some((HttpAsk::Forward { target, head: out.into_bytes() }, n)))
}

/// SOCKS5 greeting: `Ok(Some((no_auth_offered, n)))` once `buf[..n]` holds it.
pub fn parse_socks_greeting(buf: &[u8]) -> Result<Option<(bool, usize)>, &'static str> {
    match buf {
        [] | [5] => Ok(None),
        [5, n, rest @ ..] => {
            let n = *n as usize;
            if n == 0 {
                return Err("no SOCKS methods");
            }
            if rest.len() < n {
                return Ok(None);
            }
            Ok(Some((rest[..n].contains(&0), 2 + n)))
        }
        _ => Err("not SOCKS5"),
    }
}

/// SOCKS5 reply codes used here.
pub const SOCKS_OK: u8 = 0;
pub const SOCKS_FAILURE: u8 = 1;
pub const SOCKS_HOST_UNREACHABLE: u8 = 4;
pub const SOCKS_REFUSED: u8 = 5;
pub const SOCKS_CMD_UNSUPPORTED: u8 = 7;
pub const SOCKS_ATYP_UNSUPPORTED: u8 = 8;

/// SOCKS5 request: `Ok(Some((target, n)))` once `buf[..n]` holds a CONNECT request;
/// `Err(code)` is the reply code to refuse with.
pub fn parse_socks_request(buf: &[u8]) -> Result<Option<(Target, usize)>, u8> {
    if buf.len() < 5 {
        return if buf.first().is_some_and(|&v| v != 5) { Err(SOCKS_FAILURE) } else { Ok(None) };
    }
    if buf[0] != 5 || buf[2] != 0 {
        return Err(SOCKS_FAILURE);
    }
    if buf[1] != 1 {
        return Err(SOCKS_CMD_UNSUPPORTED);
    }
    let (host, at) = match buf[3] {
        1 => {
            let Some(a) = buf.get(4..8) else { return Ok(None) };
            (Host::Ip(IpAddr::from([a[0], a[1], a[2], a[3]])), 8)
        }
        4 => {
            let Some(a) = buf.get(4..20) else { return Ok(None) };
            let mut b = [0u8; 16];
            b.copy_from_slice(a);
            (Host::Ip(IpAddr::from(b)), 20)
        }
        3 => {
            let len = buf[4] as usize;
            let Some(name) = buf.get(5..5 + len) else { return Ok(None) };
            let name = std::str::from_utf8(name).map_err(|_| SOCKS_HOST_UNREACHABLE)?;
            (host_from_str(name).ok_or(SOCKS_HOST_UNREACHABLE)?, 5 + len)
        }
        _ => return Err(SOCKS_ATYP_UNSUPPORTED),
    };
    let Some(p) = buf.get(at..at + 2) else { return Ok(None) };
    let port = u16::from_be_bytes([p[0], p[1]]);
    if port == 0 {
        return Err(SOCKS_FAILURE);
    }
    Ok(Some((Target { host, port }, at + 2)))
}

/// SOCKS5 reply with an unspecified bound address.
pub fn socks_reply(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Where to cut the first bytes a client sends through a tunnel, as two TCP writes:
/// `Some((bytes, cut))` writes `bytes[..cut]`, then `bytes[cut..]`. A complete TLS
/// ClientHello record is re-framed as two records ([`crate::tls::split_record`]) and cut
/// between them. A plain HTTP request gets its `Host:` header name written as `hoSt:` (header
/// names are case-insensitive; measured: the DPI matches `Host:` exactly, and cutting the
/// value alone draws its RST) and is cut in the middle of the Host value. `None`: send
/// `first` unchanged.
pub fn desync_first(first: &[u8]) -> Option<(Vec<u8>, usize)> {
    if let Some(len) = tls::handshake_record_len(first) {
        let rec = first.get(..len)?;
        let at = tls::sni_cut(rec)?;
        let mut out = tls::split_record(rec, at)?;
        out.extend_from_slice(&first[len..]);
        return Some((out, 5 + at));
    }
    let host = crate::desync::parse_http_request(first)?.host?;
    let cut = (host.start + host.end) / 2;
    if cut <= host.start {
        return None;
    }
    let mut out = first.to_vec();
    // The header line starts after the CRLF before the value.
    let line = first[..host.start].windows(2).rposition(|w| w == b"\r\n").map(|i| i + 2)?;
    if out.get(line..line + 5).is_some_and(|n| n.eq_ignore_ascii_case(b"host:")) {
        out[line..line + 4].copy_from_slice(b"hoSt");
    }
    Some((out, cut))
}

/// The PAC script: everything through the proxy at `127.0.0.1:port`, falling back to a
/// direct connection when the proxy does not answer (so a crashed or stopped SONdpi never
/// cuts the machine off), except local names and private, loopback and link-local
/// addresses, which always go direct.
pub fn pac_script(port: u16) -> String {
    format!(
        r#"function FindProxyForURL(url, host) {{
  host = host.toLowerCase();
  if (isPlainHostName(host) || host == "localhost" ||
      /\.(local|localhost|lan|home|internal|intranet|corp|private|localdomain|test|invalid|home\.arpa)$/.test(host))
    return "DIRECT";
  if (/^[0-9.]+$/.test(host)) {{
    if (isInNet(host, "127.0.0.0", "255.0.0.0") || isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") || isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "169.254.0.0", "255.255.0.0") || isInNet(host, "100.64.0.0", "255.192.0.0"))
      return "DIRECT";
  }}
  if (host.indexOf(":") >= 0) {{
    var h = host.replace(/^\[|\]$/g, "");
    if (h == "::1" || /^(fe[89ab]|f[cd])/.test(h)) return "DIRECT";
  }}
  return "PROXY 127.0.0.1:{port}; DIRECT";
}}
"#
    )
}

// =========================================================================================
// Server
// =========================================================================================

/// Optional line logger (dev mode).
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Listening address; port 0 picks a free port.
    pub listen: SocketAddr,
    pub dial: DialConfig,
    /// Split the first request of every connection (off only for measurements).
    pub desync: bool,
    /// Pause between the two parts of a split first request, in milliseconds (0 = none;
    /// TCP_NODELAY already sends them as separate segments).
    pub gap_ms: u64,
    /// Connections served at once; more are closed right away.
    pub max_conns: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            dial: DialConfig::default(),
            desync: true,
            gap_ms: 0,
            max_conns: 4096,
        }
    }
}

/// Counters since the proxy started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyStats {
    pub accepted: u64,
    pub active: u64,
    /// Connections whose first request was split.
    pub desynced: u64,
    /// Connections won by a re-dial or by the second address family.
    pub rescued: u64,
    /// Connections refused because the target could not be resolved or reached.
    pub failed: u64,
    /// Names resolved over DoH.
    pub dns_answered: u64,
    /// Lookups that fell back to the system resolver.
    pub dns_fallbacks: u64,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    active: AtomicU64,
    desynced: AtomicU64,
    rescued: AtomicU64,
    failed: AtomicU64,
}

struct Shared {
    cfg: ProxyConfig,
    addr: SocketAddr,
    resolver: Arc<Resolver>,
    counters: Counters,
    stop: AtomicBool,
    log: Option<LogFn>,
}

impl Shared {
    fn log(&self, f: impl FnOnce() -> String) {
        if let Some(l) = &self.log {
            l(&f());
        }
    }
}

/// A running proxy. Stopping (or dropping) it closes the listener; tunnels already open keep
/// running until either side closes them.
pub struct Proxy {
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

/// Time a client gets to send its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Time the rest of a ClientHello record may take to arrive once it has started.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_BUF: usize = 64 * 1024;
const CONN_STACK: usize = 256 * 1024;

impl Proxy {
    pub fn start(cfg: ProxyConfig, resolver: Arc<Resolver>, log: Option<LogFn>) -> io::Result<Proxy> {
        let listener = TcpListener::bind(cfg.listen)?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared { cfg, addr, resolver, counters: Counters::default(), stop: AtomicBool::new(false), log });
        let sh = shared.clone();
        let accept = std::thread::Builder::new().name("sondpi-accept".into()).spawn(move || accept_loop(sh, listener))?;
        Ok(Proxy { shared, accept: Some(accept) })
    }

    pub fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    pub fn stats(&self) -> ProxyStats {
        let c = &self.shared.counters;
        ProxyStats {
            accepted: c.accepted.load(Ordering::Relaxed),
            active: c.active.load(Ordering::Relaxed),
            desynced: c.desynced.load(Ordering::Relaxed),
            rescued: c.rescued.load(Ordering::Relaxed),
            failed: c.failed.load(Ordering::Relaxed),
            dns_answered: self.shared.resolver.answered(),
            dns_fallbacks: self.shared.resolver.fallbacks(),
        }
    }

    /// True while the listener is accepting.
    pub fn is_running(&self) -> bool {
        self.accept.as_ref().is_some_and(|h| !h.is_finished())
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        // Wake the blocking accept with a connection of our own.
        let _ = TcpStream::connect_timeout(&self.shared.addr, Duration::from_millis(500));
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if self.accept.is_some() {
            self.shutdown();
        }
    }
}

fn accept_loop(sh: Arc<Shared>, listener: TcpListener) {
    loop {
        let res = listener.accept();
        if sh.stop.load(Ordering::Acquire) {
            return;
        }
        let (client, _) = match res {
            Ok(c) => c,
            Err(e) => {
                // Out of descriptors and the like: back off instead of spinning.
                sh.log(|| format!("accept: {e}"));
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        sh.counters.accepted.fetch_add(1, Ordering::Relaxed);
        if sh.counters.active.load(Ordering::Relaxed) >= sh.cfg.max_conns as u64 {
            continue; // dropped: closed
        }
        sh.counters.active.fetch_add(1, Ordering::Relaxed);
        let sh2 = sh.clone();
        let spawned = std::thread::Builder::new().name("sondpi-conn".into()).stack_size(CONN_STACK).spawn(move || {
            let _guard = ActiveGuard(&sh2);
            serve(&sh2, client);
        });
        if spawned.is_err() {
            sh.counters.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct ActiveGuard<'a>(&'a Shared);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.counters.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Read once more into `buf`; `Ok(false)` at EOF.
fn read_more(s: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<bool> {
    let mut chunk = [0u8; 4096];
    let n = s.read(&mut chunk)?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

/// Read once more into `buf` before `deadline`; false at EOF, error or when time is up.
fn read_head(s: &mut TcpStream, buf: &mut Vec<u8>, deadline: Instant) -> bool {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
        return false;
    }
    read_more(s, buf).unwrap_or(false)
}

fn serve(sh: &Shared, mut client: TcpStream) {
    let _ = client.set_nodelay(true);
    // The whole request head (or SOCKS handshake) must arrive within HEAD_TIMEOUT.
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut buf = Vec::with_capacity(2048);
    if !read_head(&mut client, &mut buf, deadline) {
        return;
    }
    if buf[0] == 5 {
        serve_socks(sh, client, buf, deadline);
    } else {
        serve_http(sh, client, buf, deadline);
    }
}

fn serve_http(sh: &Shared, mut client: TcpStream, mut buf: Vec<u8>, deadline: Instant) {
    let (ask, n) = loop {
        match parse_http(&buf) {
            Ok(Some(x)) => break x,
            Ok(None) => {
                if !read_head(&mut client, &mut buf, deadline) {
                    return;
                }
            }
            Err(e) => {
                sh.log(|| format!("http: {e}"));
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            }
        }
    };
    let rest = buf.split_off(n);
    match ask {
        HttpAsk::Local { method, path } => {
            let pac = pac_script(sh.addr.port());
            let reply = if path == PAC_PATH && (method == "GET" || method == "HEAD") {
                let body = if method == "GET" { pac.as_str() } else { "" };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\n\
                     Cache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
                    pac.len()
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            };
            let _ = client.write_all(reply.as_bytes());
        }
        HttpAsk::Tunnel(target) => {
            let Some(up) = open(sh, &target) else {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            };
            if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
                return;
            }
            relay(sh, client, up, rest, &target);
        }
        HttpAsk::Forward { target, mut head } => {
            let Some(up) = open(sh, &target) else {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            };
            head.extend_from_slice(&rest);
            relay(sh, client, up, head, &target);
        }
    }
}

fn serve_socks(sh: &Shared, mut client: TcpStream, mut buf: Vec<u8>, deadline: Instant) {
    let (no_auth, n) = loop {
        match parse_socks_greeting(&buf) {
            Ok(Some(x)) => break x,
            Ok(None) => {
                if !read_head(&mut client, &mut buf, deadline) {
                    return;
                }
            }
            Err(_) => return,
        }
    };
    if !no_auth {
        let _ = client.write_all(&[5, 0xff]);
        return;
    }
    if client.write_all(&[5, 0]).is_err() {
        return;
    }
    buf.drain(..n);
    let (target, n) = loop {
        if buf.len() > MAX_HEAD {
            return;
        }
        match parse_socks_request(&buf) {
            Ok(Some(x)) => break x,
            Ok(None) => {
                if !read_head(&mut client, &mut buf, deadline) {
                    return;
                }
            }
            Err(code) => {
                let _ = client.write_all(&socks_reply(code));
                return;
            }
        }
    };
    let rest = buf.split_off(n);
    let up = match open_err(sh, &target) {
        Ok(up) => up,
        Err(e) => {
            let code = match e.kind() {
                io::ErrorKind::ConnectionRefused => SOCKS_REFUSED,
                io::ErrorKind::NotFound | io::ErrorKind::TimedOut | io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                    SOCKS_HOST_UNREACHABLE
                }
                _ => SOCKS_FAILURE,
            };
            let _ = client.write_all(&socks_reply(code));
            return;
        }
    };
    if client.write_all(&socks_reply(SOCKS_OK)).is_err() {
        return;
    }
    relay(sh, client, up, rest, &target);
}

fn open(sh: &Shared, target: &Target) -> Option<TcpStream> {
    open_err(sh, target).ok()
}

/// Resolve and dial `target`.
fn open_err(sh: &Shared, target: &Target) -> io::Result<TcpStream> {
    let t0 = Instant::now();
    let r = (|| {
        let ips = match &target.host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(n) => sh.resolver.lookup(n)?,
        };
        let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, target.port)).collect();
        let own_port = |a: &SocketAddr| a.port() == sh.addr.port() && (a.ip().is_loopback() || a.ip().is_unspecified() || a.ip() == sh.addr.ip());
        if addrs.iter().any(own_port) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "refusing to connect to the proxy itself"));
        }
        let t1 = t0.elapsed();
        let d = dial::connect(&addrs, &sh.cfg.dial)?;
        if d.rescued() {
            sh.counters.rescued.fetch_add(1, Ordering::Relaxed);
        }
        sh.log(|| {
            format!(
                "{target} -> {} resolve {}ms connect {}ms attempt {}/{}",
                d.stream.peer_addr().map(|a| a.to_string()).unwrap_or_default(),
                t1.as_millis(),
                (t0.elapsed() - t1).as_millis(),
                d.attempt + 1,
                d.started
            )
        });
        Ok(d.stream)
    })();
    match r {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Err(e) => {
            sh.counters.failed.fetch_add(1, Ordering::Relaxed);
            sh.log(|| format!("{target}: {e} after {}ms", t0.elapsed().as_millis()));
            Err(e)
        }
    }
}

/// Send the client's first bytes (split when they are a ClientHello or HTTP request), then
/// copy both ways until both directions are closed.
fn relay(sh: &Shared, mut client: TcpStream, mut up: TcpStream, mut first: Vec<u8>, target: &Target) {
    let _ = client.set_read_timeout(None);
    let (Ok(c2), Ok(u2)) = (client.try_clone(), up.try_clone()) else { return };
    let down = std::thread::Builder::new().name("sondpi-down".into()).stack_size(CONN_STACK).spawn(move || pump(u2, c2));
    let Ok(down) = down else { return };

    // The first request may already be here (absolute-form HTTP, data after CONNECT/SOCKS)
    // or come now; a ClientHello can span reads.
    let ok = (|| -> io::Result<()> {
        if first.is_empty() && !read_more(&mut client, &mut first)? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if let Some(len) = tls::handshake_record_len(&first) {
            let _ = client.set_read_timeout(Some(HELLO_TIMEOUT));
            while first.len() < len && read_more(&mut client, &mut first).unwrap_or(false) {}
            let _ = client.set_read_timeout(None);
        }
        match desync_first(&first).filter(|_| sh.cfg.desync) {
            Some((bytes, cut)) => {
                up.write_all(&bytes[..cut])?;
                if sh.cfg.gap_ms > 0 {
                    std::thread::sleep(Duration::from_millis(sh.cfg.gap_ms));
                }
                up.write_all(&bytes[cut..])?;
                sh.counters.desynced.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                up.write_all(&first)?;
                sh.log(|| format!("{target}: first {} bytes sent unchanged", first.len()));
            }
        }
        Ok(())
    })()
    .is_ok();
    if ok {
        pump(client, up);
    } else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = up.shutdown(Shutdown::Both);
    }
    let _ = down.join();
}

/// Copy `from` -> `to` until EOF (then half-close `to`) or an error (then close both).
fn pump(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str, port: u16) -> Target {
        Target { host: Host::Name(n.into()), port }
    }
    fn ip(a: &str, port: u16) -> Target {
        Target { host: Host::Ip(a.parse().unwrap()), port }
    }

    #[test]
    fn authority() {
        assert_eq!(Target::parse_authority("Discord.COM:443", 80), Some(name("discord.com", 443)));
        assert_eq!(Target::parse_authority("discord.com.", 80), Some(name("discord.com", 80)));
        assert_eq!(Target::parse_authority("1.2.3.4:8443", 80), Some(ip("1.2.3.4", 8443)));
        assert_eq!(Target::parse_authority("[2606:4700::1]:443", 80), Some(ip("2606:4700::1", 443)));
        assert_eq!(Target::parse_authority("[::1]", 80), Some(ip("::1", 80)));
        assert_eq!(Target::parse_authority("::1", 80), Some(ip("::1", 80)));
        for bad in ["", "a:", "a:0", "a:99999", "[::1]x", "[zz]:1", "a b:1", "a..b", ":443", "-:x"] {
            assert_eq!(Target::parse_authority(bad, 80), None, "{bad:?}");
        }
        assert_eq!(name("a.b", 1).to_string(), "a.b:1");
        assert_eq!(ip("::1", 2).to_string(), "[::1]:2");
    }

    #[test]
    fn http_connect() {
        let req = b"CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\nUser-Agent: x\r\n\r\n\x16\x03";
        let (ask, n) = parse_http(req).unwrap().unwrap();
        assert_eq!(ask, HttpAsk::Tunnel(name("discord.com", 443)));
        assert_eq!(&req[n..], b"\x16\x03");
        assert_eq!(parse_http(&req[..20]), Ok(None));
        assert!(parse_http(b"CONNECT nope HTTP/1.1\r\n\r\n").is_ok()); // default port 443
        assert!(parse_http(b"CONNECT a:0 HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_http(b"CONNECT a:1 HTTP/2\r\n\r\n").is_err());
        assert!(parse_http(b"connect a:1 HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_http(b"CONNECT a:1 HTTP/1.1\r\nbroken\r\n\r\n").is_err());
        assert!(parse_http(&vec![b'A'; MAX_HEAD]).is_err());
    }

    #[test]
    fn http_forward_rewrites_head() {
        let req = b"GET http://Example.com:8080/a/b?c=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\nBODY";
        let (ask, n) = parse_http(req).unwrap().unwrap();
        let HttpAsk::Forward { target, head } = ask else { panic!() };
        assert_eq!(target, name("example.com", 8080));
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "GET /a/b?c=1 HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(&req[n..], b"BODY");
        // no path, query only, missing Host
        let (ask, _) = parse_http(b"HEAD http://a.b HTTP/1.0\r\n\r\n").unwrap().unwrap();
        let HttpAsk::Forward { head, .. } = ask else { panic!() };
        assert_eq!(String::from_utf8(head).unwrap(), "HEAD / HTTP/1.0\r\nHost: a.b\r\nConnection: close\r\n\r\n");
        let (ask, _) = parse_http(b"GET http://a.b?x HTTP/1.1\r\nHost: a.b\r\n\r\n").unwrap().unwrap();
        let HttpAsk::Forward { head, .. } = ask else { panic!() };
        assert!(head.starts_with(b"GET /?x HTTP/1.1\r\n"));
        let (ask, _) = parse_http(b"GET http://a.b/ HTTP/1.1\r\nHost: a.b\r\nConnection: Upgrade, X-Hop\r\nUpgrade: websocket\r\nX-Hop: 1\r\nX-Keep: 2\r\n\r\n").unwrap().unwrap();
        let HttpAsk::Forward { head, .. } = ask else { panic!() };
        assert_eq!(String::from_utf8(head).unwrap(), "GET / HTTP/1.1\r\nHost: a.b\r\nX-Keep: 2\r\nConnection: close\r\n\r\n");
        assert!(parse_http(b"GET https://a.b/ HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_http(b"GET http://u:p@a.b/ HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_http(b"GET ftp://a.b/ HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn http_local() {
        let (ask, _) = parse_http(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n").unwrap().unwrap();
        assert_eq!(ask, HttpAsk::Local { method: "GET".into(), path: PAC_PATH.into() });
    }

    #[test]
    fn socks() {
        assert_eq!(parse_socks_greeting(&[5]), Ok(None));
        assert_eq!(parse_socks_greeting(&[5, 2, 2]), Ok(None));
        assert_eq!(parse_socks_greeting(&[5, 2, 2, 0]), Ok(Some((true, 4))));
        assert_eq!(parse_socks_greeting(&[5, 1, 2]), Ok(Some((false, 3))));
        assert!(parse_socks_greeting(&[5, 0]).is_err());
        assert!(parse_socks_greeting(&[4, 1]).is_err());

        let mut r = vec![5, 1, 0, 3, 11];
        r.extend_from_slice(b"discord.com");
        r.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(parse_socks_request(&r), Ok(Some((name("discord.com", 443), r.len()))));
        assert_eq!(parse_socks_request(&r[..r.len() - 1]), Ok(None));
        assert_eq!(parse_socks_request(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]), Ok(Some((ip("1.2.3.4", 80), 10))));
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&"2606:4700::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[1, 187]);
        assert_eq!(parse_socks_request(&v6), Ok(Some((ip("2606:4700::1", 443), 22))));
        assert_eq!(parse_socks_request(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80]), Err(SOCKS_CMD_UNSUPPORTED));
        assert_eq!(parse_socks_request(&[5, 1, 0, 9, 1, 2, 3, 4, 0, 80]), Err(SOCKS_ATYP_UNSUPPORTED));
        assert_eq!(parse_socks_request(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 0]), Err(SOCKS_FAILURE));
        assert_eq!(parse_socks_request(&[5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80]), Err(SOCKS_HOST_UNREACHABLE));
        assert_eq!(parse_socks_request(&[4]), Err(SOCKS_FAILURE));
        assert_eq!(socks_reply(SOCKS_OK)[..2], [5, 0]);
    }

    #[test]
    fn desync_tls_and_http() {
        let mut hello = crate::tls::build_client_hello("discord.com", 9);
        hello.extend_from_slice(b"tail");
        let (out, cut) = desync_first(&hello).unwrap();
        assert_eq!(out.len(), hello.len() + 5);
        assert_eq!(crate::tls::handshake_record_len(&out), Some(cut));
        assert!(out.ends_with(b"tail"));
        assert!(!out[..cut].windows(11).any(|w| w == b"discord.com"));
        // incomplete record, no SNI, not TLS: unchanged
        assert_eq!(desync_first(&hello[..100]), None);
        assert_eq!(desync_first(&crate::tls::build_client_hello("", 9)), None);
        assert_eq!(desync_first(b"\x17\x03\x03\x00\x01\x00"), None);
        assert_eq!(desync_first(b"SSH-2.0-x\r\n"), None);

        let req = b"GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n";
        let (out, cut) = desync_first(req).unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\nhoSt: discord.com\r\n\r\n".to_vec());
        assert_eq!(&out[cut - 5..cut], b"disco");
        let req = b"POST /a HTTP/1.1\r\nAccept: */*\r\nHOST:  x.example\r\n\r\nbody";
        let (out, _) = desync_first(req).unwrap();
        assert_eq!(out, b"POST /a HTTP/1.1\r\nAccept: */*\r\nhoSt:  x.example\r\n\r\nbody".to_vec());
    }

    #[test]
    fn pac_mentions_port_and_direct_fallback() {
        let p = pac_script(8642);
        assert!(p.contains("PROXY 127.0.0.1:8642; DIRECT"));
        assert!(p.starts_with("function FindProxyForURL(url, host) {"));
    }

    // ---- server ----------------------------------------------------------------------

    fn test_proxy() -> Proxy {
        let up: crate::dns::UpstreamFn = Arc::new(|_, _, _| Err("no DoH in tests".into()));
        let res = Arc::new(Resolver::new(crate::dns::DnsConfig { upstreams: vec![], timeout_ms: 100 }, up));
        Proxy::start(ProxyConfig::default(), res, None).unwrap()
    }

    /// One-shot upstream: reads until it has `want` bytes (0: a complete request head) or EOF,
    /// replies `reply`, returns what it got.
    fn upstream(want: usize, reply: &'static [u8]) -> (SocketAddr, JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut got = Vec::new();
            while if want == 0 { !got.windows(4).any(|w| w == b"\r\n\r\n") } else { got.len() < want } {
                if !read_more(&mut s, &mut got).unwrap_or(false) {
                    break;
                }
            }
            s.write_all(reply).unwrap();
            got
        });
        (addr, h)
    }

    fn read_all(s: &mut TcpStream) -> Vec<u8> {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut v = Vec::new();
        let _ = s.read_to_end(&mut v);
        v
    }

    #[test]
    fn connect_tunnel_splits_the_client_hello() {
        let p = test_proxy();
        let hello = crate::tls::build_client_hello("discord.com", 1);
        let (up, h) = upstream(hello.len() + 5, b"server-hello");
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(format!("CONNECT {up} HTTP/1.1\r\nHost: {up}\r\n\r\n").as_bytes()).unwrap();
        let mut resp = [0u8; 39];
        c.read_exact(&mut resp).unwrap();
        assert_eq!(&resp[..], b"HTTP/1.1 200 Connection established\r\n\r\n");
        // the ClientHello arrives in two writes, as a browser might send it
        c.write_all(&hello[..100]).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        c.write_all(&hello[100..]).unwrap();
        let got = h.join().unwrap();
        let l1 = crate::tls::handshake_record_len(&got).unwrap();
        let mut joined = got[5..l1].to_vec();
        joined.extend_from_slice(&got[l1 + 5..]);
        assert_eq!(joined, hello[5..].to_vec());
        assert_eq!(read_all(&mut c), b"server-hello");
        assert_eq!(p.stats().desynced, 1);
        assert_eq!(p.stats().accepted, 1);
    }

    #[test]
    fn socks5_with_a_local_name() {
        let p = test_proxy();
        let (up, h) = upstream(5, b"pong");
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).unwrap();
        assert_eq!(r, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 9];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&up.port().to_be_bytes());
        c.write_all(&req).unwrap();
        let mut r = [0u8; 10];
        c.read_exact(&mut r).unwrap();
        assert_eq!(r[..2], [5, 0]);
        c.write_all(b"ping!").unwrap();
        assert_eq!(h.join().unwrap(), b"ping!");
        assert_eq!(read_all(&mut c), b"pong");
        assert_eq!(p.stats().desynced, 0);
    }

    #[test]
    fn forward_absolute_form_request() {
        let p = test_proxy();
        let (up, h) = upstream(0, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(format!("GET http://{up}/x HTTP/1.1\r\nHost: {up}\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes()).unwrap();
        let resp = read_all(&mut c);
        assert!(resp.ends_with(b"hi"));
        let got = String::from_utf8(h.join().unwrap()).unwrap();
        assert_eq!(got, format!("GET /x HTTP/1.1\r\nhoSt: {up}\r\nConnection: close\r\n\r\n"));
        assert_eq!(p.stats().desynced, 1); // Host value cut
    }

    #[test]
    fn serves_pac_and_refuses_bad_targets() {
        let p = test_proxy();
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let resp = String::from_utf8(read_all(&mut c)).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains(&format!("PROXY 127.0.0.1:{}; DIRECT", p.addr().port())));

        // nothing listens: 502
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(format!("CONNECT {dead} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        assert!(read_all(&mut c).starts_with(b"HTTP/1.1 502"));
        // a tunnel to the proxy itself: 502, no loop
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(format!("CONNECT {} HTTP/1.1\r\n\r\n", p.addr()).as_bytes()).unwrap();
        assert!(read_all(&mut c).starts_with(b"HTTP/1.1 502"));
        // the proxy's port on another loopback form: refused too
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(format!("CONNECT 127.0.0.2:{} HTTP/1.1\r\n\r\n", p.addr().port()).as_bytes()).unwrap();
        assert!(read_all(&mut c).starts_with(b"HTTP/1.1 502"));
        // garbage: 400
        let mut c = TcpStream::connect(p.addr()).unwrap();
        c.write_all(b"HELLO\r\n\r\n").unwrap();
        assert!(read_all(&mut c).starts_with(b"HTTP/1.1 400"));
        assert_eq!(p.stats().failed, 3);
    }

    #[test]
    fn stop_closes_the_listener() {
        let p = test_proxy();
        let addr = p.addr();
        assert!(p.is_running());
        p.stop();
        assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err());
    }
}
