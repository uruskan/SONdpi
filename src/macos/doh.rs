//! DNS-over-HTTPS client for macOS: HTTP/1.1 POST (RFC 8484) over TLS from Security.framework
//! (SecureTransport) on a socket of our own.
//!
//! Why not the system's URL loading: it honours the system proxy setting, which while SONdpi
//! is on points at our own proxy, whose name lookups come here: a loop. Our own socket goes
//! straight out, is dialled with [`crate::dial`] (the DoH addresses suffer from lost SYNs like
//! any other Cloudflare address), and stays open for the next query.
//!
//! SecureTransport is deprecated but present and working on current macOS; it speaks up to
//! TLS 1.2, which every default upstream accepts. Certificates are verified against the
//! system trust store for the URL's host (an IP literal for the defaults; their certificates
//! carry IP addresses).

use crate::dial::{self, DialConfig};
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Largest DNS response accepted.
pub const MAX_RESPONSE: usize = 64 * 1024;
/// Idle connections kept per upstream.
const POOL_MAX: usize = 4;
/// Idle connections older than this are not reused (servers close idle HTTP/1.1 connections
/// after some tens of seconds; Cloudflare after about a minute).
const IDLE_MAX: Duration = Duration::from_secs(30);

// ---- Security.framework (SecureTransport) -------------------------------------------------

type OSStatus = i32;
type SSLContextRef = *mut c_void;
type SSLConnectionRef = *const c_void;
type ReadFn = unsafe extern "C" fn(SSLConnectionRef, *mut c_void, *mut usize) -> OSStatus;
type WriteFn = unsafe extern "C" fn(SSLConnectionRef, *const c_void, *mut usize) -> OSStatus;

const K_SSL_CLIENT_SIDE: i32 = 1;
const K_SSL_STREAM_TYPE: i32 = 0;
const K_TLS_PROTOCOL_12: i32 = 8;
const ERR_SSL_CLOSED_GRACEFUL: OSStatus = -9805;
const ERR_SSL_CLOSED_ABORT: OSStatus = -9806;
const ERR_SSL_CLOSED_NO_NOTIFY: OSStatus = -9816;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SSLCreateContext(alloc: *const c_void, side: i32, kind: i32) -> SSLContextRef;
    fn SSLSetIOFuncs(ctx: SSLContextRef, read: ReadFn, write: WriteFn) -> OSStatus;
    fn SSLSetConnection(ctx: SSLContextRef, conn: SSLConnectionRef) -> OSStatus;
    fn SSLSetPeerDomainName(ctx: SSLContextRef, name: *const u8, len: usize) -> OSStatus;
    fn SSLSetProtocolVersionMin(ctx: SSLContextRef, v: i32) -> OSStatus;
    fn SSLHandshake(ctx: SSLContextRef) -> OSStatus;
    fn SSLWrite(ctx: SSLContextRef, data: *const c_void, len: usize, processed: *mut usize) -> OSStatus;
    fn SSLRead(ctx: SSLContextRef, data: *mut c_void, len: usize, processed: *mut usize) -> OSStatus;
    fn SSLClose(ctx: SSLContextRef) -> OSStatus;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: *const c_void);
}

/// I/O callbacks: SecureTransport asks for exactly `*len` bytes; a short count is an error
/// here because the socket is blocking (with a timeout).
unsafe extern "C" fn st_read(conn: SSLConnectionRef, data: *mut c_void, len: *mut usize) -> OSStatus {
    // SAFETY: `conn` is the `TcpStream` boxed in `Tls`, alive while the context is; `len` is
    // a valid in/out pointer for this call.
    let (stream, want) = unsafe { (&*(conn as *const TcpStream), *len) };
    // SAFETY: `data` points to `want` writable bytes SecureTransport owns during this call.
    let buf = unsafe { std::slice::from_raw_parts_mut(data as *mut u8, want) };
    let mut got = 0;
    let status = loop {
        if got == want {
            break 0;
        }
        match (&*stream).read(&mut buf[got..]) {
            Ok(0) => break ERR_SSL_CLOSED_NO_NOTIFY,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break ERR_SSL_CLOSED_ABORT,
        }
    };
    // SAFETY: `len` is a valid out-pointer for this call.
    unsafe { *len = got };
    status
}

unsafe extern "C" fn st_write(conn: SSLConnectionRef, data: *const c_void, len: *mut usize) -> OSStatus {
    // SAFETY: as in `st_read`: `conn` is our boxed stream, `len` a valid pointer.
    let (stream, want) = unsafe { (&*(conn as *const TcpStream), *len) };
    // SAFETY: `data` points to `want` readable bytes SecureTransport owns during this call.
    let buf = unsafe { std::slice::from_raw_parts(data as *const u8, want) };
    let status = match (&*stream).write_all(buf) {
        Ok(()) => 0,
        Err(_) => ERR_SSL_CLOSED_ABORT,
    };
    // SAFETY: `len` is a valid out-pointer for this call.
    unsafe { *len = if status == 0 { want } else { 0 } };
    status
}

/// One TLS connection. The stream is boxed so its address, handed to SecureTransport as the
/// connection reference, never moves.
struct Tls {
    ctx: SSLContextRef,
    stream: Box<TcpStream>,
    last_used: Instant,
}

// SAFETY: a `Tls` is used by one thread at a time (it lives in a pool behind a mutex or on the
// stack of the querying thread); SecureTransport contexts may move between threads.
unsafe impl Send for Tls {}

impl Drop for Tls {
    fn drop(&mut self) {
        // SAFETY: `ctx` came from SSLCreateContext and is released exactly once, here.
        unsafe {
            SSLClose(self.ctx);
            CFRelease(self.ctx as *const c_void);
        }
    }
}

fn status_err(what: &str, s: OSStatus) -> String {
    format!("TLS {what} failed (OSStatus {s})")
}

impl Tls {
    fn connect(addr: SocketAddr, peer: &str, timeout: Duration) -> Result<Tls, String> {
        let cfg = DialConfig { timeout_ms: timeout.as_millis().max(1) as u64, ..DialConfig::default() };
        let d = dial::connect(&[addr], &cfg).map_err(|e| format!("connect {addr}: {e}"))?;
        let stream = Box::new(d.stream);
        let _ = stream.set_nodelay(true);
        // SAFETY: plain constructor; a null result is handled below.
        let ctx = unsafe { SSLCreateContext(std::ptr::null(), K_SSL_CLIENT_SIDE, K_SSL_STREAM_TYPE) };
        if ctx.is_null() {
            return Err("SSLCreateContext failed".into());
        }
        let tls = Tls { ctx, stream, last_used: Instant::now() };
        tls.set_timeout(timeout);
        let conn = &*tls.stream as *const TcpStream as SSLConnectionRef;
        // SAFETY: `ctx` is valid; `conn` outlives it (both owned by `tls`, the box never moves);
        // `peer` is passed with its length.
        unsafe {
            let s = SSLSetIOFuncs(ctx, st_read, st_write);
            if s != 0 {
                return Err(status_err("setup", s));
            }
            let s = SSLSetConnection(ctx, conn);
            if s != 0 {
                return Err(status_err("setup", s));
            }
            let s = SSLSetPeerDomainName(ctx, peer.as_ptr(), peer.len());
            if s != 0 {
                return Err(status_err("setup", s));
            }
            let s = SSLSetProtocolVersionMin(ctx, K_TLS_PROTOCOL_12);
            if s != 0 {
                return Err(status_err("setup", s));
            }
            let s = SSLHandshake(ctx);
            if s != 0 {
                return Err(status_err("handshake", s));
            }
        }
        Ok(tls)
    }

    fn set_timeout(&self, t: Duration) {
        let t = Some(t.max(Duration::from_millis(1)));
        let _ = self.stream.set_read_timeout(t);
        let _ = self.stream.set_write_timeout(t);
    }

    fn write_all(&mut self, mut data: &[u8]) -> Result<(), String> {
        while !data.is_empty() {
            let mut n = 0usize;
            // SAFETY: `ctx` is valid; `data` is a live slice and `n` an out-pointer.
            let s = unsafe { SSLWrite(self.ctx, data.as_ptr() as *const c_void, data.len(), &mut n) };
            if s != 0 {
                return Err(status_err("write", s));
            }
            data = &data[n.min(data.len())..];
        }
        Ok(())
    }

    /// Up to `buf.len()` bytes; 0 at a clean close.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        let mut n = 0usize;
        // SAFETY: `ctx` is valid; `buf` is a live mutable slice and `n` an out-pointer.
        let s = unsafe { SSLRead(self.ctx, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut n) };
        match s {
            0 => Ok(n),
            ERR_SSL_CLOSED_GRACEFUL | ERR_SSL_CLOSED_NO_NOTIFY if n == 0 => Ok(0),
            _ if n > 0 => Ok(n),
            _ => Err(status_err("read", s)),
        }
    }
}

// ---- HTTP -----------------------------------------------------------------------------------

/// `https://host[:port]/path` -> (host, port, path). Only https.
pub fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("https://").ok_or("only https:// URLs are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("bad URL {url}"));
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, after) = r.split_once(']').ok_or("bad IPv6 literal")?;
        let port = match after {
            "" => 443,
            p => p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or("bad port")?,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad port")?),
            None => (authority.to_string(), 443),
        }
    };
    if host.is_empty() || port == 0 {
        return Err(format!("bad URL {url}"));
    }
    Ok((host, port, path.to_string()))
}

/// Parsed response head.
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub close: bool,
}

/// Parse a response head (without the final blank line).
pub fn parse_head(head: &[u8]) -> Result<Head, String> {
    let text = std::str::from_utf8(head).map_err(|_| "response head is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!("unexpected status line {status_line:?}"));
    }
    let status = parts.next().and_then(|s| s.parse().ok()).ok_or("bad status code")?;
    let mut h = Head { status, content_length: None, chunked: false, close: version == "HTTP/1.0" };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("content-length") {
            h.content_length = Some(v.parse().map_err(|_| "bad Content-Length")?);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            h.chunked = v.to_ascii_lowercase().contains("chunked");
        } else if k.eq_ignore_ascii_case("connection") {
            let v = v.to_ascii_lowercase();
            if v.contains("close") {
                h.close = true;
            } else if v.contains("keep-alive") {
                h.close = false;
            }
        }
    }
    Ok(h)
}

/// Decode a complete chunked body; `Ok(None)` while more bytes are needed.
pub fn dechunk(buf: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let Some(eol) = buf[pos..].windows(2).position(|w| w == b"\r\n") else { return Ok(None) };
        let line = std::str::from_utf8(&buf[pos..pos + eol]).map_err(|_| "bad chunk size")?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "bad chunk size")?;
        pos += eol + 2;
        if size == 0 {
            // trailers until an empty line
            loop {
                let Some(eol) = buf[pos..].windows(2).position(|w| w == b"\r\n") else { return Ok(None) };
                pos += eol + 2;
                if eol == 0 {
                    return Ok(Some(out));
                }
            }
        }
        if out.len() + size > MAX_RESPONSE {
            return Err("response too large".into());
        }
        if buf.len() < pos + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&buf[pos..pos + size]);
        pos += size + 2;
    }
}

/// One POST on `tls`. Returns the body and whether the connection may be reused.
fn exchange(tls: &mut Tls, host: &str, port: u16, path: &str, msg: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let host_header = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.to_string(),
    };
    let host_header = if port == 443 { host_header } else { format!("{host_header}:{port}") };
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        msg.len()
    )
    .into_bytes();
    req.extend_from_slice(msg);
    tls.write_all(&req)?;

    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 16 * 1024 {
            return Err("response head too large".into());
        }
        let n = tls.read(&mut chunk)?;
        if n == 0 {
            return Err("connection closed before the response".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = parse_head(&buf[..head_end])?;
    let mut body = buf.split_off(head_end + 4);
    let reusable = !head.close;
    let body = if head.chunked {
        loop {
            if let Some(b) = dechunk(&body)? {
                break b;
            }
            let n = tls.read(&mut chunk)?;
            if n == 0 {
                return Err("connection closed in the response body".into());
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else if let Some(len) = head.content_length {
        if len > MAX_RESPONSE {
            return Err("response too large".into());
        }
        while body.len() < len {
            let n = tls.read(&mut chunk)?;
            if n == 0 {
                return Err("connection closed in the response body".into());
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(len);
        body
    } else {
        // Delimited by the close.
        loop {
            let n = tls.read(&mut chunk)?;
            if n == 0 {
                break body;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > MAX_RESPONSE {
                return Err("response too large".into());
            }
        }
    };
    if head.status != 200 {
        return Err(format!("HTTP status {}", head.status));
    }
    let reusable = reusable && (head.chunked || head.content_length.is_some());
    Ok((body, reusable))
}

// ---- Client ---------------------------------------------------------------------------------

/// DoH client with a small pool of kept-alive connections per upstream URL.
#[derive(Default)]
pub struct Client {
    pool: Mutex<HashMap<String, Vec<Tls>>>,
}

impl Client {
    pub fn new() -> Client {
        Client::default()
    }

    /// Send the DNS message `msg` to `url`, return the response message.
    pub fn query(&self, url: &str, msg: &[u8], timeout_ms: u32) -> Result<Vec<u8>, String> {
        if msg.is_empty() {
            return Err("empty DNS message".into());
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1) as u64);
        let (host, port, path) = parse_url(url)?;
        // A kept-alive connection may have been closed by the server meanwhile: one retry on
        // a fresh connection.
        for _ in 0..2 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let (mut tls, reused) = match self.take(url) {
                Some(t) => (t, true),
                None => {
                    let addr = (host.as_str(), port)
                        .to_socket_addrs()
                        .map_err(|e| format!("{host}: {e}"))?
                        .next()
                        .ok_or_else(|| format!("{host}: no address"))?;
                    (Tls::connect(addr, &host, left)?, false)
                }
            };
            tls.set_timeout(deadline.saturating_duration_since(Instant::now()));
            match exchange(&mut tls, &host, port, &path, msg) {
                Ok((body, keep)) => {
                    if keep {
                        self.give_back(url, tls);
                    }
                    return Ok(body);
                }
                Err(_) if reused => continue,
                Err(e) => return Err(e),
            }
        }
        Err(format!("{url}: timed out"))
    }

    fn take(&self, url: &str) -> Option<Tls> {
        let mut pool = self.pool.lock().unwrap_or_else(|p| p.into_inner());
        let conns = pool.get_mut(url)?;
        while let Some(t) = conns.pop() {
            if t.last_used.elapsed() < IDLE_MAX {
                return Some(t);
            }
        }
        None
    }

    fn give_back(&self, url: &str, mut tls: Tls) {
        tls.last_used = Instant::now();
        let mut pool = self.pool.lock().unwrap_or_else(|p| p.into_inner());
        let conns = pool.entry(url.to_string()).or_default();
        if conns.len() < POOL_MAX {
            conns.push(tls);
        }
    }

    /// Close every idle connection.
    pub fn clear(&self) {
        self.pool.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

/// DoH upstreams for macOS. Quad9 (the fourth Windows default) answers HTTP/1.1 with 505 on
/// port 443, so Google's second address takes its place.
pub fn upstreams() -> Vec<String> {
    ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The client as a resolver upstream.
pub fn upstream(client: Arc<Client>) -> crate::dns::UpstreamFn {
    Arc::new(move |url, msg, t| client.query(url, msg, t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(parse_url("https://1.1.1.1/dns-query").unwrap(), ("1.1.1.1".into(), 443, "/dns-query".into()));
        assert_eq!(parse_url("https://dns.example:8443/x?y=1").unwrap(), ("dns.example".into(), 8443, "/x?y=1".into()));
        assert_eq!(parse_url("https://[2606:4700::1111]/dns-query").unwrap(), ("2606:4700::1111".into(), 443, "/dns-query".into()));
        assert_eq!(parse_url("https://[::1]:444").unwrap(), ("::1".into(), 444, "/".into()));
        for bad in ["http://1.1.1.1/dns-query", "https:///x", "https://a:99999/x", "https://u@a/x", "https://a:0/"] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn heads() {
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\ncontent-length: 45\r\n").unwrap();
        assert_eq!(h, Head { status: 200, content_length: Some(45), chunked: false, close: false });
        let h = parse_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close").unwrap();
        assert!(h.chunked && h.close);
        assert!(parse_head(b"HTTP/1.0 200 OK").unwrap().close);
        assert!(!parse_head(b"HTTP/1.0 200 OK\r\nConnection: keep-alive").unwrap().close);
        assert_eq!(parse_head(b"HTTP/1.1 400 Bad Request").unwrap().status, 400);
        assert!(parse_head(b"SSH-2.0").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: x").is_err());
    }

    #[test]
    fn chunked_bodies() {
        assert_eq!(dechunk(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap(), Some(b"abcde".to_vec()));
        assert_eq!(dechunk(b"3\r\nabc\r\n0\r\nT: v\r\n\r\n").unwrap(), Some(b"abc".to_vec()));
        assert_eq!(dechunk(b"3\r\nab").unwrap(), None);
        assert_eq!(dechunk(b"3\r\nabc\r\n0\r\n").unwrap(), None);
        assert!(dechunk(b"zz\r\n").is_err());
        assert!(dechunk(b"FFFFFF\r\n").is_err());
    }

    #[test]
    fn rejects_empty_message() {
        assert!(Client::new().query("https://1.1.1.1/dns-query", &[], 1000).is_err());
    }

    /// Needs internet access; run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_upstreams() {
        let c = Client::new();
        let q = crate::dns::build_query("example.com", crate::dns::TYPE_A, 0).unwrap();
        for url in upstreams() {
            let t0 = Instant::now();
            let r1 = c.query(&url, &q, 5000);
            let t1 = t0.elapsed();
            let r2 = c.query(&url, &q, 5000);
            println!(
                "{url}: first {:?} in {t1:?}, second {:?} in {:?}",
                r1.as_ref().map(|r| crate::dns::answer_addrs(r)),
                r2.as_ref().map(|r| crate::dns::answer_addrs(r).len()),
                t0.elapsed() - t1
            );
            assert!(!crate::dns::answer_addrs(&r1.unwrap()).is_empty());
            assert!(r2.is_ok());
        }
    }
}
