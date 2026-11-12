//! DNS-over-HTTPS client on WinHTTP (RFC 8484, POST application/dns-message).
//!
//! One process-wide WinHTTP session (direct access, no proxy configuration, HTTP/2 enabled when
//! the OS offers it) and one cached connection handle per host:port, so TCP/TLS connections are
//! reused between queries. Every request handle is closed on every path. Certificate validation
//! is left at the WinHTTP defaults. Callable from many threads at once.

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Networking::WinHttp::*;

/// Largest response message accepted.
pub const MAX_RESPONSE: usize = 64 * 1024;

const MIME: &str = "application/dns-message";

/// Whether the most recent successful response was carried over HTTP/2.
static HTTP2_SEEN: AtomicBool = AtomicBool::new(false);

/// True when the last successful query was answered over HTTP/2.
pub fn http2_used() -> bool {
    HTTP2_SEEN.load(Ordering::Relaxed)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Owned WinHTTP handle, closed on drop.
struct Handle(*mut c_void);

impl Handle {
    fn new(h: *mut c_void, what: &str) -> Result<Handle, String> {
        if h.is_null() {
            Err(format!("{what}: {}", last_error()))
        } else {
            Ok(Handle(h))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned by WinHTTP, is owned by us and is closed exactly once.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn last_error() -> String {
    // SAFETY: plain thread-local error read.
    let e = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    format!("WinHTTP error {e}")
}

/// Cached session and per-host connection handles (stored as addresses so the table is Send).
struct Shared {
    session: usize,
    conns: HashMap<(String, u16), usize>,
}

fn shared() -> &'static Mutex<Shared> {
    static S: OnceLock<Mutex<Shared>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Shared { session: 0, conns: HashMap::new() }))
}

/// Close every cached connection and the session. Later queries reopen them. Do not call while
/// queries are in flight.
pub fn shutdown() {
    let mut g = match shared().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for (_, h) in g.conns.drain() {
        // SAFETY: handle came from WinHttpConnect and was removed from the cache, so closed once.
        unsafe { WinHttpCloseHandle(h as *mut c_void) };
    }
    if g.session != 0 {
        // SAFETY: handle came from WinHttpOpen and is cleared from the cache here.
        unsafe { WinHttpCloseHandle(g.session as *mut c_void) };
        g.session = 0;
    }
}

/// Connection handle for `host:port`, creating the session and the connection when needed.
fn connection(host: &str, port: u16) -> Result<usize, String> {
    let mut g = match shared().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if g.session == 0 {
        let agent = wide("SONdpi");
        // SAFETY: valid NUL-terminated agent string; null proxy arguments with NO_PROXY.
        let s = unsafe { WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY, null(), null(), 0) };
        let s = Handle::new(s, "WinHttpOpen")?;
        let flags: u32 = WINHTTP_PROTOCOL_FLAG_HTTP2;
        // SAFETY: option takes a pointer to a u32; failure (no HTTP/2 support) is fine, HTTP/1.1 is used.
        unsafe {
            WinHttpSetOption(s.0, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flags as *const u32 as *const c_void, 4);
        }
        g.session = s.0 as usize;
        std::mem::forget(s); // ownership moves to the cache
    }
    let key = (host.to_string(), port);
    if let Some(&c) = g.conns.get(&key) {
        return Ok(c);
    }
    let w = wide(host);
    // SAFETY: session handle is live (held in the cache); host is NUL-terminated.
    let c = unsafe { WinHttpConnect(g.session as *mut c_void, w.as_ptr(), port, 0) };
    let c = Handle::new(c, "WinHttpConnect")?;
    let addr = c.0 as usize;
    std::mem::forget(c);
    g.conns.insert(key, addr);
    Ok(addr)
}

/// Split `https://host[:port]/path` into its parts. Only https is accepted.
pub(crate) fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| "only https:// URLs are supported".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("bad URL authority".into());
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let end = r.find(']').ok_or_else(|| "bad IPv6 literal".to_string())?;
        let host = &r[..end];
        let tail = &r[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| "bad port".to_string())?,
            None if tail.is_empty() => 443,
            None => return Err("bad URL authority".into()),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad port".to_string())?),
            None => (authority.to_string(), 443),
        }
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok((host, port, path.to_string()))
}

/// POST one DNS message to `url` and return the response message.
pub fn query(url: &str, message: &[u8], timeout_ms: u32) -> Result<Vec<u8>, String> {
    if message.is_empty() || message.len() > MAX_RESPONSE {
        return Err("bad message size".into());
    }
    let (host, port, path) = parse_url(url)?;
    let conn = connection(&host, port)?;

    let verb = wide("POST");
    let wpath = wide(&path);
    let mime = wide(MIME);
    let accept: [*const u16; 2] = [mime.as_ptr(), null()];
    // SAFETY: connection handle is cached and live; strings are NUL-terminated and outlive the call;
    // accept is a null-terminated array of valid pointers.
    let req = unsafe {
        WinHttpOpenRequest(conn as *mut c_void, verb.as_ptr(), wpath.as_ptr(), null(), null(), accept.as_ptr(), WINHTTP_FLAG_SECURE)
    };
    let req = Handle::new(req, "WinHttpOpenRequest")?;

    let t = timeout_ms.clamp(1, i32::MAX as u32) as i32;
    // SAFETY: request handle is live; plain integer arguments.
    if unsafe { WinHttpSetTimeouts(req.0, t, t, t, t) } == 0 {
        return Err(format!("WinHttpSetTimeouts: {}", last_error()));
    }
    let no_redirect: u32 = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    // SAFETY: option takes a pointer to a u32; the request handle is live.
    unsafe {
        WinHttpSetOption(req.0, WINHTTP_OPTION_REDIRECT_POLICY, &no_redirect as *const u32 as *const c_void, 4);
    }

    let headers = wide(&format!("Content-Type: {MIME}\r\nAccept: {MIME}\r\n"));
    let len = message.len() as u32;
    // SAFETY: headers are NUL-terminated (length -1 means "use NUL"); message outlives the call and
    // `len` is its exact size; the request handle is live.
    let ok = unsafe {
        WinHttpSendRequest(req.0, headers.as_ptr(), u32::MAX, message.as_ptr() as *const c_void, len, len, 0)
    };
    if ok == 0 {
        return Err(format!("WinHttpSendRequest: {}", last_error()));
    }
    // SAFETY: request handle is live; reserved argument must be null.
    if unsafe { WinHttpReceiveResponse(req.0, null_mut()) } == 0 {
        return Err(format!("WinHttpReceiveResponse: {}", last_error()));
    }

    let mut status: u32 = 0;
    let mut slen: u32 = 4;
    // SAFETY: NUMBER flag makes WinHTTP write a u32 into the buffer of size 4.
    let ok = unsafe {
        WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            &mut status as *mut u32 as *mut c_void,
            &mut slen,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!("status query: {}", last_error()));
    }
    if status != 200 {
        return Err(format!("HTTP status {status}"));
    }

    let mut ct = [0u16; 128];
    let mut clen: u32 = (ct.len() * 2) as u32;
    // SAFETY: buffer of clen bytes; WinHTTP writes at most that many and updates clen.
    let ok = unsafe {
        WinHttpQueryHeaders(req.0, WINHTTP_QUERY_CONTENT_TYPE, null(), ct.as_mut_ptr() as *mut c_void, &mut clen, null_mut())
    };
    if ok == 0 {
        return Err(format!("content type query: {}", last_error()));
    }
    let n = ((clen as usize) / 2).min(ct.len());
    let ctype = String::from_utf16_lossy(&ct[..n]).to_ascii_lowercase();
    if !ctype.trim().starts_with(MIME) {
        return Err(format!("unexpected content type {ctype:?}"));
    }

    let mut out: Vec<u8> = Vec::with_capacity(512);
    let mut buf = [0u8; 4096];
    loop {
        let mut got: u32 = 0;
        // SAFETY: buffer is 4096 bytes and that is the maximum we ask for; request handle is live.
        let ok = unsafe { WinHttpReadData(req.0, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut got) };
        if ok == 0 {
            return Err(format!("WinHttpReadData: {}", last_error()));
        }
        if got == 0 {
            break;
        }
        if out.len() + got as usize > MAX_RESPONSE {
            return Err("response too large".into());
        }
        out.extend_from_slice(&buf[..got as usize]);
    }
    if out.is_empty() {
        return Err("empty response".into());
    }

    let mut used: u32 = 0;
    let mut ulen: u32 = 4;
    // SAFETY: option writes a u32 of protocol flags into a 4-byte buffer.
    let ok = unsafe {
        WinHttpQueryOption(req.0, WINHTTP_OPTION_HTTP_PROTOCOL_USED, &mut used as *mut u32 as *mut c_void, &mut ulen)
    };
    if ok != 0 {
        HTTP2_SEEN.store(used & WINHTTP_PROTOCOL_FLAG_HTTP2 != 0, Ordering::Relaxed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(parse_url("https://1.1.1.1/dns-query").unwrap(), ("1.1.1.1".into(), 443, "/dns-query".into()));
        assert_eq!(parse_url("https://dns.example:8443/x?y=1").unwrap(), ("dns.example".into(), 8443, "/x?y=1".into()));
        assert_eq!(parse_url("https://[2606:4700::1111]/dns-query").unwrap(), ("2606:4700::1111".into(), 443, "/dns-query".into()));
        assert_eq!(parse_url("https://[::1]:444").unwrap(), ("::1".into(), 444, "/".into()));
        assert!(parse_url("http://1.1.1.1/dns-query").is_err());
        assert!(parse_url("https:///x").is_err());
        assert!(parse_url("https://a:99999/x").is_err());
        assert!(parse_url("https://u@a/x").is_err());
    }

    #[test]
    fn rejects_empty_message() {
        assert!(query("https://1.1.1.1/dns-query", &[], 1000).is_err());
    }

    /// Needs internet access; run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_cloudflare_example_com() {
        // Query: id 0x1234, RD, example.com A IN.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["example", "com"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let t0 = std::time::Instant::now();
        let r1 = query("https://1.1.1.1/dns-query", &q, 5000).expect("first query");
        let d1 = t0.elapsed();
        let t1 = std::time::Instant::now();
        let r2 = query("https://1.1.1.1/dns-query", &q, 5000).expect("second query");
        let d2 = t1.elapsed();
        println!("first {:?}, second {:?}, http2 {}", d1, d2, http2_used());
        for r in [&r1, &r2] {
            assert!(r.len() > 12);
            assert_eq!(&r[0..2], &[0x12, 0x34]);
            assert!(r[2] & 0x80 != 0, "QR set");
            assert_eq!(r[3] & 0x0f, 0, "NOERROR");
            assert!(u16::from_be_bytes([r[6], r[7]]) >= 1, "at least one answer");
        }
    }
}
