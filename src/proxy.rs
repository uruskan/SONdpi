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

use std::net::IpAddr;

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

    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for (k, v) in &headers {
        let drop = ["proxy-connection", "proxy-authorization", "connection", "keep-alive"].iter().any(|d| k.eq_ignore_ascii_case(d));
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
/// between them; a plain HTTP request is cut in the middle of its Host value. `None`: send
/// `first` unchanged.
pub fn desync_first(first: &[u8]) -> Option<(Vec<u8>, usize)> {
    if let Some(len) = crate::tls::handshake_record_len(first) {
        let rec = first.get(..len)?;
        let at = crate::tls::sni_cut(rec)?;
        let mut out = crate::tls::split_record(rec, at)?;
        out.extend_from_slice(&first[len..]);
        return Some((out, 5 + at));
    }
    let host = crate::desync::parse_http_request(first)?.host?;
    let cut = (host.start + host.end) / 2;
    (cut > host.start).then(|| (first.to_vec(), cut))
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
        assert_eq!(out, req.to_vec());
        assert_eq!(&req[cut - 5..cut], b"disco");
    }

    #[test]
    fn pac_mentions_port_and_direct_fallback() {
        let p = pac_script(8642);
        assert!(p.contains("PROXY 127.0.0.1:8642; DIRECT"));
        assert!(p.starts_with("function FindProxyForURL(url, host) {"));
    }
}
