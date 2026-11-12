//! TLS ClientHello parsing and generation.
//!
//! Pure logic, no Windows APIs. Nothing in here may panic on any input: every read is
//! bounds-checked, and a ClientHello that is cut off (it can continue in later TCP segments,
//! e.g. with post-quantum key shares it is ~1700 bytes) is reported without its server name
//! rather than rejected.

use std::ops::Range;

/// What we need to know about a ClientHello that starts in one TCP payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// Byte range of the server name (the host name bytes only) inside the TCP payload, when
    /// the SNI extension is present and lies completely within this payload.
    pub sni: Option<Range<usize>>,
}

/// TLS record content types and handshake types used here.
const REC_ALERT: u8 = 0x15;
const REC_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const EXT_SERVER_NAME: u16 = 0x0000;

/// True for a TLS record header (type `ty`, version 3.0 .. 3.4) at the start of `p`.
fn record_header(p: &[u8], ty: u8) -> bool {
    p.len() >= 5 && p[0] == ty && p[1] == 0x03 && p[2] <= 0x04
}

/// Bounds-checked big-endian reader over `buf[..end]`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        if self.pos < self.end {
            let v = self.buf[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }
    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Some(u16::from_be_bytes([hi, lo]))
    }
    /// Skip `n` bytes; `None` when they are not all present.
    fn skip(&mut self, n: usize) -> Option<()> {
        let to = self.pos.checked_add(n)?;
        if to <= self.end {
            self.pos = to;
            Some(())
        } else {
            None
        }
    }
}

/// `Some` when `payload` begins with a TLS handshake record carrying a ClientHello. The
/// ClientHello may continue in later segments; only what is in `payload` is inspected.
///
/// Requires the record header (`0x16 0x03 0x00..=0x04`) and the handshake type byte
/// (`0x01`), i.e. at least 6 bytes. Everything after that is best effort: when the walk to the
/// server_name extension runs out of bytes or meets inconsistent lengths, the result is
/// `Some(ClientHello { sni: None })`.
pub fn parse_client_hello(payload: &[u8]) -> Option<ClientHello> {
    if !record_header(payload, REC_HANDSHAKE) || payload.len() < 6 || payload[5] != HS_CLIENT_HELLO {
        return None;
    }
    Some(ClientHello { sni: find_sni(payload) })
}

fn find_sni(p: &[u8]) -> Option<Range<usize>> {
    let rec_len = u16::from_be_bytes([p[3], p[4]]) as usize;
    if p.len() < 9 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, p[6], p[7], p[8]]) as usize;
    // Never read past the payload, the record or the handshake message.
    let end = p.len().min(5 + rec_len).min(9 + hs_len);
    let mut r = Reader { buf: p, pos: 9, end };
    r.skip(2)?; // legacy_version
    r.skip(32)?; // random
    let sid = r.u8()? as usize;
    r.skip(sid)?;
    let cs = r.u16()? as usize;
    r.skip(cs)?;
    let comp = r.u8()? as usize;
    r.skip(comp)?;
    let ext_total = r.u16()? as usize;
    // The extension block may extend beyond this payload; walk what is here.
    let ext_end = r.pos.checked_add(ext_total)?.min(end);
    let mut e = Reader { buf: p, pos: r.pos, end: ext_end };
    loop {
        let ty = e.u16()?;
        let len = e.u16()? as usize;
        let data = e.pos;
        if ty == EXT_SERVER_NAME {
            let data_end = data.checked_add(len)?.min(ext_end);
            let mut s = Reader { buf: p, pos: data, end: data_end };
            let list_len = s.u16()? as usize;
            s.end = s.pos.checked_add(list_len)?.min(data_end);
            loop {
                let name_type = s.u8()?;
                let name_len = s.u16()? as usize;
                let start = s.pos;
                s.skip(name_len)?;
                if name_type == 0 {
                    return if name_len > 0 { Some(start..start + name_len) } else { None };
                }
            }
        }
        e.skip(len)?;
    }
}

/// Deterministic splitmix64 PRNG (no external crates; quality is irrelevant here, only that
/// the bytes look random and depend on the seed).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn fill(&mut self, out: &mut Vec<u8>, n: usize) {
        let mut left = n;
        while left > 0 {
            let w = self.next().to_le_bytes();
            let k = left.min(8);
            out.extend_from_slice(&w[..k]);
            left -= k;
        }
    }
}

/// Typical size of a browser ClientHello record (Chrome before post-quantum key shares).
const TARGET_RECORD_LEN: usize = 517;

/// Cipher suites: the three TLS 1.3 suites, then the common ECDHE / RSA suites.
const CIPHER_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE-{ECDSA,RSA}-AES{128,256}-GCM
    0xcca9, 0xcca8, // ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305
    0xc013, 0xc014, // ECDHE-RSA-AES{128,256}-SHA
    0x009c, 0x009d, 0x002f, 0x0035, // RSA-AES{128,256}-GCM, RSA-AES{128,256}-SHA
];

const SIGNATURE_ALGORITHMS: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

fn push16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn push_ext(v: &mut Vec<u8>, ty: u16, data: &[u8]) {
    push16(v, ty);
    push16(v, data.len() as u16);
    v.extend_from_slice(data);
}

/// A syntactically valid, complete TLS ClientHello record for `sni`, deterministic for a given
/// `seed`. Used for fake packets and for calibration probes.
///
/// Browser-like shape: record version 3.1, legacy_version 3.3, 32-byte random, 32-byte session
/// id, TLS 1.3 + ECDHE suites, and the extensions server_name (first, so it sits early in the
/// packet), extended_master_secret, renegotiation_info, supported_groups, ec_point_formats,
/// session_ticket, ALPN (h2, http/1.1), status_request, signature_algorithms, key_share
/// (x25519, 32 random bytes), psk_key_exchange_modes, supported_versions (1.3, 1.2) and padding
/// to exactly 517 bytes. An empty `sni` omits server_name. Host names longer than 255 bytes
/// are cut to 255 (so the record always fits 517 bytes).
pub fn build_client_hello(sni: &str, seed: u64) -> Vec<u8> {
    let name = &sni.as_bytes()[..sni.len().min(255)];
    let mut rng = Rng(seed);

    let mut ext = Vec::with_capacity(512);
    if !name.is_empty() {
        let mut d = Vec::with_capacity(name.len() + 5);
        push16(&mut d, (name.len() + 3) as u16);
        d.push(0); // host_name
        push16(&mut d, name.len() as u16);
        d.extend_from_slice(name);
        push_ext(&mut ext, 0x0000, &d);
    }
    push_ext(&mut ext, 0x0017, &[]); // extended_master_secret
    push_ext(&mut ext, 0xff01, &[0x00]); // renegotiation_info
    push_ext(&mut ext, 0x000a, &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]); // x25519, P-256, P-384
    push_ext(&mut ext, 0x000b, &[0x01, 0x00]); // ec_point_formats: uncompressed
    push_ext(&mut ext, 0x0023, &[]); // session_ticket
    push_ext(&mut ext, 0x0010, b"\x00\x0c\x02h2\x08http/1.1"); // ALPN
    push_ext(&mut ext, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]); // status_request (OCSP)
    {
        let mut d = Vec::new();
        push16(&mut d, (SIGNATURE_ALGORITHMS.len() * 2) as u16);
        for a in SIGNATURE_ALGORITHMS {
            push16(&mut d, a);
        }
        push_ext(&mut ext, 0x000d, &d);
    }
    {
        let mut d = Vec::with_capacity(38);
        push16(&mut d, 36); // client_shares length
        push16(&mut d, 0x001d); // x25519
        push16(&mut d, 32);
        rng.fill(&mut d, 32);
        push_ext(&mut ext, 0x0033, &d);
    }
    push_ext(&mut ext, 0x002d, &[0x01, 0x01]); // psk_key_exchange_modes: psk_dhe_ke
    push_ext(&mut ext, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]); // supported_versions: 1.3, 1.2

    let mut body = Vec::with_capacity(TARGET_RECORD_LEN);
    push16(&mut body, 0x0303);
    rng.fill(&mut body, 32); // random
    body.push(32);
    rng.fill(&mut body, 32); // session id
    push16(&mut body, (CIPHER_SUITES.len() * 2) as u16);
    for c in CIPHER_SUITES {
        push16(&mut body, c);
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    // record(5) + handshake(4) + body + ext length(2) + ext
    let unpadded = 5 + 4 + body.len() + 2 + ext.len();
    if unpadded + 4 <= TARGET_RECORD_LEN {
        let pad = vec![0u8; TARGET_RECORD_LEN - unpadded - 4];
        push_ext(&mut ext, 0x0015, &pad);
    }
    push16(&mut body, ext.len() as u16);
    body.extend_from_slice(&ext);

    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(&[REC_HANDSHAKE, 0x03, 0x01]);
    push16(&mut out, (body.len() + 4) as u16);
    out.push(HS_CLIENT_HELLO);
    let hl = (body.len() as u32).to_be_bytes();
    out.extend_from_slice(&hl[1..]);
    out.extend_from_slice(&body);
    out
}

/// True when `payload` looks like the start of a server's reply to a ClientHello
/// (a ServerHello handshake record or a TLS alert).
pub fn is_server_reply(payload: &[u8]) -> bool {
    if record_header(payload, REC_HANDSHAKE) {
        return payload.len() >= 6 && payload[5] == HS_SERVER_HELLO;
    }
    record_header(payload, REC_ALERT) && u16::from_be_bytes([payload[3], payload[4]]) >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-written ClientHello in the shape of a real Firefox/Chrome one: GREASE values,
    /// several extensions before server_name, and the name `discord.com`.
    fn real_world_hello() -> Vec<u8> {
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x0a0a, &[]); // GREASE
        push_ext(&mut ext, 0x0017, &[]);
        push_ext(&mut ext, 0x0023, &[]);
        push_ext(&mut ext, 0x000a, &[0x00, 0x08, 0x0a, 0x0a, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17]);
        let name = b"discord.com";
        let mut sn = vec![0x00, (name.len() + 3) as u8, 0x00, 0x00, name.len() as u8];
        sn.extend_from_slice(name);
        push_ext(&mut ext, 0x0000, &sn);
        push_ext(&mut ext, 0x0010, b"\x00\x0c\x02h2\x08http/1.1");
        push_ext(&mut ext, 0x002b, &[0x06, 0x1a, 0x1a, 0x03, 0x04, 0x03, 0x03]);
        // a large (ML-KEM sized) key share
        let mut ks = vec![0x04, 0xc4, 0x11, 0xec, 0x04, 0xc0];
        ks.extend(std::iter::repeat_n(0xab, 0x4c0));
        push_ext(&mut ext, 0x0033, &ks);
        let mut body = vec![0x03, 0x03];
        body.extend((0..32u8).map(|i| i.wrapping_mul(37)));
        body.push(32);
        body.extend((0..32u8).map(|i| i ^ 0x5a));
        body.extend_from_slice(&[0x00, 0x08, 0x2a, 0x2a, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2b]);
        body.extend_from_slice(&[0x01, 0x00]);
        push16(&mut body, ext.len() as u16);
        body.extend_from_slice(&ext);
        let mut out = vec![0x16, 0x03, 0x01];
        push16(&mut out, (body.len() + 4) as u16);
        out.push(1);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn generated_hello_round_trips() {
        for (i, name) in ["www.google.com", "a", "discord.com", "xn--bcher-kva.example", &"x".repeat(200)].iter().enumerate() {
            let h = build_client_hello(name, i as u64);
            let ch = parse_client_hello(&h).expect("parses");
            let r = ch.sni.expect("sni found");
            assert_eq!(&h[r], name.as_bytes());
        }
    }

    #[test]
    fn generated_hello_lengths_are_consistent() {
        for seed in 0..50u64 {
            let h = build_client_hello("www.google.com", seed);
            assert_eq!(h.len(), TARGET_RECORD_LEN);
            assert_eq!(&h[..3], &[0x16, 0x03, 0x01]);
            let rec = u16::from_be_bytes([h[3], h[4]]) as usize;
            assert_eq!(rec, h.len() - 5);
            assert_eq!(h[5], 1);
            let hs = u32::from_be_bytes([0, h[6], h[7], h[8]]) as usize;
            assert_eq!(hs, h.len() - 9);
            assert_eq!(&h[9..11], &[0x03, 0x03]);
            assert_eq!(h[43], 32, "session id length");
            let mut p = 44 + 32;
            let cs = u16::from_be_bytes([h[p], h[p + 1]]) as usize;
            assert_eq!(cs, CIPHER_SUITES.len() * 2);
            p += 2 + cs;
            assert_eq!(&h[p..p + 2], &[0x01, 0x00]);
            p += 2;
            let ext_total = u16::from_be_bytes([h[p], h[p + 1]]) as usize;
            p += 2;
            assert_eq!(p + ext_total, h.len());
            // every extension length adds up exactly, and the inner lengths are consistent
            let mut seen = Vec::new();
            while p < h.len() {
                let ty = u16::from_be_bytes([h[p], h[p + 1]]);
                let len = u16::from_be_bytes([h[p + 2], h[p + 3]]) as usize;
                let d = &h[p + 4..p + 4 + len];
                match ty {
                    0x0000 | 0x000a | 0x0010 | 0x000d | 0x0033 => {
                        assert_eq!(u16::from_be_bytes([d[0], d[1]]) as usize, len - 2, "ext {ty:#x}")
                    }
                    0x000b | 0x002d | 0x002b | 0xff01 => assert_eq!(d[0] as usize, len - 1, "ext {ty:#x}"),
                    _ => {}
                }
                seen.push(ty);
                p += 4 + len;
            }
            assert_eq!(p, h.len());
            for want in [0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b, 0x002d, 0x0033, 0x0015] {
                assert!(seen.contains(&want), "missing extension {want:#x}");
            }
            assert_eq!(*seen.last().unwrap(), 0x0015, "padding is last");
        }
    }

    #[test]
    fn generated_hello_is_deterministic_and_seeded() {
        assert_eq!(build_client_hello("a.b", 7), build_client_hello("a.b", 7));
        assert_ne!(build_client_hello("a.b", 7), build_client_hello("a.b", 8));
    }

    #[test]
    fn long_names_still_fit_and_stay_valid() {
        let name = "y".repeat(255);
        let h = build_client_hello(&name, 1);
        assert_eq!(h.len(), TARGET_RECORD_LEN, "zero-length padding fills exactly");
        let name = "w".repeat(300);
        let h = build_client_hello(&name, 1);
        assert_eq!(h.len(), TARGET_RECORD_LEN, "names are cut to 255 bytes");
        let name = &name[..255];
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(&h[parse_client_hello(&h).unwrap().sni.unwrap()], name.as_bytes());
        let none = build_client_hello("", 1);
        assert_eq!(parse_client_hello(&none).unwrap().sni, None);
    }

    #[test]
    fn real_world_shaped_hello() {
        let h = real_world_hello();
        assert!(h.len() > 1300, "post-quantum sized");
        let r = parse_client_hello(&h).unwrap().sni.unwrap();
        assert_eq!(&h[r.clone()], b"discord.com");
        // first TCP segment of a 1700-byte hello: the name is still inside
        let r2 = parse_client_hello(&h[..r.end + 10]).unwrap().sni.unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn truncation_never_panics_and_degrades() {
        for h in [build_client_hello("www.example.com", 3), real_world_hello()] {
            let full = parse_client_hello(&h).unwrap().sni.unwrap();
            for n in 0..=h.len() {
                let got = parse_client_hello(&h[..n]);
                if n < 6 {
                    assert_eq!(got, None, "len {n}");
                } else if n < full.end {
                    assert_eq!(got, Some(ClientHello { sni: None }), "len {n}");
                } else {
                    assert_eq!(got.unwrap().sni, Some(full.clone()), "len {n}");
                }
            }
        }
    }

    #[test]
    fn garbage_never_panics() {
        let mut rng = Rng(42);
        for i in 0..20000 {
            let n = (rng.next() % 600) as usize;
            let mut v = Vec::new();
            rng.fill(&mut v, n);
            if i % 2 == 0 && v.len() >= 6 {
                // force a valid-looking header so the deep walk is exercised
                v[0] = 0x16;
                v[1] = 3;
                v[2] = (i % 5) as u8;
                v[5] = 1;
            }
            if let Some(ch) = parse_client_hello(&v) {
                if let Some(r) = ch.sni {
                    assert!(r.start < r.end && r.end <= v.len());
                }
            }
            let _ = is_server_reply(&v);
        }
        // mutate single bytes of a valid hello
        let h = build_client_hello("www.google.com", 9);
        for i in 0..h.len() {
            for b in [0u8, 1, 0x7f, 0xff] {
                let mut m = h.clone();
                m[i] = b;
                if let Some(ch) = parse_client_hello(&m) {
                    if let Some(r) = ch.sni {
                        assert!(r.end <= m.len());
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_non_hello() {
        assert_eq!(parse_client_hello(b""), None);
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x05, 0, 4, 1]), None);
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x03, 0, 4, 2]), None);
        assert_eq!(parse_client_hello(&[0x17, 0x03, 0x03, 0, 4, 1]), None);
        assert_eq!(parse_client_hello(&[0x16, 0x03, 0x01, 0, 4, 1]), Some(ClientHello { sni: None }));
    }

    #[test]
    fn server_reply_detection() {
        assert!(is_server_reply(&[0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00]));
        assert!(is_server_reply(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]));
        assert!(!is_server_reply(&[0x16, 0x03, 0x03, 0x00, 0x7a, 0x01]));
        assert!(!is_server_reply(&[0x17, 0x03, 0x03, 0x00, 0x20]));
        assert!(!is_server_reply(&[0x16, 0x03]));
        assert!(!is_server_reply(b"HTTP/1.1 200 OK"));
        assert!(!is_server_reply(&build_client_hello("x.y", 1)));
    }
}
