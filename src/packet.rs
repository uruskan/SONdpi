//! Owned IP packet with parsed offsets: IPv4 and IPv6, TCP and UDP.
//!
//! Everything the engine does to traffic goes through this type, so it is pure logic with no
//! Windows or WinDivert dependency and is covered by unit tests. Mutators never touch
//! checksums; call [`Packet::fix_checksums`] once before sending.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    data: Vec<u8>,
    v6: bool,
    proto: u8,
    /// Offset of the TCP/UDP header.
    l4: usize,
    /// Offset of the TCP/UDP payload.
    payload: usize,
}

impl Packet {
    /// Parse a full IP packet. Returns `None` for anything that is not a well-formed,
    /// unfragmented IPv4/IPv6 packet. Trailing bytes beyond the IP length are dropped.
    pub fn parse(mut data: Vec<u8>) -> Option<Packet> {
        match data.first()? >> 4 {
            4 => {
                if data.len() < 20 {
                    return None;
                }
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                let total = u16::from_be_bytes([data[2], data[3]]) as usize;
                if ihl < 20 || total < ihl || total > data.len() {
                    return None;
                }
                // More-fragments bit or a non-zero fragment offset: not handled.
                if u16::from_be_bytes([data[6], data[7]]) & 0x3fff != 0 {
                    return None;
                }
                data.truncate(total);
                let proto = data[9];
                Self::finish(data, false, proto, ihl)
            }
            6 => {
                if data.len() < 40 {
                    return None;
                }
                let total = 40 + u16::from_be_bytes([data[4], data[5]]) as usize;
                if total > data.len() {
                    return None;
                }
                data.truncate(total);
                let mut next = data[6];
                let mut off = 40;
                loop {
                    match next {
                        // hop-by-hop, routing, destination options
                        0 | 43 | 60 => {
                            if data.len() < off + 8 {
                                return None;
                            }
                            next = data[off];
                            off += (data[off + 1] as usize + 1) * 8;
                            if off > data.len() {
                                return None;
                            }
                        }
                        // fragment header: not handled
                        44 => return None,
                        _ => break,
                    }
                }
                Self::finish(data, true, next, off)
            }
            _ => None,
        }
    }

    fn finish(data: Vec<u8>, v6: bool, proto: u8, l4: usize) -> Option<Packet> {
        let payload = match proto {
            PROTO_TCP => {
                if data.len() < l4 + 20 {
                    return None;
                }
                let doff = ((data[l4 + 12] >> 4) as usize) * 4;
                if doff < 20 || data.len() < l4 + doff {
                    return None;
                }
                l4 + doff
            }
            PROTO_UDP => {
                if data.len() < l4 + 8 {
                    return None;
                }
                l4 + 8
            }
            _ => data.len(),
        };
        Some(Packet { data, v6, proto, l4, payload })
    }

    // ---- raw access -------------------------------------------------------------------

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    // ---- IP -----------------------------------------------------------------------------

    pub fn is_ipv6(&self) -> bool {
        self.v6
    }
    pub fn protocol(&self) -> u8 {
        self.proto
    }
    pub fn is_tcp(&self) -> bool {
        self.proto == PROTO_TCP
    }
    pub fn is_udp(&self) -> bool {
        self.proto == PROTO_UDP
    }

    pub fn src_ip(&self) -> IpAddr {
        if self.v6 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&self.data[8..24]);
            IpAddr::V6(Ipv6Addr::from(a))
        } else {
            IpAddr::V4(Ipv4Addr::new(self.data[12], self.data[13], self.data[14], self.data[15]))
        }
    }
    pub fn dst_ip(&self) -> IpAddr {
        if self.v6 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&self.data[24..40]);
            IpAddr::V6(Ipv6Addr::from(a))
        } else {
            IpAddr::V4(Ipv4Addr::new(self.data[16], self.data[17], self.data[18], self.data[19]))
        }
    }

    /// TTL (IPv4) or hop limit (IPv6).
    pub fn ttl(&self) -> u8 {
        if self.v6 {
            self.data[7]
        } else {
            self.data[8]
        }
    }
    pub fn set_ttl(&mut self, ttl: u8) {
        if self.v6 {
            self.data[7] = ttl;
        } else {
            self.data[8] = ttl;
        }
    }

    /// IPv4 identification field; 0 for IPv6.
    pub fn ip_id(&self) -> u16 {
        if self.v6 {
            0
        } else {
            u16::from_be_bytes([self.data[4], self.data[5]])
        }
    }
    pub fn set_ip_id(&mut self, id: u16) {
        if !self.v6 {
            self.data[4..6].copy_from_slice(&id.to_be_bytes());
        }
    }

    // ---- TCP / UDP ports ----------------------------------------------------------------

    /// Source port. Only meaningful for TCP and UDP.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.data[self.l4], self.data[self.l4 + 1]])
    }
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.data[self.l4 + 2], self.data[self.l4 + 3]])
    }
    pub fn set_src_port(&mut self, p: u16) {
        self.data[self.l4..self.l4 + 2].copy_from_slice(&p.to_be_bytes());
    }
    pub fn set_dst_port(&mut self, p: u16) {
        self.data[self.l4 + 2..self.l4 + 4].copy_from_slice(&p.to_be_bytes());
    }
    pub fn src(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip(), self.src_port())
    }
    pub fn dst(&self) -> SocketAddr {
        SocketAddr::new(self.dst_ip(), self.dst_port())
    }

    // ---- TCP ------------------------------------------------------------------------------

    pub fn seq(&self) -> u32 {
        self.be32(self.l4 + 4)
    }
    pub fn ack(&self) -> u32 {
        self.be32(self.l4 + 8)
    }
    pub fn set_seq(&mut self, v: u32) {
        self.data[self.l4 + 4..self.l4 + 8].copy_from_slice(&v.to_be_bytes());
    }
    pub fn set_ack(&mut self, v: u32) {
        self.data[self.l4 + 8..self.l4 + 12].copy_from_slice(&v.to_be_bytes());
    }
    pub fn tcp_flags(&self) -> u8 {
        self.data[self.l4 + 13]
    }
    pub fn set_tcp_flags(&mut self, f: u8) {
        self.data[self.l4 + 13] = f;
    }
    pub fn has_flags(&self, f: u8) -> bool {
        self.tcp_flags() & f == f
    }
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.data[self.l4 + 14], self.data[self.l4 + 15]])
    }
    /// TCP options bytes (between the fixed header and the payload).
    pub fn tcp_options(&self) -> &[u8] {
        &self.data[self.l4 + 20..self.payload]
    }

    // ---- payload ----------------------------------------------------------------------------

    /// TCP or UDP payload (empty for other protocols).
    pub fn payload(&self) -> &[u8] {
        &self.data[self.payload..]
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.payload..]
    }
    pub fn payload_len(&self) -> usize {
        self.data.len() - self.payload
    }

    // ---- builders -----------------------------------------------------------------------------

    /// Same headers with a different TCP/UDP payload. For TCP, `seq_add` is added to the
    /// sequence number. Length fields are fixed; checksums are not.
    pub fn with_payload(&self, payload: &[u8], seq_add: u32) -> Packet {
        let mut data = Vec::with_capacity(self.payload + payload.len());
        data.extend_from_slice(&self.data[..self.payload]);
        data.extend_from_slice(payload);
        let mut p = Packet { data, v6: self.v6, proto: self.proto, l4: self.l4, payload: self.payload };
        if p.is_tcp() && seq_add != 0 {
            p.set_seq(self.seq().wrapping_add(seq_add));
        }
        p.fix_lengths();
        p
    }

    /// Split a TCP data packet at payload offset `at` (0 < at < payload_len). The first part
    /// loses PSH/FIN, the second keeps the original flags. Lengths and checksums are fixed.
    pub fn split_at(&self, at: usize) -> Option<(Packet, Packet)> {
        if !self.is_tcp() || at == 0 || at >= self.payload_len() {
            return None;
        }
        let pl = self.payload();
        let mut a = self.with_payload(&pl[..at], 0);
        a.set_tcp_flags(self.tcp_flags() & !(TCP_PSH | TCP_FIN));
        let mut b = self.with_payload(&pl[at..], at as u32);
        a.fix_checksums();
        b.fix_checksums();
        Some((a, b))
    }

    /// Reply to this UDP packet: addresses and ports swapped, new payload, TTL 64.
    /// Lengths and checksums are fixed.
    pub fn udp_reply(&self, payload: &[u8]) -> Option<Packet> {
        if !self.is_udp() {
            return None;
        }
        let mut p = self.with_payload(payload, 0);
        p.swap_endpoints();
        p.set_ttl(64);
        p.fix_checksums();
        Some(p)
    }

    /// Bare TCP segment for this flow (no options, no payload) in the same direction.
    /// Lengths and checksums are fixed.
    pub fn tcp_control(&self, flags: u8, seq: u32, ack: u32) -> Option<Packet> {
        if !self.is_tcp() {
            return None;
        }
        let mut data = Vec::with_capacity(self.l4 + 20);
        data.extend_from_slice(&self.data[..self.l4 + 20]);
        let mut p = Packet { data, v6: self.v6, proto: PROTO_TCP, l4: self.l4, payload: self.l4 + 20 };
        p.data[p.l4 + 12] = 5 << 4;
        p.set_tcp_flags(flags);
        p.set_seq(seq);
        p.set_ack(ack);
        // urgent pointer
        p.data[p.l4 + 18] = 0;
        p.data[p.l4 + 19] = 0;
        p.fix_lengths();
        p.fix_checksums();
        Some(p)
    }

    /// Like [`tcp_control`](Self::tcp_control) but travelling in the opposite direction.
    pub fn tcp_control_reverse(&self, flags: u8, seq: u32, ack: u32) -> Option<Packet> {
        let mut p = self.tcp_control(flags, seq, ack)?;
        p.swap_endpoints();
        p.set_ttl(64);
        p.fix_checksums();
        Some(p)
    }

    /// Swap source and destination addresses and ports. Checksums are not fixed.
    pub fn swap_endpoints(&mut self) {
        if self.v6 {
            let (a, b) = self.data[8..40].split_at_mut(16);
            a.swap_with_slice(b);
        } else {
            let (a, b) = self.data[12..20].split_at_mut(4);
            a.swap_with_slice(b);
        }
        if self.is_tcp() || self.is_udp() {
            let (a, b) = self.data[self.l4..self.l4 + 4].split_at_mut(2);
            a.swap_with_slice(b);
        }
    }

    /// Rewrite the IP total/payload length and the UDP length from the buffer size.
    pub fn fix_lengths(&mut self) {
        let len = self.data.len();
        if self.v6 {
            self.data[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        } else {
            self.data[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        }
        if self.is_udp() {
            let ulen = (len - self.l4) as u16;
            self.data[self.l4 + 4..self.l4 + 6].copy_from_slice(&ulen.to_be_bytes());
        }
    }

    /// Recompute the IPv4 header checksum and the TCP/UDP checksum.
    pub fn fix_checksums(&mut self) {
        if !self.v6 {
            self.data[10] = 0;
            self.data[11] = 0;
            let ihl = ((self.data[0] & 0x0f) as usize) * 4;
            let c = fold(sum_words(&self.data[..ihl], 0));
            self.data[10..12].copy_from_slice(&c.to_be_bytes());
        }
        let off = match self.proto {
            PROTO_TCP => self.l4 + 16,
            PROTO_UDP => self.l4 + 6,
            _ => return,
        };
        self.data[off] = 0;
        self.data[off + 1] = 0;
        let mut c = self.l4_checksum();
        if self.proto == PROTO_UDP && c == 0 {
            c = 0xffff;
        }
        self.data[off..off + 2].copy_from_slice(&c.to_be_bytes());
    }

    /// True when the stored TCP/UDP checksum matches the contents.
    pub fn l4_checksum_ok(&self) -> bool {
        match self.proto {
            PROTO_TCP | PROTO_UDP => self.l4_checksum() == 0,
            _ => true,
        }
    }

    fn l4_checksum(&self) -> u16 {
        let l4len = (self.data.len() - self.l4) as u32;
        let mut sum = if self.v6 {
            sum_words(&self.data[8..40], 0)
        } else {
            sum_words(&self.data[12..20], 0)
        };
        sum += self.proto as u32;
        sum += l4len >> 16;
        sum += l4len & 0xffff;
        fold(sum_words(&self.data[self.l4..], sum))
    }

    fn be32(&self, off: usize) -> u32 {
        u32::from_be_bytes([self.data[off], self.data[off + 1], self.data[off + 2], self.data[off + 3]])
    }
}

fn sum_words(bytes: &[u8], mut sum: u32) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        if sum > 0xffff_0000 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Test helpers shared by the other modules' unit tests.
pub mod testutil {
    use super::*;

    /// Build an IPv4 TCP packet with valid lengths and checksums.
    pub fn tcp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Packet {
        let mut d = vec![0u8; 40];
        d[0] = 0x45;
        d[6] = 0x40; // DF
        d[8] = 128;
        d[9] = PROTO_TCP;
        d[12..16].copy_from_slice(&src);
        d[16..20].copy_from_slice(&dst);
        d[20..22].copy_from_slice(&sport.to_be_bytes());
        d[22..24].copy_from_slice(&dport.to_be_bytes());
        d[24..28].copy_from_slice(&seq.to_be_bytes());
        d[28..32].copy_from_slice(&ack.to_be_bytes());
        d[32] = 5 << 4;
        d[33] = flags;
        d[34..36].copy_from_slice(&64240u16.to_be_bytes());
        d.extend_from_slice(payload);
        let total = d.len() as u16;
        d[2..4].copy_from_slice(&total.to_be_bytes());
        let mut p = Packet::parse(d).expect("valid packet");
        p.fix_checksums();
        p
    }

    /// Build an IPv6 TCP packet with valid lengths and checksums.
    pub fn tcp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Packet {
        let mut d = vec![0u8; 60];
        d[0] = 0x60;
        d[6] = PROTO_TCP;
        d[7] = 128;
        d[8..24].copy_from_slice(&src.octets());
        d[24..40].copy_from_slice(&dst.octets());
        d[40..42].copy_from_slice(&sport.to_be_bytes());
        d[42..44].copy_from_slice(&dport.to_be_bytes());
        d[44..48].copy_from_slice(&seq.to_be_bytes());
        d[48..52].copy_from_slice(&ack.to_be_bytes());
        d[52] = 5 << 4;
        d[53] = flags;
        d[54..56].copy_from_slice(&64240u16.to_be_bytes());
        d.extend_from_slice(payload);
        let plen = (d.len() - 40) as u16;
        d[4..6].copy_from_slice(&plen.to_be_bytes());
        let mut p = Packet::parse(d).expect("valid packet");
        p.fix_checksums();
        p
    }

    /// Build a UDP packet (IPv4 or IPv6, by address family) with valid lengths and checksums.
    pub fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Packet {
        let mut d = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(t)) => {
                let mut d = vec![0u8; 20];
                d[0] = 0x45;
                d[8] = 128;
                d[9] = PROTO_UDP;
                d[12..16].copy_from_slice(&s.octets());
                d[16..20].copy_from_slice(&t.octets());
                d
            }
            (IpAddr::V6(s), IpAddr::V6(t)) => {
                let mut d = vec![0u8; 40];
                d[0] = 0x60;
                d[6] = PROTO_UDP;
                d[7] = 128;
                d[8..24].copy_from_slice(&s.octets());
                d[24..40].copy_from_slice(&t.octets());
                d
            }
            _ => panic!("mixed address families"),
        };
        let l4 = d.len();
        d.extend_from_slice(&src.port().to_be_bytes());
        d.extend_from_slice(&dst.port().to_be_bytes());
        d.extend_from_slice(&[0, 0, 0, 0]);
        d.extend_from_slice(payload);
        let total = d.len();
        if d[0] >> 4 == 4 {
            d[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        } else {
            d[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        }
        d[l4 + 4..l4 + 6].copy_from_slice(&((total - l4) as u16).to_be_bytes());
        let mut p = Packet::parse(d).expect("valid packet");
        p.fix_checksums();
        p
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn ipv4_header_checksum_matches_known_vector() {
        // Classic example header; checksum 0xb861.
        let mut d = vec![
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00,
            0xc7,
        ];
        d.extend_from_slice(&[0u8; 0x73 - 20]);
        // make the UDP header self-consistent so parse() accepts it
        let ulen = (0x73u16 - 20).to_be_bytes();
        d[24] = ulen[0];
        d[25] = ulen[1];
        let mut p = Packet::parse(d).unwrap();
        p.fix_checksums();
        assert_eq!(&p.as_bytes()[10..12], &[0xb8, 0x61]);
    }

    #[test]
    fn tcp4_fields_and_checksum() {
        let p = tcp4([10, 0, 0, 2], 50000, [1, 2, 3, 4], 443, 1000, 2000, TCP_PSH | TCP_ACK, b"hello");
        assert!(p.is_tcp() && !p.is_ipv6());
        assert_eq!(p.src(), "10.0.0.2:50000".parse().unwrap());
        assert_eq!(p.dst(), "1.2.3.4:443".parse().unwrap());
        assert_eq!((p.seq(), p.ack()), (1000, 2000));
        assert_eq!(p.payload(), b"hello");
        assert!(p.l4_checksum_ok());
        let mut q = p.clone();
        q.set_src_port(40000);
        assert!(!q.l4_checksum_ok());
        q.fix_checksums();
        assert!(q.l4_checksum_ok());
        assert_eq!(q.src_port(), 40000);
    }

    #[test]
    fn split_keeps_stream_intact() {
        let p = tcp4([10, 0, 0, 2], 50000, [1, 2, 3, 4], 443, 7, 9, TCP_PSH | TCP_ACK, b"0123456789");
        let (a, b) = p.split_at(4).unwrap();
        assert_eq!(a.payload(), b"0123");
        assert_eq!(b.payload(), b"456789");
        assert_eq!(a.seq(), 7);
        assert_eq!(b.seq(), 11);
        assert_eq!(a.tcp_flags(), TCP_ACK);
        assert_eq!(b.tcp_flags(), TCP_PSH | TCP_ACK);
        assert!(a.l4_checksum_ok() && b.l4_checksum_ok());
        assert_eq!(a.len(), 40 + 4);
        assert!(p.split_at(0).is_none() && p.split_at(10).is_none());
    }

    #[test]
    fn tcp6_roundtrip_and_ttl() {
        let s: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let d: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut p = tcp6(s, 1234, d, 443, 1, 2, TCP_SYN, b"");
        assert!(p.is_ipv6() && p.l4_checksum_ok());
        assert_eq!(p.src_ip(), IpAddr::V6(s));
        p.set_ttl(5);
        assert_eq!(p.ttl(), 5);
        assert!(p.l4_checksum_ok(), "hop limit is not part of the pseudo header");
    }

    #[test]
    fn udp_reply_swaps_endpoints() {
        for (a, b) in [("192.168.1.5:55000", "192.168.1.1:53"), ("[fe80::1]:55000", "[fe80::2]:53")] {
            let q = udp(a.parse().unwrap(), b.parse().unwrap(), b"query");
            assert!(q.l4_checksum_ok());
            let r = q.udp_reply(b"a longer answer").unwrap();
            assert_eq!(r.src(), b.parse().unwrap());
            assert_eq!(r.dst(), a.parse().unwrap());
            assert_eq!(r.payload(), b"a longer answer");
            assert!(r.l4_checksum_ok());
            assert!(Packet::parse(r.as_bytes().to_vec()).is_some(), "lengths are consistent");
        }
    }

    #[test]
    fn tcp_control_reverse_is_a_valid_rst() {
        let p = tcp4([10, 0, 0, 2], 50000, [1, 2, 3, 4], 443, 7, 9, TCP_SYN, b"");
        let r = p.tcp_control_reverse(TCP_RST | TCP_ACK, 0, 8).unwrap();
        assert_eq!(r.src(), "1.2.3.4:443".parse().unwrap());
        assert_eq!(r.dst(), "10.0.0.2:50000".parse().unwrap());
        assert_eq!(r.tcp_flags(), TCP_RST | TCP_ACK);
        assert_eq!(r.payload_len(), 0);
        assert!(r.l4_checksum_ok());
    }

    #[test]
    fn rejects_garbage_and_fragments() {
        assert!(Packet::parse(vec![]).is_none());
        assert!(Packet::parse(vec![0x45; 10]).is_none());
        let mut p = tcp4([10, 0, 0, 2], 1, [1, 2, 3, 4], 2, 0, 0, TCP_ACK, b"x").into_bytes();
        p[6] = 0x20; // more fragments
        assert!(Packet::parse(p).is_none());
    }
}
