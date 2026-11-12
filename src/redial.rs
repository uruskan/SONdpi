//! Re-dial of unanswered SYNs from another source port, with port translation.
//!
//! Pure state machine: packets and a millisecond clock go in, verdicts and [`Action`]s come
//! out. `engine` does all I/O. `C` is an opaque per-packet context (the WinDivert address of
//! the captured SYN) handed back with packets the engine must originate.
//!
//! Life of a tracked connection (key: local address, original local port P, remote endpoint):
//! 1. An outbound SYN to a global address starts tracking (`outbound_syn`).
//! 2. Every `stall_ms` without a SYN-ACK, `tick` adds an alternate source port A (up to
//!    `max_alternates`) and emits a copy of the SYN from A. Before the first copy for a new
//!    destination address it emits [`Action::DestSet`], so the engine captures the
//!    application's next packets to that address before the copy leaves.
//! 3. An OS retransmission of the SYN is let through and copied from every alternate in play.
//! 4. The first SYN-ACK whose ACK matches the ISN wins. If it came to A, inbound packets are
//!    translated A->P and outbound P->A until FIN/RST + linger or an idle timeout. Any other
//!    SYN-ACK for the connection (a different port, or the original port with a server ISN
//!    that is not the winner's) is dropped and answered with a RST from its port.

use crate::packet::{Packet, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Alternate source ports: outside Windows' dynamic range (49152-65535 by default).
pub const ALT_PORT_LO: u16 = 25000;
pub const ALT_PORT_HI: u16 = 29999;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedialConfig {
    /// Time without a SYN-ACK before each further alternate is sent.
    pub stall_ms: u64,
    pub max_alternates: usize,
    pub port_lo: u16,
    pub port_hi: u16,
    /// Stop tracking a SYN that nobody answered after this long (Windows gives up after ~21 s).
    pub give_up_ms: u64,
    /// After the original port won, keep resetting late alternate SYN-ACKs for this long.
    pub loser_linger_ms: u64,
    /// Keep a translation this long after RST or FIN in both directions.
    pub close_linger_ms: u64,
    /// Drop a translation after this long without a packet.
    pub idle_ms: u64,
    /// Keep an address in the destination set this long after it stopped being needed, so
    /// that the outbound capture is not reopened for every connection.
    pub dest_linger_ms: u64,
    /// Upper bound on tracked SYNs; new SYNs are not tracked while it is reached.
    pub max_tracked: usize,
}

impl Default for RedialConfig {
    fn default() -> Self {
        RedialConfig {
            stall_ms: 250,
            max_alternates: 3,
            port_lo: ALT_PORT_LO,
            port_hi: ALT_PORT_HI,
            give_up_ms: 30_000,
            loser_linger_ms: 30_000,
            close_linger_ms: 10_000,
            idle_ms: 2 * 3600 * 1000,
            dest_linger_ms: 5_000,
            max_tracked: 16_384,
        }
    }
}

/// Things the engine must do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action<C> {
    /// Capture outbound TCP to exactly these addresses from now on (sorted). Must take effect
    /// before any later `Send` in the same batch.
    DestSet(Vec<IpAddr>),
    /// Inject this engine-originated packet outbound (checksums are fixed). `C` is the context
    /// of the packet it was derived from. It must not pass through the engine's own
    /// translation or desync again.
    Send(Packet, C),
    Event(Event),
}

/// Loggable facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// An alternate SYN was sent (`n` is 1-based).
    Alternate { remote: SocketAddr, lport: u16, alt: u16, n: usize, stalled_ms: u64 },
    /// The OS retransmitted a stalled SYN; it was also sent from `fanout` alternates.
    Retransmit { remote: SocketAddr, lport: u16, fanout: usize, after_ms: u64 },
    /// A connection that had alternates got its SYN-ACK. `alt: None` means the original port
    /// won. When `alt` is `Some`, a translation is now open.
    Won { remote: SocketAddr, lport: u16, alt: Option<u16>, after_ms: u64, alternates: usize },
    /// A losing SYN-ACK was dropped and the server got a RST on `port`.
    LoserReset { remote: SocketAddr, lport: u16, port: u16 },
    /// Nobody answered any attempt.
    GaveUp { remote: SocketAddr, lport: u16, alternates: usize },
    /// A translation ended.
    MapClosed { remote: SocketAddr, lport: u16, alt: u16, reason: &'static str, pkts_in: u64, pkts_out: u64, age_ms: u64 },
}

/// What to do with the captured packet itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Re-inject unchanged.
    Pass,
    /// The buffer was rewritten in place; re-inject it (same address, same checksum flags).
    Modified,
    /// Do not re-inject.
    Drop,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RedialStats {
    /// Outbound SYNs that started tracking.
    pub syns: u64,
    /// Connections that got at least one alternate.
    pub stalled: u64,
    /// Alternate SYNs sent (including retransmission copies).
    pub alt_syns: u64,
    /// Connections won by an alternate port.
    pub redialed: u64,
    /// Connections that stalled but were won by the original port.
    pub orig_after_stall: u64,
    pub losers_reset: u64,
    pub gave_up: u64,
    /// Translations currently alive.
    pub mapped: u64,
    pub translated_in: u64,
    pub translated_out: u64,
}

// ---- raw TCP header view ------------------------------------------------------------------

/// Header facts of a TCP packet read straight from the buffer. Does not require the IP length
/// fields to be consistent (segmentation-offloaded packets may not be).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpView {
    pub v6: bool,
    /// Offset of the TCP header.
    pub l4: usize,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
}

impl TcpView {
    pub fn is_syn(&self) -> bool {
        self.flags & (TCP_SYN | TCP_ACK) == TCP_SYN
    }
    pub fn is_synack(&self) -> bool {
        self.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
    }
}

pub fn tcp_view(b: &[u8]) -> Option<TcpView> {
    let (v6, l4, src_ip, dst_ip) = match b.first()? >> 4 {
        4 => {
            if b.len() < 20 {
                return None;
            }
            let ihl = ((b[0] & 0x0f) as usize) * 4;
            if ihl < 20 || b[9] != 6 || u16::from_be_bytes([b[6], b[7]]) & 0x3fff != 0 {
                return None;
            }
            let s = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
            let d = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
            (false, ihl, s, d)
        }
        6 => {
            if b.len() < 40 {
                return None;
            }
            let mut next = b[6];
            let mut off = 40;
            loop {
                match next {
                    0 | 43 | 60 => {
                        if b.len() < off + 8 {
                            return None;
                        }
                        next = b[off];
                        off += (b[off + 1] as usize + 1) * 8;
                    }
                    6 => break,
                    _ => return None,
                }
            }
            let s: [u8; 16] = b[8..24].try_into().ok()?;
            let d: [u8; 16] = b[24..40].try_into().ok()?;
            (true, off, IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)))
        }
        _ => return None,
    };
    if b.len() < l4 + 20 {
        return None;
    }
    let be16 = |o: usize| u16::from_be_bytes([b[o], b[o + 1]]);
    let be32 = |o: usize| u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    Some(TcpView {
        v6,
        l4,
        src: SocketAddr::new(src_ip, be16(l4)),
        dst: SocketAddr::new(dst_ip, be16(l4 + 2)),
        flags: b[l4 + 13],
        seq: be32(l4 + 4),
        ack: be32(l4 + 8),
    })
}

/// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m').
pub fn csum_update16(hc: u16, old: u16, new: u16) -> u16 {
    let mut s = (!hc) as u32 + (!old) as u32 + new as u32;
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    !(s as u16)
}

/// Rewrite the source (`src == true`) or destination port. With `csum_valid` the TCP checksum
/// is updated incrementally; otherwise it is left alone (the capture said it is not valid
/// yet: checksum offload; the driver recomputes it on send because the flag stays unset).
pub fn rewrite_port(b: &mut [u8], v: &TcpView, src: bool, new: u16, csum_valid: bool) {
    let off = v.l4 + if src { 0 } else { 2 };
    let old = u16::from_be_bytes([b[off], b[off + 1]]);
    if old == new {
        return;
    }
    b[off..off + 2].copy_from_slice(&new.to_be_bytes());
    if csum_valid {
        let c = v.l4 + 16;
        let hc = u16::from_be_bytes([b[c], b[c + 1]]);
        b[c..c + 2].copy_from_slice(&csum_update16(hc, old, new).to_be_bytes());
    }
}

/// Addresses the re-dial applies to: public unicast only.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_global(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00)
        }
    }
}

// ---- state machine ----------------------------------------------------------------------

type Key = (IpAddr, u16, SocketAddr);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending,
    /// `port` is the winning local port on the wire (P itself or an alternate).
    Won { port: u16, isn: u32, at: u64 },
}

struct Conn<C> {
    syn: Vec<u8>,
    ctx: C,
    isn: u32,
    first_at: u64,
    alts: Vec<u16>,
    state: State,
    fin_in: bool,
    fin_out: bool,
    closed: Option<(u64, &'static str)>,
    last_at: u64,
    pkts_in: u64,
    pkts_out: u64,
}

pub struct Redial<C: Clone> {
    cfg: RedialConfig,
    conns: HashMap<Key, Conn<C>>,
    /// Alternate (local ip, port A, remote) -> original key.
    alts: HashMap<Key, Key>,
    cursor: u16,
    /// Published destination set and when each address was last needed.
    published: BTreeSet<IpAddr>,
    needed_at: HashMap<IpAddr, u64>,
    stats: RedialStats,
}

impl<C: Clone> Redial<C> {
    pub fn new(cfg: RedialConfig) -> Self {
        Redial {
            cfg,
            conns: HashMap::new(),
            alts: HashMap::new(),
            cursor: 0,
            published: BTreeSet::new(),
            needed_at: HashMap::new(),
            stats: RedialStats::default(),
        }
    }

    pub fn config(&self) -> &RedialConfig {
        &self.cfg
    }
    pub fn stats(&self) -> RedialStats {
        self.stats
    }
    /// Destination addresses the outbound capture must currently cover.
    pub fn dest_set(&self) -> Vec<IpAddr> {
        self.published.iter().copied().collect()
    }
    /// Tracked connections (pending, lingering or translated).
    pub fn tracked(&self) -> usize {
        self.conns.len()
    }
    pub fn in_alt_range(&self, port: u16) -> bool {
        (self.cfg.port_lo..=self.cfg.port_hi).contains(&port)
    }

    /// The application's local port for a flow that lives on alternate `port` on the wire.
    pub fn original_port(&self, local: IpAddr, port: u16, remote: SocketAddr) -> Option<u16> {
        let orig = self.alts.get(&(local, port, remote))?;
        match self.conns.get(orig)?.state {
            State::Won { port: p, .. } if p == port => Some(orig.1),
            _ => None,
        }
    }

    /// An outbound packet seen by the logic capture. Only SYNs (SYN set, ACK clear) to global
    /// addresses matter; the packet itself is always re-injected unchanged by the engine.
    pub fn outbound_syn(&mut self, buf: &[u8], ctx: &C, now: u64, out: &mut Vec<Action<C>>) {
        let Some(v) = tcp_view(buf) else { return };
        if !v.is_syn() || !is_global(v.dst.ip()) {
            return;
        }
        let key = (v.src.ip(), v.src.port(), v.dst);
        if self.alts.contains_key(&key) {
            // Already on an alternate port (our own translation): nothing to track.
            return;
        }
        if let Some(c) = self.conns.get_mut(&key) {
            if c.isn == v.seq {
                if c.state == State::Pending {
                    // OS retransmission: let it through, copy it from every alternate in play.
                    c.syn = buf.to_vec();
                    let alts = c.alts.clone();
                    let after = now.saturating_sub(c.first_at);
                    for &a in &alts {
                        if let Some(p) = alt_copy(buf, a) {
                            out.push(Action::Send(p, ctx.clone()));
                            self.stats.alt_syns += 1;
                        }
                    }
                    out.push(Action::Event(Event::Retransmit { remote: v.dst, lport: key.1, fanout: alts.len(), after_ms: after }));
                }
                return;
            }
            // Same 4-tuple, new ISN: a new connection; forget the old one.
            self.remove(&key, now, "reused", out);
        }
        if self.conns.len() >= self.cfg.max_tracked {
            return;
        }
        self.stats.syns += 1;
        self.conns.insert(
            key,
            Conn {
                syn: buf.to_vec(),
                ctx: ctx.clone(),
                isn: v.seq,
                first_at: now,
                alts: Vec::new(),
                state: State::Pending,
                fin_in: false,
                fin_out: false,
                closed: None,
                last_at: now,
                pkts_in: 0,
                pkts_out: 0,
            },
        );
    }

    /// An inbound TCP packet: everything to the alternate port range, and SYN-ACKs to any
    /// port. Idempotent: a packet this machine already translated passes unchanged.
    /// `csum_valid` is the capture's TCPChecksum flag. `ctx` is the packet's context; RSTs
    /// derived from it are emitted with it (the engine flips the direction).
    pub fn inbound(&mut self, buf: &mut [u8], csum_valid: bool, ctx: &C, now: u64, out: &mut Vec<Action<C>>) -> Verdict {
        let Some(v) = tcp_view(buf) else { return Verdict::Pass };
        let local: Key = (v.dst.ip(), v.dst.port(), v.src);

        if let Some(orig) = self.alts.get(&local).copied() {
            let Some(c) = self.conns.get_mut(&orig) else {
                self.alts.remove(&local);
                return Verdict::Pass;
            };
            let a = local.1;
            if v.is_synack() {
                if v.ack != c.isn.wrapping_add(1) {
                    return Verdict::Pass;
                }
                match c.state {
                    State::Pending => {
                        c.state = State::Won { port: a, isn: v.seq, at: now };
                        c.last_at = now;
                        c.pkts_in += 1;
                        self.stats.redialed += 1;
                        self.stats.mapped += 1;
                        self.stats.translated_in += 1;
                        out.push(Action::Event(Event::Won {
                            remote: v.src,
                            lport: orig.1,
                            alt: Some(a),
                            after_ms: now.saturating_sub(c.first_at),
                            alternates: c.alts.len(),
                        }));
                        rewrite_port(buf, &v, false, orig.1, csum_valid);
                        return Verdict::Modified;
                    }
                    State::Won { port, isn, .. } if port == a && isn == v.seq => {
                        c.last_at = now;
                        c.pkts_in += 1;
                        self.stats.translated_in += 1;
                        rewrite_port(buf, &v, false, orig.1, csum_valid);
                        return Verdict::Modified;
                    }
                    _ => {
                        self.reset_loser(buf, &v, orig.1, ctx, out);
                        return Verdict::Drop;
                    }
                }
            }
            return match c.state {
                State::Won { port, .. } if port == a => {
                    c.last_at = now;
                    c.pkts_in += 1;
                    track_close(c, v.flags, true, now);
                    self.stats.translated_in += 1;
                    rewrite_port(buf, &v, false, orig.1, csum_valid);
                    Verdict::Modified
                }
                // Stray traffic to a losing alternate: the application must not see it.
                _ => Verdict::Drop,
            };
        }

        if v.is_synack() {
            if let Some(c) = self.conns.get_mut(&local) {
                if v.ack != c.isn.wrapping_add(1) {
                    return Verdict::Pass;
                }
                match c.state {
                    State::Pending => {
                        if c.alts.is_empty() {
                            // The normal case: answered before any stall.
                            self.conns.remove(&local);
                        } else {
                            c.state = State::Won { port: local.1, isn: v.seq, at: now };
                            self.stats.orig_after_stall += 1;
                            out.push(Action::Event(Event::Won {
                                remote: v.src,
                                lport: local.1,
                                alt: None,
                                after_ms: now.saturating_sub(c.first_at),
                                alternates: c.alts.len(),
                            }));
                        }
                        return Verdict::Pass;
                    }
                    // The winner's SYN-ACK (possibly already translated to P): deliver.
                    State::Won { isn, .. } if isn == v.seq => return Verdict::Pass,
                    // A late answer on the original port after an alternate won.
                    State::Won { .. } => {
                        self.reset_loser(buf, &v, local.1, ctx, out);
                        return Verdict::Drop;
                    }
                }
            }
        }
        Verdict::Pass
    }

    /// An outbound TCP packet seen by the dynamic capture: translate P->A for flows won by an
    /// alternate. Idempotent (a packet already on A passes unchanged).
    pub fn outbound(&mut self, buf: &mut [u8], csum_valid: bool, now: u64) -> Verdict {
        let Some(v) = tcp_view(buf) else { return Verdict::Pass };
        let key = (v.src.ip(), v.src.port(), v.dst);
        let Some(c) = self.conns.get_mut(&key) else { return Verdict::Pass };
        match c.state {
            State::Won { port, .. } if port != key.1 => {
                c.last_at = now;
                c.pkts_out += 1;
                track_close(c, v.flags, false, now);
                self.stats.translated_out += 1;
                rewrite_port(buf, &v, true, port, csum_valid);
                Verdict::Modified
            }
            _ => Verdict::Pass,
        }
    }

    fn reset_loser(&mut self, buf: &[u8], v: &TcpView, lport: u16, ctx: &C, out: &mut Vec<Action<C>>) {
        self.stats.losers_reset += 1;
        let port = v.dst.port();
        if let Some(p) = Packet::parse(buf.to_vec()) {
            // RFC 793: answer a segment carrying ACK with <SEQ=SEG.ACK><CTL=RST>.
            if let Some(mut r) = p.tcp_control_reverse(TCP_RST, v.ack, 0) {
                r.fix_checksums();
                out.push(Action::Send(r, ctx.clone()));
            }
        }
        out.push(Action::Event(Event::LoserReset { remote: v.src, lport, port }));
    }

    fn alloc_port(&mut self, key: &Key) -> Option<u16> {
        let lo = self.cfg.port_lo;
        let n = self.cfg.port_hi.checked_sub(lo)? as u32 + 1;
        for i in 0..n {
            let p = lo + ((self.cursor as u32 + i) % n) as u16;
            let k = (key.0, p, key.2);
            if p != key.1 && !self.alts.contains_key(&k) && !self.conns.contains_key(&k) {
                self.cursor = ((self.cursor as u32 + i + 1) % n) as u16;
                return Some(p);
            }
        }
        None
    }

    fn remove(&mut self, key: &Key, now: u64, reason: &'static str, out: &mut Vec<Action<C>>) {
        let Some(c) = self.conns.remove(key) else { return };
        for a in &c.alts {
            self.alts.remove(&(key.0, *a, key.2));
        }
        if let State::Won { port, at, .. } = c.state {
            if port != key.1 {
                self.stats.mapped = self.stats.mapped.saturating_sub(1);
                out.push(Action::Event(Event::MapClosed {
                    remote: key.2,
                    lport: key.1,
                    alt: port,
                    reason,
                    pkts_in: c.pkts_in,
                    pkts_out: c.pkts_out,
                    age_ms: now.saturating_sub(at),
                }));
            }
        }
    }

    /// Advance timers. Call every few milliseconds.
    pub fn tick(&mut self, now: u64, out: &mut Vec<Action<C>>) {
        let mut sends: Vec<Action<C>> = Vec::new();
        let mut gone: Vec<(Key, &'static str)> = Vec::new();
        let keys: Vec<Key> = self.conns.keys().copied().collect();
        for key in keys {
            let Some(c) = self.conns.get(&key) else { continue };
            match c.state {
                State::Pending => {
                    let elapsed = now.saturating_sub(c.first_at);
                    if elapsed >= self.cfg.give_up_ms {
                        self.stats.gave_up += 1;
                        sends.push(Action::Event(Event::GaveUp { remote: key.2, lport: key.1, alternates: c.alts.len() }));
                        gone.push((key, "gave-up"));
                        continue;
                    }
                    let due = if self.cfg.stall_ms == 0 { 0 } else { (elapsed / self.cfg.stall_ms) as usize };
                    let due = due.min(self.cfg.max_alternates);
                    while self.conns.get(&key).is_some_and(|c| c.alts.len() < due) {
                        let Some(a) = self.alloc_port(&key) else { break };
                        let Some(c) = self.conns.get_mut(&key) else { break };
                        let Some(p) = alt_copy(&c.syn, a) else { break };
                        if c.alts.is_empty() {
                            self.stats.stalled += 1;
                        }
                        c.alts.push(a);
                        self.alts.insert((key.0, a, key.2), key);
                        self.stats.alt_syns += 1;
                        sends.push(Action::Send(p, c.ctx.clone()));
                        sends.push(Action::Event(Event::Alternate { remote: key.2, lport: key.1, alt: a, n: c.alts.len(), stalled_ms: elapsed }));
                    }
                }
                State::Won { port, at, .. } if port == key.1 => {
                    if now.saturating_sub(at) >= self.cfg.loser_linger_ms {
                        gone.push((key, "linger"));
                    }
                }
                State::Won { .. } => {
                    if let Some((t, why)) = c.closed {
                        if now.saturating_sub(t) >= self.cfg.close_linger_ms {
                            gone.push((key, why));
                        }
                    } else if now.saturating_sub(c.last_at) >= self.cfg.idle_ms {
                        gone.push((key, "idle"));
                    }
                }
            }
        }
        let mut events = Vec::new();
        for (k, why) in gone {
            self.remove(&k, now, why, &mut events);
        }

        // Destination set: additions take effect now, removals after `dest_linger_ms`.
        for (k, c) in &self.conns {
            let needed = match c.state {
                State::Pending => !c.alts.is_empty(),
                State::Won { port, .. } => port != k.1,
            };
            if needed {
                self.needed_at.insert(k.2.ip(), now);
            }
        }
        let linger = self.cfg.dest_linger_ms;
        self.needed_at.retain(|_, t| now.saturating_sub(*t) < linger || *t == now);
        let set: BTreeSet<IpAddr> = self.needed_at.keys().copied().collect();
        if set != self.published {
            self.published = set;
            out.push(Action::DestSet(self.published.iter().copied().collect()));
        }
        out.extend(sends);
        out.extend(events);
    }

    /// Forget everything (engine stop). Live translations are reported as closed.
    pub fn clear(&mut self, now: u64, out: &mut Vec<Action<C>>) {
        let keys: Vec<Key> = self.conns.keys().copied().collect();
        for k in keys {
            self.remove(&k, now, "stop", out);
        }
        self.alts.clear();
        self.needed_at.clear();
        if !self.published.is_empty() {
            self.published.clear();
            out.push(Action::DestSet(Vec::new()));
        }
    }
}

fn track_close<C>(c: &mut Conn<C>, flags: u8, inbound: bool, now: u64) {
    if c.closed.is_some() {
        return;
    }
    if flags & TCP_RST != 0 {
        c.closed = Some((now, "rst"));
        return;
    }
    if flags & TCP_FIN != 0 {
        if inbound {
            c.fin_in = true;
        } else {
            c.fin_out = true;
        }
        if c.fin_in && c.fin_out {
            c.closed = Some((now, "fin"));
        }
    }
}

/// The same SYN from source port `port`, checksums recomputed.
fn alt_copy(syn: &[u8], port: u16) -> Option<Packet> {
    let mut p = Packet::parse(syn.to_vec())?;
    if !p.is_tcp() {
        return None;
    }
    p.set_src_port(port);
    p.fix_checksums();
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::testutil::*;
    use crate::packet::TCP_PSH;

    const ME: [u8; 4] = [192, 168, 1, 5];
    const CF: [u8; 4] = [104, 16, 132, 229];
    const P: u16 = 51234;
    const ISN: u32 = 1_000_000;
    const SISN: u32 = 777_000;

    fn r() -> Redial<u32> {
        Redial::new(RedialConfig::default())
    }
    fn syn() -> Packet {
        tcp4(ME, P, CF, 443, ISN, 0, TCP_SYN, b"")
    }
    fn synack(dport: u16, sisn: u32) -> Packet {
        tcp4(CF, 443, ME, dport, sisn, ISN + 1, TCP_SYN | TCP_ACK, b"")
    }
    fn sends(out: &[Action<u32>]) -> Vec<Packet> {
        out.iter().filter_map(|a| if let Action::Send(p, _) = a { Some(p.clone()) } else { None }).collect()
    }
    fn dest_sets(out: &[Action<u32>]) -> Vec<Vec<IpAddr>> {
        out.iter().filter_map(|a| if let Action::DestSet(s) = a { Some(s.clone()) } else { None }).collect()
    }
    fn events(out: &[Action<u32>]) -> Vec<Event> {
        out.iter().filter_map(|a| if let Action::Event(e) = a { Some(e.clone()) } else { None }).collect()
    }
    fn inb(r: &mut Redial<u32>, p: &Packet, now: u64, out: &mut Vec<Action<u32>>) -> (Verdict, Packet) {
        let mut b = p.as_bytes().to_vec();
        let v = r.inbound(&mut b, true, &9, now, out);
        (v, Packet::parse(b).unwrap())
    }
    fn outb(r: &mut Redial<u32>, p: &Packet, now: u64) -> (Verdict, Packet) {
        let mut b = p.as_bytes().to_vec();
        let v = r.outbound(&mut b, true, now);
        (v, Packet::parse(b).unwrap())
    }
    /// Track a SYN at t=0 and stall until one alternate is out; returns the alternate port.
    fn stall_once(r: &mut Redial<u32>) -> (u16, Vec<Action<u32>>) {
        let mut out = Vec::new();
        r.outbound_syn(syn().as_bytes(), &1, 0, &mut out);
        assert!(out.is_empty());
        r.tick(100, &mut out);
        assert!(out.is_empty(), "no alternate before the stall threshold");
        r.tick(250, &mut out);
        let s = sends(&out);
        assert_eq!(s.len(), 1);
        (s[0].src_port(), out)
    }

    #[test]
    fn original_wins_before_stall_leaves_no_state() {
        let mut r = r();
        let mut out = Vec::new();
        r.outbound_syn(syn().as_bytes(), &1, 0, &mut out);
        let (v, _) = inb(&mut r, &synack(P, SISN), 80, &mut out);
        assert_eq!(v, Verdict::Pass);
        assert_eq!(r.tracked(), 0);
        r.tick(1000, &mut out);
        assert!(out.is_empty());
        assert_eq!(r.stats().syns, 1);
    }

    #[test]
    fn stall_sends_identical_syn_from_alternate_after_dest_set() {
        let mut r = r();
        let (a, out) = stall_once(&mut r);
        assert!((ALT_PORT_LO..=ALT_PORT_HI).contains(&a));
        // DestSet comes first, then the copy.
        assert!(matches!(out[0], Action::DestSet(ref s) if s == &vec![IpAddr::from(CF)]));
        assert!(matches!(out[1], Action::Send(..)));
        let copy = &sends(&out)[0];
        let orig = syn();
        assert_eq!(copy.seq(), orig.seq());
        assert_eq!(copy.tcp_options(), orig.tcp_options());
        assert_eq!(copy.dst(), orig.dst());
        assert!(copy.l4_checksum_ok());
        assert_eq!(r.stats().stalled, 1);
        assert!(matches!(events(&out)[0], Event::Alternate { n: 1, stalled_ms: 250, .. }));
    }

    #[test]
    fn original_wins_after_stall_and_late_alternate_is_reset() {
        let mut r = r();
        let (a, _) = stall_once(&mut r);
        let mut out = Vec::new();
        let (v, _) = inb(&mut r, &synack(P, SISN), 300, &mut out);
        assert_eq!(v, Verdict::Pass);
        assert!(matches!(events(&out)[0], Event::Won { alt: None, after_ms: 300, alternates: 1, .. }));
        // Outbound on P is not translated.
        let data = tcp4(ME, P, CF, 443, ISN + 1, SISN + 1, TCP_ACK, b"");
        assert_eq!(outb(&mut r, &data, 301).0, Verdict::Pass);
        // The alternate answers late: dropped, RST from A.
        out.clear();
        let (v, _) = inb(&mut r, &synack(a, 555), 400, &mut out);
        assert_eq!(v, Verdict::Drop);
        let rst = &sends(&out)[0];
        assert_eq!(rst.src(), SocketAddr::new(IpAddr::from(ME), a));
        assert_eq!(rst.dst(), SocketAddr::new(IpAddr::from(CF), 443));
        assert_eq!(rst.tcp_flags(), TCP_RST);
        assert_eq!(rst.seq(), ISN + 1);
        assert!(rst.l4_checksum_ok());
        assert_eq!(r.stats().losers_reset, 1);
        assert_eq!(r.stats().orig_after_stall, 1);
        // The destination is no longer needed once the original won: removed after the
        // destination linger; the state itself goes away after the loser linger.
        out.clear();
        r.tick(300 + 4_000, &mut out);
        assert!(dest_sets(&out).is_empty());
        r.tick(300 + 5_000, &mut out);
        assert_eq!(dest_sets(&out), vec![Vec::<IpAddr>::new()]);
        assert_eq!(r.tracked(), 1);
        r.tick(300 + 30_000, &mut out);
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn alternate_wins_and_both_directions_translate_with_valid_checksums() {
        let mut r = r();
        let (a, _) = stall_once(&mut r);
        let mut out = Vec::new();
        let (v, sa) = inb(&mut r, &synack(a, SISN), 320, &mut out);
        assert_eq!(v, Verdict::Modified);
        assert_eq!(sa.dst_port(), P);
        assert!(sa.l4_checksum_ok());
        assert!(matches!(events(&out)[0], Event::Won { alt: Some(x), .. } if x == a));
        assert_eq!(r.stats().mapped, 1);
        assert_eq!(r.original_port(IpAddr::from(ME), a, SocketAddr::new(IpAddr::from(CF), 443)), Some(P));

        // Idempotent: the translated SYN-ACK seen again (logic capture) passes unchanged.
        let mut b = sa.as_bytes().to_vec();
        assert_eq!(r.inbound(&mut b, true, &9, 321, &mut out), Verdict::Pass);
        assert_eq!(b, sa.as_bytes());

        // Outbound P -> A.
        let req = tcp4(ME, P, CF, 443, ISN + 1, SISN + 1, TCP_PSH | TCP_ACK, b"\x16\x03\x01hello");
        let (v, o) = outb(&mut r, &req, 330);
        assert_eq!(v, Verdict::Modified);
        assert_eq!(o.src_port(), a);
        assert!(o.l4_checksum_ok());
        assert_eq!(o.payload(), req.payload());
        // Idempotent outbound: already on A.
        assert_eq!(outb(&mut r, &o, 331).0, Verdict::Pass);

        // Inbound data A -> P.
        let resp = tcp4(CF, 443, ME, a, SISN + 1, ISN + 9, TCP_ACK, b"server data");
        let (v, i) = inb(&mut r, &resp, 340, &mut out);
        assert_eq!(v, Verdict::Modified);
        assert_eq!(i.dst_port(), P);
        assert!(i.l4_checksum_ok());
        assert_eq!(r.stats().translated_in, 2);
        assert_eq!(r.stats().translated_out, 1);
    }

    #[test]
    fn offloaded_checksum_is_left_for_the_driver() {
        let mut r = r();
        let (a, _) = stall_once(&mut r);
        let mut out = Vec::new();
        inb(&mut r, &synack(a, SISN), 320, &mut out);
        let mut b = tcp4(ME, P, CF, 443, ISN + 1, SISN + 1, TCP_ACK, b"x").into_bytes();
        let l4 = 20;
        b[l4 + 16] = 0x12; // offload leaves a partial / arbitrary value
        b[l4 + 17] = 0x34;
        assert_eq!(r.outbound(&mut b, false, 330), Verdict::Modified);
        assert_eq!(u16::from_be_bytes([b[l4], b[l4 + 1]]), a);
        assert_eq!(&b[l4 + 16..l4 + 18], &[0x12, 0x34]);
    }

    #[test]
    fn late_synack_on_original_port_is_dropped_and_reset() {
        let mut r = r();
        let (a, _) = stall_once(&mut r);
        let mut out = Vec::new();
        inb(&mut r, &synack(a, SISN), 320, &mut out);
        out.clear();
        // Different server ISN on P: the original attempt's late answer.
        let (v, _) = inb(&mut r, &synack(P, 4242), 500, &mut out);
        assert_eq!(v, Verdict::Drop);
        let rst = &sends(&out)[0];
        assert_eq!(rst.src_port(), P);
        assert_eq!(rst.tcp_flags(), TCP_RST);
        assert_eq!(rst.seq(), ISN + 1);
        assert!(rst.l4_checksum_ok());
        assert!(matches!(events(&out)[0], Event::LoserReset { port: P, .. }));
    }

    #[test]
    fn late_synack_on_other_alternate_is_dropped_and_reset() {
        let mut r = r();
        let (a1, _) = stall_once(&mut r);
        let mut out = Vec::new();
        r.tick(500, &mut out);
        let a2 = sends(&out)[0].src_port();
        assert_ne!(a1, a2);
        out.clear();
        let (v, _) = inb(&mut r, &synack(a2, SISN), 520, &mut out);
        assert_eq!(v, Verdict::Modified);
        out.clear();
        let (v, _) = inb(&mut r, &synack(a1, 31337), 530, &mut out);
        assert_eq!(v, Verdict::Drop);
        assert_eq!(sends(&out)[0].src_port(), a1);
        // Retransmitted SYN-ACK of the winner is still translated.
        let (v, p) = inb(&mut r, &synack(a2, SISN), 540, &mut out);
        assert_eq!((v, p.dst_port()), (Verdict::Modified, P));
        // Stray non-SYN traffic to the loser port is dropped.
        let stray = tcp4(CF, 443, ME, a1, 31338, ISN + 1, TCP_ACK, b"");
        assert_eq!(inb(&mut r, &stray, 550, &mut out).0, Verdict::Drop);
    }

    #[test]
    fn os_retransmission_fans_out_to_alternates() {
        let mut r = r();
        let (a1, _) = stall_once(&mut r);
        let mut out = Vec::new();
        r.tick(500, &mut out);
        let a2 = sends(&out)[0].src_port();
        out.clear();
        r.outbound_syn(syn().as_bytes(), &1, 1000, &mut out);
        let s = sends(&out);
        let mut ports: Vec<u16> = s.iter().map(|p| p.src_port()).collect();
        ports.sort();
        let mut want = vec![a1, a2];
        want.sort();
        assert_eq!(ports, want);
        assert!(s.iter().all(|p| p.seq() == ISN && p.l4_checksum_ok()));
        assert!(matches!(events(&out)[0], Event::Retransmit { fanout: 2, after_ms: 1000, .. }));
        assert_eq!(r.stats().syns, 1, "a retransmission is not a new connection");
    }

    #[test]
    fn maximum_alternates_respected() {
        let mut r = r();
        let mut out = Vec::new();
        r.outbound_syn(syn().as_bytes(), &1, 0, &mut out);
        for t in (0..=20_000).step_by(10) {
            r.tick(t, &mut out);
        }
        let ports: BTreeSet<u16> = sends(&out).iter().map(|p| p.src_port()).collect();
        assert_eq!(ports.len(), 3);
        assert_eq!(sends(&out).len(), 3);
        assert!(!ports.contains(&P));
        // Gave up eventually.
        out.clear();
        r.tick(30_000, &mut out);
        assert!(events(&out).iter().any(|e| matches!(e, Event::GaveUp { alternates: 3, .. })));
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn unrelated_traffic_in_alt_range_passes_untouched() {
        let mut r = r();
        let (a, _) = stall_once(&mut r);
        let mut out = Vec::new();
        // Another program on port a+1 and on a with another remote.
        for p in [
            tcp4(CF, 443, ME, a + 1, 5, 6, TCP_ACK, b"data"),
            tcp4([8, 8, 8, 8], 443, ME, a, 5, 6, TCP_ACK, b"data"),
            tcp4(CF, 8443, ME, a, 5, 6, TCP_SYN | TCP_ACK, b""),
            tcp4(CF, 443, ME, 26000, 5, 6, TCP_SYN | TCP_ACK, b""),
        ] {
            let mut b = p.as_bytes().to_vec();
            assert_eq!(r.inbound(&mut b, true, &9, 300, &mut out), Verdict::Pass);
            assert_eq!(b, p.as_bytes());
        }
        // A SYN-ACK to the alternate that does not acknowledge our ISN is not ours either.
        let odd = tcp4(CF, 443, ME, a, 5, 12345, TCP_SYN | TCP_ACK, b"");
        let mut b = odd.as_bytes().to_vec();
        assert_eq!(r.inbound(&mut b, true, &9, 300, &mut out), Verdict::Pass);
        // Outbound from a local program that uses a port in the range.
        let o = tcp4(ME, 26001, CF, 443, 1, 2, TCP_ACK, b"x");
        assert_eq!(outb(&mut r, &o, 300), (Verdict::Pass, o.clone()));
        assert!(out.is_empty());
    }

    #[test]
    fn private_destinations_are_not_tracked() {
        let mut r = r();
        let mut out = Vec::new();
        for d in [[192, 168, 1, 1], [10, 1, 2, 3], [127, 0, 0, 1], [100, 64, 0, 1], [169, 254, 1, 1]] {
            r.outbound_syn(tcp4(ME, P, d, 443, ISN, 0, TCP_SYN, b"").as_bytes(), &1, 0, &mut out);
        }
        assert_eq!(r.tracked(), 0);
        r.tick(1000, &mut out);
        assert!(out.is_empty());
    }

    fn won_by_alt(r: &mut Redial<u32>) -> u16 {
        let (a, _) = stall_once(r);
        let mut out = Vec::new();
        assert_eq!(inb(r, &synack(a, SISN), 320, &mut out).0, Verdict::Modified);
        a
    }

    #[test]
    fn translation_ends_on_fin_both_ways_after_linger() {
        let mut r = r();
        let a = won_by_alt(&mut r);
        let mut out = Vec::new();
        outb(&mut r, &tcp4(ME, P, CF, 443, ISN + 1, SISN + 1, TCP_FIN | TCP_ACK, b""), 1000);
        r.tick(20_000, &mut out);
        assert_eq!(r.stats().mapped, 1, "half close keeps the mapping");
        inb(&mut r, &tcp4(CF, 443, ME, a, SISN + 1, ISN + 2, TCP_FIN | TCP_ACK, b""), 20_100, &mut out);
        out.clear();
        r.tick(25_000, &mut out);
        assert_eq!(r.stats().mapped, 1);
        r.tick(30_100, &mut out);
        assert_eq!(r.stats().mapped, 0);
        assert!(events(&out).iter().any(|e| matches!(e, Event::MapClosed { reason: "fin", pkts_in: 2, pkts_out: 1, .. })));
        // After removal the alternate port is free again and its traffic passes.
        let p = tcp4(CF, 443, ME, a, 1, 2, TCP_ACK, b"");
        assert_eq!(inb(&mut r, &p, 30_200, &mut out).0, Verdict::Pass);
    }

    #[test]
    fn translation_ends_on_rst() {
        let mut r = r();
        let a = won_by_alt(&mut r);
        let mut out = Vec::new();
        let (v, p) = inb(&mut r, &tcp4(CF, 443, ME, a, SISN + 1, 0, TCP_RST, b""), 1000, &mut out);
        assert_eq!((v, p.dst_port()), (Verdict::Modified, P), "the RST still reaches the application");
        r.tick(11_000, &mut out);
        assert!(events(&out).iter().any(|e| matches!(e, Event::MapClosed { reason: "rst", .. })));
        assert_eq!(r.tracked(), 0);
    }

    #[test]
    fn translation_ends_on_idle_timeout() {
        let mut r = r();
        won_by_alt(&mut r);
        let mut out = Vec::new();
        let idle = r.config().idle_ms;
        r.tick(320 + idle - 1, &mut out);
        assert_eq!(r.stats().mapped, 1);
        r.tick(320 + idle, &mut out);
        assert!(events(&out).iter().any(|e| matches!(e, Event::MapClosed { reason: "idle", .. })));
        assert_eq!(r.stats().mapped, 0);
    }

    #[test]
    fn ipv6_alternate_wins_and_translates() {
        let me: Ipv6Addr = "2a02:e0:1::5".parse().unwrap();
        let cf: Ipv6Addr = "2606:4700::6810:84e5".parse().unwrap();
        let mut r = r();
        let mut out = Vec::new();
        r.outbound_syn(tcp6(me, P, cf, 443, ISN, 0, TCP_SYN, b"").as_bytes(), &1, 0, &mut out);
        r.tick(250, &mut out);
        assert_eq!(dest_sets(&out), vec![vec![IpAddr::V6(cf)]]);
        let alt = sends(&out)[0].clone();
        assert!(alt.is_ipv6() && alt.l4_checksum_ok());
        let a = alt.src_port();
        let sa = tcp6(cf, 443, me, a, SISN, ISN + 1, TCP_SYN | TCP_ACK, b"");
        let (v, t) = inb(&mut r, &sa, 300, &mut out);
        assert_eq!((v, t.dst_port()), (Verdict::Modified, P));
        assert!(t.l4_checksum_ok());
        let d = tcp6(me, P, cf, 443, ISN + 1, SISN + 1, TCP_ACK, b"abc");
        let (v, t) = outb(&mut r, &d, 310);
        assert_eq!((v, t.src_port()), (Verdict::Modified, a));
        assert!(t.l4_checksum_ok());
        // Late loser on the original port, IPv6.
        out.clear();
        let late = tcp6(cf, 443, me, P, 99, ISN + 1, TCP_SYN | TCP_ACK, b"");
        assert_eq!(inb(&mut r, &late, 400, &mut out).0, Verdict::Drop);
        let rst = &sends(&out)[0];
        assert!(rst.is_ipv6() && rst.l4_checksum_ok() && rst.tcp_flags() == TCP_RST);
    }

    #[test]
    fn destination_set_changes() {
        let mut r = r();
        let mut out = Vec::new();
        let other = [1, 1, 1, 1];
        r.outbound_syn(syn().as_bytes(), &1, 0, &mut out);
        r.outbound_syn(tcp4(ME, P + 1, other, 443, 5, 0, TCP_SYN, b"").as_bytes(), &1, 100, &mut out);
        r.tick(250, &mut out);
        assert_eq!(dest_sets(&out), vec![vec![IpAddr::from(CF)]]);
        out.clear();
        r.tick(260, &mut out);
        assert!(dest_sets(&out).is_empty(), "no change, no notification");
        r.tick(350, &mut out);
        assert_eq!(dest_sets(&out), vec![vec![IpAddr::from(other), IpAddr::from(CF)]]);
        // The DestSet precedes the send it enables.
        let pos_set = out.iter().position(|a| matches!(a, Action::DestSet(_))).unwrap();
        let pos_send = out.iter().position(|a| matches!(a, Action::Send(..))).unwrap();
        assert!(pos_set < pos_send);
        // 1.1.1.1 answered on its original port: no longer needed, removed after the linger.
        out.clear();
        let sa = tcp4(other, 443, ME, P + 1, 9, 6, TCP_SYN | TCP_ACK, b"");
        inb(&mut r, &sa, 400, &mut out);
        r.tick(401, &mut out);
        assert!(dest_sets(&out).is_empty());
        r.tick(401 + 5_000, &mut out);
        assert_eq!(dest_sets(&out), vec![vec![IpAddr::from(CF)]]);
        // Stop clears everything.
        out.clear();
        r.clear(6_000, &mut out);
        assert_eq!(dest_sets(&out), vec![Vec::<IpAddr>::new()]);
    }

    #[test]
    fn new_connection_reusing_the_tuple_replaces_old_state() {
        let mut r = r();
        stall_once(&mut r);
        let mut out = Vec::new();
        r.outbound_syn(tcp4(ME, P, CF, 443, ISN + 5000, 0, TCP_SYN, b"").as_bytes(), &1, 400, &mut out);
        assert_eq!(r.tracked(), 1);
        assert_eq!(r.stats().syns, 2);
        // The old ISN's SYN-ACK on P is no longer matched: passes for the stack to handle.
        let (v, _) = inb(&mut r, &synack(P, SISN), 450, &mut out);
        assert_eq!(v, Verdict::Pass);
    }

    #[test]
    fn incremental_checksum_matches_full_recompute() {
        for (port, newp) in [(1u16, 2u16), (51234, 25000), (65535, 0), (0, 65535), (443, 443)] {
            let mut p = tcp4(ME, port, CF, 443, 1, 2, TCP_ACK, b"odd length payload!");
            let v = tcp_view(p.as_bytes()).unwrap();
            let mut b = p.as_bytes().to_vec();
            rewrite_port(&mut b, &v, true, newp, true);
            p.set_src_port(newp);
            p.fix_checksums();
            let q = Packet::parse(b).unwrap();
            assert!(q.l4_checksum_ok(), "{port}->{newp}");
        }
    }

    #[test]
    fn tcp_view_rejects_garbage_without_panicking() {
        assert!(tcp_view(&[]).is_none());
        assert!(tcp_view(&[0x45; 30]).is_none());
        assert!(tcp_view(&[0x60; 50]).is_none());
        let u = udp("1.2.3.4:5".parse().unwrap(), "5.6.7.8:53".parse().unwrap(), b"q");
        assert!(tcp_view(u.as_bytes()).is_none());
        let t = tcp4(ME, P, CF, 443, 1, 2, TCP_SYN, b"");
        for n in 0..t.len() {
            let _ = tcp_view(&t.as_bytes()[..n]);
        }
        let v = tcp_view(t.as_bytes()).unwrap();
        assert!(v.is_syn() && !v.is_synack());
    }
}
