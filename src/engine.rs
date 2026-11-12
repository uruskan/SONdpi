//! The engine: packet loops tying divert + desync + redial + dns together.
//!
//! Handles (higher priority sees a packet first; a packet injected by a handle is only seen by
//! handles with a lower priority):
//!
//! | handle  | prio | filter                                                         | thread |
//! |---------|------|----------------------------------------------------------------|--------|
//! | alt-in  | 1200 | inbound TCP to the alternate port range                        | yes (batch recv) |
//! | dyn-out | 1100 | outbound TCP to the addresses with a pending re-dial or a live translation; reopened when that set changes | one per generation |
//! | logic   | 1000 | outbound SYNs, inbound SYN-ACKs, outbound desync requests, outbound UDP/53 | yes |
//! | inject  |  900 | `false`, send only: engine-originated packets (alternate SYNs, RSTs, DNS replies) | no |
//!
//! So a translated flow is already on its wire port when the logic handle sees it, and the
//! winner's SYN-ACK is already on the application's port. Engine-originated packets go out
//! below every capture handle of ours, so none of them is translated or desynced again.
//! A timer thread drives the re-dial clock, reopens dyn-out, and supervises: when any thread
//! fails it shuts every handle, joins the loops and closes everything.

use crate::api::{EngineControl, Status};
use crate::desync::{self, FlowHint, Strategy, Verdict as DesyncVerdict};
use crate::divert::{self, Addr, Divert, FLAG_SEND_ONLY, MTU_MAX};
use crate::dns::{DnsAction, DnsConfig, DnsOutcome, DnsResponder};
use crate::packet::{Packet, PROTO_UDP};
use crate::redial::{self, Action, Event, Redial, RedialConfig, Verdict as RVerdict};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const PRIO_ALT_IN: i16 = 1200;
pub const PRIO_DYN_OUT: i16 = 1100;
pub const PRIO_LOGIC: i16 = 1000;
pub const PRIO_INJECT: i16 = 900;

/// Addresses one dyn-out filter holds before falling back to capturing all outbound TCP.
/// WinDivert's compiler rejects longer filters with "Filter expression too long" (256 filter
/// objects); measured with `dyn_filter_capacity_probe`: 253 addresses (IPv4 or IPv6) fit after
/// the fixed `outbound and !loopback and tcp` part. 200 leaves margin.
pub const DYN_MAX_ADDRS: usize = 200;

const TICK: Duration = Duration::from_millis(10);

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub strategy: Strategy,
    /// Desync TLS/HTTP requests.
    pub desync: bool,
    /// Re-dial unanswered SYNs from another source port.
    pub redial: bool,
    /// Answer DNS queries locally over DoH.
    pub dns: bool,
    /// Append diagnostic lines here (dev mode). `None`: no log file.
    pub log: Option<PathBuf>,
    /// Re-dial timing and limits.
    pub redial_cfg: RedialConfig,
    pub dns_cfg: DnsConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            strategy: Strategy::default(),
            desync: true,
            redial: true,
            dns: true,
            log: None,
            redial_cfg: RedialConfig::default(),
            dns_cfg: DnsConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Outbound requests (ClientHello / HTTP) that were desynced.
    pub desynced: u64,
    /// Fake packets sent.
    pub fakes: u64,
    /// Outbound SYNs seen (to global addresses, tracked for re-dial).
    pub syns: u64,
    /// SYNs that got no answer within the stall threshold (a re-dial was sent).
    pub stalled: u64,
    /// Connections that were established through a re-dialled port.
    pub redialed: u64,
    /// Port translations currently alive.
    pub mapped: u64,
    pub dns_answered: u64,
    pub dns_passed: u64,
    /// Alternate SYNs sent, retransmission copies included.
    pub alt_syns: u64,
    /// Stalled connections that the original port won after all.
    pub orig_after_stall: u64,
    /// Losing SYN-ACKs dropped and reset.
    pub losers_reset: u64,
    /// SYNs nobody answered on any port.
    pub gave_up: u64,
    pub translated_in: u64,
    pub translated_out: u64,
    /// Packets received from all capture handles.
    pub captured: u64,
    /// Failed sends (packet lost).
    pub send_errors: u64,
    /// Desync calls that panicked (packet passed unchanged).
    pub desync_panics: u64,
    /// Addresses in the dyn-out filter (0: closed); `dyn_all` when it captures all outbound TCP.
    pub dyn_addrs: u64,
    pub dyn_all: bool,
    pub dyn_reopens: u64,
}

// ---- logging ------------------------------------------------------------------------------

/// Timestamped line log to a file and optionally stdout. Cheap to clone.
#[derive(Clone)]
pub struct Logger {
    inner: Arc<Mutex<(Option<File>, bool)>>,
}

impl Logger {
    pub fn none() -> Logger {
        Logger { inner: Arc::new(Mutex::new((None, false))) }
    }
    /// Append to `path` (created if missing); `echo` also prints every line to stdout.
    pub fn open(path: Option<&Path>, echo: bool) -> io::Result<Logger> {
        let f = match path {
            Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        Ok(Logger { inner: Arc::new(Mutex::new((f, echo))) })
    }
    pub fn enabled(&self) -> bool {
        let g = lock(&self.inner);
        g.0.is_some() || g.1
    }
    pub fn line(&self, s: &str) {
        let line = format!("{} {}\n", timestamp(), s);
        let mut g = lock(&self.inner);
        if g.1 {
            print!("{line}");
            let _ = io::stdout().flush();
        }
        if let Some(f) = g.0.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

fn timestamp() -> String {
    let mut t = windows_sys::Win32::Foundation::SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    // SAFETY: GetLocalTime writes one SYSTEMTIME into a live local.
    unsafe { windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t) };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- filters ------------------------------------------------------------------------------

/// Filter of the logic handle; `None` when it has nothing to capture.
pub fn logic_filter(desync_on: bool, desync_filter: &str, redial_on: bool, dns_on: bool) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let df = desync_filter.trim();
    if desync_on && !df.is_empty() && df != "false" {
        parts.push(format!("(outbound and tcp and ({df}))"));
    }
    if redial_on {
        parts.push("(outbound and tcp.Syn and !tcp.Ack)".into());
    }
    if redial_on || desync_on {
        // SYN-ACKs: re-dial winner/loser decisions and the desync flow hint (server TTL).
        parts.push("(inbound and tcp.Syn and tcp.Ack)".into());
    }
    if dns_on {
        parts.push("(outbound and udp.DstPort == 53)".into());
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("!loopback and ({})", parts.join(" or ")))
}

/// Inbound TCP to the alternate port range.
pub fn alt_in_filter(lo: u16, hi: u16) -> String {
    format!("inbound and !loopback and tcp and tcp.DstPort >= {lo} and tcp.DstPort <= {hi}")
}

/// Outbound TCP to `addrs`; `None` when there are too many for one filter.
pub fn dyn_out_filter(addrs: &[IpAddr]) -> Option<String> {
    if addrs.is_empty() || addrs.len() > DYN_MAX_ADDRS {
        return None;
    }
    let terms: Vec<String> = addrs
        .iter()
        .map(|a| match a {
            IpAddr::V4(v) => format!("ip.DstAddr == {v}"),
            IpAddr::V6(v) => format!("ipv6.DstAddr == {v}"),
        })
        .collect();
    Some(format!("outbound and !loopback and tcp and ({})", terms.join(" or ")))
}

/// Fallback when the destination set is too large for one filter.
pub const DYN_ALL_FILTER: &str = "outbound and !loopback and tcp";

// ---- flow hints ----------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Hint {
    ttl: u8,
    mss: Option<u16>,
    at: u64,
}

const HINT_CAP: usize = 8192;
const HINT_TTL_MS: u64 = 120_000;

#[derive(Default)]
struct Hints {
    map: HashMap<(SocketAddr, SocketAddr), Hint>,
}

impl Hints {
    fn insert(&mut self, local: SocketAddr, remote: SocketAddr, h: Hint) {
        if self.map.len() >= HINT_CAP {
            self.expire(h.at, HINT_TTL_MS / 4);
            if self.map.len() >= HINT_CAP {
                self.map.clear();
            }
        }
        self.map.insert((local, remote), h);
    }
    fn expire(&mut self, now: u64, max_age: u64) {
        self.map.retain(|_, h| now.saturating_sub(h.at) < max_age);
    }
}

/// MSS option value from a SYN/SYN-ACK.
fn mss_option(p: &Packet) -> Option<u16> {
    let o = p.tcp_options();
    let mut i = 0;
    while i < o.len() {
        match o[i] {
            0 => break,
            1 => i += 1,
            k => {
                let l = *o.get(i + 1)? as usize;
                if l < 2 || i + l > o.len() {
                    break;
                }
                if k == 2 && l == 4 {
                    return Some(u16::from_be_bytes([o[i + 2], o[i + 3]]));
                }
                i += l;
            }
        }
    }
    None
}

/// Replacement packets that are not a byte-exact part of the original payload are fakes.
fn count_fakes(orig: &Packet, out: &[Packet]) -> u64 {
    let pl = orig.payload();
    out.iter()
        .filter(|p| {
            let off = p.seq().wrapping_sub(orig.seq()) as usize;
            let q = p.payload();
            !(p.ttl() == orig.ttl() && off <= pl.len() && off + q.len() <= pl.len() && &pl[off..off + q.len()] == q)
        })
        .count() as u64
}

// ---- shared state ----------------------------------------------------------------------------

#[derive(Default)]
struct Counters {
    captured: AtomicU64,
    desynced: AtomicU64,
    fakes: AtomicU64,
    desync_panics: AtomicU64,
    send_errors: AtomicU64,
    dyn_addrs: AtomicU64,
    dyn_all: AtomicBool,
    dyn_reopens: AtomicU64,
}

struct Shared {
    cfg: EngineConfig,
    log: Logger,
    t0: Instant,
    stop: AtomicBool,
    error: Mutex<Option<String>>,
    redial: Mutex<Redial<Addr>>,
    hints: Mutex<Hints>,
    inject: RwLock<Option<Arc<Divert>>>,
    /// Every receiving handle, for shutdown.
    handles: Mutex<Vec<Weak<Divert>>>,
    c: Counters,
}

impl Shared {
    fn now(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }
    fn stopping(&self) -> bool {
        self.stop.load(Relaxed)
    }
    fn register(&self, d: &Arc<Divert>) {
        let mut g = lock(&self.handles);
        g.retain(|w| w.strong_count() > 0);
        g.push(Arc::downgrade(d));
    }
    /// Begin shutdown: blocked receives return once their queues are drained.
    fn request_stop(&self) {
        self.stop.store(true, Relaxed);
        let hs: Vec<Arc<Divert>> = lock(&self.handles).iter().filter_map(Weak::upgrade).collect();
        for h in hs {
            h.shutdown();
        }
    }
    fn fail(&self, msg: String) {
        {
            let mut e = lock(&self.error);
            if e.is_none() {
                *e = Some(msg.clone());
            } else {
                return;
            }
        }
        self.log.line(&format!("ERROR {msg}; engine shutting down"));
        self.request_stop();
    }
    fn send(&self, h: &Divert, pkt: &[u8], addr: &Addr) {
        if let Err(e) = h.send(pkt, addr) {
            let n = self.c.send_errors.fetch_add(1, Relaxed) + 1;
            if n <= 20 || n % 1000 == 0 {
                self.log.line(&format!("send error #{n}: {e} (len={} {:?})", pkt.len(), addr));
            }
        }
    }
    /// Send an engine-originated packet through the inject handle.
    fn originate(&self, pkt: &[u8], mut addr: Addr, outbound: bool) {
        addr.set_outbound(outbound);
        addr.set_impostor(false);
        addr.set_checksums_valid(true);
        let h = self.inject.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(h) = h {
            self.send(&h, pkt, &addr);
        }
    }
    /// Carry out re-dial actions produced outside the timer thread (sends and events only).
    fn run_actions(&self, acts: &mut Vec<Action<Addr>>) {
        for a in acts.drain(..) {
            match a {
                Action::Send(p, ctx) => self.originate(p.as_bytes(), ctx, true),
                Action::Event(e) => self.log_event(&e),
                Action::DestSet(_) => {}
            }
        }
    }
    fn log_event(&self, e: &Event) {
        if !self.log.enabled() {
            return;
        }
        let s = match e {
            Event::Alternate { remote, lport, alt, n, stalled_ms } => {
                format!("redial alt#{n} {remote} lport={lport} alt={alt} stalled={stalled_ms}ms")
            }
            Event::Retransmit { remote, lport, fanout, after_ms } => {
                format!("redial os-retx {remote} lport={lport} after={after_ms}ms fanout={fanout}")
            }
            Event::Won { remote, lport, alt: Some(a), after_ms, alternates } => {
                format!("redial won {remote} lport={lport} by=alt:{a} after={after_ms}ms alts={alternates} | map open {lport}<->{a}")
            }
            Event::Won { remote, lport, alt: None, after_ms, alternates } => {
                format!("redial won {remote} lport={lport} by=orig after={after_ms}ms alts={alternates}")
            }
            Event::LoserReset { remote, lport, port } => format!("redial loser-rst {remote} lport={lport} port={port}"),
            Event::GaveUp { remote, lport, alternates } => format!("redial gave-up {remote} lport={lport} alts={alternates}"),
            Event::MapClosed { remote, lport, alt, reason, pkts_in, pkts_out, age_ms } => {
                format!("map close {remote} {lport}<->{alt} reason={reason} age={age_ms}ms in={pkts_in} out={pkts_out}")
            }
        };
        self.log.line(&s);
    }
}

// ---- loops ---------------------------------------------------------------------------------

/// Run `f` on a named thread; an error or a panic fails the whole engine.
fn spawn_loop(sh: &Arc<Shared>, name: &str, f: impl FnOnce(&Arc<Shared>) -> io::Result<()> + Send + 'static) -> io::Result<JoinHandle<()>> {
    let s = sh.clone();
    let n = name.to_string();
    thread::Builder::new().name(format!("sondpi-{name}")).spawn(move || {
        match catch_unwind(AssertUnwindSafe(|| f(&s))) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => s.fail(format!("{n} loop: {e}")),
            Err(p) => s.fail(format!("{n} loop panicked: {}", panic_text(&p))),
        }
    })
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "?".into())
}

/// `Ok(None)` after shutdown (queue drained).
fn recv_one(h: &Divert, buf: &mut [u8]) -> io::Result<Option<(usize, Addr)>> {
    match h.recv(buf) {
        Ok(r) => Ok(Some(r)),
        Err(e) if divert::is_shutdown(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

fn logic_loop(sh: &Arc<Shared>, h: Arc<Divert>, dns: Option<Arc<DnsResponder<Addr>>>) -> io::Result<()> {
    let mut buf = vec![0u8; MTU_MAX];
    let mut acts: Vec<Action<Addr>> = Vec::new();
    while let Some((n, addr)) = recv_one(&h, &mut buf)? {
        sh.c.captured.fetch_add(1, Relaxed);
        let pkt = &mut buf[..n];
        let outbound = addr.outbound();
        if let Some(v) = redial::tcp_view(pkt) {
            if outbound && v.is_syn() {
                if sh.cfg.redial {
                    let now = sh.now();
                    lock(&sh.redial).outbound_syn(pkt, &addr, now, &mut acts);
                }
                sh.send(&h, pkt, &addr);
                sh.run_actions(&mut acts);
            } else if !outbound && v.is_synack() {
                let verdict = if sh.cfg.redial {
                    let now = sh.now();
                    lock(&sh.redial).inbound(pkt, addr.tcp_checksum(), &addr, now, &mut acts)
                } else {
                    RVerdict::Pass
                };
                if verdict != RVerdict::Drop {
                    if sh.cfg.desync {
                        record_hint(sh, pkt);
                    }
                    sh.send(&h, pkt, &addr);
                }
                sh.run_actions(&mut acts);
            } else if outbound && sh.cfg.desync {
                desync_one(sh, &h, pkt, &addr);
            } else {
                sh.send(&h, pkt, &addr);
            }
            continue;
        }
        if outbound && sh.cfg.dns {
            if let Some(d) = dns.as_ref() {
                if let Some(q) = Packet::parse(pkt.to_vec()).filter(|q| q.protocol() == PROTO_UDP && q.dst_port() == 53) {
                    // No engine lock is held here: the responder may call back synchronously.
                    match d.handle(q, addr) {
                        DnsAction::Pass(q) => sh.send(&h, q.as_bytes(), &addr),
                        DnsAction::Taken => {}
                    }
                    continue;
                }
            }
        }
        sh.send(&h, pkt, &addr);
    }
    Ok(())
}

fn record_hint(sh: &Shared, pkt: &[u8]) {
    let Some(p) = Packet::parse(pkt.to_vec()) else { return };
    let h = Hint { ttl: p.ttl(), mss: mss_option(&p), at: sh.now() };
    lock(&sh.hints).insert(p.dst(), p.src(), h);
}

fn flow_hint(sh: &Shared, p: &Packet) -> FlowHint {
    let (local, remote) = (p.src(), p.dst());
    let mut h = lock(&sh.hints).map.get(&(local, remote)).copied();
    if h.is_none() && sh.cfg.redial {
        let orig = lock(&sh.redial).original_port(local.ip(), local.port(), remote);
        if let Some(op) = orig {
            h = lock(&sh.hints).map.get(&(SocketAddr::new(local.ip(), op), remote)).copied();
        }
    }
    match h {
        Some(h) => FlowHint { server_ttl: Some(h.ttl), max_payload: h.mss },
        None => FlowHint::default(),
    }
}

fn desync_one(sh: &Shared, h: &Divert, pkt: &[u8], addr: &Addr) {
    let Some(p) = Packet::parse(pkt.to_vec()) else {
        sh.send(h, pkt, addr);
        return;
    };
    if !p.is_tcp() {
        sh.send(h, pkt, addr);
        return;
    }
    let hint = flow_hint(sh, &p);
    let verdict = catch_unwind(AssertUnwindSafe(|| desync::apply(&sh.cfg.strategy, &p, &hint)));
    match verdict {
        Ok(DesyncVerdict::Pass) => sh.send(h, pkt, addr),
        Ok(DesyncVerdict::Replace(out)) => {
            let mut a = *addr;
            a.set_checksums_valid(true);
            for q in &out {
                sh.send(h, q.as_bytes(), &a);
            }
            sh.c.desynced.fetch_add(1, Relaxed);
            sh.c.fakes.fetch_add(count_fakes(&p, &out), Relaxed);
        }
        Err(e) => {
            let n = sh.c.desync_panics.fetch_add(1, Relaxed) + 1;
            if n <= 5 {
                sh.log.line(&format!("desync panicked ({}) on {} -> {}; packet passed", panic_text(&e), p.src(), p.dst()));
            }
            sh.send(h, pkt, addr);
        }
    }
}

fn alt_in_loop(sh: &Arc<Shared>, h: Arc<Divert>) -> io::Result<()> {
    let mut buf = vec![0u8; MTU_MAX * 4];
    let mut addrs = vec![Addr::default(); 32];
    let mut lens = Vec::with_capacity(32);
    let mut acts: Vec<Action<Addr>> = Vec::new();
    loop {
        let n = match h.recv_batch(&mut buf, &mut addrs, &mut lens) {
            Ok(n) => n,
            Err(e) if divert::is_shutdown(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        sh.c.captured.fetch_add(n as u64, Relaxed);
        let now = sh.now();
        let mut off = 0;
        for i in 0..n {
            let len = lens[i];
            let addr = addrs[i];
            let pkt = &mut buf[off..off + len];
            off += len;
            let v = lock(&sh.redial).inbound(pkt, addr.tcp_checksum(), &addr, now, &mut acts);
            if v != RVerdict::Drop {
                sh.send(&h, pkt, &addr);
            }
            sh.run_actions(&mut acts);
        }
    }
}

fn dyn_out_loop(sh: &Arc<Shared>, h: Arc<Divert>) -> io::Result<()> {
    let mut buf = vec![0u8; MTU_MAX];
    while let Some((n, addr)) = recv_one(&h, &mut buf)? {
        sh.c.captured.fetch_add(1, Relaxed);
        let pkt = &mut buf[..n];
        let now = sh.now();
        let _ = lock(&sh.redial).outbound(pkt, addr.tcp_checksum(), now);
        sh.send(&h, pkt, &addr);
    }
    Ok(())
}

// ---- timer / supervisor -------------------------------------------------------------------------

struct DynOut {
    handle: Arc<Divert>,
    thread: JoinHandle<()>,
    all: bool,
}

struct Timer {
    sh: Arc<Shared>,
    loops: Vec<JoinHandle<()>>,
    current: Option<DynOut>,
    retired: Vec<JoinHandle<()>>,
}

impl Timer {
    fn run(mut self) {
        let mut acts: Vec<Action<Addr>> = Vec::new();
        let mut last_hint_gc = 0u64;
        let r = catch_unwind(AssertUnwindSafe(|| {
            while !self.sh.stopping() {
                thread::sleep(TICK);
                if self.sh.cfg.redial {
                    let now = self.sh.now();
                    lock(&self.sh.redial).tick(now, &mut acts);
                    self.apply(&mut acts);
                }
                let now = self.sh.now();
                if now - last_hint_gc > 5000 {
                    last_hint_gc = now;
                    lock(&self.sh.hints).expire(now, HINT_TTL_MS);
                }
                self.retired.retain(|t| !t.is_finished());
                if self.loops.iter().any(|t| t.is_finished()) && !self.sh.stopping() {
                    self.sh.fail("a packet loop exited unexpectedly".into());
                }
            }
        }));
        if let Err(p) = r {
            self.sh.fail(format!("timer panicked: {}", panic_text(&p)));
        }
        self.sh.request_stop();
        for t in self.loops.drain(..) {
            let _ = t.join();
        }
        if let Some(d) = self.current.take() {
            d.handle.shutdown();
            drop(d.handle);
            let _ = d.thread.join();
        }
        for t in self.retired.drain(..) {
            let _ = t.join();
        }
        let now = self.sh.now();
        lock(&self.sh.redial).clear(now, &mut acts);
        for a in acts.drain(..) {
            if let Action::Event(e) = a {
                self.sh.log_event(&e);
            }
        }
        // Last handle: the send-only injector. Every capture handle is closed by now.
        let inj = self.sh.inject.write().unwrap_or_else(|e| e.into_inner()).take();
        drop(inj);
        self.sh.c.dyn_addrs.store(0, Relaxed);
        self.sh.c.dyn_all.store(false, Relaxed);
    }

    /// Apply tick actions in order: a destination-set change takes effect (new capture open)
    /// before the packets that follow it are sent.
    fn apply(&mut self, acts: &mut Vec<Action<Addr>>) {
        for a in acts.drain(..) {
            match a {
                Action::DestSet(set) => {
                    if let Err(e) = self.set_dest(&set) {
                        self.sh.fail(format!("dyn-out capture: {e}"));
                    }
                }
                Action::Send(p, ctx) => self.sh.originate(p.as_bytes(), ctx, true),
                Action::Event(e) => self.sh.log_event(&e),
            }
        }
    }

    fn set_dest(&mut self, set: &[IpAddr]) -> io::Result<()> {
        if self.sh.stopping() {
            return Ok(());
        }
        if set.is_empty() {
            if let Some(old) = self.current.take() {
                self.retire(old);
                self.sh.log.line("handle dyn-out closed (no destinations)");
            }
            self.sh.c.dyn_addrs.store(0, Relaxed);
            self.sh.c.dyn_all.store(false, Relaxed);
            return Ok(());
        }
        let (filter, all) = match dyn_out_filter(set) {
            Some(f) => (f, false),
            None => (DYN_ALL_FILTER.to_string(), true),
        };
        if all && self.current.as_ref().is_some_and(|c| c.all) {
            self.sh.c.dyn_addrs.store(set.len() as u64, Relaxed);
            return Ok(());
        }
        let opened = match Divert::open(&filter, PRIO_DYN_OUT, 0) {
            Ok(h) => Ok((h, filter, all)),
            Err(e) if !all && e.kind() == io::ErrorKind::InvalidInput => {
                self.sh.log.line(&format!("handle dyn-out addrs={} rejected ({e}); falling back to all outbound TCP", set.len()));
                Divert::open(DYN_ALL_FILTER, PRIO_DYN_OUT, 0).map(|h| (h, DYN_ALL_FILTER.to_string(), true))
            }
            Err(e) => Err(e),
        };
        let (h, filter, all) = match opened {
            Ok(x) => x,
            Err(e) => {
                self.sh.log.line(&format!("handle dyn-out prio={PRIO_DYN_OUT} addrs={} FAILED: {e}", set.len()));
                return Err(e);
            }
        };
        let h = Arc::new(h);
        self.sh.register(&h);
        let reopen = self.sh.c.dyn_reopens.fetch_add(1, Relaxed) + 1;
        let hc = h.clone();
        let thread = spawn_loop(&self.sh, "dyn-out", move |s| dyn_out_loop(s, hc))?;
        if self.sh.stopping() {
            h.shutdown();
        }
        if let Some(old) = self.current.replace(DynOut { handle: h, thread, all }) {
            self.retire(old);
        }
        self.sh.c.dyn_addrs.store(set.len() as u64, Relaxed);
        self.sh.c.dyn_all.store(all, Relaxed);
        self.sh.log.line(&format!("handle dyn-out prio={PRIO_DYN_OUT} open #{reopen} addrs={} filter=\"{filter}\"", set.len()));
        Ok(())
    }

    fn retire(&mut self, old: DynOut) {
        // Drain: queued packets are still received and re-injected, then the thread exits and
        // its handle (last reference) closes.
        old.handle.shutdown();
        drop(old.handle);
        self.retired.push(old.thread);
    }
}

// ---- engine --------------------------------------------------------------------------------

/// A running engine. Dropping it stops it.
pub struct Engine {
    sh: Arc<Shared>,
    timer: Option<JoinHandle<()>>,
    dns: Option<Arc<DnsResponder<Addr>>>,
    filters: Vec<(String, i16, String)>,
}

impl Engine {
    pub fn start(cfg: EngineConfig) -> io::Result<Engine> {
        let log = Logger::open(cfg.log.as_deref(), false)?;
        Engine::start_logged(cfg, log)
    }

    /// Start with a caller-provided logger (dev mode writes its own lines to the same log).
    pub fn start_logged(cfg: EngineConfig, log: Logger) -> io::Result<Engine> {
        let r = Engine::try_start(cfg, log.clone());
        if let Err(e) = &r {
            log.line(&format!("engine start FAILED: {e}"));
        }
        r
    }

    fn try_start(cfg: EngineConfig, log: Logger) -> io::Result<Engine> {
        divert::ensure_loaded()?;
        let mut filters: Vec<(String, i16, String)> = Vec::new();

        let open = |name: &str, filter: &str, prio: i16, flags: u64| -> io::Result<Arc<Divert>> {
            match Divert::open(filter, prio, flags) {
                Ok(h) => {
                    let ver = h.version().map(|(a, b)| format!(" driver={a}.{b}")).unwrap_or_default();
                    log.line(&format!("handle {name} prio={prio} open{ver} filter=\"{filter}\""));
                    Ok(Arc::new(h))
                }
                Err(e) => {
                    log.line(&format!("handle {name} prio={prio} FAILED: {e} filter=\"{filter}\""));
                    Err(e)
                }
            }
        };

        // Opened first: it is the cheapest way to learn about elevation and the driver.
        let inject = open("inject", "false", PRIO_INJECT, FLAG_SEND_ONLY)?;
        filters.push(("inject".into(), PRIO_INJECT, "false".into()));

        let rc = cfg.redial_cfg.clone();
        let alt_in = if cfg.redial {
            let f = alt_in_filter(rc.port_lo, rc.port_hi);
            let h = open("alt-in", &f, PRIO_ALT_IN, 0)?;
            filters.push(("alt-in".into(), PRIO_ALT_IN, f));
            Some(h)
        } else {
            None
        };
        let logic = match logic_filter(cfg.desync, desync::FILTER, cfg.redial, cfg.dns) {
            Some(f) => {
                let h = open("logic", &f, PRIO_LOGIC, 0)?;
                filters.push(("logic".into(), PRIO_LOGIC, f));
                Some(h)
            }
            None => None,
        };

        let sh = Arc::new(Shared {
            log: log.clone(),
            t0: Instant::now(),
            stop: AtomicBool::new(false),
            error: Mutex::new(None),
            redial: Mutex::new(Redial::new(rc)),
            hints: Mutex::new(Hints::default()),
            inject: RwLock::new(Some(inject)),
            handles: Mutex::new(Vec::new()),
            c: Counters::default(),
            cfg,
        });
        for h in alt_in.iter().chain(logic.iter()) {
            sh.register(h);
        }

        let dns = if sh.cfg.dns {
            let s = sh.clone();
            let cb: Box<dyn Fn(DnsOutcome, Addr) + Send + Sync> = Box::new(move |o, ctx| match o {
                // Inbound on the interface the query left from, as if the server answered.
                DnsOutcome::Reply(p) => s.originate(p.as_bytes(), ctx, false),
                // Below the logic handle, so it is not captured again.
                DnsOutcome::Fallback(p) => s.originate(p.as_bytes(), ctx, true),
            });
            Some(Arc::new(DnsResponder::new(sh.cfg.dns_cfg.clone(), cb)))
        } else {
            None
        };

        let mut loops = Vec::new();
        let spawned = (|| -> io::Result<()> {
            if let Some(h) = alt_in {
                loops.push(spawn_loop(&sh, "alt-in", move |s| alt_in_loop(s, h))?);
            }
            if let Some(h) = logic {
                let d = dns.clone();
                loops.push(spawn_loop(&sh, "logic", move |s| logic_loop(s, h, d))?);
            }
            Ok(())
        })();
        let timer = Timer { sh: sh.clone(), loops, current: None, retired: Vec::new() };
        if let Err(e) = spawned {
            sh.request_stop();
            timer.run();
            return Err(e);
        }
        let t = thread::Builder::new().name("sondpi-timer".into()).spawn(move || timer.run());
        let timer = match t {
            Ok(t) => t,
            Err(e) => {
                // The closure (and the Timer in it) is dropped: loops still hold their handles.
                sh.request_stop();
                return Err(e);
            }
        };
        log.line("engine started");
        Ok(Engine { sh, timer: Some(timer), dns, filters })
    }

    pub fn stats(&self) -> EngineStats {
        let r = lock(&self.sh.redial).stats();
        let c = &self.sh.c;
        let (da, dp) = self.dns.as_ref().map_or((0, 0), |d| (d.answered(), d.passed()));
        EngineStats {
            desynced: c.desynced.load(Relaxed),
            fakes: c.fakes.load(Relaxed),
            syns: r.syns,
            stalled: r.stalled,
            redialed: r.redialed,
            mapped: r.mapped,
            dns_answered: da,
            dns_passed: dp,
            alt_syns: r.alt_syns,
            orig_after_stall: r.orig_after_stall,
            losers_reset: r.losers_reset,
            gave_up: r.gave_up,
            translated_in: r.translated_in,
            translated_out: r.translated_out,
            captured: c.captured.load(Relaxed),
            send_errors: c.send_errors.load(Relaxed),
            desync_panics: c.desync_panics.load(Relaxed),
            dyn_addrs: c.dyn_addrs.load(Relaxed),
            dyn_all: c.dyn_all.load(Relaxed),
            dyn_reopens: c.dyn_reopens.load(Relaxed),
        }
    }

    /// The error that shut the engine down, if any.
    pub fn error(&self) -> Option<String> {
        lock(&self.sh.error).clone()
    }

    /// Loops alive and no failure.
    pub fn is_running(&self) -> bool {
        !self.sh.stopping() && self.timer.as_ref().is_some_and(|t| !t.is_finished())
    }

    pub fn config(&self) -> &EngineConfig {
        &self.sh.cfg
    }

    /// (name, priority, filter) of each static handle.
    pub fn filters(&self) -> &[(String, i16, String)] {
        &self.filters
    }

    pub fn log(&self, line: &str) {
        self.sh.log.line(line);
    }

    /// Stop all loops and close the driver handles; returns when everything is down.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let Some(t) = self.timer.take() else { return };
        self.sh.request_stop();
        let _ = t.join();
        // After the handles are closed: dropping the responder joins its workers.
        self.dns = None;
        self.sh.log.line("engine stopped");
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// One-line statistics summary for logs.
pub fn stats_line(s: &EngineStats) -> String {
    format!(
        "stats syns={} stalled={} alt_syns={} redialed={} orig_late={} losers_rst={} gave_up={} mapped={} xlat_in={} xlat_out={} dyn={}{} reopens={} desynced={} fakes={} dns_ans={} dns_pass={} captured={} send_err={}{}",
        s.syns,
        s.stalled,
        s.alt_syns,
        s.redialed,
        s.orig_after_stall,
        s.losers_reset,
        s.gave_up,
        s.mapped,
        s.translated_in,
        s.translated_out,
        s.dyn_addrs,
        if s.dyn_all { "(all-tcp)" } else { "" },
        s.dyn_reopens,
        s.desynced,
        s.fakes,
        s.dns_answered,
        s.dns_passed,
        s.captured,
        s.send_errors,
        if s.desync_panics > 0 { format!(" desync_panics={}", s.desync_panics) } else { String::new() },
    )
}

// ---- controller ------------------------------------------------------------------------------

/// The on/off switch around an [`Engine`]; this is what the service hands to the control pipe.
pub struct Controller {
    cfg: Mutex<EngineConfig>,
    engine: Mutex<Option<Engine>>,
    enabled: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl Controller {
    pub fn new(cfg: EngineConfig) -> Controller {
        Controller { cfg: Mutex::new(cfg), engine: Mutex::new(None), enabled: AtomicBool::new(false), last_error: Mutex::new(None) }
    }

    /// Configuration used the next time the engine starts.
    pub fn set_config(&self, cfg: EngineConfig) {
        *lock(&self.cfg) = cfg;
    }

    pub fn stats(&self) -> Option<EngineStats> {
        lock(&self.engine).as_ref().map(Engine::stats)
    }
}

impl EngineControl for Controller {
    fn set_enabled(&self, on: bool) -> Result<(), String> {
        self.enabled.store(on, Relaxed);
        let mut g = lock(&self.engine);
        if on {
            if g.as_ref().is_some_and(Engine::is_running) {
                return Ok(());
            }
            if let Some(dead) = g.take() {
                dead.stop();
            }
            let cfg = lock(&self.cfg).clone();
            match Engine::start(cfg) {
                Ok(e) => {
                    *g = Some(e);
                    *lock(&self.last_error) = None;
                    Ok(())
                }
                Err(e) => {
                    let m = e.to_string();
                    *lock(&self.last_error) = Some(m.clone());
                    Err(m)
                }
            }
        } else {
            if let Some(e) = g.take() {
                if let Some(err) = e.error() {
                    *lock(&self.last_error) = Some(err);
                }
                e.stop();
            }
            Ok(())
        }
    }

    fn status(&self) -> Status {
        let g = lock(&self.engine);
        let strategy = lock(&self.cfg).strategy.to_spec();
        let mut st = Status { enabled: self.enabled.load(Relaxed), strategy, ..Status::default() };
        if let Some(e) = g.as_ref() {
            let s = e.stats();
            st.active = e.is_running();
            st.strategy = e.config().strategy.to_spec();
            st.desynced = s.desynced;
            st.redialed = s.redialed;
            st.dns_answered = s.dns_answered;
            st.error = e.error();
        }
        if st.error.is_none() {
            st.error = lock(&self.last_error).clone();
        }
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::testutil::*;

    #[test]
    fn logic_filter_parts() {
        assert_eq!(logic_filter(false, "x", false, false), None);
        assert_eq!(
            logic_filter(true, "false", false, false).unwrap(),
            "!loopback and ((inbound and tcp.Syn and tcp.Ack))"
        );
        let f = logic_filter(true, "tcp.PayloadLength > 0", true, true).unwrap();
        assert_eq!(
            f,
            "!loopback and ((outbound and tcp and (tcp.PayloadLength > 0)) or (outbound and tcp.Syn and !tcp.Ack) or \
             (inbound and tcp.Syn and tcp.Ack) or (outbound and udp.DstPort == 53))"
        );
        assert_eq!(logic_filter(false, "", false, true).unwrap(), "!loopback and ((outbound and udp.DstPort == 53))");
    }

    #[test]
    fn alt_and_dyn_filters() {
        assert_eq!(alt_in_filter(25000, 29999), "inbound and !loopback and tcp and tcp.DstPort >= 25000 and tcp.DstPort <= 29999");
        assert_eq!(dyn_out_filter(&[]), None);
        let a: Vec<IpAddr> = vec!["104.16.1.2".parse().unwrap(), "2606:4700::1".parse().unwrap()];
        assert_eq!(
            dyn_out_filter(&a).unwrap(),
            "outbound and !loopback and tcp and (ip.DstAddr == 104.16.1.2 or ipv6.DstAddr == 2606:4700::1)"
        );
        let many: Vec<IpAddr> = (0..=DYN_MAX_ADDRS as u32).map(|i| IpAddr::from((0x0101_0000u32 + i).to_be_bytes())).collect();
        assert_eq!(dyn_out_filter(&many), None);
        assert!(dyn_out_filter(&many[..DYN_MAX_ADDRS]).is_some());
    }

    /// Compiles every filter the engine can produce with WinDivert's own compiler. Needs
    /// WinDivert.dll next to the test binary (no elevation); skipped otherwise.
    #[test]
    fn filters_compile_with_windivert() {
        if divert::ensure_loaded().is_err() {
            eprintln!("WinDivert.dll not next to the test binary; skipping");
            return;
        }
        let ok = |f: &str| match divert::compile_filter(f).unwrap() {
            Ok(()) => (),
            Err((m, p)) => panic!("{f}: {m} at {p}"),
        };
        ok(&logic_filter(true, desync::FILTER, true, true).unwrap());
        ok(&logic_filter(true, "tcp.PayloadLength > 0 and tcp.Payload[0] == 0x16", true, true).unwrap());
        ok(&alt_in_filter(25000, 29999));
        ok(DYN_ALL_FILTER);
        let mut addrs: Vec<IpAddr> = Vec::new();
        for i in 0..DYN_MAX_ADDRS as u32 {
            if i % 2 == 0 {
                addrs.push(IpAddr::from((0x6810_0000u32 + i).to_be_bytes()));
            } else {
                addrs.push(IpAddr::from((0x2606_4700_0000_0000_0000_0000_0000_0000u128 + i as u128).to_be_bytes()));
            }
        }
        ok(&dyn_out_filter(&addrs).unwrap());
        ok(&dyn_out_filter(&addrs[..1]).unwrap());
    }

    /// Prints how many addresses WinDivert's compiler accepts in one dyn-out filter.
    #[test]
    #[ignore]
    fn dyn_filter_capacity_probe() {
        divert::ensure_loaded().unwrap();
        for v6 in [false, true] {
            let mut n = 1usize;
            loop {
                let addrs: Vec<IpAddr> = (0..n as u32)
                    .map(|i| if v6 { IpAddr::from((0x2606_4700u128 << 96 | i as u128).to_be_bytes()) } else { IpAddr::from((0x6810_0000u32 + i).to_be_bytes()) })
                    .collect();
                let terms: Vec<String> = addrs.iter().map(|a| match a { IpAddr::V4(v) => format!("ip.DstAddr == {v}"), IpAddr::V6(v) => format!("ipv6.DstAddr == {v}") }).collect();
                let f = format!("outbound and !loopback and tcp and ({})", terms.join(" or "));
                if let Err((m, p)) = divert::compile_filter(&f).unwrap() {
                    println!("v6={v6}: {} addresses compile, {n} fail: {m} at {p}", n - 1);
                    break;
                }
                n += 1;
            }
        }
    }

    #[test]
    fn mss_and_fakes() {
        let mut d = tcp4([1, 1, 1, 1], 443, [10, 0, 0, 1], 5000, 1, 2, 0x12, b"").into_bytes();
        // add options: NOP, MSS 1400, end
        d[32] = 7 << 4;
        d.splice(40..40, [1u8, 2, 4, 0x05, 0x78, 0, 0, 0]);
        let len = d.len() as u16;
        d[2..4].copy_from_slice(&len.to_be_bytes());
        let p = Packet::parse(d).unwrap();
        assert_eq!(mss_option(&p), Some(1400));

        let orig = tcp4([10, 0, 0, 1], 5000, [1, 1, 1, 1], 443, 100, 1, 0x18, b"0123456789");
        let (a, b) = orig.split_at(4).unwrap();
        let mut fake = orig.with_payload(b"XXXXXXXXXX", 0);
        fake.set_ttl(8);
        assert_eq!(count_fakes(&orig, &[fake.clone(), a.clone(), b.clone()]), 1);
        let mut fake2 = a.clone();
        fake2.set_ttl(5);
        assert_eq!(count_fakes(&orig, &[fake2, a, b]), 1);
    }
}
