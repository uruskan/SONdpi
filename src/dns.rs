//! Answers intercepted DNS queries locally through DoH.
//!
//! The engine hands every outbound UDP/53 query to [`DnsResponder::handle`]. The responder
//! either returns it for unchanged delivery or takes it and later reports the outcome through
//! the callback given to [`DnsResponder::new`]. `C` is an opaque per-packet context the engine
//! needs back (its WinDivert address).
//!
//! `handle` never blocks. A cache hit is answered inline: the callback then runs on the calling
//! thread before `handle` returns `Taken`. Everything else is resolved on a small fixed pool of
//! worker threads and the callback runs on one of them. After the responder is dropped the
//! callback is never called again; queries still pending at that moment are discarded.

use crate::packet::Packet;
use std::collections::{HashMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// DoH endpoints, tried in order / raced.
    pub upstreams: Vec<String>,
    pub timeout_ms: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            upstreams: vec![
                "https://1.1.1.1/dns-query".into(),
                "https://1.0.0.1/dns-query".into(),
                "https://8.8.8.8/dns-query".into(),
                "https://9.9.9.9/dns-query".into(),
            ],
            timeout_ms: 2500,
        }
    }
}

/// Immediate decision for one query.
pub enum DnsAction {
    /// Deliver the query unchanged (the engine re-injects it outbound).
    Pass(Packet),
    /// The responder kept it; the outcome arrives through the callback.
    Taken,
}

/// Final outcome of a taken query.
pub enum DnsOutcome {
    /// Inject this packet inbound: it is the answer, addressed from the original DNS server
    /// to the client. Checksums are already fixed.
    Reply(Packet),
    /// DoH failed; deliver the original query unchanged (re-inject outbound).
    Fallback(Packet),
}

// =========================================================================================
// DNS message helpers (pure, bounds-checked)
// =========================================================================================

const TTL_MIN: u32 = 5;
const TTL_MAX: u32 = 3600;
const NEGATIVE_TTL: u32 = 30;
const MAX_QUERY: usize = 4096;
const MAX_UDP_REPLY: usize = 4096;
const OPT: u16 = 41;

/// Canonical cache key: lower-cased wire-format name, type, class.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    name: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

/// The single question of a message. Labels are lower-cased.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub labels: Vec<Vec<u8>>,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just after the question section.
    end: usize,
}

impl Question {
    pub fn key(&self) -> Key {
        let mut name = Vec::new();
        for l in &self.labels {
            name.push(l.len() as u8);
            name.extend_from_slice(l);
        }
        name.push(0);
        Key { name, qtype: self.qtype, qclass: self.qclass }
    }
}

fn be16(m: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(o)?, *m.get(o + 1)?]))
}

/// Read a (possibly compressed) name at `off`. Returns the lower-cased labels and the offset just
/// after the name as it appears at `off` (after the first pointer, if any). Pointer loops, bad
/// label types, over-long names and out-of-range pointers yield `None`.
pub fn read_name(msg: &[u8], mut off: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let b = *msg.get(off)?;
        match b & 0xC0 {
            0x00 => {
                let len = b as usize;
                if len == 0 {
                    return Some((labels, end.unwrap_or(off + 1)));
                }
                let l = msg.get(off + 1..off + 1 + len)?;
                total += len + 1;
                if total > 254 {
                    return None;
                }
                labels.push(l.to_ascii_lowercase());
                off += 1 + len;
            }
            0xC0 => {
                let b2 = *msg.get(off + 1)?;
                if end.is_none() {
                    end = Some(off + 2);
                }
                jumps += 1;
                if jumps > 32 {
                    return None;
                }
                let ptr = (((b & 0x3f) as usize) << 8) | b2 as usize;
                if ptr >= msg.len() {
                    return None;
                }
                off = ptr;
            }
            _ => return None, // 0x40 / 0x80 label types are not valid
        }
    }
}

/// Parse the question of a message that has exactly one. Does not look at QR / opcode.
pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 || be16(msg, 4)? != 1 {
        return None;
    }
    let (labels, p) = read_name(msg, 12)?;
    let qtype = be16(msg, p)?;
    let qclass = be16(msg, p + 2)?;
    Some(Question { labels, qtype, qclass, end: p + 4 })
}

/// Well-formed standard query: QR=0, opcode 0, exactly one question, nothing in the answer or
/// authority sections.
pub fn parse_query(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 || msg[2] & 0xF8 != 0 {
        return None;
    }
    if be16(msg, 6)? != 0 || be16(msg, 8)? != 0 {
        return None;
    }
    parse_question(msg)
}

const LOCAL_SUFFIXES: [&str; 12] =
    ["local", "lan", "home", "internal", "intranet", "corp", "private", "localdomain", "localhost", "test", "invalid", "onion"];

fn label_is(l: &[u8], s: &str) -> bool {
    l == s.as_bytes()
}

fn octet(l: &[u8]) -> Option<u8> {
    if l.is_empty() || l.len() > 3 || !l.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(l).ok()?.parse().ok()
}

fn nibble(l: &[u8]) -> Option<u8> {
    match l {
        [c] => (*c as char).to_digit(16).map(|d| d as u8),
        _ => None,
    }
}

/// True for names that belong to the local network and must not be sent to a public resolver.
pub fn policy_pass(labels: &[Vec<u8>]) -> bool {
    let n = labels.len();
    if n == 0 {
        return false;
    }
    if n == 1 {
        return true;
    }
    let last = &labels[n - 1];
    if LOCAL_SUFFIXES.iter().any(|s| label_is(last, s)) {
        return true;
    }
    if label_is(last, "arpa") {
        let prev = &labels[n - 2];
        if label_is(prev, "home") {
            return true;
        }
        let rest = &labels[..n - 2];
        if label_is(prev, "in-addr") {
            // labels before "in-addr.arpa", nearest-to-root first = first octet first
            let mut o = rest.iter().rev().map(|l| octet(l));
            let a = match o.next() {
                Some(Some(a)) => a,
                _ => return false,
            };
            let b = match o.next() {
                Some(Some(b)) => Some(b),
                Some(None) => return false,
                None => None,
            };
            return match (a, b) {
                (10, _) | (127, _) => true,
                (192, Some(168)) | (169, Some(254)) => true,
                (172, Some(16..=31)) => true,
                _ => false,
            };
        }
        if label_is(prev, "ip6") {
            let nibs: Vec<Option<u8>> = rest.iter().rev().map(|l| nibble(l)).collect();
            if nibs.iter().any(|x| x.is_none()) {
                return false;
            }
            let nb: Vec<u8> = nibs.into_iter().flatten().collect();
            // fe80::/10 : f e {8,9,a,b}
            if nb.len() >= 3 && nb[0] == 0xf && nb[1] == 0xe && (8..=0xb).contains(&nb[2]) {
                return true;
            }
            // fc00::/7 : f {c,d}
            if nb.len() >= 2 && nb[0] == 0xf && (nb[1] == 0xc || nb[1] == 0xd) {
                return true;
            }
            // ::1
            if nb.len() == 32 && nb[..31].iter().all(|&x| x == 0) && nb[31] == 1 {
                return true;
            }
        }
    }
    false
}

/// One resource record located inside a message.
#[derive(Clone, Copy, Debug)]
struct Rr {
    ty: u16,
    ttl_pos: usize,
    ttl: u32,
    next: usize,
}

fn read_rr(msg: &[u8], off: usize) -> Option<Rr> {
    let (_, p) = read_name(msg, off)?;
    let h = msg.get(p..p + 10)?;
    let ty = u16::from_be_bytes([h[0], h[1]]);
    let ttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
    let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
    let next = p + 10 + rdlen;
    if next > msg.len() {
        return None;
    }
    Some(Rr { ty, ttl_pos: p + 4, ttl, next })
}

/// All records after the question as (section, record); section 0 answer, 1 authority, 2 additional.
fn records(msg: &[u8]) -> Option<Vec<(u8, Rr)>> {
    let q = parse_question(msg)?;
    let counts = [be16(msg, 6)?, be16(msg, 8)?, be16(msg, 10)?];
    let mut off = q.end;
    let mut out = Vec::new();
    for (sec, &c) in counts.iter().enumerate() {
        for _ in 0..c {
            let rr = read_rr(msg, off)?;
            off = rr.next;
            out.push((sec as u8, rr));
        }
    }
    Some(out)
}

/// UDP payload size the client can take: EDNS(0) OPT class if present, else 512.
pub fn client_udp_size(query: &[u8]) -> usize {
    let f = || -> Option<usize> {
        let q = parse_question(query)?;
        let mut off = q.end;
        let counts = [be16(query, 6)?, be16(query, 8)?, be16(query, 10)?];
        let total = counts[0] as usize + counts[1] as usize + counts[2] as usize;
        for _ in 0..total {
            let (_, p) = read_name(query, off)?;
            let rr = read_rr(query, off)?;
            if rr.ty == OPT {
                return Some(be16(query, p + 2)? as usize);
            }
            off = rr.next;
        }
        None
    };
    f().unwrap_or(512).clamp(512, MAX_UDP_REPLY)
}

/// How long a response may be cached, in seconds, or `None` when it must not be cached.
pub fn cache_ttl(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 || resp[2] & 0x02 != 0 {
        return None; // truncated
    }
    let an = be16(resp, 6)?;
    match resp[3] & 0x0f {
        3 => Some(NEGATIVE_TTL),
        0 if an == 0 => Some(NEGATIVE_TTL),
        0 => {
            let min = records(resp)?.iter().filter(|(s, rr)| *s == 0 && rr.ty != OPT).map(|(_, rr)| rr.ttl).min()?;
            Some(min.clamp(TTL_MIN, TTL_MAX))
        }
        _ => None,
    }
}

/// Subtract `secs` from every record TTL (not below 1), leaving OPT alone.
fn age_ttls(msg: &mut [u8], secs: u32) {
    if secs == 0 {
        return;
    }
    if let Some(rrs) = records(msg) {
        for (_, rr) in rrs {
            if rr.ty != OPT {
                let t = rr.ttl.saturating_sub(secs).max(1);
                msg[rr.ttl_pos..rr.ttl_pos + 4].copy_from_slice(&t.to_be_bytes());
            }
        }
    }
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// Shorten a response that does not fit in `limit` bytes: header plus question, TC set.
fn truncate_for_udp(resp: &mut Vec<u8>, limit: usize) {
    if resp.len() <= limit {
        return;
    }
    let keep = parse_question(resp).map(|q| q.end).unwrap_or(12).min(resp.len());
    resp.truncate(keep);
    if resp.len() >= 12 {
        resp[2] |= 0x02;
        for b in &mut resp[6..12] {
            *b = 0;
        }
    }
}

/// Wrap `response` (ID patched to the query's) in a UDP packet from the asked server to the client.
pub fn build_reply(query: &Packet, response: &[u8]) -> Option<Packet> {
    let qp = query.payload();
    if qp.len() < 12 || response.len() < 12 {
        return None;
    }
    let mut r = response.to_vec();
    set_id(&mut r, u16::from_be_bytes([qp[0], qp[1]]));
    truncate_for_udp(&mut r, client_udp_size(qp));
    query.udp_reply(&r)
}

/// An upstream answer we are willing to hand to the client for `key`.
fn acceptable(resp: &[u8], key: &Key) -> bool {
    if resp.len() < 12 || resp[2] & 0x80 == 0 {
        return false;
    }
    if !matches!(resp[3] & 0x0f, 0 | 3) {
        return false; // SERVFAIL, REFUSED...: another upstream or the ISP may do better
    }
    match parse_question(resp) {
        Some(q) if q.key() == *key => {}
        _ => return false,
    }
    resp[2] & 0x02 != 0 || records(resp).is_some()
}

// =========================================================================================
// Cache
// =========================================================================================

struct Entry {
    resp: Vec<u8>,
    stored: u64,
    expires: u64,
    seq: u64,
}

/// Bounded TTL cache. Time is passed in (milliseconds) so tests control the clock.
pub struct Cache {
    map: HashMap<Key, Entry>,
    cap: usize,
    seq: u64,
}

impl Cache {
    pub fn new(cap: usize) -> Cache {
        Cache { map: HashMap::new(), cap: cap.max(1), seq: 0 }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Store a response for `ttl_secs` (already clamped by [`cache_ttl`]).
    pub fn insert(&mut self, key: Key, resp: Vec<u8>, ttl_secs: u32, now: u64) {
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            self.map.retain(|_, e| e.expires > now);
            if self.map.len() >= self.cap {
                if let Some(oldest) = self.map.iter().min_by_key(|(_, e)| e.seq).map(|(k, _)| k.clone()) {
                    self.map.remove(&oldest);
                }
            }
        }
        self.seq += 1;
        self.map.insert(key, Entry { resp, stored: now, expires: now + ttl_secs as u64 * 1000, seq: self.seq });
    }
    /// Cached response with TTLs reduced by the time spent in the cache; `None` if absent or expired.
    pub fn get(&mut self, key: &Key, now: u64) -> Option<Vec<u8>> {
        let e = self.map.get(key)?;
        if e.expires <= now {
            self.map.remove(key);
            return None;
        }
        let mut r = e.resp.clone();
        age_ttls(&mut r, ((now.saturating_sub(e.stored)) / 1000) as u32);
        Some(r)
    }
}

// =========================================================================================
// Responder
// =========================================================================================

/// Upstream transport: (url, DNS message, timeout ms) -> response message.
pub type UpstreamFn = Arc<dyn Fn(&str, &[u8], u32) -> Result<Vec<u8>, String> + Send + Sync>;
/// Millisecond clock used by the cache.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    pub workers: usize,
    pub queue_max: usize,
    pub cache_max: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning { workers: 4, queue_max: 256, cache_max: 4096 }
    }
}

struct Waiter<C> {
    query: Packet,
    ctx: C,
}

struct Job {
    key: Key,
    msg: Vec<u8>,
}

struct Shared<C: Send + 'static> {
    cfg: DnsConfig,
    on_done: Box<dyn Fn(DnsOutcome, C) + Send + Sync>,
    upstream: UpstreamFn,
    clock: ClockFn,
    queue_max: usize,
    cache: Mutex<Cache>,
    inflight: Mutex<HashMap<Key, Vec<Waiter<C>>>>,
    queue: Mutex<VecDeque<Job>>,
    cv: Condvar,
    shutdown: AtomicBool,
    last_good: AtomicUsize,
    answered: AtomicU64,
    passed: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl<C: Send + 'static> Shared<C> {
    fn finish(&self, o: DnsOutcome, ctx: C) {
        if self.shutdown.load(Ordering::Acquire) {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| (self.on_done)(o, ctx)));
    }

    fn pass(&self, q: Packet) -> DnsAction {
        self.passed.fetch_add(1, Ordering::Relaxed);
        DnsAction::Pass(q)
    }

    /// Ask the upstreams in turn within the total budget.
    fn resolve(&self, key: &Key, msg: &[u8]) -> Option<Vec<u8>> {
        let n = self.cfg.upstreams.len();
        if n == 0 {
            return None;
        }
        let start = self.last_good.load(Ordering::Relaxed) % n;
        let t0 = Instant::now();
        let budget = Duration::from_millis(self.cfg.timeout_ms as u64);
        for i in 0..n {
            if self.shutdown.load(Ordering::Acquire) {
                return None;
            }
            let remaining = budget.checked_sub(t0.elapsed())?;
            if remaining.is_zero() {
                return None;
            }
            let share = (n - i).min(2) as u32;
            let attempt = ((remaining / share).as_millis() as u32).max(1);
            let idx = (start + i) % n;
            if let Ok(r) = (self.upstream)(&self.cfg.upstreams[idx], msg, attempt) {
                if acceptable(&r, key) {
                    self.last_good.store(idx, Ordering::Relaxed);
                    return Some(r);
                }
            }
        }
        None
    }
}

fn worker<C: Send + 'static>(sh: Arc<Shared<C>>) {
    loop {
        let job = {
            let mut q = lock(&sh.queue);
            loop {
                if sh.shutdown.load(Ordering::Acquire) {
                    return;
                }
                if let Some(j) = q.pop_front() {
                    break j;
                }
                q = sh.cv.wait(q).unwrap_or_else(|p| p.into_inner());
            }
        };
        let result = catch_unwind(AssertUnwindSafe(|| sh.resolve(&job.key, &job.msg))).unwrap_or(None);
        if let Some(r) = &result {
            if let Some(ttl) = cache_ttl(r) {
                let now = (sh.clock)();
                lock(&sh.cache).insert(job.key.clone(), r.clone(), ttl, now);
            }
        }
        let waiters = lock(&sh.inflight).remove(&job.key).unwrap_or_default();
        for w in waiters {
            let reply = result.as_ref().and_then(|r| build_reply(&w.query, r));
            match reply {
                Some(p) => {
                    sh.answered.fetch_add(1, Ordering::Relaxed);
                    sh.finish(DnsOutcome::Reply(p), w.ctx);
                }
                None => {
                    sh.passed.fetch_add(1, Ordering::Relaxed);
                    sh.finish(DnsOutcome::Fallback(w.query), w.ctx);
                }
            }
        }
    }
}

pub struct DnsResponder<C: Send + 'static> {
    shared: Arc<Shared<C>>,
    threads: Vec<JoinHandle<()>>,
}

impl<C: Send + 'static> DnsResponder<C> {
    pub fn new(cfg: DnsConfig, on_done: Box<dyn Fn(DnsOutcome, C) + Send + Sync>) -> Self {
        let t0 = Instant::now();
        let clock: ClockFn = Arc::new(move || t0.elapsed().as_millis() as u64);
        let up: UpstreamFn = Arc::new(|url, msg, t| crate::doh::query(url, msg, t));
        Self::with_parts(cfg, on_done, up, clock, Tuning::default())
    }

    /// Like [`new`](Self::new) with the upstream transport, clock and sizes supplied (tests).
    pub fn with_parts(
        cfg: DnsConfig,
        on_done: Box<dyn Fn(DnsOutcome, C) + Send + Sync>,
        upstream: UpstreamFn,
        clock: ClockFn,
        tuning: Tuning,
    ) -> Self {
        let shared = Arc::new(Shared {
            cfg,
            on_done,
            upstream,
            clock,
            queue_max: tuning.queue_max,
            cache: Mutex::new(Cache::new(tuning.cache_max)),
            inflight: Mutex::new(HashMap::new()),
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
            last_good: AtomicUsize::new(0),
            answered: AtomicU64::new(0),
            passed: AtomicU64::new(0),
        });
        let mut threads = Vec::new();
        for i in 0..tuning.workers.max(1) {
            let sh = shared.clone();
            if let Ok(t) = std::thread::Builder::new().name(format!("sondpi-dns-{i}")).spawn(move || worker(sh)) {
                threads.push(t);
            }
        }
        DnsResponder { shared, threads }
    }

    /// Never blocks.
    pub fn handle(&self, query: Packet, ctx: C) -> DnsAction {
        let sh = &*self.shared;
        if sh.shutdown.load(Ordering::Acquire) || self.threads.is_empty() || !query.is_udp() {
            return sh.pass(query);
        }
        let payload = query.payload();
        if payload.len() > MAX_QUERY {
            return sh.pass(query);
        }
        let q = match parse_query(payload) {
            Some(q) => q,
            None => return sh.pass(query),
        };
        // Names of the local network and non-Internet classes belong to the resolver the client asked.
        if q.qclass != 1 || policy_pass(&q.labels) {
            return sh.pass(query);
        }
        let key = q.key();

        let hit = lock(&sh.cache).get(&key, (sh.clock)());
        if let Some(resp) = hit {
            return match build_reply(&query, &resp) {
                Some(p) => {
                    sh.answered.fetch_add(1, Ordering::Relaxed);
                    sh.finish(DnsOutcome::Reply(p), ctx);
                    DnsAction::Taken
                }
                None => sh.pass(query),
            };
        }

        let mut msg = payload.to_vec();
        set_id(&mut msg, 0); // RFC 8484: ID 0 keeps HTTP caches useful; the real ID is put back in the reply
        {
            let mut inf = lock(&sh.inflight);
            if let Some(list) = inf.get_mut(&key) {
                list.push(Waiter { query, ctx });
                return DnsAction::Taken;
            }
            let mut q = lock(&sh.queue);
            if q.len() >= sh.queue_max {
                drop(q);
                drop(inf);
                return sh.pass(query);
            }
            q.push_back(Job { key: key.clone(), msg });
            inf.insert(key, vec![Waiter { query, ctx }]);
        }
        sh.cv.notify_one();
        DnsAction::Taken
    }

    /// Queries answered locally so far.
    pub fn answered(&self) -> u64 {
        self.shared.answered.load(Ordering::Relaxed)
    }
    /// Queries passed through or fallen back so far.
    pub fn passed(&self) -> u64 {
        self.shared.passed.load(Ordering::Relaxed)
    }
}

impl<C: Send + 'static> Drop for DnsResponder<C> {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        {
            // Hold the queue lock while notifying so no worker misses the wake-up.
            let _g = lock(&self.shared.queue);
            self.shared.cv.notify_all();
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

// =========================================================================================
// Tests
// =========================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::testutil::udp;
    use std::sync::mpsc;

    fn labels(s: &str) -> Vec<Vec<u8>> {
        s.split('.').filter(|l| !l.is_empty()).map(|l| l.as_bytes().to_ascii_lowercase()).collect()
    }

    fn qname(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in name.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn make_query(id: u16, name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
        let mut m = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, if edns.is_some() { 1 } else { 0 }];
        m.extend(qname(name));
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        if let Some(sz) = edns {
            m.extend_from_slice(&[0, 0, 41]);
            m.extend_from_slice(&sz.to_be_bytes());
            m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        m
    }

    /// Response to `query` with one A answer carrying `ttl`.
    fn make_response(query: &[u8], ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let q = parse_question(query).unwrap();
        let mut r = query[..q.end].to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6..8].copy_from_slice(&1u16.to_be_bytes());
        r[8..12].copy_from_slice(&[0; 4]);
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[0, 4]);
        r.extend_from_slice(&ip);
        r
    }

    fn nxdomain(query: &[u8]) -> Vec<u8> {
        let q = parse_question(query).unwrap();
        let mut r = query[..q.end].to_vec();
        r[2] = 0x81;
        r[3] = 0x83;
        r[6..12].copy_from_slice(&[0; 6]);
        r
    }

    fn client_query(id: u16, name: &str, port: u16) -> Packet {
        udp(format!("192.168.1.10:{port}").parse().unwrap(), "192.168.1.1:53".parse().unwrap(), &make_query(id, name, 1, None))
    }

    // ---- names -------------------------------------------------------------------------

    #[test]
    fn names_plain_and_compressed() {
        let mut m = make_query(1, "www.Example.COM", 1, None);
        let (l, e) = read_name(&m, 12).unwrap();
        assert_eq!(l, labels("www.example.com"));
        assert_eq!(e, 12 + 17);
        // a name that is a pointer to offset 16 ("example.com" part)
        let at = m.len();
        m.extend_from_slice(&[3, b'f', b't', b'p', 0xc0, 16]);
        let (l, e) = read_name(&m, at).unwrap();
        assert_eq!(l, labels("ftp.example.com"));
        assert_eq!(e, at + 6);
    }

    #[test]
    fn names_reject_malformed() {
        // pointer loop, self pointer
        assert!(read_name(&[0, 0, 0xc0, 0x02], 2).is_none());
        let mut m = vec![0u8; 14];
        m[12] = 0xc0;
        m[13] = 12;
        assert!(read_name(&m, 12).is_none());
        // two pointers pointing at each other
        let m = vec![0xc0, 2, 0xc0, 0];
        assert!(read_name(&m, 0).is_none());
        // pointer out of range
        assert!(read_name(&[0xc0, 0x40], 0).is_none());
        // truncated label and missing terminator
        assert!(read_name(&[5, b'a', b'b'], 0).is_none());
        assert!(read_name(&[1, b'a'], 0).is_none());
        // reserved label types
        assert!(read_name(&[0x40, 0], 0).is_none());
        assert!(read_name(&[0x80, 0], 0).is_none());
        // offset past the end
        assert!(read_name(&[], 0).is_none());
        // over-long name
        let mut long = Vec::new();
        for _ in 0..10 {
            long.push(30);
            long.extend_from_slice(&[b'a'; 30]);
        }
        long.push(0);
        assert!(read_name(&long, 0).is_none());
    }

    #[test]
    fn question_parsing_truncation_everywhere() {
        let m = make_query(7, "example.com", 28, Some(1232));
        assert!(parse_query(&m).is_some());
        for cut in 0..(12 + 13 + 4) {
            // no truncated prefix may panic or succeed before the question is complete
            let r = parse_query(&m[..cut]);
            assert!(r.is_none(), "cut {cut}");
        }
        for cut in 0..m.len() {
            let _ = client_udp_size(&m[..cut]);
            let _ = cache_ttl(&m[..cut]);
        }
        let q = parse_query(&m).unwrap();
        assert_eq!((q.qtype, q.qclass), (28, 1));
    }

    #[test]
    fn query_shape_checks() {
        let ok = make_query(1, "a.example.com", 1, None);
        assert!(parse_query(&ok).is_some());
        let mut resp = ok.clone();
        resp[2] |= 0x80;
        assert!(parse_query(&resp).is_none(), "QR set");
        let mut op = ok.clone();
        op[2] |= 0x28; // opcode 5 (update)
        assert!(parse_query(&op).is_none());
        let mut two = ok.clone();
        two[5] = 2;
        assert!(parse_query(&two).is_none());
        let mut zero = ok.clone();
        zero[5] = 0;
        assert!(parse_query(&zero).is_none());
        let mut an = ok.clone();
        an[7] = 1;
        assert!(parse_query(&an).is_none());
    }

    #[test]
    fn key_ignores_case_and_distinguishes_type() {
        let a = parse_query(&make_query(1, "WwW.Example.Com", 1, None)).unwrap().key();
        let b = parse_query(&make_query(2, "www.example.com", 1, Some(4096))).unwrap().key();
        let c = parse_query(&make_query(2, "www.example.com", 28, None)).unwrap().key();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ---- policy --------------------------------------------------------------------------

    #[test]
    fn policy_table() {
        for n in [
            "printer", "nas", "router.local", "a.b.lan", "x.home", "foo.home.arpa", "svc.internal", "x.intranet", "x.corp",
            "x.private", "x.localdomain", "localhost", "a.localhost", "a.test", "a.invalid", "abc.onion", "A.LAN",
            "10.in-addr.arpa", "5.4.3.10.in-addr.arpa", "168.192.in-addr.arpa", "1.1.168.192.in-addr.arpa", "16.172.in-addr.arpa",
            "31.172.in-addr.arpa", "9.9.20.172.in-addr.arpa", "254.169.in-addr.arpa", "1.2.254.169.in-addr.arpa",
            "127.in-addr.arpa", "1.0.0.127.in-addr.arpa",
        ] {
            assert!(policy_pass(&labels(n)), "{n} should pass");
        }
        let ll = |first: &str| format!("1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.{first}.ip6.arpa");
        let loopback = format!("1.{}ip6.arpa", "0.".repeat(31));
        for n in [
            ll("0.8.e.f"), ll("9.8.e.f"), ll("a.8.e.f"), ll("b.8.e.f"), ll("c.f"), ll("d.f"), "8.e.f.ip6.arpa".into(), loopback,
        ] {
            assert!(policy_pass(&labels(&n)), "{n} should pass");
        }
        for n in [
            "example.com", "www.google.com", "a.b.c.example.org", "localhost.example.com", "lan.example.com", "local.example.com",
            "home.example", "11.in-addr.arpa", "1.1.1.1.in-addr.arpa", "8.8.8.8.in-addr.arpa", "15.172.in-addr.arpa",
            "32.172.in-addr.arpa", "169.in-addr.arpa", "1.169.in-addr.arpa", "0.169.in-addr.arpa", "169.192.in-addr.arpa",
            "ip6.arpa", "0.8.e.f.0.ip6.arpa.example.com", "1.ip6.arpa", "e.f.ip6.arpa", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.ip6.arpa",
            "x.arpa", "cloudflare-dns.com",
        ] {
            assert!(!policy_pass(&labels(n)), "{n} must not pass");
        }
        assert!(!policy_pass(&[]), "root is resolved upstream");
    }

    // ---- TTL, cache ------------------------------------------------------------------------

    #[test]
    fn ttl_extraction_and_clamping() {
        let q = make_query(1, "example.com", 1, None);
        assert_eq!(cache_ttl(&make_response(&q, 300, [1, 2, 3, 4])), Some(300));
        assert_eq!(cache_ttl(&make_response(&q, 0, [1, 2, 3, 4])), Some(5));
        assert_eq!(cache_ttl(&make_response(&q, 2, [1, 2, 3, 4])), Some(5));
        assert_eq!(cache_ttl(&make_response(&q, 86400, [1, 2, 3, 4])), Some(3600));
        assert_eq!(cache_ttl(&nxdomain(&q)), Some(30));
        // NOERROR, no answers = no data
        let mut nodata = nxdomain(&q);
        nodata[3] = 0x80;
        assert_eq!(cache_ttl(&nodata), Some(30));
        // SERVFAIL and truncated are not cached
        let mut sf = nxdomain(&q);
        sf[3] = 0x82;
        assert_eq!(cache_ttl(&sf), None);
        let mut tc = make_response(&q, 300, [1, 2, 3, 4]);
        tc[2] |= 0x02;
        assert_eq!(cache_ttl(&tc), None);
        // smallest TTL of two answers wins
        let mut two = make_response(&q, 300, [1, 2, 3, 4]);
        two[6..8].copy_from_slice(&2u16.to_be_bytes());
        two.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 5, 6, 7, 8]);
        assert_eq!(cache_ttl(&two), Some(60));
        // answer count lies: malformed, not cached, no panic
        let mut bad = make_response(&q, 300, [1, 2, 3, 4]);
        bad[7] = 9;
        assert_eq!(cache_ttl(&bad), None);
    }

    #[test]
    fn cache_expiry_aging_and_bound() {
        let q = make_query(1, "example.com", 1, None);
        let key = parse_query(&q).unwrap().key();
        let resp = make_response(&q, 100, [1, 2, 3, 4]);
        let mut c = Cache::new(4);
        c.insert(key.clone(), resp.clone(), 100, 1_000);
        assert!(c.get(&key, 1_000 + 99_999).is_some());
        let aged = c.get(&key, 1_000 + 40_000).unwrap();
        assert_eq!(cache_ttl(&aged), Some(60), "TTL reduced by the 40 s spent in the cache");
        assert!(c.get(&key, 1_000 + 100_000).is_none(), "expired");
        assert!(c.is_empty(), "expired entry dropped on lookup");

        // size bound: oldest goes first
        let mut c = Cache::new(3);
        let keys: Vec<Key> = (0..5).map(|i| parse_query(&make_query(1, &format!("h{i}.example.com"), 1, None)).unwrap().key()).collect();
        for (i, k) in keys.iter().enumerate() {
            c.insert(k.clone(), resp.clone(), 1000, i as u64);
            assert!(c.len() <= 3);
        }
        assert_eq!(c.len(), 3);
        assert!(c.get(&keys[0], 10).is_none() && c.get(&keys[1], 10).is_none());
        assert!(c.get(&keys[4], 10).is_some() && c.get(&keys[2], 10).is_some());

        // expired entries are evicted before live ones
        let mut c = Cache::new(2);
        c.insert(keys[0].clone(), resp.clone(), 1, 0); // expires at 1 s
        c.insert(keys[1].clone(), resp.clone(), 1000, 1);
        c.insert(keys[2].clone(), resp.clone(), 1000, 5_000);
        assert!(c.get(&keys[1], 5_001).is_some(), "live entry kept");
        assert!(c.get(&keys[0], 5_001).is_none());
        assert_eq!(c.len(), 2);
    }

    // ---- reply building ----------------------------------------------------------------

    #[test]
    fn id_patching() {
        let mut m = make_query(0x1111, "example.com", 1, None);
        set_id(&mut m, 0xabcd);
        assert_eq!(&m[..2], &[0xab, 0xcd]);
        set_id(&mut [], 1);
        set_id(&mut [0], 1);
    }

    #[test]
    fn reply_packets_v4_and_v6_link_local() {
        for (client, server) in [("192.168.1.10:55000", "192.168.1.1:53"), ("[fe80::1234]:55000", "[fe80::1]:53")] {
            let qm = make_query(0x4242, "example.com", 1, None);
            let pkt = udp(client.parse().unwrap(), server.parse().unwrap(), &qm);
            let resp = make_response(&make_query(0, "example.com", 1, None), 60, [93, 184, 216, 34]);
            let r = build_reply(&pkt, &resp).unwrap();
            assert_eq!(r.src(), server.parse().unwrap());
            assert_eq!(r.dst(), client.parse().unwrap());
            assert!(r.is_udp() && r.l4_checksum_ok());
            assert_eq!(&r.payload()[..2], &[0x42, 0x42], "ID of the query");
            assert_eq!(&r.payload()[2..], &resp[2..]);
            let re = Packet::parse(r.as_bytes().to_vec()).expect("lengths consistent");
            assert_eq!(re.payload(), r.payload());
            assert_eq!(r.is_ipv6(), client.starts_with('['));
        }
    }

    #[test]
    fn oversized_reply_is_truncated_for_plain_clients() {
        let q = make_query(1, "example.com", 16, None);
        let mut resp = make_response(&q, 60, [1, 2, 3, 4]);
        resp.extend(std::iter::repeat(0u8).take(1200));
        let pkt = udp("10.0.0.2:5000".parse().unwrap(), "10.0.0.1:53".parse().unwrap(), &q);
        let r = build_reply(&pkt, &resp).unwrap();
        let p = r.payload();
        assert!(p.len() <= 512 && p[2] & 0x02 != 0);
        assert_eq!(&p[6..12], &[0; 6]);
        assert_eq!(parse_question(p).unwrap().labels, labels("example.com"));
        // an EDNS client advertising 4096 gets it whole
        let q2 = make_query(1, "example.com", 16, Some(4096));
        let pkt2 = udp("10.0.0.2:5000".parse().unwrap(), "10.0.0.1:53".parse().unwrap(), &q2);
        assert_eq!(build_reply(&pkt2, &resp).unwrap().payload().len(), resp.len());
        assert_eq!(client_udp_size(&q2), 4096);
        assert_eq!(client_udp_size(&q), 512);
    }

    #[test]
    fn rejects_wrong_upstream_answers() {
        let q = make_query(1, "example.com", 1, None);
        let key = parse_query(&q).unwrap().key();
        let good = make_response(&q, 60, [1, 2, 3, 4]);
        assert!(acceptable(&good, &key));
        assert!(acceptable(&nxdomain(&q), &key));
        let other = make_response(&make_query(1, "evil.com", 1, None), 60, [1, 2, 3, 4]);
        assert!(!acceptable(&other, &key), "different question");
        let mut notresp = good.clone();
        notresp[2] &= 0x7f;
        assert!(!acceptable(&notresp, &key));
        let mut sf = good.clone();
        sf[3] = 0x82;
        assert!(!acceptable(&sf, &key));
        assert!(!acceptable(&good[..20], &key));
        assert!(!acceptable(&[], &key));
    }

    // ---- responder ----------------------------------------------------------------------------

    type Rx = mpsc::Receiver<(DnsOutcome, u32)>;

    fn collector() -> (Box<dyn Fn(DnsOutcome, u32) + Send + Sync>, Rx) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        (Box::new(move |o, c| {
            let _ = lock(&tx).send((o, c));
        }), rx)
    }

    fn cfg(n: usize) -> DnsConfig {
        DnsConfig { upstreams: (0..n).map(|i| format!("https://u{i}/dns-query")).collect(), timeout_ms: 2000 }
    }

    fn fake_clock() -> (ClockFn, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(0));
        let t2 = t.clone();
        (Arc::new(move || t2.load(Ordering::Relaxed)), t)
    }

    /// Upstream that answers every query with an A record, counting calls.
    fn answering(calls: Arc<AtomicU64>) -> UpstreamFn {
        Arc::new(move |_url, msg, _t| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(make_response(msg, 120, [9, 9, 9, 9]))
        })
    }

    fn recv(rx: &Rx) -> (DnsOutcome, u32) {
        rx.recv_timeout(Duration::from_secs(5)).expect("callback")
    }

    #[test]
    fn passes_unanswerable_queries() {
        let (cb, _rx) = collector();
        let (clock, _) = fake_clock();
        let r = DnsResponder::<u32>::with_parts(cfg(1), cb, answering(Arc::default()), clock, Tuning::default());
        for name in ["printer", "nas.local", "1.1.168.192.in-addr.arpa"] {
            assert!(matches!(r.handle(client_query(1, name, 5000), 0), DnsAction::Pass(_)), "{name}");
        }
        // junk payload, response instead of query, TCP packet
        let junk = udp("10.0.0.2:5000".parse().unwrap(), "10.0.0.1:53".parse().unwrap(), b"hello");
        assert!(matches!(r.handle(junk, 0), DnsAction::Pass(_)));
        let mut resp = make_query(1, "example.com", 1, None);
        resp[2] |= 0x80;
        let p = udp("10.0.0.2:5000".parse().unwrap(), "10.0.0.1:53".parse().unwrap(), &resp);
        assert!(matches!(r.handle(p, 0), DnsAction::Pass(_)));
        let tcp = crate::packet::testutil::tcp4([10, 0, 0, 2], 5000, [10, 0, 0, 1], 53, 1, 1, crate::packet::TCP_ACK, b"x");
        assert!(matches!(r.handle(tcp, 0), DnsAction::Pass(_)));
        assert_eq!(r.passed(), 6);
        assert_eq!(r.answered(), 0);
    }

    #[test]
    fn resolves_then_serves_from_cache_until_expiry() {
        let (cb, rx) = collector();
        let (clock, now) = fake_clock();
        let calls = Arc::new(AtomicU64::new(0));
        let r = DnsResponder::<u32>::with_parts(cfg(1), cb, answering(calls.clone()), clock, Tuning::default());

        assert!(matches!(r.handle(client_query(0x0101, "Example.com", 5001), 1), DnsAction::Taken));
        let (o, ctx) = recv(&rx);
        assert_eq!(ctx, 1);
        match o {
            DnsOutcome::Reply(p) => {
                assert_eq!(&p.payload()[..2], &[1, 1]);
                assert_eq!(p.src(), "192.168.1.1:53".parse().unwrap());
                assert_eq!(p.dst(), "192.168.1.10:5001".parse().unwrap());
                assert!(p.l4_checksum_ok());
            }
            _ => panic!("expected reply"),
        }
        // cache hit: answered inline, no new upstream call, different ID honoured
        now.store(10_000, Ordering::Relaxed);
        assert!(matches!(r.handle(client_query(0x0202, "EXAMPLE.com", 5002), 2), DnsAction::Taken));
        let (o, ctx) = rx.try_recv().expect("inline reply");
        assert_eq!(ctx, 2);
        match o {
            DnsOutcome::Reply(p) => {
                assert_eq!(&p.payload()[..2], &[2, 2]);
                assert_eq!(cache_ttl(p.payload()), Some(110), "aged by 10 s");
            }
            _ => panic!(),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // expired: asks again
        now.store(200_000, Ordering::Relaxed);
        assert!(matches!(r.handle(client_query(3, "example.com", 5003), 3), DnsAction::Taken));
        let _ = recv(&rx);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(r.answered(), 3);
        assert_eq!(r.passed(), 0);
    }

    #[test]
    fn upstream_failover_remembers_last_good() {
        let (cb, rx) = collector();
        let (clock, _) = fake_clock();
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let l2 = log.clone();
        let up: UpstreamFn = Arc::new(move |url, msg, _| {
            lock(&l2).push(url.to_string());
            if url.contains("u2") {
                Ok(make_response(msg, 60, [1, 1, 1, 1]))
            } else {
                Err("down".into())
            }
        });
        let r = DnsResponder::<u32>::with_parts(cfg(3), cb, up, clock, Tuning::default());
        r.handle(client_query(1, "a.example.com", 5000), 0);
        assert!(matches!(recv(&rx).0, DnsOutcome::Reply(_)));
        assert_eq!(*lock(&log), ["https://u0/dns-query", "https://u1/dns-query", "https://u2/dns-query"]);
        lock(&log).clear();
        r.handle(client_query(2, "b.example.com", 5000), 0);
        assert!(matches!(recv(&rx).0, DnsOutcome::Reply(_)));
        assert_eq!(*lock(&log), ["https://u2/dns-query"], "last working upstream first");
    }

    #[test]
    fn total_failure_falls_back_to_the_original_query() {
        let (cb, rx) = collector();
        let (clock, _) = fake_clock();
        let up: UpstreamFn = Arc::new(|_, _, _| Err("down".into()));
        let r = DnsResponder::<u32>::with_parts(cfg(2), cb, up, clock, Tuning::default());
        let q = client_query(9, "example.com", 5000);
        let orig = q.clone();
        assert!(matches!(r.handle(q, 7), DnsAction::Taken));
        match recv(&rx) {
            (DnsOutcome::Fallback(p), 7) => assert_eq!(p, orig),
            _ => panic!("expected fallback"),
        }
        assert_eq!((r.answered(), r.passed()), (0, 1));
        // garbage and SERVFAIL answers count as failure too
        let (cb, rx) = collector();
        let (clock, _) = fake_clock();
        let up: UpstreamFn = Arc::new(|_, msg, _| {
            let mut r = make_response(msg, 60, [1, 1, 1, 1]);
            r[3] = 0x82;
            Ok(r)
        });
        let r = DnsResponder::<u32>::with_parts(cfg(2), cb, up, clock, Tuning::default());
        r.handle(client_query(9, "example.com", 5000), 8);
        assert!(matches!(recv(&rx), (DnsOutcome::Fallback(_), 8)));
    }

    /// Upstream that blocks until `release` is set; `entered` counts calls that started.
    struct Gate {
        open: Mutex<bool>,
        cv: Condvar,
        entered: Mutex<u32>,
        entered_cv: Condvar,
        calls: AtomicU64,
    }
    impl Gate {
        fn new() -> Arc<Gate> {
            Arc::new(Gate { open: Mutex::new(false), cv: Condvar::new(), entered: Mutex::new(0), entered_cv: Condvar::new(), calls: AtomicU64::new(0) })
        }
        fn upstream(self: &Arc<Self>) -> UpstreamFn {
            let g = self.clone();
            Arc::new(move |_, msg, _| {
                g.calls.fetch_add(1, Ordering::SeqCst);
                *lock(&g.entered) += 1;
                g.entered_cv.notify_all();
                let mut o = lock(&g.open);
                while !*o {
                    o = g.cv.wait(o).unwrap();
                }
                Ok(make_response(msg, 60, [4, 4, 4, 4]))
            })
        }
        fn wait_entered(&self, n: u32) {
            let mut e = lock(&self.entered);
            while *e < n {
                let (g, t) = self.entered_cv.wait_timeout(e, Duration::from_secs(5)).unwrap();
                e = g;
                assert!(!t.timed_out(), "upstream never entered");
            }
        }
        fn release(&self) {
            *lock(&self.open) = true;
            self.cv.notify_all();
        }
    }

    #[test]
    fn identical_questions_in_flight_share_one_request() {
        let (cb, rx) = collector();
        let (clock, _) = fake_clock();
        let gate = Gate::new();
        let r = DnsResponder::<u32>::with_parts(cfg(1), cb, gate.upstream(), clock, Tuning::default());
        for i in 0..3u16 {
            assert!(matches!(r.handle(client_query(0x100 + i, "Same.example.com", 6000 + i), i as u32), DnsAction::Taken));
            if i == 0 {
                gate.wait_entered(1);
            }
        }
        gate.release();
        let mut seen = Vec::new();
        for _ in 0..3 {
            match recv(&rx) {
                (DnsOutcome::Reply(p), ctx) => {
                    assert_eq!(&p.payload()[..2], &(0x100 + ctx as u16).to_be_bytes());
                    assert_eq!(p.dst().port(), 6000 + ctx as u16);
                    seen.push(ctx);
                }
                _ => panic!("expected reply"),
            }
        }
        seen.sort();
        assert_eq!(seen, [0, 1, 2]);
        assert_eq!(gate.calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.answered(), 3);
    }

    #[test]
    fn full_queue_passes_instead_of_blocking() {
        let (cb, rx) = collector();
        let (clock, _) = fake_clock();
        let gate = Gate::new();
        let t = Tuning { workers: 1, queue_max: 2, cache_max: 16 };
        let r = DnsResponder::<u32>::with_parts(cfg(1), cb, gate.upstream(), clock, t);
        assert!(matches!(r.handle(client_query(1, "n1.example.com", 7001), 1), DnsAction::Taken));
        gate.wait_entered(1); // the only worker is now busy
        assert!(matches!(r.handle(client_query(2, "n2.example.com", 7002), 2), DnsAction::Taken));
        assert!(matches!(r.handle(client_query(3, "n3.example.com", 7003), 3), DnsAction::Taken));
        let t0 = Instant::now();
        assert!(matches!(r.handle(client_query(4, "n4.example.com", 7004), 4), DnsAction::Pass(_)));
        assert!(t0.elapsed() < Duration::from_millis(500), "handle did not block");
        // but a duplicate of a queued question still joins it
        assert!(matches!(r.handle(client_query(5, "n3.example.com", 7005), 5), DnsAction::Taken));
        assert_eq!(r.passed(), 1);
        gate.release();
        let mut got = 0;
        while got < 4 {
            assert!(matches!(recv(&rx).0, DnsOutcome::Reply(_)));
            got += 1;
        }
        assert_eq!(r.answered(), 4);
    }

    #[test]
    fn drop_joins_workers_and_stops_callbacks() {
        let count = Arc::new(AtomicU64::new(0));
        let c2 = count.clone();
        let (clock, _) = fake_clock();
        let up: UpstreamFn = Arc::new(|_, msg, _| {
            std::thread::sleep(Duration::from_millis(30));
            Ok(make_response(msg, 60, [1, 1, 1, 1]))
        });
        let r = DnsResponder::<u32>::with_parts(
            cfg(1),
            Box::new(move |_, _| {
                c2.fetch_add(1, Ordering::SeqCst);
            }),
            up,
            clock,
            Tuning { workers: 2, queue_max: 64, cache_max: 16 },
        );
        for i in 0..20u16 {
            let _ = r.handle(client_query(i, &format!("h{i}.example.com"), 8000 + i), 0);
        }
        let t0 = Instant::now();
        drop(r);
        assert!(t0.elapsed() < Duration::from_secs(3));
        let after = count.load(Ordering::SeqCst);
        assert!(after < 20, "pending work was discarded");
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(count.load(Ordering::SeqCst), after, "no callback after drop returned");
    }

    #[test]
    fn idle_responder_drops_promptly() {
        let (cb, _rx) = collector();
        let (clock, _) = fake_clock();
        let r = DnsResponder::<u32>::with_parts(cfg(1), cb, answering(Arc::default()), clock, Tuning::default());
        let t0 = Instant::now();
        drop(r);
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn hostile_messages_do_not_panic() {
        // every prefix and a few byte-smashed variants of a real answer go through all parsers
        let q = make_query(1, "example.com", 1, Some(1232));
        let mut base = make_response(&q, 60, [1, 2, 3, 4]);
        base.extend_from_slice(&[0xc0, 12, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        base[11] = 1;
        let key = parse_query(&q).unwrap().key();
        for cut in 0..=base.len() {
            let m = &base[..cut];
            let _ = (cache_ttl(m), acceptable(m, &key), records(m).is_some(), client_udp_size(m));
            let mut c = m.to_vec();
            age_ttls(&mut c, 5);
        }
        for i in 0..base.len() {
            for v in [0x00u8, 0xff, 0xc0, 0x3f] {
                let mut m = base.clone();
                m[i] = v;
                let _ = (cache_ttl(&m), acceptable(&m, &key), client_udp_size(&m), parse_query(&m));
                age_ttls(&mut m, 5);
            }
        }
    }
}
