//! Host name resolution for the proxy: A and AAAA over DoH, cached, with concurrent lookups
//! of the same name sharing one upstream query.
//!
//! The ISP's resolver rewrites blocked names to its block page (CLAUDE.md, DNS), and the
//! system resolver on macOS asks it first, so the proxy never uses the system resolver for
//! public names while DoH works. Local names ([`dns::policy_pass`]) always go to the system
//! resolver, and so does everything when every DoH upstream fails (a working block page beats
//! no answer, and unblocked names keep working).

use crate::dns::{self, Cache, ClockFn, DnsConfig, Key, UpstreamFn};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const CACHE_MAX: usize = 4096;

/// Result shared by concurrent lookups of one key: `None` while running, then
/// `Some(None)` (DoH failed) or `Some(Some(response))`.
#[derive(Default)]
struct Slot {
    done: Mutex<Option<Option<Vec<u8>>>>,
    cv: Condvar,
}

pub struct Resolver {
    cfg: DnsConfig,
    upstream: UpstreamFn,
    clock: ClockFn,
    cache: Mutex<Cache>,
    inflight: Mutex<HashMap<Key, Arc<Slot>>>,
    last_good: AtomicUsize,
    answered: AtomicU64,
    fallbacks: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Resolver {
    pub fn new(cfg: DnsConfig, upstream: UpstreamFn) -> Resolver {
        let t0 = Instant::now();
        let clock: ClockFn = Arc::new(move || t0.elapsed().as_millis() as u64);
        Self::with_clock(cfg, upstream, clock)
    }

    pub fn with_clock(cfg: DnsConfig, upstream: UpstreamFn, clock: ClockFn) -> Resolver {
        Resolver {
            cfg,
            upstream,
            clock,
            cache: Mutex::new(Cache::new(CACHE_MAX)),
            inflight: Mutex::new(HashMap::new()),
            last_good: AtomicUsize::new(0),
            answered: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
        }
    }

    /// Names resolved over DoH (from the cache or the network).
    pub fn answered(&self) -> u64 {
        self.answered.load(Ordering::Relaxed)
    }

    /// Lookups that had to use the system resolver because DoH failed.
    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }

    /// Addresses of `name`, IPv6 first. An IP literal is returned as is.
    pub fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        let labels: Vec<Vec<u8>> = name.split('.').map(|l| l.as_bytes().to_vec()).collect();
        if dns::policy_pass(&labels) {
            return system(&name);
        }
        let cached = (self.cached(&name, dns::TYPE_AAAA), self.cached(&name, dns::TYPE_A));
        let (v6, v4) = if let (Some(v6), Some(v4)) = cached {
            (Some(v6), Some(v4))
        } else {
            self.query_both(&name)
        };
        self.finish(&name, v6, v4)
    }

    fn cached(&self, name: &str, qtype: u16) -> Option<Vec<u8>> {
        let key = dns::parse_query(&dns::build_query(name, qtype, 0)?)?.key();
        lock(&self.cache).get(&key, (self.clock)())
    }

    /// AAAA on a second thread, A on this one.
    fn query_both(&self, name: &str) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        std::thread::scope(|s| {
            let h = std::thread::Builder::new().stack_size(128 * 1024).spawn_scoped(s, || self.query(name, dns::TYPE_AAAA));
            let v4 = self.query(name, dns::TYPE_A);
            let v6 = match h {
                Ok(h) => h.join().unwrap_or(None),
                Err(_) => self.query(name, dns::TYPE_AAAA),
            };
            (v6, v4)
        })
    }

    fn finish(&self, name: &str, v6: Option<Vec<u8>>, v4: Option<Vec<u8>>) -> io::Result<Vec<IpAddr>> {
        if v6.is_none() && v4.is_none() {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
            return system(name);
        }
        self.answered.fetch_add(1, Ordering::Relaxed);
        let mut out = Vec::new();
        for r in [&v6, &v4].into_iter().flatten() {
            out.extend(dns::answer_addrs(r));
        }
        if out.is_empty() {
            let nx = [&v6, &v4].into_iter().flatten().any(|r| r.len() >= 4 && r[3] & 0x0f == 3);
            let msg = if nx { "name does not exist" } else { "name has no address" };
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{name}: {msg}")));
        }
        Ok(out)
    }

    /// One response for (`name`, `qtype`): cached, joined from a running lookup, or fetched.
    fn query(&self, name: &str, qtype: u16) -> Option<Vec<u8>> {
        // DoH asks for id 0 (RFC 8484 4.1) so that HTTP caches can share answers.
        let msg = dns::build_query(name, qtype, 0)?;
        let key = dns::parse_query(&msg)?.key();
        if let Some(r) = lock(&self.cache).get(&key, (self.clock)()) {
            return Some(r);
        }
        let (slot, leader) = {
            let mut inflight = lock(&self.inflight);
            match inflight.get(&key) {
                Some(s) => (s.clone(), false),
                None => {
                    let s = Arc::new(Slot::default());
                    inflight.insert(key.clone(), s.clone());
                    (s, true)
                }
            }
        };
        if !leader {
            let wait = Duration::from_millis(self.cfg.timeout_ms as u64 + 1000);
            let g = lock(&slot.done);
            let (g, _) = slot.cv.wait_timeout_while(g, wait, |d| d.is_none()).unwrap_or_else(|p| p.into_inner());
            return g.clone().flatten();
        }
        let r = self.fetch(&key, &msg);
        if let Some(resp) = &r {
            if let Some(ttl) = dns::cache_ttl(resp) {
                lock(&self.cache).insert(key.clone(), resp.clone(), ttl, (self.clock)());
            }
        }
        *lock(&slot.done) = Some(r.clone());
        slot.cv.notify_all();
        lock(&self.inflight).remove(&key);
        r
    }

    /// Ask the upstreams in turn, starting with the last one that worked, within the budget.
    fn fetch(&self, key: &Key, msg: &[u8]) -> Option<Vec<u8>> {
        let n = self.cfg.upstreams.len();
        if n == 0 {
            return None;
        }
        let start = self.last_good.load(Ordering::Relaxed) % n;
        let t0 = Instant::now();
        let budget = Duration::from_millis(self.cfg.timeout_ms as u64);
        for i in 0..n {
            let remaining = budget.checked_sub(t0.elapsed())?;
            if remaining.is_zero() {
                return None;
            }
            // Leave the next upstream some time too.
            let share = (n - i).min(2) as u32;
            let attempt = ((remaining / share).as_millis() as u32).max(1);
            let idx = (start + i) % n;
            if let Ok(r) = (self.upstream)(&self.cfg.upstreams[idx], msg, attempt) {
                if dns::acceptable(&r, key) {
                    self.last_good.store(idx, Ordering::Relaxed);
                    return Some(r);
                }
            }
        }
        None
    }
}

/// Longest wait for the system resolver; getaddrinfo itself has no timeout.
const SYSTEM_TIMEOUT: Duration = Duration::from_secs(5);

/// The system resolver (getaddrinfo), IPv6 first, given at most [`SYSTEM_TIMEOUT`] (a
/// lookup still running then finishes on its own thread and is discarded).
fn system(name: &str) -> io::Result<Vec<IpAddr>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let n = name.to_string();
    std::thread::Builder::new().name("sondpi-getaddrinfo".into()).stack_size(256 * 1024).spawn(move || {
        let _ = tx.send(system_blocking(&n));
    })?;
    rx.recv_timeout(SYSTEM_TIMEOUT)
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, format!("{name}: system resolver timed out"))))
}

fn system_blocking(name: &str) -> io::Result<Vec<IpAddr>> {
    let mut v: Vec<IpAddr> = Vec::new();
    for a in (name, 0u16).to_socket_addrs()? {
        if !v.contains(&a.ip()) {
            v.push(a.ip());
        }
    }
    v.sort_by_key(|ip| ip.is_ipv4());
    if v.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{name}: no address")));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// Answer every query with one A (10.0.0.n) or AAAA (fd00::n) record; `n` counts calls.
    fn answer(q: &[u8], rcode: u8, with_record: bool) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[3] = 0x80 | rcode;
        if with_record {
            let qtype = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
            r[7] = 1;
            r.extend_from_slice(&[0xc0, 0x0c]);
            r.extend_from_slice(&qtype.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 1, 0]);
            if qtype == dns::TYPE_A {
                r.extend_from_slice(&[0, 4, 10, 0, 0, 1]);
            } else {
                r.extend_from_slice(&[0, 16, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
        }
        r
    }

    fn cfg(urls: &[&str]) -> DnsConfig {
        DnsConfig { upstreams: urls.iter().map(|s| s.to_string()).collect(), timeout_ms: 1000 }
    }

    #[test]
    fn resolves_both_families_and_caches() {
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let up: UpstreamFn = Arc::new(move |_, q, _| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(answer(q, 0, true))
        });
        let r = Resolver::new(cfg(&["u1"]), up);
        let want: Vec<IpAddr> = vec!["fd00::1".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        assert_eq!(r.lookup("Discord.com.").unwrap(), want);
        assert_eq!(r.lookup("discord.com").unwrap(), want);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(r.answered(), 2);
        assert_eq!(r.lookup("1.2.3.4").unwrap(), vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn concurrent_lookups_share_one_query() {
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let up: UpstreamFn = Arc::new(move |_, q, _| {
            c.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
            Ok(answer(q, 0, true))
        });
        let r = Arc::new(Resolver::new(cfg(&["u1"]), up));
        let hs: Vec<_> = (0..8).map(|_| {
            let r = r.clone();
            std::thread::spawn(move || r.lookup("a.example").unwrap().len())
        }).collect();
        for h in hs {
            assert_eq!(h.join().unwrap(), 2);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn fails_over_and_remembers_the_good_upstream() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let up: UpstreamFn = Arc::new(move |url, q, _| {
            s.lock().unwrap().push(url.to_string());
            if url == "bad" {
                Err("down".into())
            } else {
                Ok(answer(q, 0, true))
            }
        });
        let r = Resolver::new(cfg(&["bad", "good"]), up);
        assert_eq!(r.lookup("x.example").unwrap().len(), 2);
        seen.lock().unwrap().clear();
        assert_eq!(r.lookup("y.example").unwrap().len(), 2);
        assert!(seen.lock().unwrap().iter().all(|u| u == "good"));
    }

    #[test]
    fn nxdomain_and_nodata_are_errors_without_fallback() {
        let up: UpstreamFn = Arc::new(|_, q, _| Ok(answer(q, 3, false)));
        let r = Resolver::new(cfg(&["u"]), up);
        let e = r.lookup("nope.example").unwrap_err();
        assert!(e.to_string().contains("does not exist"));
        let up: UpstreamFn = Arc::new(|_, q, _| Ok(answer(q, 0, false)));
        let r = Resolver::new(cfg(&["u"]), up);
        assert!(r.lookup("empty.example").unwrap_err().to_string().contains("no address"));
        assert_eq!(r.fallbacks(), 0);
    }

    #[test]
    fn local_names_and_doh_failure_use_the_system_resolver() {
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let up: UpstreamFn = Arc::new(move |_, _, _| {
            c.fetch_add(1, Ordering::SeqCst);
            Err("down".into())
        });
        let r = Resolver::new(cfg(&["u"]), up);
        assert!(r.lookup("localhost").unwrap().iter().all(|ip| ip.is_loopback()));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // a public name with DoH down falls back (the answer itself depends on the machine)
        let _ = r.lookup("doh-down.invalid-tld-for-test");
        assert_eq!(r.fallbacks(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn mismatched_answers_are_rejected() {
        let up: UpstreamFn = Arc::new(|_, _, _| {
            let q = dns::build_query("other.example", dns::TYPE_A, 0).unwrap();
            Ok(answer(&q, 0, true))
        });
        let r = Resolver::new(cfg(&["u"]), up);
        let _ = r.lookup("x.example");
        assert_eq!(r.fallbacks(), 1);
        assert_eq!(r.answered(), 0);
    }
}
