//! Connection racing for the proxy: Happy Eyeballs order plus re-dial of lost SYNs.
//!
//! On the measured line a few percent of IPv4 SYNs to Cloudflare are never answered, and the
//! operating system's own retransmissions of that SYN stay unanswered too (the loss sticks to
//! the flow; see CLAUDE.md). The packet engine on Windows re-sends such a SYN from another
//! source port. A user-space dialer gets the same effect by opening a second socket (a new
//! source port) when the first has not connected after [`DialConfig::stall_ms`], and keeping
//! whichever connects first. The same schedule walks the addresses in Happy Eyeballs order
//! (RFC 8305: families interleaved), so a host with a broken IPv6 path costs one stall, not a
//! timeout.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialConfig {
    /// Time without a connection before the next attempt starts. Normal connections on the
    /// measured line take 60-110 ms; the Windows engine re-dials after 250 ms as well.
    pub stall_ms: u64,
    /// Attempts in total, first one included, across all addresses.
    pub max_attempts: usize,
    /// Give up after this long.
    pub timeout_ms: u64,
}

impl Default for DialConfig {
    fn default() -> Self {
        DialConfig { stall_ms: 250, max_attempts: 6, timeout_ms: 10_000 }
    }
}

/// A connected stream and how it was won.
#[derive(Debug)]
pub struct Dialed<T> {
    pub stream: T,
    /// Index of the winning attempt; 0 means the first attempt won.
    pub attempt: usize,
    /// Attempts started.
    pub started: usize,
}

impl<T> Dialed<T> {
    /// True when the first attempt did not win: a re-dial (or the other address family) saved
    /// the connection.
    pub fn rescued(&self) -> bool {
        self.attempt > 0
    }
}

/// RFC 8305 order: the family of the first address first, then alternating, each family in
/// its original order. Duplicates are dropped.
pub fn order(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut uniq: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !uniq.contains(a) {
            uniq.push(*a);
        }
    }
    let Some(first) = uniq.first() else { return uniq };
    let first_v6 = first.is_ipv6();
    let (mut a, mut b): (Vec<SocketAddr>, Vec<SocketAddr>) = uniq.into_iter().partition(|x| x.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(a.len() + b.len());
    a.reverse();
    b.reverse();
    loop {
        match (a.pop(), b.pop()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

/// Errors after which an address is not tried again.
fn is_hard(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    !matches!(e.kind(), TimedOut | WouldBlock | Interrupted)
}

/// Dial `addrs` with a real TCP connect.
pub fn connect(addrs: &[SocketAddr], cfg: &DialConfig) -> io::Result<Dialed<TcpStream>> {
    connect_with(addrs, cfg, Arc::new(|a: SocketAddr, t: Duration| TcpStream::connect_timeout(&a, t)))
}

/// Attempt function: (address, time left) -> connection. Must give up within the time given.
pub type AttemptFn<T> = Arc<dyn Fn(SocketAddr, Duration) -> io::Result<T> + Send + Sync>;

/// The racing schedule over any attempt function (tests use fakes).
///
/// Attempt `k` starts when attempt `k-1` has been running for `stall_ms` without a winner, or
/// right away when an attempt fails. Each attempt takes the next address in [`order`] that
/// has not failed hard (refused, unreachable...), wrapping around, so a single address is
/// re-dialled from fresh sockets. The first attempt to connect wins; attempts that finish
/// later are dropped (their connections closed) on their own threads.
pub fn connect_with<T: Send + 'static>(addrs: &[SocketAddr], cfg: &DialConfig, attempt: AttemptFn<T>) -> io::Result<Dialed<T>> {
    let order = order(addrs);
    if order.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to"));
    }
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_millis(cfg.timeout_ms);
    let stall = Duration::from_millis(cfg.stall_ms.max(1));
    let max_attempts = cfg.max_attempts.max(1);
    let (tx, rx) = mpsc::channel::<(usize, usize, io::Result<T>)>();
    let mut dead = vec![false; order.len()];
    let mut next_addr = 0usize;
    let mut started = 0usize;
    let mut pending = 0usize;
    let mut next_start = t0;
    let mut last_err: Option<io::Error> = None;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out"));
        }
        let alive = (0..order.len()).map(|k| (next_addr + k) % order.len()).find(|&i| !dead[i]);
        if started < max_attempts && now >= next_start {
            if let Some(i) = alive {
                let (tx, f, addr, k, left) = (tx.clone(), attempt.clone(), order[i], started, deadline - now);
                let spawned = std::thread::Builder::new()
                    .name("sondpi-dial".into())
                    .stack_size(128 * 1024)
                    .spawn(move || {
                        // A send error means the race is over; dropping the result closes it.
                        let _ = tx.send((k, i, f(addr, left)));
                    });
                match spawned {
                    Ok(_) => pending += 1,
                    Err(e) => last_err = Some(e),
                }
                started += 1;
                next_addr = i + 1;
                next_start = now + stall;
            }
        }
        let more = started < max_attempts && (0..order.len()).any(|i| !dead[i]);
        if pending == 0 && !more {
            return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection timed out")));
        }
        let until = if more { next_start.min(deadline) } else { deadline };
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok((k, _, Ok(stream))) => return Ok(Dialed { stream, attempt: k, started }),
            Ok((_, i, Err(e))) => {
                pending -= 1;
                if is_hard(&e) {
                    dead[i] = true;
                }
                last_err = Some(e);
                if pending == 0 {
                    // Nothing else is in flight: do not wait out the stall.
                    next_start = Instant::now();
                }
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn happy_eyeballs_order() {
        let v = [a("[::1]:1"), a("[::2]:1"), a("1.1.1.1:1"), a("[::1]:1"), a("2.2.2.2:1"), a("3.3.3.3:1")];
        assert_eq!(order(&v), vec![a("[::1]:1"), a("1.1.1.1:1"), a("[::2]:1"), a("2.2.2.2:1"), a("3.3.3.3:1")]);
        let w = [a("1.1.1.1:1"), a("[::1]:1")];
        assert_eq!(order(&w), vec![a("1.1.1.1:1"), a("[::1]:1")]);
        assert!(order(&[]).is_empty());
    }

    /// Fake attempt: per address, a list of (delay ms, ok) outcomes consumed in turn.
    fn fake(script: Vec<(SocketAddr, Vec<(u64, bool)>)>) -> (AttemptFn<SocketAddr>, Arc<Mutex<Vec<SocketAddr>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(script));
        let l2 = log.clone();
        let f: AttemptFn<SocketAddr> = Arc::new(move |addr, left| {
            l2.lock().unwrap().push(addr);
            let (delay, ok) = {
                let mut s = state.lock().unwrap();
                let e = s.iter_mut().find(|(x, _)| *x == addr).expect("unknown address");
                if e.1.is_empty() {
                    (10_000, true)
                } else {
                    e.1.remove(0)
                }
            };
            if Duration::from_millis(delay) > left {
                std::thread::sleep(left);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "t"));
            }
            std::thread::sleep(Duration::from_millis(delay));
            if ok {
                Ok(addr)
            } else {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
            }
        });
        (f, log)
    }

    fn cfg(stall: u64, max: usize, timeout: u64) -> DialConfig {
        DialConfig { stall_ms: stall, max_attempts: max, timeout_ms: timeout }
    }

    #[test]
    fn first_attempt_wins_when_quick() {
        let (f, log) = fake(vec![(a("1.1.1.1:443"), vec![(5, true)])]);
        let d = connect_with(&[a("1.1.1.1:443")], &cfg(100, 4, 2000), f).unwrap();
        assert_eq!((d.stream, d.attempt, d.started, d.rescued()), (a("1.1.1.1:443"), 0, 1, false));
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn lost_syn_is_redialled_on_the_same_address() {
        let x = a("1.1.1.1:443");
        let (f, log) = fake(vec![(x, vec![(5000, true), (10, true)])]);
        let t = Instant::now();
        let d = connect_with(&[x], &cfg(50, 4, 3000), f).unwrap();
        assert!(d.rescued());
        assert_eq!(d.attempt, 1);
        assert!(t.elapsed() < Duration::from_millis(1000), "{:?}", t.elapsed());
        assert_eq!(*log.lock().unwrap(), vec![x, x]);
    }

    #[test]
    fn stalled_family_falls_back_to_the_other() {
        let (v6, v4) = (a("[2001:db8::1]:443"), a("192.0.2.1:443"));
        let (f, _) = fake(vec![(v6, vec![(5000, true)]), (v4, vec![(10, true)])]);
        let d = connect_with(&[v6, v4], &cfg(50, 4, 3000), f).unwrap();
        assert_eq!(d.stream, v4);
        assert_eq!(d.attempt, 1);
    }

    #[test]
    fn refused_addresses_are_skipped_and_reported() {
        let (x, y) = (a("192.0.2.1:443"), a("192.0.2.2:443"));
        let (f, log) = fake(vec![(x, vec![(1, false)]), (y, vec![(1, false)])]);
        let t = Instant::now();
        let e = connect_with(&[x, y], &cfg(1000, 6, 5000), f).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        assert!(t.elapsed() < Duration::from_millis(500));
        assert_eq!(*log.lock().unwrap(), vec![x, y]);
    }

    #[test]
    fn refused_then_next_starts_immediately() {
        let (x, y) = (a("192.0.2.1:443"), a("192.0.2.2:443"));
        let (f, _) = fake(vec![(x, vec![(1, false)]), (y, vec![(1, true)])]);
        let t = Instant::now();
        let d = connect_with(&[x, y], &cfg(1000, 6, 5000), f).unwrap();
        assert_eq!(d.stream, y);
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn gives_up_at_the_deadline_and_respects_max_attempts() {
        let x = a("192.0.2.1:443");
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let f: AttemptFn<()> = Arc::new(move |_, left| {
            c2.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(left);
            Err(io::Error::new(io::ErrorKind::TimedOut, "t"))
        });
        let t = Instant::now();
        let e = connect_with(&[x], &cfg(20, 3, 300), f).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        let el = t.elapsed();
        assert!(el >= Duration::from_millis(290) && el < Duration::from_millis(1000), "{el:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn real_connect_to_local_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let d = connect(&[addr], &DialConfig::default()).unwrap();
        assert_eq!(d.stream.peer_addr().unwrap(), addr);
        drop(l);
        // nothing listens there any more: refused, fast
        let t = Instant::now();
        assert!(connect(&[addr], &DialConfig::default()).is_err());
        // Windows retries a refused loopback SYN for about 2 s before reporting it.
        let limit = if cfg!(windows) { 5 } else { 2 };
        assert!(t.elapsed() < Duration::from_secs(limit));
    }
}
