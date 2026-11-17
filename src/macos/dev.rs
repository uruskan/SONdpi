//! `sondpi dev`: the proxy in the foreground, logging every connection, for measurements.
//! Touches no system setting; point clients at it by hand (`curl -x`, `--socks5-hostname`).

use crate::proxy::{Proxy, ProxyConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const USAGE: &str = "usage: sondpi dev [--port N] [--no-desync] [--gap MS] [--quiet]";

pub fn run(args: &[String]) -> i32 {
    let mut cfg = ProxyConfig { listen: SocketAddr::from(([127, 0, 0, 1], super::DEFAULT_PORT)), ..ProxyConfig::default() };
    let mut quiet = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => match it.next().and_then(|v| v.parse().ok()) {
                Some(p) => cfg.listen.set_port(p),
                None => return usage(),
            },
            "--gap" => match it.next().and_then(|v| v.parse().ok()) {
                Some(g) => cfg.gap_ms = g,
                None => return usage(),
            },
            "--no-desync" => cfg.desync = false,
            "--quiet" => quiet = true,
            _ => return usage(),
        }
    }
    let t0 = Instant::now();
    let log: Option<crate::proxy::LogFn> = if quiet {
        None
    } else {
        Some(Arc::new(move |line: &str| eprintln!("{:>9.3} {line}", t0.elapsed().as_secs_f64())))
    };
    let proxy = match Proxy::start(cfg.clone(), super::new_resolver(), log) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sondpi dev: cannot listen on {}: {e}", cfg.listen);
            return 1;
        }
    };
    println!("SONdpi proxy on {} (desync {}, gap {} ms)", proxy.addr(), if cfg.desync { "on" } else { "off" }, cfg.gap_ms);
    println!("PAC: http://{}{}", proxy.addr(), crate::proxy::PAC_PATH);
    loop {
        std::thread::sleep(Duration::from_secs(10));
        let s = proxy.stats();
        println!(
            "stats: accepted {} active {} desynced {} rescued {} failed {} dns {} (system {})",
            s.accepted, s.active, s.desynced, s.rescued, s.failed, s.dns_answered, s.dns_fallbacks
        );
        if !proxy.is_running() {
            eprintln!("sondpi dev: listener stopped");
            return 1;
        }
    }
}

fn usage() -> i32 {
    eprintln!("{USAGE}");
    2
}
