//! `sondpi dev`: runs the engine in the foreground for measurements.
//!
//! ```text
//! sondpi dev [--strategy SPEC] [--no-desync] [--no-redial] [--no-dns] [--stall-ms N]
//!            [--max-alts N] [--log FILE] [--stop-file FILE] [--stats-every MS]
//! ```
//! Runs until Ctrl+C or until the stop file appears, then stops cleanly (exit code 0).
//! Exit code 1: the engine could not start; 2: bad arguments; 3: the engine failed while
//! running.

use crate::desync::Strategy;
use crate::engine::{stats_line, Engine, EngineConfig, Logger};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static CTRL_C: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_ctrl(_kind: u32) -> windows_sys::core::BOOL {
    CTRL_C.store(true, Ordering::SeqCst);
    1
}

#[derive(Debug)]
pub struct DevArgs {
    pub cfg: EngineConfig,
    pub stop_file: Option<PathBuf>,
    pub stats_every_ms: u64,
}

pub const USAGE: &str = "usage: sondpi dev [--strategy SPEC] [--no-desync] [--no-redial] [--no-dns] [--stall-ms N] [--max-alts N] [--log FILE] [--stop-file FILE] [--stats-every MS]";

pub fn parse_args(args: &[String]) -> Result<DevArgs, String> {
    let mut cfg = EngineConfig::default();
    let mut stop_file = None;
    let mut stats_every_ms = 10_000;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--strategy" => cfg.strategy = Strategy::from_spec(&val("--strategy")?).map_err(|e| format!("--strategy: {e}"))?,
            "--no-desync" => cfg.desync = false,
            "--no-redial" => cfg.redial = false,
            "--no-dns" => cfg.dns = false,
            "--stall-ms" => {
                let n: u64 = val("--stall-ms")?.parse().map_err(|_| "--stall-ms needs a number")?;
                if n < 20 {
                    return Err("--stall-ms must be at least 20".into());
                }
                cfg.redial_cfg.stall_ms = n;
            }
            "--max-alts" => {
                let n: usize = val("--max-alts")?.parse().map_err(|_| "--max-alts needs a number")?;
                if !(1..=16).contains(&n) {
                    return Err("--max-alts must be 1..16".into());
                }
                cfg.redial_cfg.max_alternates = n;
            }
            "--log" => cfg.log = Some(PathBuf::from(val("--log")?)),
            "--stop-file" => stop_file = Some(PathBuf::from(val("--stop-file")?)),
            "--stats-every" => {
                stats_every_ms = val("--stats-every")?.parse().map_err(|_| "--stats-every needs a number (ms)")?;
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    Ok(DevArgs { cfg, stop_file, stats_every_ms })
}

/// Run the engine in the foreground with the given command-line arguments; returns the
/// process exit code.
pub fn run(args: &[String]) -> i32 {
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let log = match Logger::open(a.cfg.log.as_deref(), true) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot open log file: {e}");
            return 2;
        }
    };
    let c = &a.cfg;
    log.line(&format!(
        "sondpi {} dev: strategy=\"{}\" desync={} redial={} dns={} stall={}ms max_alts={} alt_ports={}-{} stats_every={}ms stop_file={}",
        env!("CARGO_PKG_VERSION"),
        c.strategy.to_spec(),
        c.desync,
        c.redial,
        c.dns,
        c.redial_cfg.stall_ms,
        c.redial_cfg.max_alternates,
        c.redial_cfg.port_lo,
        c.redial_cfg.port_hi,
        a.stats_every_ms,
        a.stop_file.as_ref().map_or("-".to_string(), |p| p.display().to_string()),
    ));
    if let Some(f) = &a.stop_file {
        if f.exists() {
            let _ = std::fs::remove_file(f);
            log.line(&format!("removed stale stop file {}", f.display()));
        }
    }
    // SAFETY: registers a plain function that only stores to an atomic.
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) };

    let engine = match Engine::start_logged(a.cfg.clone(), log.clone()) {
        Ok(e) => e,
        Err(e) => {
            let msg = format!("engine could not start: {e}");
            eprintln!("{msg}");
            return 1;
        }
    };

    let mut last_stats = Instant::now();
    let reason;
    loop {
        std::thread::sleep(Duration::from_millis(100));
        if CTRL_C.load(Ordering::SeqCst) {
            reason = "ctrl+c";
            break;
        }
        if a.stop_file.as_ref().is_some_and(|f| f.exists()) {
            reason = "stop file";
            break;
        }
        if !engine.is_running() {
            reason = "engine failed";
            break;
        }
        if a.stats_every_ms > 0 && last_stats.elapsed() >= Duration::from_millis(a.stats_every_ms) {
            last_stats = Instant::now();
            log.line(&stats_line(&engine.stats()));
        }
    }
    log.line(&format!("stopping ({reason})"));
    let err = engine.error();
    let final_stats = engine.stats();
    engine.stop();
    log.line(&stats_line(&final_stats));
    match err {
        Some(e) => {
            log.line(&format!("exit 3: engine failed: {e}"));
            eprintln!("engine failed: {e}");
            3
        }
        None => {
            log.line("exit 0: stopped cleanly");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_all_options() {
        let a = parse_args(&s(&[
            "--no-desync", "--no-dns", "--stall-ms", "300", "--max-alts", "2", "--log", "x.log", "--stop-file", "stop", "--stats-every", "5000",
        ]))
        .unwrap();
        assert!(!a.cfg.desync && a.cfg.redial && !a.cfg.dns);
        assert_eq!(a.cfg.redial_cfg.stall_ms, 300);
        assert_eq!(a.cfg.redial_cfg.max_alternates, 2);
        assert_eq!(a.cfg.log, Some(PathBuf::from("x.log")));
        assert_eq!(a.stop_file, Some(PathBuf::from("stop")));
        assert_eq!(a.stats_every_ms, 5000);
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(parse_args(&s(&["--bogus"])).is_err());
        assert!(parse_args(&s(&["--stall-ms"])).is_err());
        assert!(parse_args(&s(&["--stall-ms", "abc"])).is_err());
        assert!(parse_args(&s(&["--stall-ms", "5"])).is_err());
        assert!(parse_args(&s(&["--max-alts", "0"])).is_err());
        assert_eq!(parse_args(&[]).unwrap().cfg.redial_cfg.stall_ms, 250);
    }
}
