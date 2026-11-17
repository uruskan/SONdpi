//! The switch behind the menu-bar icon: owns the proxy and the system proxy setting.
//!
//! All slow work (networksetup, the administrator dialog) runs on one worker thread, in the
//! order it was asked for; the UI only sends commands and reads a snapshot. The worker also
//! watches: when the switch is on it re-applies the system setting if it went missing (a new
//! network service, another program changed it) and restarts the proxy if its listener died.

use super::sysproxy;
use crate::proxy::{Proxy, ProxyConfig, ProxyStats};
use crate::resolve::Resolver;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How often the worker checks the proxy and the system setting while the switch is on.
const WATCH_EVERY: Duration = Duration::from_secs(10);
/// Least time between two repairs of the system setting by the watcher. A primary service
/// that never shows our PAC (a VPN with its own proxy settings) must not cause a networksetup
/// storm.
const REPAIR_EVERY: Duration = Duration::from_secs(300);

/// What the menu shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// The switch position.
    pub enabled: bool,
    /// Proxy running and system setting applied.
    pub active: bool,
    /// A change is in progress.
    pub busy: bool,
    pub error: Option<String>,
    pub stats: ProxyStats,
    /// The proxy exists, so the counters mean something.
    pub has_stats: bool,
    pub mascot: bool,
    pub autostart: bool,
}

/// Persisted settings (`ayarlar` in the support folder): `key=value` lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub mascot: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: false, mascot: true }
    }
}

impl Settings {
    pub fn decode(s: &str) -> Settings {
        let mut out = Settings::default();
        for line in s.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "enabled" => out.enabled = v.trim() == "1",
                "mascot" => out.mascot = v.trim() != "0",
                _ => {}
            }
        }
        out
    }
    pub fn encode(&self) -> String {
        format!("enabled={}\nmascot={}\n", self.enabled as u8, self.mascot as u8)
    }
}

/// `~/Library/Application Support/SONdpi`.
pub fn support_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Library/Application Support/SONdpi")
}

fn settings_path(dir: &Path) -> PathBuf {
    dir.join("ayarlar")
}

pub fn load_settings(dir: &Path) -> Settings {
    std::fs::read_to_string(settings_path(dir)).map(|t| Settings::decode(&t)).unwrap_or_default()
}

pub fn save_settings(dir: &Path, s: &Settings) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let p = settings_path(dir);
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, s.encode())?;
    std::fs::rename(tmp, p)
}

/// `scutil --proxy` output: is the primary service's PAC `url`, switched on?
pub fn scutil_has_pac(out: &str, url: &str) -> bool {
    let mut enabled = false;
    let mut found = false;
    for line in out.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim() {
            "ProxyAutoConfigEnable" => enabled = v.trim() == "1",
            "ProxyAutoConfigURLString" => found = v.trim() == url,
            _ => {}
        }
    }
    enabled && found
}

fn primary_has_pac(url: &str) -> bool {
    match Command::new("/usr/sbin/scutil").arg("--proxy").output() {
        Ok(o) => scutil_has_pac(&String::from_utf8_lossy(&o.stdout), url),
        // Cannot tell: do not fight over it.
        Err(_) => true,
    }
}

enum Cmd {
    SetEnabled(bool),
    Shutdown(Sender<()>),
}

struct State {
    proxy: Option<Proxy>,
    settings: Settings,
    applied: bool,
    busy: bool,
    last_repair: Option<Instant>,
    error: Option<String>,
}

pub struct Core {
    dir: PathBuf,
    resolver: Arc<Resolver>,
    state: Mutex<State>,
    tx: Mutex<Sender<Cmd>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Core {
    /// Load the settings, start the worker, and bring the system in line with the saved
    /// switch position (this also repairs what a crash left behind).
    pub fn start(dir: PathBuf, resolver: Arc<Resolver>) -> Arc<Core> {
        let settings = load_settings(&dir);
        let (tx, rx) = mpsc::channel();
        let core = Arc::new(Core {
            dir,
            resolver,
            state: Mutex::new(State { proxy: None, settings, applied: false, busy: true, last_repair: None, error: None }),
            tx: Mutex::new(tx),
        });
        let c = core.clone();
        let _ = std::thread::Builder::new().name("sondpi-core".into()).spawn(move || c.worker(rx));
        let _ = lock(&core.tx).send(Cmd::SetEnabled(settings.enabled));
        core
    }

    pub fn view(&self) -> View {
        let st = lock(&self.state);
        View {
            enabled: st.settings.enabled,
            active: st.applied && st.proxy.as_ref().is_some_and(|p| p.is_running()),
            busy: st.busy,
            error: st.error.clone(),
            stats: st.proxy.as_ref().map(|p| p.stats()).unwrap_or_default(),
            has_stats: st.proxy.is_some(),
            mascot: st.settings.mascot,
            autostart: super::autostart::is_enabled(),
        }
    }

    /// Flip the switch (asynchronously).
    pub fn set_enabled(&self, on: bool) {
        {
            let mut st = lock(&self.state);
            st.busy = true;
            st.settings.enabled = on;
            st.error = None;
        }
        let _ = lock(&self.tx).send(Cmd::SetEnabled(on));
    }

    pub fn set_mascot(&self, on: bool) {
        let mut st = lock(&self.state);
        st.settings.mascot = on;
        let s = st.settings;
        drop(st);
        let _ = save_settings(&self.dir, &s);
    }

    /// Put the system proxy setting back and stop the proxy; waits up to `timeout`. The saved
    /// switch position is kept, so the next start switches on again.
    pub fn shutdown(&self, timeout: Duration) {
        let (tx, rx) = mpsc::channel();
        if lock(&self.tx).send(Cmd::Shutdown(tx)).is_ok() {
            let _ = rx.recv_timeout(timeout);
        }
    }

    fn worker(&self, rx: Receiver<Cmd>) {
        loop {
            match rx.recv_timeout(WATCH_EVERY) {
                Ok(Cmd::SetEnabled(on)) => {
                    // Only the latest of several queued flips matters.
                    let mut on = on;
                    let mut shutdown = None;
                    while let Ok(c) = rx.try_recv() {
                        match c {
                            Cmd::SetEnabled(x) => on = x,
                            Cmd::Shutdown(r) => shutdown = Some(r),
                        }
                    }
                    if let Some(r) = shutdown {
                        self.go_off();
                        let _ = r.send(());
                        return;
                    }
                    if on {
                        self.go_on(true);
                    } else {
                        self.go_off();
                    }
                    let mut st = lock(&self.state);
                    st.busy = false;
                    let s = st.settings;
                    drop(st);
                    let _ = save_settings(&self.dir, &s);
                }
                Ok(Cmd::Shutdown(r)) => {
                    self.go_off();
                    let _ = r.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => self.watch(),
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn pac_url(port: u16) -> String {
        format!("http://127.0.0.1:{port}{}", crate::proxy::PAC_PATH)
    }

    /// Start the proxy if needed; its port.
    fn ensure_proxy(&self) -> io::Result<u16> {
        let mut st = lock(&self.state);
        if let Some(p) = &st.proxy {
            if p.is_running() {
                return Ok(p.addr().port());
            }
        }
        st.proxy = None;
        let mk = |port: u16| {
            let cfg = ProxyConfig { listen: SocketAddr::from(([127, 0, 0, 1], port)), ..ProxyConfig::default() };
            Proxy::start(cfg, self.resolver.clone(), None)
        };
        // The usual port keeps the PAC address stable; any free port will do otherwise.
        let p = mk(super::DEFAULT_PORT).or_else(|_| mk(0))?;
        let port = p.addr().port();
        st.proxy = Some(p);
        Ok(port)
    }

    /// Start the proxy and apply the system setting. On failure a user's flip is undone (the
    /// switch goes back to off and says why); a repair by the watcher only reports.
    fn go_on(&self, revert_on_failure: bool) {
        let r = self.ensure_proxy().and_then(|port| sysproxy::apply(&self.dir, &Self::pac_url(port), revert_on_failure));
        let mut st = lock(&self.state);
        match r {
            Ok(()) => {
                st.applied = true;
                st.error = None;
            }
            Err(e) if !revert_on_failure => {
                st.applied = false;
                st.error = Some(format!("Sistem proxy ayarı yenilenemedi: {e}"));
            }
            Err(e) => {
                // Without the system setting the proxy is of no use: back to off, and say why.
                st.applied = false;
                st.settings.enabled = false;
                st.error = Some(format!("Açılamadı: {e}"));
                let p = st.proxy.take();
                drop(st);
                drop(p);
                if let Err(re) = sysproxy::restore(&self.dir) {
                    lock(&self.state).error = Some(format!("Açılamadı: {e}; eski proxy ayarı da geri yüklenemedi: {re}"));
                }
            }
        }
    }

    fn go_off(&self) {
        let r = sysproxy::restore(&self.dir);
        let mut st = lock(&self.state);
        st.applied = false;
        let p = st.proxy.take();
        if let Err(e) = r {
            st.error = Some(format!("Sistem proxy ayarı geri yüklenemedi: {e}"));
        }
        drop(st);
        drop(p);
    }

    fn watch(&self) {
        let (on, port) = {
            let st = lock(&self.state);
            (st.settings.enabled && !st.busy, st.proxy.as_ref().filter(|p| p.is_running()).map(|p| p.addr().port()))
        };
        if !on {
            return;
        }
        let ok = port.is_some_and(|p| primary_has_pac(&Self::pac_url(p)));
        let due = lock(&self.state).last_repair.is_none_or(|t| t.elapsed() >= REPAIR_EVERY);
        if !ok && (due || port.is_none()) {
            {
                let mut st = lock(&self.state);
                st.busy = true;
                st.last_repair = Some(Instant::now());
            }
            // Without prompting: a repair never shows the administrator dialog.
            self.go_on(false);
            lock(&self.state).busy = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        assert_eq!(Settings::decode(""), Settings::default());
        let s = Settings { enabled: true, mascot: false };
        assert_eq!(Settings::decode(&s.encode()), s);
        assert_eq!(Settings::decode("enabled = 1\nmascot=1\njunk\n"), Settings { enabled: true, mascot: true });
    }

    #[test]
    fn scutil_output() {
        let url = "http://127.0.0.1:18642/proxy.pac";
        let on = format!("<dictionary> {{\n  ExceptionsList : <array> {{\n    0 : *.local\n  }}\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : {url}\n}}\n");
        assert!(scutil_has_pac(&on, url));
        assert!(!scutil_has_pac(&on.replace("Enable : 1", "Enable : 0"), url));
        assert!(!scutil_has_pac(&on, "http://127.0.0.1:1/proxy.pac"));
        assert!(!scutil_has_pac("<dictionary> {\n  FTPPassive : 1\n}\n", url));
    }
}
