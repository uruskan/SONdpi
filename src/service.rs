//! Windows service host for the engine, and its console twin for development.
//!
//! `sondpi service`                   started by the Service Control Manager
//! `sondpi service --console`         same pipe server in the foreground (real engine; needs admin)
//! `sondpi service --console --mock`  fake engine, runs unelevated; for exercising the tray

use crate::api::{self, EngineControl, Status};
use crate::engine::{Controller, EngineConfig};
use crate::install::{read_enabled, wide, write_enabled};
use crate::ipc::{Server, StopSignal};
use std::ffi::c_void;
use std::io::Write;
use std::panic::AssertUnwindSafe;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR, TRUE};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};

/// How long the engine may take to shut down before the service reports stopped anyway.
const ENGINE_STOP_BUDGET: Duration = Duration::from_secs(15);

static STOP: OnceLock<StopSignal> = OnceLock::new();
static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);
static STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);
static CONSOLE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------------------------

fn log_path() -> Option<std::path::PathBuf> {
    Some(std::env::current_exe().ok()?.parent()?.join("service.log"))
}

/// Console mode: stderr. Service mode: `service.log` next to the executable (best effort).
pub fn log(msg: &str) {
    if CONSOLE.load(Ordering::Relaxed) {
        eprintln!("{msg}");
        return;
    }
    let Some(p) = log_path() else { return };
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "[{secs}] {msg}");
    }
}

fn trim_log() {
    if let Some(p) = log_path() {
        if std::fs::metadata(&p).map(|m| m.len() > 256 * 1024).unwrap_or(false) {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The switch with a persisted position
// ---------------------------------------------------------------------------------------------

/// Where the switch position lives between runs.
pub trait Store: Send + Sync {
    fn get(&self) -> bool;
    fn set(&self, on: bool) -> Result<(), String>;
}

/// `HKLM\SOFTWARE\SONdpi\Enabled` (DWORD, default on).
pub struct RegistryStore;
impl Store for RegistryStore {
    fn get(&self) -> bool {
        read_enabled()
    }
    fn set(&self, on: bool) -> Result<(), String> {
        write_enabled(on)
    }
}

pub struct MemoryStore(AtomicBool);
impl MemoryStore {
    pub fn new(on: bool) -> MemoryStore {
        MemoryStore(AtomicBool::new(on))
    }
}
impl Store for MemoryStore {
    fn get(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    fn set(&self, on: bool) -> Result<(), String> {
        self.0.store(on, Ordering::SeqCst);
        Ok(())
    }
}

/// Wraps an engine switch: every successful flip is persisted, the persisted position is applied
/// at start, and shutdown turns the engine off without touching the persisted position.
pub struct Persisting {
    inner: Arc<dyn EngineControl>,
    store: Arc<dyn Store>,
    /// Serialises flips; `true` once the service is shutting down.
    closed: Mutex<bool>,
}

impl Persisting {
    pub fn new(inner: Arc<dyn EngineControl>, store: Arc<dyn Store>) -> Persisting {
        Persisting { inner, store, closed: Mutex::new(false) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, bool> {
        self.closed.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Put the engine in the persisted position (called once at start).
    pub fn apply_persisted(&self) {
        let closed = self.lock();
        if *closed {
            return;
        }
        if self.store.get() {
            if let Err(e) = self.inner.set_enabled(true) {
                log(&format!("kayıtlı konum uygulanamadı (açık): {e}"));
            }
        }
    }

    /// Turn the engine off for good; the persisted position stays as it was.
    pub fn shutdown(&self) {
        let mut closed = self.lock();
        *closed = true;
        if let Err(e) = self.inner.set_enabled(false) {
            log(&format!("motor kapatılamadı: {e}"));
        }
    }
}

impl EngineControl for Persisting {
    fn set_enabled(&self, on: bool) -> Result<(), String> {
        let closed = self.lock();
        if *closed {
            return Err("servis kapanıyor".into());
        }
        self.inner.set_enabled(on)?;
        if let Err(e) = self.store.set(on) {
            // The switch did flip; only the memory of it failed.
            log(&format!("anahtar konumu kaydedilemedi: {e}"));
        }
        Ok(())
    }
    fn status(&self) -> Status {
        self.inner.status()
    }
}

// ---------------------------------------------------------------------------------------------
// Fake engine for development
// ---------------------------------------------------------------------------------------------

struct MockState {
    enabled: AtomicBool,
    desynced: AtomicU64,
    redialed: AtomicU64,
    dns: AtomicU64,
    fail_on: bool,
}

/// In-memory switch whose counters tick while it is on.
pub struct MockControl(Arc<MockState>);

impl MockControl {
    /// `fail_on`: turning it on fails with an error (to see the tray's problem state).
    pub fn new(fail_on: bool) -> MockControl {
        let st = Arc::new(MockState {
            enabled: AtomicBool::new(false),
            desynced: AtomicU64::new(0),
            redialed: AtomicU64::new(0),
            dns: AtomicU64::new(0),
            fail_on,
        });
        let weak: Weak<MockState> = Arc::downgrade(&st);
        let _ = std::thread::Builder::new().name("sondpi-mock".into()).spawn(move || {
            let mut n = 0u64;
            while let Some(s) = weak.upgrade() {
                if s.enabled.load(Ordering::SeqCst) {
                    n += 1;
                    s.desynced.fetch_add(3, Ordering::SeqCst);
                    s.dns.fetch_add(2, Ordering::SeqCst);
                    if n % 4 == 0 {
                        s.redialed.fetch_add(1, Ordering::SeqCst);
                    }
                }
                drop(s);
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        MockControl(st)
    }
}

impl EngineControl for MockControl {
    fn set_enabled(&self, on: bool) -> Result<(), String> {
        if on && self.0.fail_on {
            return Err("sürücü yüklenemedi (deneme hatası)".into());
        }
        self.0.enabled.store(on, Ordering::SeqCst);
        Ok(())
    }
    fn status(&self) -> Status {
        let on = self.0.enabled.load(Ordering::SeqCst);
        Status {
            enabled: on,
            active: on,
            strategy: "sahte".into(),
            desynced: self.0.desynced.load(Ordering::SeqCst),
            redialed: self.0.redialed.load(Ordering::SeqCst),
            dns_answered: self.0.dns.load(Ordering::SeqCst),
            error: if self.0.fail_on && !on { Some("sürücü yüklenemedi (deneme hatası)".into()) } else { None },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Hosting
// ---------------------------------------------------------------------------------------------

/// Run the pipe server around `ctl` until `stop`; returns the process exit code.
fn host(ctl: Arc<Persisting>, stop: &StopSignal, on_ready: impl FnOnce()) -> u32 {
    let server = match Server::start(ctl.clone(), stop) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("boru sunucusu başlamadı: {e}"));
            return 1;
        }
    };
    on_ready();
    let applier = ctl.clone();
    let _ = std::thread::Builder::new().name("sondpi-apply".into()).spawn(move || applier.apply_persisted());
    server.join();
    // Turn the engine off, but never let a stuck engine hold the SCM hostage.
    let (tx, rx) = std::sync::mpsc::channel();
    let down = ctl.clone();
    let spawned = std::thread::Builder::new().name("sondpi-shutdown".into()).spawn(move || {
        down.shutdown();
        let _ = tx.send(());
    });
    if spawned.is_err() || rx.recv_timeout(ENGINE_STOP_BUDGET).is_err() {
        log("motor zamanında kapanmadı; servis yine de duruyor");
    }
    0
}

fn real_or_mock(mock: bool, fail: bool) -> Arc<Persisting> {
    if mock {
        Arc::new(Persisting::new(Arc::new(MockControl::new(fail)), Arc::new(MemoryStore::new(true))))
    } else {
        let engine: Arc<dyn EngineControl> = Arc::new(Controller::new(EngineConfig::default()));
        Arc::new(Persisting::new(engine, Arc::new(RegistryStore)))
    }
}

unsafe extern "system" fn console_ctrl(_kind: u32) -> i32 {
    if let Some(s) = STOP.get() {
        s.stop();
    }
    TRUE
}

fn run_console(mock: bool, fail: bool) -> i32 {
    CONSOLE.store(true, Ordering::Relaxed);
    let Some(stop) = STOP.get() else { return 1 };
    // SAFETY: the handler only signals an event.
    unsafe { SetConsoleCtrlHandler(Some(console_ctrl), TRUE) };
    let ctl = real_or_mock(mock, fail);
    eprintln!(
        "SONdpi servisi konsol kipinde{}; boru: {}. Ctrl+C ile durdurulur.",
        if mock { " (sahte motor)" } else { "" },
        api::PIPE_NAME
    );
    let code = host(ctl, stop, || eprintln!("hazır"));
    eprintln!("durdu");
    code as i32
}

fn report(state: u32, exit_code: u32, wait_hint: u32) {
    let h = STATUS_HANDLE.load(Ordering::SeqCst);
    if h == 0 {
        return;
    }
    STATE.store(state, Ordering::SeqCst);
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if pending { CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1 } else { 0 },
        dwWaitHint: wait_hint,
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and lives for the process.
    unsafe { SetServiceStatus(h as _, &st) };
}

unsafe extern "system" fn control_handler(control: u32, _event: u32, _data: *mut c_void, _ctx: *mut c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0, 30_000);
            if let Some(s) = STOP.get() {
                s.stop();
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            report(STATE.load(Ordering::SeqCst), 0, 10_000);
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name = wide(api::SERVICE_NAME);
    // SAFETY: valid NUL-terminated name and a handler that stays valid.
    let h = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), null()) };
    if (h as usize) == 0 {
        return;
    }
    STATUS_HANDLE.store(h as usize, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0, 15_000);
    trim_log();
    let Some(stop) = STOP.get() else {
        report(SERVICE_STOPPED, 1, 0);
        return;
    };
    let code = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let ctl = real_or_mock(false, false);
        host(ctl, stop, || report(SERVICE_RUNNING, 0, 0))
    }))
    .unwrap_or_else(|_| {
        log("servis beklenmedik bir hatayla durdu");
        1
    });
    report(SERVICE_STOPPED, code, 0);
}

/// Entry point for `sondpi service` (started by the Service Control Manager); returns the
/// process exit code.
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    let stop = match StopSignal::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let _ = STOP.set(stop);
    if has("--console") {
        return run_console(has("--mock") || has("--mock-fail"), has("--mock-fail"));
    }
    let mut name = wide(api::SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table is terminated by a null entry and outlives the (blocking) call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        eprintln!("Bu komutu Windows başlatır. Geliştirme için: sondpi service --console [--mock]");
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Probe {
        on: AtomicBool,
        fail: AtomicBool,
        calls: Mutex<Vec<bool>>,
    }
    impl Probe {
        fn new() -> Arc<Probe> {
            Arc::new(Probe { on: AtomicBool::new(false), fail: AtomicBool::new(false), calls: Mutex::new(vec![]) })
        }
    }
    impl EngineControl for Probe {
        fn set_enabled(&self, on: bool) -> Result<(), String> {
            self.calls.lock().unwrap().push(on);
            if self.fail.load(Ordering::SeqCst) {
                return Err("başarısız".into());
            }
            self.on.store(on, Ordering::SeqCst);
            Ok(())
        }
        fn status(&self) -> Status {
            Status { enabled: self.on.load(Ordering::SeqCst), ..Default::default() }
        }
    }

    #[test]
    fn flips_are_persisted() {
        let probe = Probe::new();
        let store = Arc::new(MemoryStore::new(true));
        let p = Persisting::new(probe.clone(), store.clone());
        p.set_enabled(false).unwrap();
        assert!(!store.get());
        p.set_enabled(true).unwrap();
        assert!(store.get());
        probe.fail.store(true, Ordering::SeqCst);
        assert!(p.set_enabled(false).is_err());
        assert!(store.get(), "a failed flip must not be remembered");
    }

    #[test]
    fn persisted_position_is_applied_and_shutdown_keeps_it() {
        let probe = Probe::new();
        let store = Arc::new(MemoryStore::new(true));
        let p = Persisting::new(probe.clone(), store.clone());
        p.apply_persisted();
        assert!(probe.on.load(Ordering::SeqCst));
        p.shutdown();
        assert!(!probe.on.load(Ordering::SeqCst));
        assert!(store.get(), "shutdown keeps the persisted position");
        assert!(p.set_enabled(true).is_err(), "no flips after shutdown");
        p.apply_persisted();
        assert!(!probe.on.load(Ordering::SeqCst));

        let probe = Probe::new();
        let off = Persisting::new(probe.clone(), Arc::new(MemoryStore::new(false)));
        off.apply_persisted();
        assert!(!probe.on.load(Ordering::SeqCst));
        assert!(probe.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn mock_counts_while_enabled() {
        let m = MockControl::new(false);
        assert_eq!(m.status().desynced, 0);
        m.set_enabled(true).unwrap();
        std::thread::sleep(Duration::from_millis(700));
        let s = m.status();
        assert!(s.enabled && s.active && s.desynced > 0 && s.dns_answered > 0);
        m.set_enabled(false).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let a = m.status().desynced;
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(m.status().desynced, a);
        let f = MockControl::new(true);
        assert!(f.set_enabled(true).is_err());
        assert!(f.status().error.is_some());
    }
}
