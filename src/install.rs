//! Self-install / uninstall, plus the small Win32 helpers (registry, elevation, service control
//! manager) that the other shell modules share.
//!
//! Install touches only: the folder `%ProgramFiles%\SONdpi`, the `SONdpi` service, the
//! `HKLM\SOFTWARE\SONdpi` key and the per-user autostart value. Nothing else on the system.

use crate::api;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_NOT_ACTIVE, FALSE, HANDLE, TRUE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    QueryServiceConfigW, QUERY_SERVICE_CONFIGW, SERVICE_CHANGE_CONFIG, SERVICE_DEMAND_START,
    SERVICE_QUERY_CONFIG,
    CreateServiceW, SC_HANDLE, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    StartServiceW, SC_ACTION, SC_ACTION_RESTART, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG,
    SERVICE_NO_CHANGE, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, SHGetKnownFolderPath, ShellExecuteExW, ShellExecuteW,
    SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IsWindowVisible, MessageBoxW, MB_ICONERROR, MB_OK, SW_HIDE, SW_SHOWNORMAL,
};

/// File name of the installed executable.
pub const EXE_NAME: &str = "sondpi.exe";
/// Per-user autostart key and value name.
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const SUPPORT_FILES: [&str; 2] = ["WinDivert.dll", "WinDivert64.sys"];
const SERVICE_DESCRIPTION: &str =
    "SONdpi: DPI engellerini aşan motoru çalıştırır. Bildirim alanındaki anahtarla açılıp kapatılır.";

// ---------------------------------------------------------------------------------------------
// Strings and command lines
// ---------------------------------------------------------------------------------------------

/// UTF-16, NUL-terminated.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// UTF-16, NUL-terminated, from a path (keeps unpaired surrogates intact).
pub fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// UTF-16 pointer to a NUL-terminated string, to a `String` (lossy).
///
/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: caller promises NUL termination.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: n elements were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// Quote one argument for a Windows command line (CommandLineToArgvW rules).
pub fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"', '\n']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

pub fn join_args<S: AsRef<str>>(args: &[S]) -> String {
    args.iter().map(|a| quote_arg(a.as_ref())).collect::<Vec<_>>().join(" ")
}

/// The service's binary path: the quoted executable plus the `service` role argument.
pub fn service_command_line(exe: &Path) -> String {
    format!("{} service", quote_arg(&exe.to_string_lossy()))
}

/// Value of the per-user autostart entry for the tray.
pub fn autostart_command(exe: &Path) -> String {
    quote_arg(&exe.to_string_lossy())
}

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

/// `%ProgramFiles%` from the shell's known-folder API (environment variable as a fallback).
pub fn program_files() -> PathBuf {
    let mut out: *mut u16 = null_mut();
    // SAFETY: valid GUID pointer, null token, out receives a CoTaskMem string we free below.
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, null_mut(), &mut out) };
    if hr >= 0 && !out.is_null() {
        // SAFETY: the API returned a NUL-terminated string.
        let s = unsafe { from_wide_ptr(out) };
        // SAFETY: allocated by the shell with CoTaskMemAlloc.
        unsafe { CoTaskMemFree(out as *const c_void) };
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    } else if !out.is_null() {
        // SAFETY: as above.
        unsafe { CoTaskMemFree(out as *const c_void) };
    }
    std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
}

pub fn install_dir() -> PathBuf {
    program_files().join(api::INSTALL_DIR_NAME)
}

pub fn installed_exe() -> PathBuf {
    install_dir().join(EXE_NAME)
}

/// Where the autostart entry should point: the installed copy when it exists, else this exe.
pub fn autostart_target() -> PathBuf {
    let inst = installed_exe();
    if inst.is_file() {
        inst
    } else {
        std::env::current_exe().unwrap_or(inst)
    }
}

// ---------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------

struct RegKey(HKEY);
impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: handle came from RegOpen/CreateKeyEx and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn reg_open(root: HKEY, sub: &str, write: bool, create: bool) -> Result<RegKey, u32> {
    let sub = wide(sub);
    let mut h: HKEY = null_mut();
    let rc = if create {
        // SAFETY: valid NUL-terminated key name, out pointers live for the call.
        unsafe {
            RegCreateKeyExW(root, sub.as_ptr(), 0, null(), REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, null(), &mut h, null_mut())
        }
    } else {
        let access = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
        // SAFETY: as above.
        unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, access, &mut h) }
    };
    if rc == 0 {
        Ok(RegKey(h))
    } else {
        Err(rc)
    }
}

fn reg_query(key: &RegKey, name: &str) -> Option<(u32, Vec<u8>)> {
    let name = wide(name);
    let mut ty = 0u32;
    let mut size = 0u32;
    // SAFETY: size query with a null buffer.
    let rc = unsafe { RegQueryValueExW(key.0, name.as_ptr(), null(), &mut ty, null_mut(), &mut size) };
    if rc != 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize + 2];
    let mut size2 = size;
    // SAFETY: buffer has at least `size` bytes.
    let rc = unsafe { RegQueryValueExW(key.0, name.as_ptr(), null(), &mut ty, buf.as_mut_ptr(), &mut size2) };
    if rc != 0 {
        return None;
    }
    buf.truncate(size2 as usize);
    Some((ty, buf))
}

pub fn reg_get_dword(root: HKEY, sub: &str, name: &str) -> Option<u32> {
    let key = reg_open(root, sub, false, false).ok()?;
    let (ty, data) = reg_query(&key, name)?;
    if ty != REG_DWORD || data.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

pub fn reg_set_dword(root: HKEY, sub: &str, name: &str, value: u32) -> Result<(), String> {
    let key = reg_open(root, sub, true, true).map_err(|e| format!("kayıt defteri açılamadı ({e})"))?;
    let name = wide(name);
    let data = value.to_le_bytes();
    // SAFETY: 4 readable bytes for a REG_DWORD.
    let rc = unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_DWORD, data.as_ptr(), 4) };
    if rc == 0 { Ok(()) } else { Err(format!("kayıt defterine yazılamadı ({rc})")) }
}

pub fn reg_get_string(root: HKEY, sub: &str, name: &str) -> Option<String> {
    let key = reg_open(root, sub, false, false).ok()?;
    let (ty, data) = reg_query(&key, name)?;
    if ty != REG_SZ {
        return None;
    }
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    Some(String::from_utf16_lossy(&units[..end]))
}

pub fn reg_set_string(root: HKEY, sub: &str, name: &str, value: &str) -> Result<(), String> {
    let key = reg_open(root, sub, true, true).map_err(|e| format!("kayıt defteri açılamadı ({e})"))?;
    let name = wide(name);
    let v = wide(value);
    // SAFETY: v.len()*2 bytes are readable.
    let rc = unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, v.as_ptr() as *const u8, (v.len() * 2) as u32) };
    if rc == 0 { Ok(()) } else { Err(format!("kayıt defterine yazılamadı ({rc})")) }
}

/// Deleting something that is not there is success.
pub fn reg_delete_value(root: HKEY, sub: &str, name: &str) -> Result<(), String> {
    let key = match reg_open(root, sub, true, false) {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };
    let name = wide(name);
    // SAFETY: valid NUL-terminated name.
    let rc = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
    if rc == 0 || rc == 2 { Ok(()) } else { Err(format!("kayıt değeri silinemedi ({rc})")) }
}

/// Deleting a key that is not there is success.
pub fn reg_delete_tree(root: HKEY, sub: &str) -> Result<(), String> {
    let sub = wide(sub);
    // SAFETY: valid NUL-terminated name.
    let rc = unsafe { RegDeleteTreeW(root, sub.as_ptr()) };
    if rc == 0 || rc == 2 { Ok(()) } else { Err(format!("kayıt anahtarı silinemedi ({rc})")) }
}

// ----- the switch position and the autostart entry built on the helpers -----

/// The persisted switch position (`Enabled` under HKLM); default on.
pub fn read_enabled() -> bool {
    reg_get_dword(HKEY_LOCAL_MACHINE, api::REG_KEY, "Enabled").map(|v| v != 0).unwrap_or(true)
}

pub fn write_enabled(on: bool) -> Result<(), String> {
    reg_set_dword(HKEY_LOCAL_MACHINE, api::REG_KEY, "Enabled", on as u32)
}

pub fn autostart_enabled_in(root: HKEY, sub: &str, name: &str) -> bool {
    reg_get_string(root, sub, name).map(|s| !s.is_empty()).unwrap_or(false)
}

pub fn autostart_set_in(root: HKEY, sub: &str, name: &str, exe: &Path, on: bool) -> Result<(), String> {
    if on {
        reg_set_string(root, sub, name, &autostart_command(exe))
    } else {
        reg_delete_value(root, sub, name)
    }
}

/// Per-user tray autostart (HKCU Run).
pub fn autostart_enabled() -> bool {
    autostart_enabled_in(HKEY_CURRENT_USER, RUN_KEY, api::APP_NAME)
}

pub fn autostart_set(on: bool) -> Result<(), String> {
    autostart_set_in(HKEY_CURRENT_USER, RUN_KEY, api::APP_NAME, &autostart_target(), on)
}

// ---------------------------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------------------------

pub fn is_elevated() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: current-process pseudo handle, out pointer valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    // SAFETY: buffer is exactly one TOKEN_ELEVATION.
    let ok = unsafe {
        GetTokenInformation(token, TokenElevation, &mut elev as *mut _ as *mut c_void, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut ret)
    };
    // SAFETY: token was opened above.
    unsafe { CloseHandle(token) };
    ok != 0 && elev.TokenIsElevated != 0
}

/// Run `exe params` through the shell. `elevated`: the `runas` verb (UAC prompt). With `wait`
/// returns the exit code, else 0 right after launch. Err when the user declined or launch failed.
pub fn shell_run(exe: &Path, params: &str, elevated: bool, wait: bool, hidden: bool) -> Result<u32, String> {
    let verb = wide(if elevated { "runas" } else { "open" });
    let file = wide_path(exe);
    let par = wide(params);
    // SAFETY: all-zero is a valid SHELLEXECUTEINFOW; fields are filled below.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = if wait { SEE_MASK_NOCLOSEPROCESS } else { 0 };
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = par.as_ptr();
    info.nShow = if hidden { SW_HIDE } else { SW_SHOWNORMAL };
    // SAFETY: info and the strings it points to outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        // SAFETY: trivial.
        let e = unsafe { GetLastError() };
        return Err(if e == 1223 { "yönetici onayı verilmedi".to_string() } else { format!("başlatılamadı (hata {e})") });
    }
    if !wait || info.hProcess.is_null() {
        return Ok(0);
    }
    // SAFETY: hProcess was returned because of SEE_MASK_NOCLOSEPROCESS.
    unsafe { WaitForSingleObject(info.hProcess, u32::MAX) };
    let mut code = 1u32;
    // SAFETY: valid process handle, out pointer valid.
    unsafe {
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    Ok(code)
}

fn has_visible_console() -> bool {
    // SAFETY: trivial queries.
    unsafe {
        let w = GetConsoleWindow();
        !w.is_null() && IsWindowVisible(w) != 0
    }
}

pub fn message_box(text: &str, error: bool) {
    let t = wide(text);
    let title = wide(api::APP_NAME);
    // SAFETY: both strings NUL-terminated.
    unsafe { MessageBoxW(null_mut(), t.as_ptr(), title.as_ptr(), MB_OK | if error { MB_ICONERROR } else { 0 }) };
}

// ---------------------------------------------------------------------------------------------
// Service control manager
// ---------------------------------------------------------------------------------------------

pub struct ScHandle(pub SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle from OpenSCManager/OpenService/CreateService, closed once.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn open_scm(access: u32) -> Result<ScHandle, String> {
    // SAFETY: null machine/database names select the local active database.
    let h = unsafe { OpenSCManagerW(null(), null(), access) };
    if h.is_null() {
        // SAFETY: trivial.
        Err(format!("hizmet yöneticisine bağlanılamadı (hata {})", unsafe { GetLastError() }))
    } else {
        Ok(ScHandle(h))
    }
}

fn open_service(scm: &ScHandle, access: u32) -> Option<ScHandle> {
    open_service_named(scm, api::SERVICE_NAME, access).ok()
}

/// Open a service by name; `Err` carries the Win32 error code.
fn open_service_named(scm: &ScHandle, name: &str, access: u32) -> Result<ScHandle, u32> {
    let name = wide(name);
    // SAFETY: valid handle and name.
    let h = unsafe { OpenServiceW(scm.0, name.as_ptr(), access) };
    if h.is_null() {
        // SAFETY: trivial.
        Err(unsafe { GetLastError() })
    } else {
        Ok(ScHandle(h))
    }
}

// ---------------------------------------------------------------------------------------------
// Hand-over from GoodbyeDPI
// ---------------------------------------------------------------------------------------------
//
// Two DPI tools must not run together. On install the `GoodbyeDPI` service (if any) is stopped
// and set to demand start; its original start type and running state are remembered under HKLM
// and put back on uninstall. That service is never deleted or changed in any other way.

pub const GOODBYEDPI_SERVICE: &str = "GoodbyeDPI";
const GDPI_START_VALUE: &str = "GoodbyeDpiStart";
const GDPI_RUNNING_VALUE: &str = "GoodbyeDpiWasRunning";
const START_AUTO: u32 = 2;

/// The state of the GoodbyeDPI service as it was before SONdpi touched it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdpiSaved {
    pub start: u32,
    pub was_running: bool,
}

/// Inputs of the install decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdpiProbe {
    pub present: bool,
    pub start_type: u32,
    /// Running or on its way up/down (anything but stopped).
    pub running: bool,
    /// Values already stored by an earlier install.
    pub stored: Option<GdpiSaved>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdpiInstallPlan {
    /// Remember these (only when nothing is stored yet).
    pub store: Option<GdpiSaved>,
    pub stop: bool,
    /// Switch an automatic service to demand start. Manual and disabled ones stay as they are:
    /// neither comes back at boot.
    pub set_demand: bool,
}

pub fn plan_install_handover(p: &GdpiProbe) -> GdpiInstallPlan {
    if !p.present {
        return GdpiInstallPlan { store: None, stop: false, set_demand: false };
    }
    GdpiInstallPlan {
        store: if p.stored.is_none() { Some(GdpiSaved { start: p.start_type, was_running: p.running }) } else { None },
        stop: p.running,
        set_demand: p.start_type == START_AUTO,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdpiRestorePlan {
    pub set_start: Option<u32>,
    pub start: bool,
}

pub fn plan_restore(present: bool, stored: Option<GdpiSaved>) -> GdpiRestorePlan {
    match (present, stored) {
        (true, Some(s)) => GdpiRestorePlan { set_start: Some(s.start), start: s.was_running },
        _ => GdpiRestorePlan { set_start: None, start: false },
    }
}

fn read_gdpi_saved() -> Option<GdpiSaved> {
    let start = reg_get_dword(HKEY_LOCAL_MACHINE, api::REG_KEY, GDPI_START_VALUE)?;
    let running = reg_get_dword(HKEY_LOCAL_MACHINE, api::REG_KEY, GDPI_RUNNING_VALUE)?;
    Some(GdpiSaved { start, was_running: running != 0 })
}

fn write_gdpi_saved(s: GdpiSaved) -> Result<(), String> {
    reg_set_dword(HKEY_LOCAL_MACHINE, api::REG_KEY, GDPI_START_VALUE, s.start)?;
    reg_set_dword(HKEY_LOCAL_MACHINE, api::REG_KEY, GDPI_RUNNING_VALUE, s.was_running as u32)
}

fn query_start_type(svc: &ScHandle) -> Option<u32> {
    let mut buf = vec![0u64; 1024];
    let mut need = 0u32;
    for _ in 0..2 {
        // SAFETY: buffer of buf.len()*8 bytes, 8-aligned, as QUERY_SERVICE_CONFIGW requires.
        let ok = unsafe { QueryServiceConfigW(svc.0, buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW, (buf.len() * 8) as u32, &mut need) };
        if ok != 0 {
            // SAFETY: the call filled a QUERY_SERVICE_CONFIGW at the start of the buffer.
            return Some(unsafe { (*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW)).dwStartType });
        }
        // SAFETY: trivial.
        if unsafe { GetLastError() } != 122 {
            return None;
        }
        buf = vec![0u64; (need as usize).div_ceil(8) + 1];
    }
    None
}

fn set_start_type(svc: &ScHandle, start: u32) -> Result<(), String> {
    // SAFETY: only the start type is changed; everything else is NO_CHANGE / null.
    let ok = unsafe {
        ChangeServiceConfigW(svc.0, SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE, null(), null(), null_mut(), null(), null(), null(), null())
    };
    if ok == 0 {
        // SAFETY: trivial.
        Err(format!("başlangıç türü değiştirilemedi (hata {})", unsafe { GetLastError() }))
    } else {
        Ok(())
    }
}

const GDPI_ACCESS: u32 = SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP;

/// Install side. Returns the sentence to append to the final message ("" when there was nothing
/// to hand over).
fn handover_install(scm: &ScHandle) -> String {
    let svc = match open_service_named(scm, GOODBYEDPI_SERVICE, GDPI_ACCESS) {
        Ok(s) => s,
        Err(e) if e == ERROR_SERVICE_DOES_NOT_EXIST => return String::new(),
        Err(e) => return gdpi_install_failed(&format!("hizmete erişilemedi, hata {e}")),
    };
    let (Some(start_type), Some((state, _))) = (query_start_type(&svc), query_state(&svc)) else {
        return gdpi_install_failed("durumu okunamadı");
    };
    let stored = read_gdpi_saved();
    let probe = GdpiProbe { present: true, start_type, running: state != SERVICE_STOPPED, stored };
    let plan = plan_install_handover(&probe);
    if let Some(s) = plan.store {
        if let Err(e) = write_gdpi_saved(s) {
            // Without a record we must not change anything.
            return gdpi_install_failed(&format!("özgün ayar kaydedilemedi ({e}), hizmete dokunulmadı"));
        }
    }
    let mut errs: Vec<String> = Vec::new();
    if plan.stop {
        if let Err(e) = stop_service(&svc, Duration::from_secs(15)) {
            errs.push(e);
        }
    }
    if plan.set_demand {
        if let Err(e) = set_start_type(&svc, SERVICE_DEMAND_START) {
            errs.push(e);
        }
    }
    if !errs.is_empty() {
        return gdpi_install_failed(&errs.join("; "));
    }
    if plan.stop || plan.set_demand || stored.is_some() {
        " GoodbyeDPI hizmeti durduruldu; SONdpi kaldırılırsa eski haline döndürülecek.".to_string()
    } else {
        String::new()
    }
}

fn gdpi_install_failed(detail: &str) -> String {
    format!(" Dikkat: GoodbyeDPI hizmeti durdurulamadı ({detail}). İki araç aynı anda çalışmamalı; GoodbyeDPI'yi elle durdurun.")
}

/// Uninstall side. Returns the sentence to append ("" when nothing was stored or the service is gone).
fn handover_restore(scm: &ScHandle) -> String {
    let stored = read_gdpi_saved();
    if stored.is_none() {
        return String::new();
    }
    let svc = match open_service_named(scm, GOODBYEDPI_SERVICE, GDPI_ACCESS) {
        Ok(s) => Some(s),
        Err(e) if e == ERROR_SERVICE_DOES_NOT_EXIST => None,
        Err(e) => return gdpi_restore_failed(&format!("hizmete erişilemedi, hata {e}")),
    };
    let plan = plan_restore(svc.is_some(), stored);
    let Some(svc) = svc else { return String::new() };
    let mut errs: Vec<String> = Vec::new();
    if let Some(st) = plan.set_start {
        if let Err(e) = set_start_type(&svc, st) {
            errs.push(e);
        }
    }
    if plan.start {
        if let Err(e) = start_service(&svc, Duration::from_secs(15)) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        " GoodbyeDPI hizmeti eski haline döndürüldü.".to_string()
    } else {
        gdpi_restore_failed(&errs.join("; "))
    }
}

fn gdpi_restore_failed(detail: &str) -> String {
    format!(" GoodbyeDPI hizmeti eski haline döndürülemedi ({detail}); gerekirse elle ayarlayın.")
}

/// Is the SONdpi service registered with the SCM? Works unelevated.
pub fn service_installed() -> bool {
    match open_scm(SC_MANAGER_CONNECT) {
        Ok(scm) => open_service(&scm, SERVICE_QUERY_STATUS).is_some(),
        Err(_) => false,
    }
}

fn query_state(svc: &ScHandle) -> Option<(u32, u32)> {
    // SAFETY: all-zero is a valid SERVICE_STATUS_PROCESS.
    let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    // SAFETY: buffer size matches the struct.
    let ok = unsafe {
        QueryServiceStatusEx(svc.0, SC_STATUS_PROCESS_INFO, &mut st as *mut _ as *mut u8, std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut needed)
    };
    if ok == 0 { None } else { Some((st.dwCurrentState, st.dwWin32ExitCode)) }
}

fn stop_service(svc: &ScHandle, timeout: Duration) -> Result<(), String> {
    // SAFETY: all-zero is a valid SERVICE_STATUS.
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle and out struct.
    if unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
        // SAFETY: trivial.
        let e = unsafe { GetLastError() };
        if e == ERROR_SERVICE_NOT_ACTIVE {
            return Ok(());
        }
    }
    let end = Instant::now() + timeout;
    loop {
        match query_state(svc) {
            Some((s, _)) if s == SERVICE_STOPPED => return Ok(()),
            None => return Ok(()),
            _ => {}
        }
        if Instant::now() >= end {
            return Err("servis zamanında durmadı".into());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn start_service(svc: &ScHandle, timeout: Duration) -> Result<(), String> {
    // SAFETY: no arguments.
    if unsafe { StartServiceW(svc.0, 0, null()) } == 0 {
        // SAFETY: trivial.
        let e = unsafe { GetLastError() };
        if e != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(format!("servis başlatılamadı (hata {e})"));
        }
    }
    let end = Instant::now() + timeout;
    loop {
        match query_state(svc) {
            Some((s, _)) if s == SERVICE_RUNNING => return Ok(()),
            Some((s, code)) if s == SERVICE_STOPPED => {
                return Err(format!("servis başladıktan hemen sonra durdu (kod {code})"));
            }
            _ => {}
        }
        if Instant::now() >= end {
            return Err("servis zamanında başlamadı".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn configure_extras(svc: &ScHandle) {
    let mut desc = wide(SERVICE_DESCRIPTION);
    let d = SERVICE_DESCRIPTIONW { lpDescription: desc.as_mut_ptr() };
    // SAFETY: d points to a valid SERVICE_DESCRIPTIONW for the call. Failure is cosmetic.
    unsafe { ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, &d as *const _ as *const c_void) };

    let mut actions = [SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5000 }; 3];
    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86400,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: 3,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: fa and its action array live across the call.
    unsafe { ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_FAILURE_ACTIONS, &fa as *const _ as *const c_void) };
    let flag = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: TRUE };
    // SAFETY: flag is valid for the call.
    unsafe { ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag as *const _ as *const c_void) };
}

/// Create the service, or update an existing one in place.
fn create_or_update_service(scm: &ScHandle, exe: &Path) -> Result<(), String> {
    let name = wide(api::SERVICE_NAME);
    let path = wide(&service_command_line(exe));
    if let Some(svc) = open_service(scm, SERVICE_ALL_ACCESS) {
        // SAFETY: valid handle; null leaves the other settings unchanged.
        let ok = unsafe {
            ChangeServiceConfigW(svc.0, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, path.as_ptr(), null(), null_mut(), null(), null(), null(), name.as_ptr())
        };
        if ok == 0 {
            // SAFETY: trivial.
            return Err(format!("servis ayarı güncellenemedi (hata {})", unsafe { GetLastError() }));
        }
        configure_extras(&svc);
        return Ok(());
    }
    // SAFETY: trivial.
    let e = unsafe { GetLastError() };
    if e != ERROR_SERVICE_DOES_NOT_EXIST {
        return Err(format!("servis açılamadı (hata {e})"));
    }
    // SAFETY: null account = LocalSystem; strings outlive the call.
    let h = unsafe {
        CreateServiceW(scm.0, name.as_ptr(), name.as_ptr(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, path.as_ptr(), null(), null_mut(), null(), null(), null())
    };
    if h.is_null() {
        // SAFETY: trivial.
        return Err(format!("servis oluşturulamadı (hata {})", unsafe { GetLastError() }));
    }
    configure_extras(&ScHandle(h));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------

fn is_leftover(name: &str) -> bool {
    match name.rfind(".old") {
        Some(i) => name[i + 4..].chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

fn cleanup_leftovers(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if is_leftover(&e.file_name().to_string_lossy()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Copy `src` over `dst`. A destination that cannot be deleted (a running tray) is renamed aside.
fn copy_replace(src: &Path, dst: &Path) -> Result<(), String> {
    let mut aside: Option<PathBuf> = None;
    if dst.exists() && std::fs::remove_file(dst).is_err() {
        for n in 0..20 {
            let cand = PathBuf::from(format!("{}.old{}", dst.display(), if n == 0 { String::new() } else { n.to_string() }));
            let _ = std::fs::remove_file(&cand);
            if std::fs::rename(dst, &cand).is_ok() {
                aside = Some(cand);
                break;
            }
        }
        if aside.is_none() {
            return Err(format!("{} değiştirilemedi (kullanımda)", dst.display()));
        }
    }
    if let Err(e) = std::fs::copy(src, dst) {
        if let Some(a) = &aside {
            let _ = std::fs::rename(a, dst);
        }
        return Err(format!("{} kopyalanamadı: {e}", dst.display()));
    }
    if let Some(a) = aside {
        let _ = std::fs::remove_file(a);
    }
    Ok(())
}

fn find_support_file(name: &str, exe_dir: &Path) -> Result<PathBuf, String> {
    let mut cands = vec![exe_dir.join(name), exe_dir.join("windivert").join(name)];
    // Developer convenience: a source checkout keeps them under vendor/windivert.
    for anc in exe_dir.ancestors().take(5) {
        cands.push(anc.join("vendor").join("windivert").join(name));
    }
    cands.into_iter().find(|p| p.is_file()).ok_or_else(|| format!("{name} bulunamadı (sondpi.exe ile aynı klasörde olmalı)"))
}

// ---------------------------------------------------------------------------------------------
// Options and result plumbing
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Opts {
    pub no_autostart: bool,
    pub no_tray: bool,
    /// The elevated child writes its final message here for the unelevated parent.
    pub result: Option<PathBuf>,
}

impl Opts {
    pub fn parse(args: &[String]) -> Opts {
        let mut o = Opts::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--no-autostart" => o.no_autostart = true,
                "--no-tray" => o.no_tray = true,
                "--result" => o.result = it.next().map(PathBuf::from),
                _ => {}
            }
        }
        o
    }
}

fn finish(opts: &Opts, r: Result<String, String>) -> i32 {
    let (code, msg) = match r {
        Ok(m) => (0, m),
        Err(m) => (1, m),
    };
    if let Some(p) = &opts.result {
        let _ = std::fs::write(p, &msg);
    } else if code == 0 {
        println!("{msg}");
    } else {
        eprintln!("{msg}");
        if !has_visible_console() {
            message_box(&msg, true);
        }
    }
    code
}

/// Unelevated entry: run the same role elevated, wait, relay its message, then do the
/// per-user parts (autostart, tray) in this, the user's own, context.
fn relaunch_elevated(role: &str, args: &[String], opts: &Opts) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Çalışan dosyanın yolu alınamadı: {e}");
            return 1;
        }
    };
    let result = std::env::temp_dir().join(format!("sondpi-{role}-{}.txt", std::process::id()));
    let mut child: Vec<String> = vec![role.to_string(), "--no-autostart".into(), "--no-tray".into()];
    // Keep nothing else: the known flags are re-added above.
    let _ = args;
    child.push("--result".into());
    child.push(result.to_string_lossy().into_owned());
    let code = match shell_run(&exe, &join_args(&child), true, true, true) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Yönetici onayı alınamadı: {e}");
            return finish(&Opts::default(), Err(msg));
        }
    };
    let msg = std::fs::read_to_string(&result).unwrap_or_default();
    let _ = std::fs::remove_file(&result);
    if code != 0 {
        let m = if msg.is_empty() { format!("İşlem başarısız oldu (kod {code}).") } else { msg };
        return finish(&Opts::default(), Err(m));
    }
    if role == "install" {
        if !opts.no_autostart {
            let _ = autostart_set(true);
        }
        if !opts.no_tray {
            launch_tray_unelevated(&installed_exe());
        }
    }
    finish(&Opts::default(), Ok(msg))
}

/// Start the tray in the logged-in user's normal (unelevated) context via the shell.
fn launch_tray_unelevated(exe: &Path) {
    let verb = wide("open");
    let file = wide("explorer.exe");
    let par = wide(&quote_arg(&exe.to_string_lossy()));
    // SAFETY: strings NUL-terminated and alive for the call; launch failure is not fatal.
    unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), par.as_ptr(), null(), SW_SHOWNORMAL) };
}

// ---------------------------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------------------------

/// Entry point for `sondpi install`; returns the process exit code.
pub fn install(args: &[String]) -> i32 {
    let opts = Opts::parse(args);
    if !is_elevated() {
        return relaunch_elevated("install", args, &opts);
    }
    let r = do_install(&opts);
    finish(&opts, r)
}

fn do_install(opts: &Opts) -> Result<String, String> {
    let src_exe = std::env::current_exe().map_err(|e| format!("Çalışan dosyanın yolu alınamadı: {e}"))?;
    let src_dir = src_exe.parent().ok_or("Çalışan dosyanın klasörü alınamadı")?.to_path_buf();
    let support: Vec<(PathBuf, &str)> = {
        let mut v = Vec::new();
        for n in SUPPORT_FILES {
            v.push((find_support_file(n, &src_dir)?, n));
        }
        v
    };
    let dir = install_dir();
    let dst_exe = installed_exe();
    let scm = open_scm(SC_MANAGER_ALL_ACCESS).map_err(|e| format!("Kurulamadı: {e}"))?;

    // Upgrade in place: stop the running service first.
    if let Some(svc) = open_service(&scm, SERVICE_QUERY_STATUS | SERVICE_STOP) {
        stop_service(&svc, Duration::from_secs(30)).map_err(|e| format!("Kurulamadı: {e}"))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("Klasör oluşturulamadı ({}): {e}", dir.display()))?;
    cleanup_leftovers(&dir);

    let same = match (std::fs::canonicalize(&src_exe), std::fs::canonicalize(&dst_exe)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        copy_replace(&src_exe, &dst_exe)?;
    }
    for (src, name) in &support {
        let dst = dir.join(name);
        let same = matches!((std::fs::canonicalize(src), std::fs::canonicalize(&dst)), (Ok(a), Ok(b)) if a == b);
        if !same {
            copy_replace(src, &dst)?;
        }
    }

    // Hand over from GoodbyeDPI before our engine starts (never fatal).
    let gdpi_note = handover_install(&scm);

    create_or_update_service(&scm, &dst_exe).map_err(|e| format!("Kurulamadı: {e}"))?;
    let svc = open_service(&scm, SERVICE_QUERY_STATUS | SERVICE_START).ok_or("Kurulamadı: servis açılamadı")?;
    start_service(&svc, Duration::from_secs(30)).map_err(|e| format!("Servis kuruldu ama başlamadı: {e}"))?;

    let mut note = String::new();
    if !opts.no_autostart {
        if let Err(e) = autostart_set(true) {
            note = format!(" (Windows açılışında başlatma ayarlanamadı: {e})");
        }
    }
    if !opts.no_tray {
        launch_tray_unelevated(&dst_exe);
    }
    Ok(format!("SONdpi kuruldu ve çalışıyor. Bildirim alanındaki anahtardan açıp kapatabilirsiniz.{note}{gdpi_note}"))
}

// ---------------------------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------------------------

/// Entry point for `sondpi uninstall`; returns the process exit code.
pub fn uninstall(args: &[String]) -> i32 {
    let opts = Opts::parse(args);
    if !is_elevated() {
        return relaunch_elevated("uninstall", args, &opts);
    }
    let r = do_uninstall(&opts);
    finish(&opts, r)
}

fn image_path_of(pid: u32) -> Option<(PathBuf, HANDLE)> {
    // SAFETY: plain query/terminate access to another process; failure just skips it.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: buffer length passed in `len`.
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        // SAFETY: handle opened above.
        unsafe { CloseHandle(h) };
        return None;
    }
    Some((PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])), h))
}

/// Terminate other processes running an executable from `dir` (a tray holding the file open).
fn kill_processes_in(dir: &Path) {
    // SAFETY: snapshot of processes; handle closed below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() || snap as isize == -1 {
        return;
    }
    // SAFETY: all-zero is valid; dwSize must be set.
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: snapshot handle and struct are valid.
    let mut more = unsafe { Process32FirstW(snap, &mut pe) } != 0;
    // SAFETY: trivial.
    let me = unsafe { GetCurrentProcessId() };
    let want = dir.to_string_lossy().to_lowercase();
    while more {
        if pe.th32ProcessID != me {
            if let Some((path, h)) = image_path_of(pe.th32ProcessID) {
                let p = path.to_string_lossy().to_lowercase();
                if p.starts_with(&want) && p[want.len()..].starts_with('\\') {
                    // SAFETY: handle has PROCESS_TERMINATE.
                    unsafe {
                        TerminateProcess(h, 0);
                        WaitForSingleObject(h, 3000);
                    }
                }
                // SAFETY: handle opened by image_path_of.
                unsafe { CloseHandle(h) };
            }
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap, &mut pe) } != 0;
    }
    // SAFETY: snapshot handle from above.
    unsafe { CloseHandle(snap) };
}

fn remove_with_retries(p: &Path) -> bool {
    for _ in 0..15 {
        match std::fs::remove_file(p) {
            Ok(()) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    false
}

fn schedule_delete_on_reboot(p: &Path) {
    let w = wide_path(p);
    // SAFETY: valid path; null destination = delete at reboot (needs admin, which we have).
    unsafe { MoveFileExW(w.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

/// Detached helper that deletes our own exe and the folder once this process has exited.
fn spawn_delayed_cleanup(exe: &Path, dir: &Path) {
    let line = delayed_cleanup_line(exe, dir);
    let _ = std::process::Command::new("cmd.exe")
        .raw_arg("/d /s /c")
        .raw_arg(format!("\"{line}\""))
        .creation_flags(0x0800_0000 | 0x0000_0008) // CREATE_NO_WINDOW | DETACHED_PROCESS
        .spawn();
}

pub fn delayed_cleanup_line(exe: &Path, dir: &Path) -> String {
    format!(
        "ping -n 4 127.0.0.1 >nul & del /f /q \"{}\" & rmdir \"{}\"",
        exe.display(),
        dir.display()
    )
}

fn do_uninstall(opts: &Opts) -> Result<String, String> {
    let dir = install_dir();
    // Never delete anything but the folder we own.
    if dir.file_name().map(|n| n != api::INSTALL_DIR_NAME).unwrap_or(true) {
        return Err("Kurulum klasörü doğrulanamadı; hiçbir şey silinmedi.".into());
    }
    let mut problems: Vec<String> = Vec::new();
    let mut gdpi_note = String::new();

    if let Ok(scm) = open_scm(SC_MANAGER_ALL_ACCESS) {
        if let Some(svc) = open_service(&scm, SERVICE_QUERY_STATUS | SERVICE_STOP | 0x0001_0000 /* DELETE */) {
            if let Err(e) = stop_service(&svc, Duration::from_secs(30)) {
                problems.push(e);
            }
            // SAFETY: valid handle with DELETE access.
            if unsafe { DeleteService(svc.0) } == 0 {
                // SAFETY: trivial.
                let e = unsafe { GetLastError() };
                if e != 1072 {
                    // 1072 = already marked for deletion
                    problems.push(format!("servis silinemedi (hata {e})"));
                }
            }
        }
        // SONdpi is stopped and gone: give GoodbyeDPI back (before the registry record is removed).
        gdpi_note = handover_restore(&scm);
    }

    kill_processes_in(&dir);
    if !opts.no_autostart {
        let _ = autostart_set(false);
    }
    if let Err(e) = reg_delete_tree(HKEY_LOCAL_MACHINE, api::REG_KEY) {
        problems.push(e);
    }

    let me = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok());
    let mut deferred_self: Option<PathBuf> = None;
    let mut at_reboot = false;
    if dir.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let _ = std::fs::remove_dir_all(&p);
                    continue;
                }
                if remove_with_retries(&p) {
                    continue;
                }
                let is_me = match (&me, std::fs::canonicalize(&p)) {
                    (Some(m), Ok(c)) => *m == c,
                    _ => false,
                };
                if is_me {
                    deferred_self = Some(p);
                } else {
                    schedule_delete_on_reboot(&p);
                    at_reboot = true;
                }
            }
        }
        if let Some(p) = &deferred_self {
            spawn_delayed_cleanup(p, &dir);
        } else if std::fs::remove_dir(&dir).is_err() {
            schedule_delete_on_reboot(&dir);
            at_reboot = true;
        }
    }

    if !problems.is_empty() {
        return Err(format!("Kaldırma tamamlanamadı: {}.{gdpi_note}", problems.join("; ")));
    }
    let mut msg = String::from("SONdpi kaldırıldı.");
    if at_reboot {
        msg.push_str(" Bazı dosyalar bilgisayar yeniden başlatılınca silinecek.");
    }
    msg.push_str(&gdpi_note);
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote_arg("abc"), "abc");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg(r"C:\Program Files\SONdpi\sondpi.exe"), "\"C:\\Program Files\\SONdpi\\sondpi.exe\"");
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_arg(r"dir with space\"), "\"dir with space\\\\\"");
        assert_eq!(join_args(&["install", "--result", r"C:\a b\r.txt"]), "install --result \"C:\\a b\\r.txt\"");
    }

    #[test]
    fn command_lines() {
        let exe = Path::new(r"C:\Program Files\SONdpi\sondpi.exe");
        assert_eq!(service_command_line(exe), "\"C:\\Program Files\\SONdpi\\sondpi.exe\" service");
        assert_eq!(autostart_command(exe), "\"C:\\Program Files\\SONdpi\\sondpi.exe\"");
        let l = delayed_cleanup_line(exe, exe.parent().unwrap());
        assert!(l.contains("del /f /q \"C:\\Program Files\\SONdpi\\sondpi.exe\""));
        assert!(l.ends_with("rmdir \"C:\\Program Files\\SONdpi\""));
    }

    fn probe(present: bool, start: u32, running: bool, stored: Option<GdpiSaved>) -> GdpiProbe {
        GdpiProbe { present, start_type: start, running, stored }
    }

    #[test]
    fn handover_absent_changes_nothing() {
        let p = plan_install_handover(&probe(false, 2, true, None));
        assert_eq!(p, GdpiInstallPlan { store: None, stop: false, set_demand: false });
        // Even a stale record does not make us act on a missing service.
        let p = plan_install_handover(&probe(false, 0, false, Some(GdpiSaved { start: 2, was_running: true })));
        assert_eq!(p, GdpiInstallPlan { store: None, stop: false, set_demand: false });
    }

    #[test]
    fn handover_auto_running_first_install() {
        let p = plan_install_handover(&probe(true, 2, true, None));
        assert_eq!(p, GdpiInstallPlan { store: Some(GdpiSaved { start: 2, was_running: true }), stop: true, set_demand: true });
    }

    #[test]
    fn handover_auto_but_stopped() {
        let p = plan_install_handover(&probe(true, 2, false, None));
        assert_eq!(p, GdpiInstallPlan { store: Some(GdpiSaved { start: 2, was_running: false }), stop: false, set_demand: true });
    }

    #[test]
    fn handover_disabled_and_manual_keep_their_start_type() {
        let p = plan_install_handover(&probe(true, 4, false, None));
        assert_eq!(p, GdpiInstallPlan { store: Some(GdpiSaved { start: 4, was_running: false }), stop: false, set_demand: false });
        let p = plan_install_handover(&probe(true, 3, true, None));
        assert_eq!(p, GdpiInstallPlan { store: Some(GdpiSaved { start: 3, was_running: true }), stop: true, set_demand: false });
    }

    #[test]
    fn handover_upgrade_never_overwrites_the_original() {
        let orig = GdpiSaved { start: 2, was_running: true };
        // We left it manual and stopped last time: the record must stay as it was.
        let p = plan_install_handover(&probe(true, 3, false, Some(orig)));
        assert_eq!(p, GdpiInstallPlan { store: None, stop: false, set_demand: false });
        // The user started it again meanwhile: stop it again, still keep the record.
        let p = plan_install_handover(&probe(true, 3, true, Some(orig)));
        assert_eq!(p, GdpiInstallPlan { store: None, stop: true, set_demand: false });
        // Someone put it back to automatic.
        let p = plan_install_handover(&probe(true, 2, true, Some(orig)));
        assert_eq!(p, GdpiInstallPlan { store: None, stop: true, set_demand: true });
    }

    #[test]
    fn restore_branches() {
        let s = GdpiSaved { start: 2, was_running: true };
        assert_eq!(plan_restore(true, Some(s)), GdpiRestorePlan { set_start: Some(2), start: true });
        let s = GdpiSaved { start: 2, was_running: false };
        assert_eq!(plan_restore(true, Some(s)), GdpiRestorePlan { set_start: Some(2), start: false });
        let s = GdpiSaved { start: 4, was_running: false };
        assert_eq!(plan_restore(true, Some(s)), GdpiRestorePlan { set_start: Some(4), start: false });
        // Service removed meanwhile, or nothing stored: do nothing.
        let s = GdpiSaved { start: 2, was_running: true };
        assert_eq!(plan_restore(false, Some(s)), GdpiRestorePlan { set_start: None, start: false });
        assert_eq!(plan_restore(true, None), GdpiRestorePlan { set_start: None, start: false });
        assert_eq!(plan_restore(false, None), GdpiRestorePlan { set_start: None, start: false });
    }

    #[test]
    fn paths() {
        let d = install_dir();
        assert_eq!(d.file_name().unwrap(), api::INSTALL_DIR_NAME);
        assert_eq!(installed_exe().file_name().unwrap(), EXE_NAME);
    }

    #[test]
    fn option_parsing() {
        let a: Vec<String> = ["--no-tray", "--result", r"C:\t\r.txt", "--other"].iter().map(|s| s.to_string()).collect();
        let o = Opts::parse(&a);
        assert!(o.no_tray && !o.no_autostart);
        assert_eq!(o.result, Some(PathBuf::from(r"C:\t\r.txt")));
        assert_eq!(Opts::parse(&[]), Opts::default());
    }

    #[test]
    fn leftover_names() {
        assert!(is_leftover("sondpi.exe.old"));
        assert!(is_leftover("sondpi.exe.old12"));
        assert!(!is_leftover("sondpi.exe"));
        assert!(!is_leftover("my.older"));
    }

    fn test_key() -> String {
        format!(r"Software\SONdpi-test-{}", std::process::id())
    }

    #[test]
    fn registry_roundtrip_hkcu() {
        let key = test_key();
        assert_eq!(reg_get_dword(HKEY_CURRENT_USER, &key, "Enabled"), None);
        reg_set_dword(HKEY_CURRENT_USER, &key, "Enabled", 0).unwrap();
        assert_eq!(reg_get_dword(HKEY_CURRENT_USER, &key, "Enabled"), Some(0));
        reg_set_dword(HKEY_CURRENT_USER, &key, "Enabled", 1).unwrap();
        assert_eq!(reg_get_dword(HKEY_CURRENT_USER, &key, "Enabled"), Some(1));
        reg_set_string(HKEY_CURRENT_USER, &key, "S", "çay \"x\"").unwrap();
        assert_eq!(reg_get_string(HKEY_CURRENT_USER, &key, "S").as_deref(), Some("çay \"x\""));
        assert_eq!(reg_get_dword(HKEY_CURRENT_USER, &key, "S"), None);
        reg_delete_value(HKEY_CURRENT_USER, &key, "S").unwrap();
        reg_delete_value(HKEY_CURRENT_USER, &key, "S").unwrap();
        assert_eq!(reg_get_string(HKEY_CURRENT_USER, &key, "S"), None);
        reg_delete_tree(HKEY_CURRENT_USER, &key).unwrap();
        reg_delete_tree(HKEY_CURRENT_USER, &key).unwrap();
        assert_eq!(reg_get_dword(HKEY_CURRENT_USER, &key, "Enabled"), None);
    }

    #[test]
    fn autostart_entry_hkcu() {
        let key = test_key() + "-run";
        let exe = Path::new(r"C:\Program Files\SONdpi\sondpi.exe");
        assert!(!autostart_enabled_in(HKEY_CURRENT_USER, &key, "SONdpi"));
        autostart_set_in(HKEY_CURRENT_USER, &key, "SONdpi", exe, true).unwrap();
        assert!(autostart_enabled_in(HKEY_CURRENT_USER, &key, "SONdpi"));
        assert_eq!(
            reg_get_string(HKEY_CURRENT_USER, &key, "SONdpi").unwrap(),
            "\"C:\\Program Files\\SONdpi\\sondpi.exe\""
        );
        autostart_set_in(HKEY_CURRENT_USER, &key, "SONdpi", exe, false).unwrap();
        assert!(!autostart_enabled_in(HKEY_CURRENT_USER, &key, "SONdpi"));
        reg_delete_tree(HKEY_CURRENT_USER, &key).unwrap();
    }
}

