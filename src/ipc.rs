//! Named-pipe control channel between the tray (client, unelevated) and the service (server).
//!
//! Protocol: UTF-8 lines over a byte-mode pipe. A client sends one request line (`status`, `on`
//! or `off`) and reads one reply line. The server keeps reading further request lines from the
//! same connection until the client closes it or stays idle for 5 s.
//!
//! Reply: `ok <key>=<value> ...` or `err <message>`. Keys (all always present except `error`):
//! `enabled` and `active` (`0`/`1`), `strategy` (escaped), `desynced`, `redialed`,
//! `dns_answered` (decimal), `error` (escaped; absent means `None`). Values are percent-escaped
//! (`%XX` for every byte <= 0x20, `%`, `=` and 0x7f), so a value never contains a space, `=`
//! or line break. Unknown keys are ignored by the decoder.

use crate::api::{self, EngineControl, Status};
use crate::install::{from_wide_ptr, wide};
use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_ANONYMOUS,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, ResetEvent, SetEvent,
    WaitForMultipleObjects, WaitForSingleObject,
};

/// Pipe instances served at once, so a slow client cannot block the others.
const INSTANCES: usize = 4;
const MAX_LINE: usize = 16 * 1024;
const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------------------------
// Encoding (pure logic)
// ---------------------------------------------------------------------------------------------

/// Percent-escape so the result has no space, `=`, control character or line break.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() && (c as u32 <= 0x20 || c == '%' || c == '=' || c as u32 == 0x7f) {
            out.push_str(&format!("%{:02X}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

pub fn unescape(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or("bozuk kaçış dizisi")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "bozuk kaçış dizisi".to_string())?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "geçersiz UTF-8".to_string())
}

pub fn encode_status(s: &Status) -> String {
    let mut line = format!(
        "ok enabled={} active={} strategy={} desynced={} redialed={} dns_answered={}",
        s.enabled as u8,
        s.active as u8,
        escape(&s.strategy),
        s.desynced,
        s.redialed,
        s.dns_answered
    );
    if let Some(e) = &s.error {
        line.push_str(" error=");
        line.push_str(&escape(e));
    }
    line
}

pub fn encode_err(msg: &str) -> String {
    let flat: String = msg.chars().map(|c| if c == '\r' || c == '\n' { ' ' } else { c }).collect();
    format!("err {flat}")
}

/// Why a request did not produce a [`Status`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReqError {
    /// The pipe does not exist or could not be opened: the service is not running.
    Unreachable(String),
    /// No reply in time.
    Timeout,
    /// The service answered `err <message>`.
    Service(String),
    /// Anything else (broken reply, I/O error).
    Protocol(String),
}

impl std::fmt::Display for ReqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReqError::Unreachable(m) | ReqError::Service(m) | ReqError::Protocol(m) => f.write_str(m),
            ReqError::Timeout => f.write_str("servis yanıt vermedi"),
        }
    }
}

pub fn decode_reply(line: &str) -> Result<Status, ReqError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(m) = line.strip_prefix("err ") {
        return Err(ReqError::Service(m.to_string()));
    }
    if line == "err" {
        return Err(ReqError::Service(String::new()));
    }
    let body = line.strip_prefix("ok").ok_or_else(|| ReqError::Protocol(format!("anlaşılmayan yanıt: {line}")))?;
    let mut st = Status::default();
    for tok in body.split(' ').filter(|t| !t.is_empty()) {
        let (k, v) = tok.split_once('=').ok_or_else(|| ReqError::Protocol(format!("bozuk alan: {tok}")))?;
        let num = |v: &str| v.parse::<u64>().map_err(|_| ReqError::Protocol(format!("bozuk sayı: {tok}")));
        match k {
            "enabled" => st.enabled = v == "1",
            "active" => st.active = v == "1",
            "strategy" => st.strategy = unescape(v).map_err(ReqError::Protocol)?,
            "desynced" => st.desynced = num(v)?,
            "redialed" => st.redialed = num(v)?,
            "dns_answered" => st.dns_answered = num(v)?,
            "error" => st.error = Some(unescape(v).map_err(ReqError::Protocol)?),
            _ => {}
        }
    }
    Ok(st)
}

/// Turn one request line into one reply line.
fn handle_line(line: &str, ctl: &dyn EngineControl) -> String {
    let run = || match line.trim() {
        "status" => encode_status(&ctl.status()),
        "on" | "off" => {
            let on = line.trim() == "on";
            match ctl.set_enabled(on) {
                Ok(()) => encode_status(&ctl.status()),
                Err(e) => encode_err(&e),
            }
        }
        other => encode_err(&format!("bilinmeyen komut: {}", other.chars().take(32).collect::<String>())),
    };
    std::panic::catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|_| encode_err("iç hata"))
}

// ---------------------------------------------------------------------------------------------
// Win32 plumbing
// ---------------------------------------------------------------------------------------------

struct Event(HANDLE);
// SAFETY: an event handle may be used and closed from any thread.
unsafe impl Send for Event {}
// SAFETY: SetEvent/Wait on the same handle from several threads is allowed.
unsafe impl Sync for Event {}
impl Event {
    fn new(manual_reset: bool) -> Result<Event, String> {
        // SAFETY: no security attributes, no name.
        let h = unsafe { CreateEventW(null(), manual_reset as i32, 0, null()) };
        if h.is_null() {
            // SAFETY: trivial.
            Err(format!("olay nesnesi oluşturulamadı (hata {})", unsafe { GetLastError() }))
        } else {
            Ok(Event(h))
        }
    }
}
impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: handle created in `new`, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Raw handle that may move to a worker thread.
struct SendHandle(HANDLE);
// SAFETY: a pipe handle is just a kernel object reference.
unsafe impl Send for SendHandle {}

/// Tells [`serve`] / [`Server`] to stop. Cheap to clone; safe to call from any thread, also from
/// a service control handler.
#[derive(Clone)]
pub struct StopSignal(Arc<Event>);

impl StopSignal {
    pub fn new() -> Result<StopSignal, String> {
        Ok(StopSignal(Arc::new(Event::new(true)?)))
    }
    pub fn stop(&self) {
        // SAFETY: valid event handle.
        unsafe { SetEvent(self.0 .0) };
    }
    pub fn is_stopped(&self) -> bool {
        // SAFETY: valid event handle; zero timeout polls.
        unsafe { WaitForSingleObject(self.0 .0, 0) == WAIT_OBJECT_0 }
    }
    /// Sleep up to `d`; true when the stop signal fired meanwhile.
    fn sleep(&self, d: Duration) -> bool {
        // SAFETY: valid event handle.
        unsafe { WaitForSingleObject(self.0 .0, d.as_millis().min(u32::MAX as u128 - 1) as u32) == WAIT_OBJECT_0 }
    }
}

#[derive(Debug)]
enum IoErr {
    Timeout,
    Stopped,
    Eof,
    TooLong,
    Os(u32),
}

fn remaining_ms(deadline: Option<Instant>) -> u32 {
    match deadline {
        None => u32::MAX,
        Some(d) => d.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128 - 1) as u32,
    }
}

/// Wait for the overlapped operation `ov` started on `h`; cancel it on timeout or stop.
fn finish_overlapped(h: HANDLE, ov: &mut OVERLAPPED, stop: Option<&StopSignal>, deadline: Option<Instant>) -> Result<usize, IoErr> {
    let handles = [ov.hEvent, stop.map(|s| s.0 .0).unwrap_or(null_mut())];
    let count = if stop.is_some() { 2 } else { 1 };
    // SAFETY: `handles` holds `count` valid handles.
    let r = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, remaining_ms(deadline)) };
    let outcome = if r == WAIT_OBJECT_0 {
        None
    } else if r == WAIT_OBJECT_0 + 1 {
        Some(IoErr::Stopped)
    } else if r == WAIT_TIMEOUT {
        Some(IoErr::Timeout)
    } else {
        // SAFETY: trivial.
        Some(IoErr::Os(unsafe { GetLastError() }))
    };
    let mut n = 0u32;
    if let Some(e) = outcome {
        // SAFETY: cancel then wait for the cancelled operation so `ov` can be released.
        unsafe {
            CancelIoEx(h, ov);
            GetOverlappedResult(h, ov, &mut n, 1);
        }
        return Err(e);
    }
    // SAFETY: the operation has completed.
    if unsafe { GetOverlappedResult(h, ov, &mut n, 0) } == 0 {
        // SAFETY: trivial.
        let e = unsafe { GetLastError() };
        return Err(if e == ERROR_BROKEN_PIPE || e == 233 { IoErr::Eof } else { IoErr::Os(e) });
    }
    Ok(n as usize)
}

fn new_overlapped(ev: &Event) -> OVERLAPPED {
    // SAFETY: all-zero is a valid OVERLAPPED.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.0;
    // SAFETY: valid event handle.
    unsafe { ResetEvent(ev.0) };
    ov
}

fn read_some(h: HANDLE, ev: &Event, buf: &mut [u8], stop: Option<&StopSignal>, deadline: Option<Instant>) -> Result<usize, IoErr> {
    let mut ov = new_overlapped(ev);
    let mut n = 0u32;
    // SAFETY: buf and ov outlive the operation (finish_overlapped waits or cancels).
    let ok = unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, &mut ov) };
    if ok != 0 {
        return Ok(n as usize);
    }
    // SAFETY: trivial.
    let e = unsafe { GetLastError() };
    if e == ERROR_IO_PENDING {
        finish_overlapped(h, &mut ov, stop, deadline)
    } else if e == ERROR_BROKEN_PIPE || e == 233 {
        Err(IoErr::Eof)
    } else {
        Err(IoErr::Os(e))
    }
}

fn read_line(h: HANDLE, ev: &Event, carry: &mut Vec<u8>, stop: Option<&StopSignal>, deadline: Option<Instant>) -> Result<String, IoErr> {
    loop {
        if let Some(i) = carry.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = carry.drain(..=i).collect();
            return Ok(String::from_utf8_lossy(&line[..line.len() - 1]).trim_end_matches('\r').to_string());
        }
        if carry.len() > MAX_LINE {
            return Err(IoErr::TooLong);
        }
        let mut buf = [0u8; 1024];
        match read_some(h, ev, &mut buf, stop, deadline) {
            Ok(0) => return Err(IoErr::Eof),
            Ok(n) => carry.extend_from_slice(&buf[..n]),
            Err(IoErr::Eof) if !carry.is_empty() => {
                // The peer closed without a final newline: take what we have.
                let line = String::from_utf8_lossy(carry).to_string();
                carry.clear();
                return Ok(line);
            }
            Err(e) => return Err(e),
        }
    }
}

fn write_all(h: HANDLE, ev: &Event, mut data: &[u8], stop: Option<&StopSignal>, deadline: Option<Instant>) -> Result<(), IoErr> {
    while !data.is_empty() {
        let mut ov = new_overlapped(ev);
        let mut n = 0u32;
        // SAFETY: data and ov outlive the operation.
        let ok = unsafe { WriteFile(h, data.as_ptr(), data.len() as u32, &mut n, &mut ov) };
        let written = if ok != 0 {
            n as usize
        } else {
            // SAFETY: trivial.
            let e = unsafe { GetLastError() };
            if e == ERROR_IO_PENDING {
                finish_overlapped(h, &mut ov, stop, deadline)?
            } else if e == ERROR_BROKEN_PIPE || e == 232 || e == 233 {
                return Err(IoErr::Eof);
            } else {
                return Err(IoErr::Os(e));
            }
        };
        if written == 0 {
            return Err(IoErr::Eof);
        }
        data = &data[written..];
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------------

/// Security descriptor: SYSTEM, Administrators and the creating account get everything;
/// interactive users get read/write data but not the right to create further pipe instances
/// (so nobody else can stand up a look-alike server); nothing for network clients.
struct Descriptor(PSECURITY_DESCRIPTOR);
// SAFETY: the descriptor is immutable after creation.
unsafe impl Send for Descriptor {}
// SAFETY: as above.
unsafe impl Sync for Descriptor {}
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

pub fn pipe_sddl(extra_sid: Option<&str>) -> String {
    let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)");
    if let Some(sid) = extra_sid {
        s.push_str(&format!("(A;;GA;;;{sid})"));
    }
    s
}

fn current_user_sid_string() -> Option<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: current-process pseudo handle, valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut need = 0u32;
    // SAFETY: size query.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut need) };
    let mut buf = vec![0u64; (need as usize).div_ceil(8).max(8)];
    // SAFETY: buffer of at least `need` bytes, 8-aligned.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, (buf.len() * 8) as u32, &mut need) };
    // SAFETY: token opened above.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return None;
    }
    // SAFETY: the buffer now holds a TOKEN_USER.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut s: *mut u16 = null_mut();
    // SAFETY: sid points into `buf`, still alive.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 || s.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated string allocated by the API.
    let out = unsafe { from_wide_ptr(s) };
    // SAFETY: allocated with LocalAlloc by the API.
    unsafe { LocalFree(s as *mut c_void) };
    Some(out)
}

fn build_descriptor() -> Result<Descriptor, String> {
    let sddl = wide(&pipe_sddl(current_user_sid_string().as_deref()));
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: valid SDDL string and out pointer.
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) };
    if ok == 0 {
        // SAFETY: trivial.
        return Err(format!("boru güvenlik tanımı kurulamadı (hata {})", unsafe { GetLastError() }));
    }
    Ok(Descriptor(sd))
}

fn create_instance(name: &[u16], first: bool, sd: &Descriptor) -> Result<HANDLE, u32> {
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: 0 };
    let mut open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: name is NUL-terminated; sa and its descriptor outlive the call.
    let h = unsafe {
        CreateNamedPipeW(name.as_ptr(), open, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, INSTANCES as u32, 4096, 4096, 0, &sa)
    };
    if h == INVALID_HANDLE_VALUE {
        // SAFETY: trivial.
        Err(unsafe { GetLastError() })
    } else {
        Ok(h)
    }
}

/// A running pipe server. It stops when its [`StopSignal`] fires; [`Server::join`] waits for that.
pub struct Server {
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Server {
    /// Create the pipe (failing if another server already owns the name) and start serving.
    pub fn start(ctl: Arc<dyn EngineControl>, stop: &StopSignal) -> Result<Server, String> {
        Server::start_on(api::PIPE_NAME, ctl, stop)
    }

    pub fn start_on(pipe_name: &str, ctl: Arc<dyn EngineControl>, stop: &StopSignal) -> Result<Server, String> {
        let name: Arc<Vec<u16>> = Arc::new(wide(pipe_name));
        let sd = Arc::new(build_descriptor()?);
        let first = create_instance(&name, true, &sd).map_err(|e| {
            if e == 5 || e == 231 {
                "kontrol borusu zaten başka bir SONdpi servisi tarafından kullanılıyor".to_string()
            } else {
                format!("kontrol borusu oluşturulamadı (hata {e})")
            }
        })?;
        let mut first = Some(SendHandle(first));
        let mut threads = Vec::new();
        for i in 0..INSTANCES {
            let (ctl, stop_c, name, sd) = (ctl.clone(), stop.clone(), name.clone(), sd.clone());
            let h = first.take();
            let t = std::thread::Builder::new().name(format!("sondpi-pipe-{i}")).spawn(move || instance_loop(h, &name, &sd, ctl, stop_c));
            match t {
                Ok(t) => threads.push(t),
                Err(e) => {
                    stop.stop();
                    for t in threads {
                        let _ = t.join();
                    }
                    return Err(format!("boru iş parçacığı başlatılamadı: {e}"));
                }
            }
        }
        Ok(Server { threads })
    }

    /// Block until the server has stopped (the stop signal fired and all clients are done).
    pub fn join(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// Serve `ctl` on [`api::PIPE_NAME`] until `stop` fires.
pub fn serve(ctl: Arc<dyn EngineControl>, stop: &StopSignal) -> Result<(), String> {
    Server::start(ctl, stop)?.join();
    Ok(())
}

fn instance_loop(first: Option<SendHandle>, name: &[u16], sd: &Descriptor, ctl: Arc<dyn EngineControl>, stop: StopSignal) {
    let ev = match Event::new(true) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut pipe: Option<HANDLE> = first.map(|h| h.0);
    while !stop.is_stopped() {
        let h = match pipe.take() {
            Some(h) => h,
            None => match create_instance(name, false, sd) {
                Ok(h) => h,
                Err(_) => {
                    if stop.sleep(Duration::from_millis(300)) {
                        break;
                    }
                    continue;
                }
            },
        };
        let mut ov = new_overlapped(&ev);
        // SAFETY: h is a valid overlapped pipe handle; ov outlives the wait below.
        let ok = unsafe { ConnectNamedPipe(h, &mut ov) };
        let connected = if ok != 0 {
            true
        } else {
            // SAFETY: trivial.
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => true,
                ERROR_IO_PENDING => match finish_overlapped(h, &mut ov, Some(&stop), None) {
                    Ok(_) => true,
                    Err(IoErr::Stopped) => {
                        // SAFETY: handle created by this thread.
                        unsafe { CloseHandle(h) };
                        break;
                    }
                    Err(_) => false,
                },
                _ => false,
            }
        };
        if !connected {
            // SAFETY: handle created by this thread; recreate on the next round.
            unsafe { CloseHandle(h) };
            if stop.sleep(Duration::from_millis(100)) {
                break;
            }
            continue;
        }
        serve_client(h, &ev, &*ctl, &stop);
        // SAFETY: disconnect then reuse the instance for the next client.
        unsafe { DisconnectNamedPipe(h) };
        pipe = Some(h);
    }
    if let Some(h) = pipe {
        // SAFETY: handle created by this thread.
        unsafe { CloseHandle(h) };
    }
}

fn serve_client(h: HANDLE, ev: &Event, ctl: &dyn EngineControl, stop: &StopSignal) {
    let mut carry = Vec::new();
    loop {
        let line = match read_line(h, ev, &mut carry, Some(stop), Some(Instant::now() + SERVER_IO_TIMEOUT)) {
            Ok(l) => l,
            Err(_) => return,
        };
        let mut reply = handle_line(&line, ctl);
        reply.push('\n');
        if write_all(h, ev, reply.as_bytes(), Some(stop), Some(Instant::now() + SERVER_IO_TIMEOUT)).is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// Send `cmd` (`status`, `on`, `off`) and return the resulting status. `timeout_ms` covers the
/// whole exchange. Used by the tray.
pub fn request(cmd: &str, timeout_ms: u32) -> Result<Status, String> {
    request_ex(cmd, timeout_ms).map_err(|e| e.to_string())
}

/// Like [`request`] but says why it failed.
pub fn request_ex(cmd: &str, timeout_ms: u32) -> Result<Status, ReqError> {
    request_on(api::PIPE_NAME, cmd, timeout_ms)
}

pub fn request_on(pipe_name: &str, cmd: &str, timeout_ms: u32) -> Result<Status, ReqError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    let name = wide(pipe_name);
    let h = loop {
        // SAFETY: NUL-terminated name; anonymous impersonation so the server cannot act as us.
        let h = unsafe {
            CreateFileW(name.as_ptr(), FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 0, null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, null_mut())
        };
        if h != INVALID_HANDLE_VALUE {
            break h;
        }
        // SAFETY: trivial.
        let e = unsafe { GetLastError() };
        if e == ERROR_PIPE_BUSY {
            let left = remaining_ms(Some(deadline));
            if left == 0 {
                return Err(ReqError::Timeout);
            }
            // SAFETY: valid name; waits for a free instance.
            unsafe { WaitNamedPipeW(name.as_ptr(), left.min(500)) };
            continue;
        }
        return Err(if e == ERROR_FILE_NOT_FOUND {
            ReqError::Unreachable("servis çalışmıyor".into())
        } else {
            ReqError::Unreachable(format!("servise bağlanılamadı (hata {e})"))
        });
    };
    let result = (|| {
        let ev = Event::new(true).map_err(ReqError::Protocol)?;
        let map = |e: IoErr| match e {
            IoErr::Timeout => ReqError::Timeout,
            IoErr::Eof => ReqError::Protocol("servis bağlantıyı kapattı".into()),
            IoErr::TooLong => ReqError::Protocol("yanıt çok uzun".into()),
            IoErr::Stopped => ReqError::Protocol("durduruldu".into()),
            IoErr::Os(c) => ReqError::Protocol(format!("boru hatası ({c})")),
        };
        write_all(h, &ev, format!("{cmd}\n").as_bytes(), None, Some(deadline)).map_err(map)?;
        let mut carry = Vec::new();
        let line = read_line(h, &ev, &mut carry, None, Some(deadline)).map_err(map)?;
        decode_reply(&line)
    })();
    // SAFETY: handle opened above.
    unsafe { CloseHandle(h) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn awkward() -> Vec<String> {
        vec![
            String::new(),
            "a b".into(),
            "x=y=z".into(),
            "100% sure%".into(),
            "satır\nsonu\r\nve\tsekme".into(),
            "çay şeker ğüşiöç İI 日本語 🙂".into(),
            "%41 %zz = ".into(),
            "\u{0}\u{1}\u{7f}".into(),
            " ".into(),
            "ok err".into(),
        ]
    }

    #[test]
    fn escape_roundtrip() {
        for s in awkward() {
            let e = escape(&s);
            assert!(!e.contains([' ', '=', '\n', '\r', '\t']), "{e:?}");
            assert_eq!(unescape(&e).unwrap(), s);
        }
        assert!(unescape("%").is_err());
        assert!(unescape("%4").is_err());
        assert!(unescape("%GG").is_err());
        assert!(unescape("%FF").is_err());
    }

    #[test]
    fn status_roundtrip() {
        for s in awkward() {
            for err in [None, Some(s.clone())] {
                let st = Status { enabled: true, active: false, strategy: s.clone(), desynced: u64::MAX, redialed: 7, dns_answered: 0, error: err };
                let line = encode_status(&st);
                assert!(!line.contains('\n'));
                assert_eq!(decode_reply(&line).unwrap(), st);
            }
        }
        let d = Status::default();
        assert_eq!(decode_reply(&encode_status(&d)).unwrap(), d);
    }

    #[test]
    fn reply_edge_cases() {
        assert_eq!(decode_reply("err boom\r\n"), Err(ReqError::Service("boom".into())));
        assert_eq!(decode_reply(&encode_err("a\nb")), Err(ReqError::Service("a b".into())));
        assert!(matches!(decode_reply("hello"), Err(ReqError::Protocol(_))));
        assert!(matches!(decode_reply("ok enabled"), Err(ReqError::Protocol(_))));
        assert!(matches!(decode_reply("ok desynced=x"), Err(ReqError::Protocol(_))));
        // Unknown keys are ignored.
        assert_eq!(decode_reply("ok enabled=1 future=zzz").unwrap().enabled, true);
    }

    #[test]
    fn sddl_has_no_network_grant() {
        let s = pipe_sddl(Some("S-1-5-21-1-2-3-1001"));
        assert!(s.starts_with("D:P("));
        assert!(s.contains("(A;;GA;;;SY)") && s.contains("(A;;GA;;;BA)") && s.contains(";;;IU)"));
        assert!(s.ends_with("(A;;GA;;;S-1-5-21-1-2-3-1001)"));
        assert!(!s.contains(";;;WD") && !s.contains(";;;NU"));
        assert!(build_descriptor().is_ok());
    }

    struct Mock {
        on: AtomicBool,
        calls: AtomicU64,
    }
    impl EngineControl for Mock {
        fn set_enabled(&self, on: bool) -> Result<(), String> {
            if on && self.calls.load(Ordering::SeqCst) == 99 {
                return Err("sürücü\nyok = hata".into());
            }
            self.on.store(on, Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn status(&self) -> Status {
            let on = self.on.load(Ordering::SeqCst);
            Status { enabled: on, active: on, strategy: "fake ttl=8".into(), desynced: self.calls.load(Ordering::SeqCst), ..Default::default() }
        }
    }

    #[test]
    fn pipe_end_to_end() {
        let name = format!(r"\\.\pipe\sondpi-test-{}", std::process::id());
        let mock = Arc::new(Mock { on: AtomicBool::new(false), calls: AtomicU64::new(0) });
        let stop = StopSignal::new().unwrap();
        assert_eq!(request_on(&name, "status", 300), Err(ReqError::Unreachable("servis çalışmıyor".into())));
        let server = Server::start_on(&name, mock.clone(), &stop).unwrap();
        // A second server on the same name must be refused.
        let stop2 = StopSignal::new().unwrap();
        assert!(Server::start_on(&name, mock.clone(), &stop2).is_err());

        assert!(!request_on(&name, "status", 2000).unwrap().enabled);
        let st = request_on(&name, "on", 2000).unwrap();
        assert!(st.enabled && st.active && st.strategy == "fake ttl=8");
        assert!(mock.on.load(Ordering::SeqCst));
        assert!(!request_on(&name, "off", 2000).unwrap().enabled);
        assert!(matches!(request_on(&name, "bogus", 2000), Err(ReqError::Service(_))));

        // Several clients at once.
        let handles: Vec<_> = (0..12)
            .map(|_| {
                let n = name.clone();
                std::thread::spawn(move || request_on(&n, "status", 5000).is_ok())
            })
            .collect();
        for h in handles {
            assert!(h.join().unwrap());
        }

        // An idle client holding a connection does not block others.
        let idle = unsafe {
            let w = wide(&name);
            CreateFileW(w.as_ptr(), FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 0, null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, null_mut())
        };
        assert!(idle != INVALID_HANDLE_VALUE);
        assert!(request_on(&name, "status", 2000).is_ok());

        let t = Instant::now();
        stop.stop();
        server.join();
        assert!(t.elapsed() < Duration::from_secs(2), "stop must be prompt");
        // SAFETY: handle opened above.
        unsafe { CloseHandle(idle) };
        assert!(request_on(&name, "status", 300).is_err());
    }

    #[test]
    fn engine_error_is_carried() {
        let name = format!(r"\\.\pipe\sondpi-test-err-{}", std::process::id());
        let mock = Arc::new(Mock { on: AtomicBool::new(false), calls: AtomicU64::new(99) });
        let stop = StopSignal::new().unwrap();
        let server = Server::start_on(&name, mock, &stop).unwrap();
        assert_eq!(request_on(&name, "on", 2000), Err(ReqError::Service("sürücü yok = hata".into())));
        stop.stop();
        server.join();
    }
}

