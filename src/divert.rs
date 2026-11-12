//! WinDivert 2.2 FFI, bound at run time from `WinDivert.dll` next to the executable.
//!
//! Prototypes, the 80-byte `WINDIVERT_ADDRESS` layout, flags and parameter values follow the
//! official `windivert.h` (WinDivert 2.2). There is no import library: the DLL is loaded with
//! `LoadLibraryW` on first use and every function is resolved with `GetProcAddress`.
//!
//! Facts from the WinDivert documentation and driver source this module and the engine rely on:
//! - A captured packet "is guaranteed to have correct checksums or have the corresponding
//!   `*Checksum` flag unset" (checksum offload leaves arbitrary values in the field). On send,
//!   a set flag means "trust the field"; an unset flag makes the driver compute that checksum
//!   from scratch before injecting (`windivert_inject_packet` calls the checksum helper with
//!   only the unset ones enabled).
//! - Packets injected by a handle are only seen by handles with a *lower* priority; higher
//!   priority values see packets first.
//! - Captured packets can be up to `WINDIVERT_MTU_MAX` (40 + 65535) bytes: segmentation
//!   offload hands the driver one large outbound segment.

use std::ffi::{c_char, c_void, CStr};
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

/// WinDivert flags for [`Divert::open`].
pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_DROP: u64 = 0x0002;
pub const FLAG_RECV_ONLY: u64 = 0x0004;
pub const FLAG_SEND_ONLY: u64 = 0x0008;
pub const FLAG_NO_INSTALL: u64 = 0x0010;
pub const FLAG_FRAGMENTS: u64 = 0x0020;

pub const PRIORITY_HIGHEST: i16 = 30000;
pub const PRIORITY_LOWEST: i16 = -30000;

/// Largest packet the driver can hand out (`WINDIVERT_MTU_MAX`).
pub const MTU_MAX: usize = 40 + 0xFFFF;
/// Largest batch for `WinDivertRecvEx`/`SendEx` (`WINDIVERT_BATCH_MAX`).
pub const BATCH_MAX: usize = 0xFF;

const LAYER_NETWORK: u32 = 0;

const PARAM_QUEUE_LENGTH: u32 = 0;
const PARAM_QUEUE_TIME: u32 = 1;
const PARAM_QUEUE_SIZE: u32 = 2;
const PARAM_VERSION_MAJOR: u32 = 3;
const PARAM_VERSION_MINOR: u32 = 4;

/// Queue parameters set on every receiving handle (maximum length and size from the header,
/// time doubled from the 2 s default so that a briefly descheduled loop does not drop bursts).
pub const QUEUE_LENGTH: u64 = 16384;
pub const QUEUE_SIZE: u64 = 33_554_432;
pub const QUEUE_TIME_MS: u64 = 4000;

const SHUTDOWN_RECV: u32 = 0x1;
const SHUTDOWN_BOTH: u32 = 0x3;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NO_DATA: u32 = 232;
const ERROR_INVALID_IMAGE_HASH: u32 = 577;
const ERROR_DRIVER_FAILED_PRIOR_UNLOAD: u32 = 654;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_DRIVER_BLOCKED: u32 = 1275;
const EPT_S_NOT_REGISTERED: u32 = 1753;

// ---- address ----------------------------------------------------------------------------

/// WINDIVERT_ADDRESS (80 bytes), opaque apart from the accessors.
///
/// Layout: `INT64 Timestamp` at 0; a `UINT32` of bit fields at 8 (Layer:8, Event:8, Sniffed,
/// Outbound, Loopback, Impostor, IPv6, IPChecksum, TCPChecksum, UDPChecksum, Reserved1:8; MSVC
/// allocates bit fields from the least significant bit); `UINT32 Reserved2` at 12; a 64-byte
/// union at 16 whose network-layer member is `UINT32 IfIdx; UINT32 SubIfIdx`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Addr {
    raw: [u8; 80],
}

const BIT_SNIFFED: u32 = 16;
const BIT_OUTBOUND: u32 = 17;
const BIT_LOOPBACK: u32 = 18;
const BIT_IMPOSTOR: u32 = 19;
const BIT_IPV6: u32 = 20;
const BIT_IP_CSUM: u32 = 21;
const BIT_TCP_CSUM: u32 = 22;
const BIT_UDP_CSUM: u32 = 23;

impl Default for Addr {
    fn default() -> Self {
        Addr { raw: [0; 80] }
    }
}

impl std::fmt::Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Addr{{{} if={}.{}{}{}{} csum={}{}{}}}",
            if self.outbound() { "out" } else { "in" },
            self.if_idx(),
            self.sub_if_idx(),
            if self.ipv6() { " v6" } else { "" },
            if self.loopback() { " loopback" } else { "" },
            if self.impostor() { " impostor" } else { "" },
            self.ip_checksum() as u8,
            self.tcp_checksum() as u8,
            self.udp_checksum() as u8
        )
    }
}

impl Addr {
    /// Raw 80 bytes, exactly as the driver lays them out.
    pub fn from_raw(raw: [u8; 80]) -> Addr {
        Addr { raw }
    }
    pub fn as_raw(&self) -> &[u8; 80] {
        &self.raw
    }

    fn bits(&self) -> u32 {
        u32::from_le_bytes([self.raw[8], self.raw[9], self.raw[10], self.raw[11]])
    }
    fn set_bits(&mut self, v: u32) {
        self.raw[8..12].copy_from_slice(&v.to_le_bytes());
    }
    fn bit(&self, n: u32) -> bool {
        self.bits() >> n & 1 == 1
    }
    fn set_bit(&mut self, n: u32, on: bool) {
        let b = self.bits();
        self.set_bits(if on { b | 1 << n } else { b & !(1 << n) });
    }

    pub fn timestamp(&self) -> i64 {
        i64::from_le_bytes(self.raw[0..8].try_into().unwrap_or([0; 8]))
    }
    pub fn layer(&self) -> u8 {
        (self.bits() & 0xff) as u8
    }
    pub fn event(&self) -> u8 {
        (self.bits() >> 8 & 0xff) as u8
    }
    pub fn sniffed(&self) -> bool {
        self.bit(BIT_SNIFFED)
    }
    pub fn outbound(&self) -> bool {
        self.bit(BIT_OUTBOUND)
    }
    pub fn set_outbound(&mut self, outbound: bool) {
        self.set_bit(BIT_OUTBOUND, outbound)
    }
    pub fn ipv6(&self) -> bool {
        self.bit(BIT_IPV6)
    }
    pub fn loopback(&self) -> bool {
        self.bit(BIT_LOOPBACK)
    }
    /// True when the packet was injected by another driver (not by WinDivert itself).
    pub fn impostor(&self) -> bool {
        self.bit(BIT_IMPOSTOR)
    }
    pub fn set_impostor(&mut self, on: bool) {
        self.set_bit(BIT_IMPOSTOR, on)
    }
    /// The IPv4 header checksum in the packet is valid.
    pub fn ip_checksum(&self) -> bool {
        self.bit(BIT_IP_CSUM)
    }
    /// The TCP checksum in the packet is valid (unset: offload left an arbitrary value).
    pub fn tcp_checksum(&self) -> bool {
        self.bit(BIT_TCP_CSUM)
    }
    pub fn udp_checksum(&self) -> bool {
        self.bit(BIT_UDP_CSUM)
    }
    pub fn set_ip_checksum(&mut self, on: bool) {
        self.set_bit(BIT_IP_CSUM, on)
    }
    pub fn set_tcp_checksum(&mut self, on: bool) {
        self.set_bit(BIT_TCP_CSUM, on)
    }
    pub fn set_udp_checksum(&mut self, on: bool) {
        self.set_bit(BIT_UDP_CSUM, on)
    }
    /// `true`: the checksums in the packet are correct, send as is. `false`: the driver
    /// recomputes every checksum before injecting.
    pub fn set_checksums_valid(&mut self, valid: bool) {
        self.set_ip_checksum(valid);
        self.set_tcp_checksum(valid);
        self.set_udp_checksum(valid);
    }
    pub fn if_idx(&self) -> u32 {
        u32::from_le_bytes([self.raw[16], self.raw[17], self.raw[18], self.raw[19]])
    }
    pub fn sub_if_idx(&self) -> u32 {
        u32::from_le_bytes([self.raw[20], self.raw[21], self.raw[22], self.raw[23]])
    }
}

// ---- dynamic binding ----------------------------------------------------------------------

type FnOpen = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> HANDLE;
type FnRecv = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Addr) -> i32;
type FnRecvEx =
    unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, u64, *mut Addr, *mut u32, *mut c_void) -> i32;
type FnSend = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Addr) -> i32;
type FnShutdown = unsafe extern "C" fn(HANDLE, u32) -> i32;
type FnClose = unsafe extern "C" fn(HANDLE) -> i32;
type FnSetParam = unsafe extern "C" fn(HANDLE, u32, u64) -> i32;
type FnGetParam = unsafe extern "C" fn(HANDLE, u32, *mut u64) -> i32;
type FnCalcChecksums = unsafe extern "C" fn(*mut c_void, u32, *mut Addr, u64) -> i32;
type FnCompile = unsafe extern "C" fn(*const c_char, u32, *mut c_char, u32, *mut *const c_char, *mut u32) -> i32;

struct Api {
    open: FnOpen,
    recv: FnRecv,
    recv_ex: FnRecvEx,
    send: FnSend,
    shutdown: FnShutdown,
    close: FnClose,
    set_param: FnSetParam,
    get_param: FnGetParam,
    calc_checksums: FnCalcChecksums,
    compile: FnCompile,
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

/// Folder WinDivert.dll and WinDivert64.sys are expected in.
pub fn driver_dir() -> Option<PathBuf> {
    exe_dir()
}

fn load() -> Result<Api, String> {
    let dir = exe_dir().ok_or("cannot locate the running executable")?;
    let dll = dir.join("WinDivert.dll");
    if !dll.is_file() {
        return Err(format!("WinDivert.dll is missing: expected at {}", dll.display()));
    }
    let wide: Vec<u16> = dll.as_os_str().encode_wide_nul();
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    if module.is_null() {
        // SAFETY: plain thread-local error read right after the failing call.
        let e = unsafe { GetLastError() };
        return Err(format!("cannot load {} (Windows error {e}: {})", dll.display(), io::Error::from_raw_os_error(e as i32)));
    }
    macro_rules! sym {
        ($name:literal, $ty:ty) => {{
            // SAFETY: `module` is a loaded library and the name is a NUL-terminated literal.
            let p = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
            match p {
                // SAFETY: the prototype matches the declaration in the official windivert.h.
                Some(f) => unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f) },
                None => return Err(format!("{} does not export {} (not WinDivert 2.x?)", dll.display(), $name)),
            }
        }};
    }
    Ok(Api {
        open: sym!("WinDivertOpen", FnOpen),
        recv: sym!("WinDivertRecv", FnRecv),
        recv_ex: sym!("WinDivertRecvEx", FnRecvEx),
        send: sym!("WinDivertSend", FnSend),
        shutdown: sym!("WinDivertShutdown", FnShutdown),
        close: sym!("WinDivertClose", FnClose),
        set_param: sym!("WinDivertSetParam", FnSetParam),
        get_param: sym!("WinDivertGetParam", FnGetParam),
        calc_checksums: sym!("WinDivertHelperCalcChecksums", FnCalcChecksums),
        compile: sym!("WinDivertHelperCompileFilter", FnCompile),
    })
}

trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}
impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

fn api() -> io::Result<&'static Api> {
    match API.get_or_init(load) {
        Ok(a) => Ok(a),
        Err(e) => Err(io::Error::new(io::ErrorKind::NotFound, e.clone())),
    }
}

/// Load WinDivert.dll now (it is otherwise loaded on first use). Error text is user-readable.
pub fn ensure_loaded() -> io::Result<()> {
    api().map(|_| ())
}

fn last_error() -> u32 {
    // SAFETY: plain thread-local error read.
    unsafe { GetLastError() }
}

/// Compile `filter` for the network layer without opening a handle (needs no elevation).
/// On failure returns the compiler's message and the character position.
pub fn compile_filter(filter: &str) -> io::Result<Result<(), (String, u32)>> {
    let api = api()?;
    let c = std::ffi::CString::new(filter).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filter contains NUL"))?;
    let mut err: *const c_char = std::ptr::null();
    let mut pos: u32 = 0;
    // SAFETY: valid NUL-terminated filter; object buffer omitted (NULL, 0) as the header allows;
    // err/pos point to locals.
    let ok = unsafe { (api.compile)(c.as_ptr(), LAYER_NETWORK, std::ptr::null_mut(), 0, &mut err, &mut pos) };
    if ok != 0 {
        return Ok(Ok(()));
    }
    let msg = if err.is_null() {
        "unknown filter error".to_string()
    } else {
        // SAFETY: WinDivert returns a pointer to a static NUL-terminated string.
        unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned()
    };
    Ok(Err((msg, pos)))
}

/// Recompute IPv4/TCP/UDP checksums of `packet` in place (WinDivertHelperCalcChecksums) and set
/// the matching flags in `addr` when given.
pub fn calc_checksums(packet: &mut [u8], addr: Option<&mut Addr>) -> io::Result<()> {
    let api = api()?;
    let a = addr.map_or(std::ptr::null_mut(), |a| a as *mut Addr);
    // SAFETY: buffer pointer and length describe a live mutable slice; `a` is null or a live Addr.
    let ok = unsafe { (api.calc_checksums)(packet.as_mut_ptr().cast(), packet.len() as u32, a, 0) };
    if ok == 0 {
        return Err(io::Error::from_raw_os_error(last_error() as i32));
    }
    Ok(())
}

fn open_error(code: u32, filter: &str) -> io::Error {
    let dir = exe_dir().map(|d| d.display().to_string()).unwrap_or_default();
    let (kind, msg) = match code {
        ERROR_FILE_NOT_FOUND => (
            io::ErrorKind::NotFound,
            format!("WinDivert driver file is missing: WinDivert64.sys must be next to WinDivert.dll in {dir}"),
        ),
        ERROR_ACCESS_DENIED => (
            io::ErrorKind::PermissionDenied,
            "administrator rights required: WinDivert can only be opened by an elevated process".to_string(),
        ),
        ERROR_INVALID_PARAMETER => {
            let detail = match compile_filter(filter) {
                Ok(Err((m, pos))) => format!("filter error at position {pos}: {m}"),
                _ => "invalid filter, layer, priority or flags".to_string(),
            };
            (io::ErrorKind::InvalidInput, format!("WinDivert rejected the handle: {detail} (filter: {filter})"))
        }
        ERROR_INVALID_IMAGE_HASH => (
            io::ErrorKind::PermissionDenied,
            "WinDivert64.sys has no valid signature for this system (error 577)".to_string(),
        ),
        ERROR_DRIVER_FAILED_PRIOR_UNLOAD => (
            io::ErrorKind::AlreadyExists,
            "an incompatible WinDivert driver version is already loaded (another program uses a different WinDivert); close it or reboot (error 654)".to_string(),
        ),
        ERROR_SERVICE_DOES_NOT_EXIST => (io::ErrorKind::NotFound, "WinDivert driver is not installed (error 1060)".to_string()),
        ERROR_DRIVER_BLOCKED => (
            io::ErrorKind::PermissionDenied,
            "the WinDivert driver was blocked by security software or the system (error 1275)".to_string(),
        ),
        EPT_S_NOT_REGISTERED => (
            io::ErrorKind::Other,
            "the Base Filtering Engine service is not running (error 1753)".to_string(),
        ),
        c => (io::ErrorKind::Other, format!("WinDivertOpen failed: Windows error {c}: {}", io::Error::from_raw_os_error(c as i32))),
    };
    io::Error::new(kind, msg)
}

// ---- handle -------------------------------------------------------------------------------

/// One WinDivert handle at the network layer. `recv`, `send` and `shutdown` may be called
/// from different threads at the same time; dropping it closes the handle.
pub struct Divert {
    handle: HANDLE,
    api: &'static Api,
}

// SAFETY: a WinDivert HANDLE is a kernel file handle; the API is documented as usable from
// several threads at once (one thread blocked in recv while another sends or shuts down).
unsafe impl Send for Divert {}
// SAFETY: see above; no interior Rust state.
unsafe impl Sync for Divert {}

impl Divert {
    /// Open a handle. Fails with a clear message when the DLL or driver is missing, the
    /// process is not elevated, or the filter does not compile.
    pub fn open(filter: &str, priority: i16, flags: u64) -> io::Result<Divert> {
        let api = api()?;
        if flags & FLAG_SEND_ONLY == 0 {
            if let Err((m, pos)) = compile_filter(filter)? {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("filter error at position {pos}: {m} (filter: {filter})")));
            }
        }
        if let Some(dir) = exe_dir() {
            if !dir.join("WinDivert64.sys").is_file() {
                return Err(open_error(ERROR_FILE_NOT_FOUND, filter));
            }
        }
        let c = std::ffi::CString::new(filter).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filter contains NUL"))?;
        // SAFETY: NUL-terminated filter string valid for the call; other arguments are plain values.
        let h = unsafe { (api.open)(c.as_ptr(), LAYER_NETWORK, priority, flags) };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(open_error(last_error(), filter));
        }
        let d = Divert { handle: h, api };
        if flags & FLAG_SEND_ONLY == 0 {
            // Failures here are not fatal: the defaults still work, only slower under load.
            let _ = d.set_param(PARAM_QUEUE_LENGTH, QUEUE_LENGTH);
            let _ = d.set_param(PARAM_QUEUE_SIZE, QUEUE_SIZE);
            let _ = d.set_param(PARAM_QUEUE_TIME, QUEUE_TIME_MS);
        }
        Ok(d)
    }

    fn set_param(&self, p: u32, v: u64) -> io::Result<()> {
        // SAFETY: live handle, plain values.
        if unsafe { (self.api.set_param)(self.handle, p, v) } == 0 {
            return Err(io::Error::from_raw_os_error(last_error() as i32));
        }
        Ok(())
    }

    fn get_param(&self, p: u32) -> io::Result<u64> {
        let mut v = 0u64;
        // SAFETY: live handle; `v` is a local the driver writes one UINT64 into.
        if unsafe { (self.api.get_param)(self.handle, p, &mut v) } == 0 {
            return Err(io::Error::from_raw_os_error(last_error() as i32));
        }
        Ok(v)
    }

    /// Driver version as (major, minor).
    pub fn version(&self) -> io::Result<(u64, u64)> {
        Ok((self.get_param(PARAM_VERSION_MAJOR)?, self.get_param(PARAM_VERSION_MINOR)?))
    }

    /// Block until a packet arrives; returns its length in `buf` and its address.
    /// Returns an error once [`shutdown`](Self::shutdown) was called and the queue is empty
    /// (kind `BrokenPipe`, see [`is_shutdown`]).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Addr)> {
        let mut addr = Addr::default();
        let mut len = 0u32;
        let cap = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: buffer pointer/length describe a live mutable slice; len and addr are locals.
        let ok = unsafe { (self.api.recv)(self.handle, buf.as_mut_ptr().cast(), cap, &mut len, &mut addr) };
        if ok == 0 {
            return Err(recv_error(last_error()));
        }
        Ok((len as usize, addr))
    }

    /// Receive up to `addrs.len()` packets at once (WinDivertRecvEx batch mode). Packets are
    /// packed back to back in `buf`; the returned lengths are taken from each IP header.
    /// Returns the number of packets; their lengths go into `lens`.
    pub fn recv_batch(&self, buf: &mut [u8], addrs: &mut [Addr], lens: &mut Vec<usize>) -> io::Result<usize> {
        lens.clear();
        let n = addrs.len().clamp(1, BATCH_MAX);
        let mut alen = (n * std::mem::size_of::<Addr>()) as u32;
        let mut len = 0u32;
        let cap = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: buffer and address array are live mutable slices of the stated sizes; no
        // OVERLAPPED (synchronous call).
        let ok = unsafe {
            (self.api.recv_ex)(self.handle, buf.as_mut_ptr().cast(), cap, &mut len, 0, addrs.as_mut_ptr(), &mut alen, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(recv_error(last_error()));
        }
        let count = alen as usize / std::mem::size_of::<Addr>();
        split_batch(&buf[..len as usize], count, lens);
        Ok(lens.len())
    }

    pub fn send(&self, packet: &[u8], addr: &Addr) -> io::Result<()> {
        let mut sent = 0u32;
        // SAFETY: packet slice and addr are live for the call; sent is a local.
        let ok = unsafe { (self.api.send)(self.handle, packet.as_ptr().cast(), packet.len() as u32, &mut sent, addr) };
        if ok == 0 {
            return Err(io::Error::from_raw_os_error(last_error() as i32));
        }
        Ok(())
    }

    /// Stop receiving so that blocked `recv` calls return once the queue is empty. Packets
    /// still queued can be received and re-injected (sending keeps working), so a handle can be
    /// drained without losing traffic. Safe to call from another thread and more than once.
    pub fn shutdown(&self) {
        // SAFETY: live handle; shutting down twice is harmless (the call just fails).
        unsafe { (self.api.shutdown)(self.handle, SHUTDOWN_RECV) };
    }

    /// Stop receiving and sending.
    pub fn shutdown_both(&self) {
        // SAFETY: live handle; shutting down twice is harmless.
        unsafe { (self.api.shutdown)(self.handle, SHUTDOWN_BOTH) };
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by us and is closed exactly once here.
        unsafe { (self.api.close)(self.handle) };
    }
}

fn recv_error(code: u32) -> io::Error {
    if code == ERROR_NO_DATA {
        io::Error::new(io::ErrorKind::BrokenPipe, "WinDivert handle shut down")
    } else {
        io::Error::from_raw_os_error(code as i32)
    }
}

/// True for the error `recv` returns after `shutdown`.
pub fn is_shutdown(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::BrokenPipe
}

/// Split a batch buffer into packet lengths using the IP length fields. Stops at the first
/// inconsistent header; the remainder (if any) is reported as one final packet so that it is
/// still re-injected rather than lost.
pub fn split_batch(buf: &[u8], count: usize, lens: &mut Vec<usize>) {
    lens.clear();
    let mut off = 0;
    while off < buf.len() && lens.len() < count {
        let rest = &buf[off..];
        let l = ip_len(rest).filter(|&l| l > 0 && l <= rest.len()).unwrap_or(rest.len());
        let l = if lens.len() + 1 == count { rest.len() } else { l };
        lens.push(l);
        off += l;
    }
}

fn ip_len(p: &[u8]) -> Option<usize> {
    match p.first()? >> 4 {
        4 if p.len() >= 4 => Some(u16::from_be_bytes([p[2], p[3]]) as usize),
        6 if p.len() >= 6 => Some(40 + u16::from_be_bytes([p[4], p[5]]) as usize),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_is_80_bytes_aligned_8() {
        assert_eq!(std::mem::size_of::<Addr>(), 80);
        assert_eq!(std::mem::align_of::<Addr>(), 8);
        assert_eq!(std::mem::size_of::<[Addr; 3]>(), 240);
    }

    #[test]
    fn addr_bits_match_header_layout() {
        // Bit fields in the UINT32 at offset 8, LSB first: Layer:8 Event:8 Sniffed Outbound
        // Loopback Impostor IPv6 IPChecksum TCPChecksum UDPChecksum Reserved1:8.
        let mut raw = [0u8; 80];
        raw[8] = 0x00; // layer NETWORK
        raw[10] = 0b0000_0010; // bit 17: Outbound
        let a = Addr::from_raw(raw);
        assert!(a.outbound() && !a.loopback() && !a.impostor() && !a.ipv6() && !a.sniffed());
        raw[10] = 0b0001_0101; // bits 16 (Sniffed), 18 (Loopback), 20 (IPv6)
        let a = Addr::from_raw(raw);
        assert!(a.sniffed() && a.loopback() && a.ipv6() && !a.outbound() && !a.impostor());
        raw[10] = 0b1110_1000; // bits 19 (Impostor), 21, 22, 23 (checksums)
        let a = Addr::from_raw(raw);
        assert!(a.impostor() && a.ip_checksum() && a.tcp_checksum() && a.udp_checksum());
        assert!(!a.ipv6());
        raw[8] = 4; // REFLECT layer
        raw[9] = 7; // event
        let a = Addr::from_raw(raw);
        assert_eq!((a.layer(), a.event()), (4, 7));
    }

    #[test]
    fn addr_setters_touch_only_their_bit() {
        let mut a = Addr::default();
        a.set_outbound(true);
        assert_eq!(a.as_raw()[10], 0b10);
        a.set_checksums_valid(true);
        assert_eq!(a.as_raw()[10], 0b1110_0010);
        a.set_tcp_checksum(false);
        assert!(a.ip_checksum() && !a.tcp_checksum() && a.udp_checksum());
        a.set_outbound(false);
        a.set_impostor(true);
        assert_eq!(a.as_raw()[10], 0b1010_1000);
        assert!(a.as_raw()[..8].iter().all(|&b| b == 0));
        assert!(a.as_raw()[11..].iter().all(|&b| b == 0));
    }

    #[test]
    fn addr_interface_and_timestamp() {
        let mut raw = [0u8; 80];
        raw[0..8].copy_from_slice(&123456789i64.to_le_bytes());
        raw[16..20].copy_from_slice(&17u32.to_le_bytes());
        raw[20..24].copy_from_slice(&3u32.to_le_bytes());
        let a = Addr::from_raw(raw);
        assert_eq!(a.timestamp(), 123456789);
        assert_eq!((a.if_idx(), a.sub_if_idx()), (17, 3));
    }

    #[test]
    fn batch_split_by_ip_lengths() {
        use crate::packet::testutil::*;
        let a = tcp4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, 0, 0, 0x10, b"abc");
        let b = tcp6("::1".parse().unwrap(), 1, "::2".parse().unwrap(), 2, 0, 0, 0x10, b"hello");
        let mut buf = a.as_bytes().to_vec();
        buf.extend_from_slice(b.as_bytes());
        let mut lens = Vec::new();
        split_batch(&buf, 2, &mut lens);
        assert_eq!(lens, vec![a.len(), b.len()]);
        split_batch(&buf[..a.len()], 1, &mut lens);
        assert_eq!(lens, vec![a.len()]);
    }

    /// Needs vendor\windivert\WinDivert.dll next to the test executable; skipped otherwise.
    #[test]
    fn filters_compile_when_dll_present() {
        if ensure_loaded().is_err() {
            eprintln!("WinDivert.dll not next to the test binary; skipping");
            return;
        }
        assert!(compile_filter("outbound and tcp.Syn and !tcp.Ack").unwrap().is_ok());
        let e = compile_filter("outbound and tcp.Bogus").unwrap().unwrap_err();
        assert!(!e.0.is_empty());
    }
}
