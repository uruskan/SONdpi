//! WinDivert FFI, loaded at run time from the executable's folder. STUB: signatures are the
//! contract, bodies are not written yet.

use std::io;

/// WinDivert flags for [`Divert::open`].
pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_DROP: u64 = 0x0002;
pub const FLAG_RECV_ONLY: u64 = 0x0004;
pub const FLAG_SEND_ONLY: u64 = 0x0008;

/// WINDIVERT_ADDRESS (80 bytes), opaque apart from the accessors.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Addr {
    raw: [u8; 80],
}

impl Addr {
    pub fn outbound(&self) -> bool {
        false
    }
    pub fn set_outbound(&mut self, _outbound: bool) {}
    pub fn ipv6(&self) -> bool {
        false
    }
    pub fn loopback(&self) -> bool {
        false
    }
    /// True when the packet was injected by a WinDivert handle (ours or someone else's).
    pub fn impostor(&self) -> bool {
        false
    }
    /// Let WinDivert/the stack recompute checksums on send instead of trusting ours.
    pub fn set_checksums_valid(&mut self, _valid: bool) {}
}

/// One WinDivert handle at the network layer.
pub struct Divert {
    _private: (),
}

impl Divert {
    /// Open a handle. Fails with a clear message when the DLL or driver is missing, the
    /// process is not elevated, or the filter does not compile.
    pub fn open(_filter: &str, _priority: i16, _flags: u64) -> io::Result<Divert> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "divert stub"))
    }
    /// Block until a packet arrives; returns its length in `buf` and its address.
    /// Returns an error once [`shutdown`](Self::shutdown) was called and the queue is empty.
    pub fn recv(&self, _buf: &mut [u8]) -> io::Result<(usize, Addr)> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "divert stub"))
    }
    pub fn send(&self, _packet: &[u8], _addr: &Addr) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "divert stub"))
    }
    /// Stop receiving so that blocked `recv` calls return. Safe to call from another thread.
    pub fn shutdown(&self) {}
}
