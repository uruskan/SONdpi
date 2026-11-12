//! The engine: packet loops tying divert + desync + redial + dns together. STUB: signatures are
//! the contract, bodies are not written yet.

use crate::api::{EngineControl, Status};
use crate::desync::Strategy;
use std::io;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub strategy: Strategy,
    /// Desync TLS/HTTP requests.
    pub desync: bool,
    /// Re-dial unanswered SYNs from another source port.
    pub redial: bool,
    /// Answer DNS queries locally over DoH.
    pub dns: bool,
    /// Append diagnostic lines here (dev mode). `None`: no log file.
    pub log: Option<PathBuf>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig { strategy: Strategy::default(), desync: true, redial: true, dns: true, log: None }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Outbound requests (ClientHello / HTTP) that were desynced.
    pub desynced: u64,
    /// Fake packets sent.
    pub fakes: u64,
    /// Outbound SYNs seen.
    pub syns: u64,
    /// SYNs that got no answer within the stall threshold (a re-dial was sent).
    pub stalled: u64,
    /// Connections that were established through a re-dialled port.
    pub redialed: u64,
    /// Port translations currently alive.
    pub mapped: u64,
    pub dns_answered: u64,
    pub dns_passed: u64,
}

/// A running engine. Dropping it stops it.
pub struct Engine {
    _private: (),
}

impl Engine {
    pub fn start(_cfg: EngineConfig) -> io::Result<Engine> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "engine stub"))
    }
    pub fn stats(&self) -> EngineStats {
        EngineStats::default()
    }
    /// Stop all loops and close the driver handles; returns when everything is down.
    pub fn stop(self) {}
}

/// The on/off switch around an [`Engine`]; this is what the service hands to the control pipe.
pub struct Controller {
    _private: (),
}

impl Controller {
    pub fn new(_cfg: EngineConfig) -> Controller {
        Controller { _private: () }
    }
}

impl EngineControl for Controller {
    fn set_enabled(&self, _on: bool) -> Result<(), String> {
        Err("engine stub".into())
    }
    fn status(&self) -> Status {
        Status::default()
    }
}
