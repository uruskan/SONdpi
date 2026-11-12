//! Desync strategies. STUB: signatures are the contract, bodies are not written yet.
//!
//! Pure logic: given one outbound TCP packet that starts a TLS ClientHello or an HTTP request,
//! produce the packets to send instead (fakes first, then the real data in fragments).

use crate::packet::Packet;

/// WinDivert filter sub-expression matching the outbound TCP packets `apply` cares about
/// (payload starts a TLS ClientHello or an HTTP request). The engine wraps it with direction,
/// loopback and address conditions.
pub const FILTER: &str = "false";

/// A complete description of how to desync one request. Round-trips through a spec string so
/// it can be passed on the command line, stored in the registry and shown in the tray.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Strategy {
    spec: String,
}

impl Strategy {
    pub fn from_spec(spec: &str) -> Result<Strategy, String> {
        Ok(Strategy { spec: spec.to_string() })
    }
    pub fn to_spec(&self) -> String {
        self.spec.clone()
    }
    /// Strategies worth trying during calibration, most likely to work first.
    pub fn candidates() -> Vec<Strategy> {
        vec![Strategy::default()]
    }
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy { spec: String::new() }
    }
}

/// Per-connection facts the engine learned before the request was sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowHint {
    /// TTL / hop limit observed on the server's SYN-ACK, when the engine saw it.
    pub server_ttl: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Send the packet unchanged.
    Pass,
    /// Drop the packet and send these instead, in order. Checksums are already fixed.
    Replace(Vec<Packet>),
}

/// Decide what to do with one outbound TCP packet.
pub fn apply(_strategy: &Strategy, _pkt: &Packet, _hint: &FlowHint) -> Verdict {
    Verdict::Pass
}

/// Hop distance of a peer estimated from the TTL its packet arrived with (initial TTL assumed
/// to be 64, 128 or 255). `None` when no sensible estimate exists.
pub fn hops_from_ttl(_observed_ttl: u8) -> Option<u8> {
    None
}
