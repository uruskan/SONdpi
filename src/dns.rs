//! Answers intercepted DNS queries locally through DoH. STUB: signatures are the contract,
//! bodies are not written yet.
//!
//! The engine hands every outbound UDP/53 query to [`DnsResponder::handle`]. The responder
//! either returns it for unchanged delivery or takes it and later reports the outcome through
//! the callback given to [`DnsResponder::new`]. `C` is an opaque per-packet context the engine
//! needs back (its WinDivert address).

use crate::packet::Packet;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// DoH endpoints, tried in order / raced.
    pub upstreams: Vec<String>,
    pub timeout_ms: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            upstreams: vec![
                "https://1.1.1.1/dns-query".into(),
                "https://1.0.0.1/dns-query".into(),
                "https://8.8.8.8/dns-query".into(),
                "https://9.9.9.9/dns-query".into(),
            ],
            timeout_ms: 2500,
        }
    }
}

/// Immediate decision for one query.
pub enum DnsAction {
    /// Deliver the query unchanged (the engine re-injects it outbound).
    Pass(Packet),
    /// The responder kept it; the outcome arrives through the callback.
    Taken,
}

/// Final outcome of a taken query.
pub enum DnsOutcome {
    /// Inject this packet inbound: it is the answer, addressed from the original DNS server
    /// to the client. Checksums are already fixed.
    Reply(Packet),
    /// DoH failed; deliver the original query unchanged (re-inject outbound).
    Fallback(Packet),
}

pub struct DnsResponder<C: Send + 'static> {
    _ctx: PhantomData<fn(C)>,
}

impl<C: Send + 'static> DnsResponder<C> {
    pub fn new(_cfg: DnsConfig, _on_done: Box<dyn Fn(DnsOutcome, C) + Send + Sync>) -> Self {
        DnsResponder { _ctx: PhantomData }
    }
    /// Never blocks.
    pub fn handle(&self, query: Packet, _ctx: C) -> DnsAction {
        DnsAction::Pass(query)
    }
    /// Queries answered locally so far.
    pub fn answered(&self) -> u64 {
        0
    }
    /// Queries passed through or fallen back so far.
    pub fn passed(&self) -> u64 {
        0
    }
}
