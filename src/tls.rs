//! TLS ClientHello parsing and generation. STUB: signatures are the contract, bodies are not written yet.

use std::ops::Range;

/// What we need to know about a ClientHello that starts in one TCP payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// Byte range of the server name (the host name bytes only) inside the TCP payload, when
    /// the SNI extension is present and lies completely within this payload.
    pub sni: Option<Range<usize>>,
}

/// `Some` when `payload` begins with a TLS handshake record carrying a ClientHello. The
/// ClientHello may continue in later segments; only what is in `payload` is inspected.
pub fn parse_client_hello(_payload: &[u8]) -> Option<ClientHello> {
    None
}

/// A syntactically valid, complete TLS ClientHello record for `sni`, deterministic for a given
/// `seed`. Used for fake packets and for calibration probes.
pub fn build_client_hello(_sni: &str, _seed: u64) -> Vec<u8> {
    Vec::new()
}

/// True when `payload` looks like the start of a server's reply to a ClientHello
/// (a ServerHello handshake record or a TLS alert).
pub fn is_server_reply(_payload: &[u8]) -> bool {
    false
}
