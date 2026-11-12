//! DNS-over-HTTPS client on WinHTTP (RFC 8484, POST application/dns-message). STUB: signatures
//! are the contract, bodies are not written yet.

/// POST one DNS message to `url` and return the response message.
pub fn query(_url: &str, _message: &[u8], _timeout_ms: u32) -> Result<Vec<u8>, String> {
    Err("doh stub".into())
}
