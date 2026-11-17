//! macOS front end: the proxy from [`crate::proxy`] behind a menu-bar switch that points the
//! system proxy setting at it.
//!
//! Every system interface is declared by hand (no crates beyond `windows-sys`, which is
//! Windows-only): libc and Security.framework in the modules that use them, the Objective-C
//! runtime in `objc`.

pub mod app;
pub mod autostart;
pub mod core;
pub mod dev;
pub mod doh;
pub mod objc;
pub mod sysproxy;

use crate::dns::DnsConfig;
use crate::resolve::Resolver;
use std::sync::Arc;

/// Port the proxy prefers; another free port is taken when it is busy.
pub const DEFAULT_PORT: u16 = 18642;

/// Resolver over the macOS DoH client and upstreams.
pub fn new_resolver() -> Arc<Resolver> {
    let cfg = DnsConfig { upstreams: doh::upstreams(), timeout_ms: 2500 };
    Arc::new(Resolver::new(cfg, doh::upstream(Arc::new(doh::Client::new()))))
}
