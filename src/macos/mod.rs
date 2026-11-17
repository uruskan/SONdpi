//! macOS front end: the proxy from [`crate::proxy`] behind a menu-bar switch that points the
//! system proxy setting at it.
//!
//! Every system interface is declared by hand (no crates beyond `windows-sys`, which is
//! Windows-only): libc and Security.framework in the modules that use them, the Objective-C
//! runtime in `objc`.

pub mod doh;
