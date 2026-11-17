//! SONdpi: one-switch DPI circumvention for Windows and macOS.
//!
//! Module map (see CLAUDE.md for who owns what):
//!
//! Pure logic, built and tested everywhere:
//! - `packet`  owned IP packet, parsing, mutation, checksums
//! - `tls`     TLS ClientHello parsing, generation and record splitting
//! - `desync`  strategies that turn one outbound request packet into fakes + fragments
//! - `redial`  re-dial of unanswered SYNs from another source port, with port translation
//! - `dns`     DNS message helpers, cache, and the responder for intercepted queries
//!
//! Portable (std only), used by the macOS build:
//! - `dial`    connection racing: Happy Eyeballs order plus re-dial of lost SYNs
//! - `resolve` host name resolution over DoH with a cache
//! - `proxy`   local HTTP/SOCKS5 proxy that splits the first TLS record of every connection
//!
//! Windows only:
//! - `divert`  WinDivert FFI, loaded at run time
//! - `engine`  packet loops that tie divert + desync + redial + dns together
//! - `dev`     console/dev mode used for measurements
//! - `doh`     DNS-over-HTTPS client (WinHTTP)
//! - `ipc`     named-pipe control channel between tray and service
//! - `service` Windows service host for the engine
//! - `tray`    notification-area switch
//! - `install` self-install / uninstall
//!
//! macOS only:
//! - `macos`   menu-bar switch, system proxy setting, DoH over SecureTransport, autostart

pub mod api;
pub mod packet;

pub mod desync;
pub mod tls;

pub mod redial;

pub mod dns;

#[cfg(windows)]
pub mod divert;
#[cfg(windows)]
pub mod engine;

#[cfg(windows)]
pub mod dev;

#[cfg(windows)]
pub mod doh;

#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod ipc;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod tray;
