//! SONdpi: one-switch DPI circumvention for Windows.
//!
//! Module map (see CLAUDE.md for who owns what):
//! - `packet`  owned IP packet, parsing, mutation, checksums (pure logic)
//! - `tls`     TLS ClientHello parsing and generation (pure logic)
//! - `desync`  strategies that turn one outbound request packet into fakes + fragments (pure logic)
//! - `divert`  WinDivert FFI, loaded at run time
//! - `redial`  re-dial of unanswered SYNs from another source port, with port translation
//! - `engine`  packet loops that tie divert + desync + redial + dns together
//! - `dev`     console/dev mode used for measurements
//! - `doh`     DNS-over-HTTPS client (WinHTTP)
//! - `dns`     answers intercepted DNS queries locally through `doh`
//! - `ipc`     named-pipe control channel between tray and service
//! - `service` Windows service host for the engine
//! - `tray`    notification-area switch
//! - `install` self-install / uninstall

pub mod api;
pub mod packet;

pub mod desync;
pub mod tls;

pub mod divert;
pub mod engine;
pub mod redial;

pub mod dev;

pub mod dns;
pub mod doh;

pub mod install;
pub mod ipc;
pub mod service;
pub mod tray;
