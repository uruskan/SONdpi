//! Single executable, several roles.
//!
//! Windows:
//!   sondpi                 tray switch (installs itself on first run)
//!   sondpi service         engine, started by the Service Control Manager
//!   sondpi dev [...]       console/dev mode for measurements (needs administrator)
//!   sondpi install|uninstall
//!
//! macOS:
//!   sondpi                 menu-bar switch (inside SONdpi.app)
//!   sondpi dev [...]       the proxy in the foreground, for measurements
//!
//! On Windows the binary is built for the GUI subsystem so the tray opens no console window.
//! The console roles do not rely on stdout: `dev` writes its log file, `ctl` attaches to the
//! parent console itself.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("dev") => sondpi::dev::run(&args[1..]),
        Some("service") => sondpi::service::run(),
        Some("install") => sondpi::install::install(&args[1..]),
        Some("uninstall") => sondpi::install::uninstall(&args[1..]),
        _ => sondpi::tray::run(&args),
    };
    std::process::exit(code);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("SONdpi: this platform is not supported yet");
    std::process::exit(1);
}
