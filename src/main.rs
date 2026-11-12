//! Single executable, several roles:
//!   sondpi                 tray switch (installs itself on first run)
//!   sondpi service         engine, started by the Service Control Manager
//!   sondpi dev [...]       console/dev mode for measurements (needs administrator)
//!   sondpi install|uninstall

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
