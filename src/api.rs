//! Names and types shared by every module. Owned by the lead; do not change without asking.

pub const APP_NAME: &str = "SONdpi";
/// Windows service name.
pub const SERVICE_NAME: &str = "SONdpi";
/// Control pipe between the tray and the service.
pub const PIPE_NAME: &str = r"\\.\pipe\sondpi";
/// Registry key (under HKLM) holding persisted state such as the on/off switch.
pub const REG_KEY: &str = r"SOFTWARE\SONdpi";
/// Folder under %ProgramFiles% the executable installs itself into.
pub const INSTALL_DIR_NAME: &str = "SONdpi";

/// What the tray shows. Produced by the engine side, carried over the control pipe.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The user's switch position.
    pub enabled: bool,
    /// The engine is actually running (driver open, loops alive).
    pub active: bool,
    /// Desync strategy in use, as a spec string.
    pub strategy: String,
    /// Connections whose first request was desynced since the engine started.
    pub desynced: u64,
    /// Connections rescued by re-dialling an unanswered SYN from another port.
    pub redialed: u64,
    /// DNS queries answered locally over DoH.
    pub dns_answered: u64,
    /// Last engine error, if any (shown in the tray tooltip/menu).
    pub error: Option<String>,
}

/// The switch. Implemented by the engine side (`engine::Controller`), used by `service`/`ipc`.
pub trait EngineControl: Send + Sync {
    /// Turn the engine on or off. Must be idempotent and return once the change took effect.
    fn set_enabled(&self, on: bool) -> Result<(), String>;
    fn status(&self) -> Status;
}
