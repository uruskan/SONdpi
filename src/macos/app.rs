//! The menu-bar switch (`NSStatusItem`), the macOS counterpart of the Windows tray icon.
//!
//! Any click opens the menu, headed by the mascot's portrait with the name and the state, then
//! the switch ("Açık"), the counters, "Mac açılışında başlat", "Maskot simgesi" and "Çıkış"
//! (the user's choice, 2026-11-17: the switch lives in the menu, next to the mascot). No Dock icon (`LSUIElement` in the bundle and the
//! accessory activation policy). The icon is the mascot's face (awake, asleep, worried) or,
//! with the mascot off, a template shield symbol.
//!
//! All AppKit calls happen on the main thread: the click and menu actions, a 0.5 s timer that
//! redraws from [`Core::view`], and the termination callback. Slow work runs in [`Core`].

use super::core::{self, Core, View};
use super::objc::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const ICONS: [&[u8]; 3] = [
    include_bytes!("../../assets/macos/acik.png"),
    include_bytes!("../../assets/macos/kapali.png"),
    include_bytes!("../../assets/macos/sorun.png"),
];
const PORTRAITS: [&[u8]; 3] = [
    include_bytes!("../../assets/macos/acik-portre.png"),
    include_bytes!("../../assets/macos/kapali-portre.png"),
    include_bytes!("../../assets/macos/sorun-portre.png"),
];
const SYMBOLS: [&str; 3] = ["shield.lefthalf.filled", "shield.slash", "exclamationmark.shield"];

const NS_ACTIVATION_POLICY_ACCESSORY: isize = 1;
const NS_VARIABLE_STATUS_ITEM_LENGTH: f64 = -1.0;
const STATUS_ICON_PT: f64 = 18.0;
const PORTRAIT_PT: f64 = 56.0;

#[link(name = "Foundation", kind = "framework")]
extern "C" {
    static NSRunLoopCommonModes: Id;
}
#[link(name = "AppKit", kind = "framework")]
extern "C" {
    static NSFontAttributeName: Id;
}

/// Icon state, also the index into the image arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    On = 0,
    Off = 1,
    Problem = 2,
}

pub fn look(v: &View) -> Look {
    if v.error.is_some() || (v.enabled && !v.active && !v.busy) {
        Look::Problem
    } else if v.enabled {
        Look::On
    } else {
        Look::Off
    }
}

/// Tooltip text (same wording as the Windows tray).
pub fn tooltip(v: &View) -> String {
    let line = if v.busy {
        "SONdpi: değiştiriliyor…".to_string()
    } else if let Some(e) = &v.error {
        format!("SONdpi: sorun, {e}")
    } else if v.enabled && v.active {
        if v.stats.desynced == 0 {
            "SONdpi: açık, hazır".to_string()
        } else {
            format!("SONdpi: açık, {} bağlantı korundu", v.stats.desynced)
        }
    } else if v.enabled {
        "SONdpi: açık ama motor çalışmıyor".to_string()
    } else {
        "SONdpi: kapalı".to_string()
    };
    line
}

/// The state line under the mascot's name.
pub fn state_line(v: &View) -> &'static str {
    if v.busy {
        "Değiştiriliyor…"
    } else {
        match look(v) {
            Look::On => "Açık",
            Look::Off => "Kapalı",
            Look::Problem => "Sorun var",
        }
    }
}

struct Ui {
    item: Id,
    header: Id,
    toggle: Id,
    error: Id,
    stats: [Id; 3],
    autostart: Id,
    mascot: Id,
    icons: [Id; 3],
    portraits: [Id; 3],
    symbols: [Id; 3],
    shown: Option<View>,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
}
static CORE: OnceLock<Arc<Core>> = OnceLock::new();

fn core() -> Option<&'static Arc<Core>> {
    CORE.get()
}

// ---- Objective-C callbacks (main thread) ----------------------------------------------------

extern "C" fn on_toggle(_this: Id, _cmd: Sel, _sender: Id) {
    toggle();
}

extern "C" fn on_autostart(_this: Id, _cmd: Sel, _sender: Id) {
    let on = !super::autostart::is_enabled();
    if let Err(e) = super::autostart::set_enabled(on) {
        eprintln!("SONdpi: başlangıç ayarı değiştirilemedi: {e}");
    }
    refresh(true);
}

extern "C" fn on_mascot(_this: Id, _cmd: Sel, _sender: Id) {
    if let Some(c) = core() {
        let on = !c.view().mascot;
        c.set_mascot(on);
    }
    refresh(true);
}

extern "C" fn on_quit(_this: Id, _cmd: Sel, _sender: Id) {
    // SAFETY: terminate: on the shared application; ends in will_terminate, then exit.
    unsafe {
        let app: Id = send0(class("NSApplication"), "sharedApplication");
        send1::<Id, ()>(app, "terminate:", NIL);
    }
}

extern "C" fn on_tick(_this: Id, _cmd: Sel, _timer: Id) {
    with_pool(|| refresh(false));
}

extern "C" fn will_terminate(_this: Id, _cmd: Sel, _note: Id) {
    if let Some(c) = core() {
        c.shutdown(Duration::from_secs(15));
    }
}

fn toggle() {
    if let Some(c) = core() {
        let v = c.view();
        if !v.busy {
            c.set_enabled(!v.enabled);
        }
    }
    refresh(true);
}

// ---- building and redrawing -----------------------------------------------------------------

fn image_png(bytes: &[u8], pt: f64) -> Id {
    // SAFETY: alloc/initWithData: returns a retained image (or nil for bad data); setSize: takes
    // an NSSize by value.
    unsafe {
        let img: Id = send0(class("NSImage"), "alloc");
        let img: Id = send1(img, "initWithData:", nsdata(bytes));
        if !img.is_null() {
            send1::<NSSize, ()>(img, "setSize:", NSSize { width: pt, height: pt });
        }
        img
    }
}

fn image_symbol(name: &str) -> Id {
    // SAFETY: class method returning an autoreleased image or nil (macOS 11+); retained here.
    unsafe {
        let img: Id = send2(class("NSImage"), "imageWithSystemSymbolName:accessibilityDescription:", nsstring(name), nsstring("SONdpi"));
        if !img.is_null() {
            let _: Id = send0(img, "retain");
            send1::<bool, ()>(img, "setTemplate:", true);
        }
        img
    }
}

fn menu_item(menu: Id, target: Id, title: &str, action: Option<&str>) -> Id {
    // SAFETY: standard NSMenuItem construction; the menu retains the item, and we keep our own
    // reference from alloc/init.
    unsafe {
        let it: Id = send0(class("NSMenuItem"), "alloc");
        let sel_action = action.map(sel).unwrap_or(std::ptr::null_mut());
        let it: Id = send3(it, "initWithTitle:action:keyEquivalent:", nsstring(title), sel_action, nsstring(""));
        if action.is_some() {
            send1::<Id, ()>(it, "setTarget:", target);
        } else {
            send1::<bool, ()>(it, "setEnabled:", false);
        }
        send1::<Id, ()>(menu, "addItem:", it);
        it
    }
}

fn separator(menu: Id) {
    // SAFETY: separatorItem is an autoreleased item the menu retains.
    unsafe {
        let s: Id = send0(class("NSMenuItem"), "separatorItem");
        send1::<Id, ()>(menu, "addItem:", s);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NSRange {
    location: usize,
    length: usize,
}

/// "SONdpi" in bold over the state line.
fn header_title(line: &str) -> Id {
    let text = format!("SONdpi\n{line}");
    // SAFETY: attributed-string construction with valid objects; ranges are in UTF-16 units and
    // inside the string.
    unsafe {
        let s: Id = send0(class("NSMutableAttributedString"), "alloc");
        let s: Id = send1(s, "initWithString:", nsstring(&text));
        let regular: Id = send1(class("NSFont"), "menuFontOfSize:", 0.0f64);
        let bold: Id = send1(class("NSFont"), "boldSystemFontOfSize:", 15.0f64);
        let all = NSRange { location: 0, length: text.encode_utf16().count() };
        send3::<Id, Id, NSRange, ()>(s, "addAttribute:value:range:", NSFontAttributeName, regular, all);
        send3::<Id, Id, NSRange, ()>(s, "addAttribute:value:range:", NSFontAttributeName, bold, NSRange { location: 0, length: 6 });
        let _: Id = send0(s, "autorelease");
        s
    }
}

fn build(target: Id) -> Ui {
    // SAFETY: AppKit object construction on the main thread; every object kept in `Ui` is
    // retained (alloc/init or an explicit retain) for the life of the process.
    unsafe {
        let bar: Id = send0(class("NSStatusBar"), "systemStatusBar");
        let item: Id = send1(bar, "statusItemWithLength:", NS_VARIABLE_STATUS_ITEM_LENGTH);
        let _: Id = send0(item, "retain");

        let menu: Id = send0(class("NSMenu"), "alloc");
        let menu: Id = send1(menu, "initWithTitle:", nsstring("SONdpi"));
        send1::<bool, ()>(menu, "setAutoenablesItems:", false);

        let header = menu_item(menu, target, "SONdpi", None);
        separator(menu);
        let toggle = menu_item(menu, target, "Açık", Some("toggle:"));
        let error = menu_item(menu, target, "", None);
        separator(menu);
        let stats = [
            menu_item(menu, target, "Korunan bağlantı: 0", None),
            menu_item(menu, target, "Kurtarılan bağlantı: 0", None),
            menu_item(menu, target, "DNS yanıtı: 0", None),
        ];
        separator(menu);
        let autostart = menu_item(menu, target, "Mac açılışında başlat", Some("autostart:"));
        let mascot = menu_item(menu, target, "Maskot simgesi", Some("mascot:"));
        separator(menu);
        menu_item(menu, target, "Çıkış", Some("quit:"));
        // Every click opens it.
        send1::<Id, ()>(item, "setMenu:", menu);

        Ui {
            item,
            header,
            toggle,
            error,
            stats,
            autostart,
            mascot,
            icons: ICONS.map(|b| image_png(b, STATUS_ICON_PT)),
            portraits: PORTRAITS.map(|b| image_png(b, PORTRAIT_PT)),
            symbols: SYMBOLS.map(image_symbol),
            shown: None,
        }
    }
}

fn refresh(force: bool) {
    let Some(c) = core() else { return };
    let v = c.view();
    UI.with(|u| {
        let mut u = u.borrow_mut();
        let Some(ui) = u.as_mut() else { return };
        if !force && ui.shown.as_ref() == Some(&v) {
            return;
        }
        let k = look(&v) as usize;
        // SAFETY: all objects are retained by `Ui`; strings are autoreleased inside the pool of
        // the calling callback (or the run loop's).
        unsafe {
            let button: Id = send0(ui.item, "button");
            let icon = if v.mascot { ui.icons[k] } else { ui.symbols[k] };
            send1::<Id, ()>(button, "setImage:", icon);
            send1::<Id, ()>(button, "setToolTip:", nsstring(&tooltip(&v)));

            send1::<Id, ()>(ui.header, "setImage:", if v.mascot { ui.portraits[k] } else { NIL });
            send1::<Id, ()>(ui.header, "setAttributedTitle:", header_title(state_line(&v)));
            send1::<isize, ()>(ui.toggle, "setState:", v.enabled as isize);
            send1::<bool, ()>(ui.toggle, "setEnabled:", !v.busy);
            match &v.error {
                Some(e) => {
                    send1::<Id, ()>(ui.error, "setTitle:", nsstring(e));
                    send1::<bool, ()>(ui.error, "setHidden:", false);
                }
                None => send1::<bool, ()>(ui.error, "setHidden:", true),
            }
            let on = v.enabled && v.active;
            let nums = [v.stats.desynced, v.stats.rescued, v.stats.dns_answered];
            for (i, (label, n)) in ["Korunan bağlantı", "Kurtarılan bağlantı", "DNS yanıtı"].iter().zip(nums).enumerate() {
                let t = if on { format!("{label}: {n}") } else { format!("{label}: -") };
                send1::<Id, ()>(ui.stats[i], "setTitle:", nsstring(&t));
            }
            send1::<isize, ()>(ui.autostart, "setState:", v.autostart as isize);
            send1::<isize, ()>(ui.mascot, "setState:", v.mascot as isize);
        }
        ui.shown = Some(v);
    });
}

// ---- process plumbing -----------------------------------------------------------------------

extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    fn pipe(fds: *mut i32) -> i32;
    fn write(fd: i32, buf: *const c_void, n: usize) -> isize;
    fn flock(fd: i32, op: i32) -> i32;
}

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

static SIG_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_sig: i32) {
    let fd = SIG_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let b = 1u8;
        // SAFETY: write(2) is async-signal-safe; `b` lives for the call.
        unsafe { write(fd, &b as *const u8 as *const c_void, 1) };
    }
}

/// SIGTERM/SIGINT/SIGHUP: put the system setting back, then exit.
fn install_signals(core: Arc<Core>) {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` has room for the two descriptors pipe(2) writes.
    if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
        return;
    }
    SIG_FD.store(fds[1], Ordering::Relaxed);
    // SAFETY: the read end is ours alone from here on.
    let mut r = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _ = std::thread::Builder::new().name("sondpi-signals".into()).spawn(move || {
        let mut b = [0u8; 1];
        if r.read(&mut b).is_ok() {
            core.shutdown(Duration::from_secs(15));
            std::process::exit(0);
        }
    });
    for s in [SIGHUP, SIGINT, SIGTERM] {
        // SAFETY: `on_signal` only calls write(2).
        unsafe { signal(s, on_signal) };
    }
}

/// One copy per user: an exclusive lock on a file in the support folder, held until exit.
fn single_instance(dir: &std::path::Path) -> bool {
    use std::os::fd::AsRawFd;
    let _ = std::fs::create_dir_all(dir);
    let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("kilit")) else {
        return true; // cannot tell; run anyway
    };
    // SAFETY: valid descriptor owned by `f`.
    let ok = unsafe { flock(f.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0;
    if ok {
        std::mem::forget(f); // keep the descriptor (and the lock) for the life of the process
    }
    ok
}

pub fn run() -> i32 {
    let dir = core::support_dir();
    if !single_instance(&dir) {
        return 0;
    }
    let c = Core::start(dir, super::new_resolver());
    let _ = CORE.set(c.clone());
    install_signals(c);

    let methods: [(&str, *const c_void, &str); 6] = [
        ("toggle:", on_toggle as *const c_void, "v@:@"),
        ("autostart:", on_autostart as *const c_void, "v@:@"),
        ("mascot:", on_mascot as *const c_void, "v@:@"),
        ("quit:", on_quit as *const c_void, "v@:@"),
        ("tick:", on_tick as *const c_void, "v@:@"),
        ("applicationWillTerminate:", will_terminate as *const c_void, "v@:@"),
    ];
    let app = with_pool(|| {
        let cls = make_class("SONdpiTarget", "NSObject", &methods);
        // SAFETY: AppKit setup on the main thread with valid objects; the target is retained
        // (alloc/init) for the life of the process.
        unsafe {
            let app: Id = send0(class("NSApplication"), "sharedApplication");
            let _: bool = send1(app, "setActivationPolicy:", NS_ACTIVATION_POLICY_ACCESSORY);
            let target: Id = send0(send0::<Id>(cls, "alloc"), "init");
            send1::<Id, ()>(app, "setDelegate:", target);
            let ui = build(target);
            UI.with(|u| *u.borrow_mut() = Some(ui));
            refresh(true);
            let timer: Id = send5(class("NSTimer"), "timerWithTimeInterval:target:selector:userInfo:repeats:", 0.5f64, target, sel("tick:"), NIL, true);
            let rl: Id = send0(class("NSRunLoop"), "currentRunLoop");
            send2::<Id, Id, ()>(rl, "addTimer:forMode:", timer, NSRunLoopCommonModes);
            app
        }
    });
    // SAFETY: runs the main event loop; returns only if the app is stopped.
    unsafe { send0::<()>(app, "run") };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyStats;

    fn v(enabled: bool, active: bool, busy: bool, error: Option<&str>, desynced: u64) -> View {
        View {
            enabled,
            active,
            busy,
            error: error.map(String::from),
            stats: ProxyStats { desynced, ..ProxyStats::default() },
            mascot: true,
            autostart: false,
        }
    }

    #[test]
    fn looks_and_texts() {
        assert_eq!(look(&v(false, false, false, None, 0)), Look::Off);
        assert_eq!(look(&v(true, true, false, None, 0)), Look::On);
        assert_eq!(look(&v(true, false, false, None, 0)), Look::Problem);
        assert_eq!(look(&v(true, false, true, None, 0)), Look::On); // switching on
        assert_eq!(look(&v(false, false, false, Some("x"), 0)), Look::Problem);
        assert_eq!(tooltip(&v(true, true, false, None, 0)), "SONdpi: açık, hazır");
        assert!(tooltip(&v(true, true, false, None, 5)).starts_with("SONdpi: açık, 5 bağlantı korundu"));
        assert!(tooltip(&v(false, false, false, None, 0)).starts_with("SONdpi: kapalı"));
        assert!(tooltip(&v(false, false, false, Some("Açılamadı: x"), 0)).starts_with("SONdpi: sorun, Açılamadı: x"));
        assert!(tooltip(&v(true, false, true, None, 0)).starts_with("SONdpi: değiştiriliyor"));
        assert_eq!(state_line(&v(true, true, false, None, 0)), "Açık");
        assert_eq!(state_line(&v(false, false, false, None, 0)), "Kapalı");
        assert_eq!(state_line(&v(true, false, false, None, 0)), "Sorun var");
    }
}
