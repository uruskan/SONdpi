//! The menu-bar switch (`NSStatusItem`), the macOS counterpart of the Windows tray icon.
//!
//! The menu is the Windows tray menu, item for item: the mascot header (portrait, "SONdpi" in
//! bold, the state line in green / grey / amber, and under it an on/off switch, green or red,
//! that flips with one click (the user's wish, 2026-11-18); only with the mascot on), "Açık", the three
//! counters, the error line when there is one, "Mac açılışında başlat", "Maskot simgesi",
//! "SONdpi'yi kaldır…", "Çıkış". The one difference is the user's (2026-11-17): on macOS a left
//! click opens the menu (on Windows a right click does). No Dock icon (`LSUIElement` and the
//! accessory activation policy). The icon is the mascot's face (awake, asleep, worried) or,
//! with the mascot off, a template shield symbol.
//!
//! All AppKit calls happen on the main thread: the menu actions, a 0.5 s timer that redraws
//! from [`Core::view`], and the termination callback. Slow work runs in [`Core`].

use super::core::{self, Core, View};
use super::objc::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
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
const NS_VIEW_WIDTH_SIZABLE: usize = 2;
const NS_VIEW_MIN_X_MARGIN: usize = 1;
const NS_VIEW_MAX_X_MARGIN: usize = 4;
const NS_ALERT_FIRST_BUTTON: isize = 1000;
/// NSTextAlignmentCenter: 1 where AppKit uses the iOS values (Apple silicon), 2 on Intel.
#[cfg(target_arch = "x86_64")]
const NS_TEXT_ALIGNMENT_CENTER: isize = 2;
#[cfg(not(target_arch = "x86_64"))]
const NS_TEXT_ALIGNMENT_CENTER: isize = 1;
const STATUS_ICON_PT: f64 = 18.0;

/// Header layout, in points, as `tray::header_metrics` at 100 %: the portrait is 128 wide,
/// 14 from the top; the name 6 below it, the state line 1 below the name, 14 below that; the
/// item is 40 wider than the portrait.
const PORTRAIT_PT: f64 = 128.0;
const TITLE_H: f64 = 17.0;
const LINE_H: f64 = 16.0;
const HEADER_W: f64 = PORTRAIT_PT + 40.0;
/// The switch under the state line: the size of a standard macOS switch, 8 below the line.
const SWITCH_W: f64 = 38.0;
const SWITCH_H: f64 = 22.0;
const SWITCH_GAP: f64 = 8.0;
const HEADER_H: f64 = 14.0 + PORTRAIT_PT + 6.0 + TITLE_H + 1.0 + LINE_H + SWITCH_GAP + SWITCH_H + 14.0;

#[link(name = "Foundation", kind = "framework")]
extern "C" {
    static NSRunLoopCommonModes: Id;
}

/// Icon state, also the index into the image arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    On = 0,
    Off = 1,
    Problem = 2,
}

/// `tray::icon_state`.
pub fn look(v: &View) -> Look {
    if v.error.is_some() || (v.enabled && !v.active && !v.busy) {
        Look::Problem
    } else if v.enabled {
        Look::On
    } else {
        Look::Off
    }
}

/// `tray::tooltip`.
pub fn tooltip(v: &View) -> String {
    if v.busy {
        "SONdpi: değiştiriliyor…".to_string()
    } else if let Some(e) = &v.error {
        format!("SONdpi: sorun, {e}")
    } else if v.enabled && !v.active {
        "SONdpi: açık ama motor çalışmıyor".to_string()
    } else if v.enabled {
        if v.stats.desynced == 0 && v.stats.rescued == 0 {
            "SONdpi: açık, hazır".to_string()
        } else {
            format!("SONdpi: açık, {} bağlantı korundu", v.stats.desynced)
        }
    } else {
        "SONdpi: kapalı".to_string()
    }
}

/// `tray::state_line`.
pub fn state_line(l: Look) -> &'static str {
    match l {
        Look::On => "Açık",
        Look::Off => "Kapalı",
        Look::Problem => "Sorun var",
    }
}

/// `tray::state_line_color`: green, grey, amber.
pub fn state_line_color(l: Look) -> (u8, u8, u8) {
    match l {
        Look::On => (36, 168, 96),
        Look::Off => (128, 135, 148),
        Look::Problem => (224, 150, 0),
    }
}

/// `tray::menu_model` lines: the counters while there are any, a dash otherwise.
pub fn counter_lines(v: &View) -> [String; 3] {
    let f = |label: &str, n: u64| if v.has_stats { format!("{label}: {n}") } else { format!("{label}: –") };
    [
        f("Korunan bağlantı", v.stats.desynced),
        f("Kurtarılan bağlantı", v.stats.rescued),
        f("DNS yanıtı", v.stats.dns_answered),
    ]
}

struct Ui {
    item: Id,
    header: Id,
    header_sep: Id,
    portrait: Id,
    state: Id,
    switch: Id,
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

// ---- the header switch ----------------------------------------------------------------------

/// What the switch shows (one switch per process; read by its drawRect:).
static SWITCH_ON: AtomicBool = AtomicBool::new(false);
static SWITCH_BUSY: AtomicBool = AtomicBool::new(false);

/// Track and knob of the switch, in its own coordinates: (track, knob).
pub fn switch_geometry(on: bool) -> (NSRect, NSRect) {
    let d = SWITCH_H - 4.0;
    let x = if on { SWITCH_W - 2.0 - d } else { 2.0 };
    (rect(0.0, 0.0, SWITCH_W, SWITCH_H), rect(x, 2.0, d, d))
}

extern "C" fn switch_draw(_this: Id, _cmd: Sel, _dirty: NSRect) {
    let on = SWITCH_ON.load(Ordering::Relaxed);
    let busy = SWITCH_BUSY.load(Ordering::Relaxed);
    let (track, knob) = switch_geometry(on);
    // SAFETY: called by AppKit inside the view's drawing context; every object used is a
    // valid class or an autoreleased object living for this call.
    unsafe {
        let mut color: Id = send0(class("NSColor"), if on { "systemGreenColor" } else { "systemRedColor" });
        if busy {
            color = send1(color, "colorWithAlphaComponent:", 0.45f64);
        }
        send0::<()>(color, "setFill");
        let path: Id = send3(class("NSBezierPath"), "bezierPathWithRoundedRect:xRadius:yRadius:", track, SWITCH_H / 2.0, SWITCH_H / 2.0);
        send0::<()>(path, "fill");
        let white: Id = send0(class("NSColor"), "whiteColor");
        send0::<()>(white, "setFill");
        let k: Id = send1(class("NSBezierPath"), "bezierPathWithOvalInRect:", knob);
        send0::<()>(k, "fill");
        let edge: Id = send2(class("NSColor"), "colorWithWhite:alpha:", 0.0f64, 0.15f64);
        send0::<()>(edge, "setStroke");
        send1::<f64, ()>(k, "setLineWidth:", 0.5f64);
        send0::<()>(k, "stroke");
    }
}

/// A press began on the switch (a release counts only after one).
static SWITCH_PRESSED: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Clone, Copy)]
struct NSPoint {
    x: f64,
    y: f64,
}

/// Is the event's pointer inside the switch?
fn event_inside(this: Id, ev: Id) -> bool {
    // SAFETY: `ev` is the mouse event AppKit passed to `this`; NSPoint (two doubles) comes
    // back in registers on arm64 and x86_64, so plain objc_msgSend is right.
    let p: NSPoint = unsafe {
        let w: NSPoint = send0(ev, "locationInWindow");
        send2(this, "convertPoint:fromView:", w, NIL)
    };
    p.x >= 0.0 && p.y >= 0.0 && p.x <= SWITCH_W && p.y <= SWITCH_H
}

/// Claim the press so the release comes to this view.
extern "C" fn switch_mouse_down(_this: Id, _cmd: Sel, _ev: Id) {
    SWITCH_PRESSED.store(true, Ordering::Relaxed);
}

/// Flip on a click: pressed and released on the switch (dragging off cancels, as on a standard
/// switch; a release without a press, as when the menu is opened by press-drag, does nothing).
extern "C" fn switch_mouse_up(this: Id, _cmd: Sel, ev: Id) {
    if !SWITCH_PRESSED.swap(false, Ordering::Relaxed) || !event_inside(this, ev) {
        return;
    }
    if let Some(c) = core() {
        let v = c.view();
        if !v.busy {
            c.set_enabled(!v.enabled);
        }
    }
    // The menu stays open; refresh redraws the switch now and the timer as the change completes.
    with_pool(|| refresh(true));
}

extern "C" fn switch_accepts_first_mouse(_this: Id, _cmd: Sel, _ev: Id) -> bool {
    true
}

/// The switch view class (registered once).
fn switch_class() -> Id {
    static CLS: AtomicUsize = AtomicUsize::new(0);
    let c = CLS.load(Ordering::Acquire);
    if c != 0 {
        return c as Id;
    }
    let methods: [(&str, *const c_void, &str); 4] = [
        ("drawRect:", switch_draw as *const c_void, "v@:{CGRect={CGPoint=dd}{CGSize=dd}}"),
        ("mouseDown:", switch_mouse_down as *const c_void, "v@:@"),
        ("mouseUp:", switch_mouse_up as *const c_void, "v@:@"),
        ("acceptsFirstMouse:", switch_accepts_first_mouse as *const c_void, "B@:@"),
    ];
    let mut cls = make_class("SONdpiSwitch", "NSView", &methods);
    if cls.is_null() {
        // Already registered in this process.
        cls = class("SONdpiSwitch");
    }
    CLS.store(cls as usize, Ordering::Release);
    cls
}

// ---- Objective-C callbacks (main thread) ----------------------------------------------------

extern "C" fn on_toggle(_this: Id, _cmd: Sel, _sender: Id) {
    if let Some(c) = core() {
        let v = c.view();
        if !v.busy {
            c.set_enabled(!v.enabled);
        }
    }
    with_pool(|| refresh(true));
}

extern "C" fn on_autostart(_this: Id, _cmd: Sel, _sender: Id) {
    let on = !super::autostart::is_enabled();
    if let Err(e) = super::autostart::set_enabled(on) {
        with_pool(|| info("Başlangıç ayarı değiştirilemedi", &e.to_string()));
    }
    with_pool(|| refresh(true));
}

extern "C" fn on_mascot(_this: Id, _cmd: Sel, _sender: Id) {
    if let Some(c) = core() {
        let on = !c.view().mascot;
        c.set_mascot(on);
    }
    with_pool(|| refresh(true));
}

extern "C" fn on_uninstall(_this: Id, _cmd: Sel, _sender: Id) {
    with_pool(|| {
        let exe = std::env::current_exe().ok();
        if exe.as_deref().is_some_and(super::autostart::is_translocated) {
            info("SONdpi kaldırılamıyor", "Uygulama indirildiği yerden geçici bir kopya olarak çalışıyor. Çıkış yapıp SONdpi.app'i çöpe atmanız yeterli.");
            return;
        }
        if !confirm(
            "SONdpi bu Mac'ten kaldırılsın mı?",
            "Proxy ayarı eski hâline döner, ayarlar silinir ve uygulama Çöp Sepeti'ne taşınır.",
            "Kaldır",
        ) {
            return;
        }
        if let Some(c) = core() {
            c.shutdown(Duration::from_secs(15));
        }
        let _ = super::autostart::set_enabled(false);
        let _ = std::fs::remove_dir_all(core::support_dir());
        if let Some(app) = std::env::current_exe().ok().and_then(|e| super::autostart::bundle_of(&e)) {
            // SAFETY: NSFileManager/NSURL calls with valid objects; errors are ignored (null
            // out-pointers are allowed).
            unsafe {
                let fm: Id = send0(class("NSFileManager"), "defaultManager");
                let url: Id = send1(class("NSURL"), "fileURLWithPath:", nsstring(&app.display().to_string()));
                let _: bool = send3(fm, "trashItemAtURL:resultingItemURL:error:", url, std::ptr::null_mut::<Id>(), std::ptr::null_mut::<Id>());
            }
        }
        std::process::exit(0);
    });
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

/// NSMenuDelegate: redraw just before the menu shows.
extern "C" fn menu_will_open(_this: Id, _cmd: Sel, _menu: Id) {
    with_pool(|| refresh(true));
}

extern "C" fn will_terminate(_this: Id, _cmd: Sel, _note: Id) {
    if let Some(c) = core() {
        c.shutdown(Duration::from_secs(15));
    }
}

/// A modal alert with one button.
fn info(message: &str, text: &str) {
    // SAFETY: as in `confirm`.
    unsafe {
        let app: Id = send0(class("NSApplication"), "sharedApplication");
        send1::<bool, ()>(app, "activateIgnoringOtherApps:", true);
        let a: Id = send0(send0::<Id>(class("NSAlert"), "alloc"), "init");
        send1::<Id, ()>(a, "setMessageText:", nsstring(message));
        send1::<Id, ()>(a, "setInformativeText:", nsstring(text));
        let _: isize = send0(a, "runModal");
        let _: () = send0(a, "release");
    }
}

/// A modal yes/no alert; true for the first button.
fn confirm(message: &str, info: &str, yes: &str) -> bool {
    // SAFETY: NSAlert on the main thread with valid strings; the app is brought forward so the
    // alert is not hidden behind other windows (an accessory app has none of its own).
    unsafe {
        let app: Id = send0(class("NSApplication"), "sharedApplication");
        send1::<bool, ()>(app, "activateIgnoringOtherApps:", true);
        let a: Id = send0(send0::<Id>(class("NSAlert"), "alloc"), "init");
        send1::<Id, ()>(a, "setMessageText:", nsstring(message));
        send1::<Id, ()>(a, "setInformativeText:", nsstring(info));
        let _: Id = send1(a, "addButtonWithTitle:", nsstring(yes));
        let _: Id = send1(a, "addButtonWithTitle:", nsstring("Vazgeç"));
        let r: isize = send0(a, "runModal");
        let _: () = send0(a, "release");
        r == NS_ALERT_FIRST_BUTTON
    }
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

fn separator(menu: Id) -> Id {
    // SAFETY: separatorItem is autoreleased; the menu retains it and so do we.
    unsafe {
        let s: Id = send0(class("NSMenuItem"), "separatorItem");
        let _: Id = send0(s, "retain");
        send1::<Id, ()>(menu, "addItem:", s);
        s
    }
}

fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect { x, y, w, h }
}

/// A centred, non-editable label.
fn label(font: Id, frame: NSRect) -> Id {
    // SAFETY: labelWithString: (macOS 10.12+) returns an autoreleased text field; the caller
    // adds it to a view, which retains it.
    unsafe {
        let l: Id = send1(class("NSTextField"), "labelWithString:", nsstring(""));
        send1::<NSRect, ()>(l, "setFrame:", frame);
        send1::<Id, ()>(l, "setFont:", font);
        send1::<isize, ()>(l, "setAlignment:", NS_TEXT_ALIGNMENT_CENTER);
        send1::<usize, ()>(l, "setAutoresizingMask:", NS_VIEW_WIDTH_SIZABLE);
        l
    }
}

/// The header view: portrait, "SONdpi", state line, laid out like the Windows owner-drawn item,
/// and the switch under them. Returns (view, image view, state label, switch).
fn header_view() -> (Id, Id, Id, Id) {
    // SAFETY: view construction on the main thread; subviews are retained by their superview,
    // the header view by its menu item (and by us via alloc/init).
    unsafe {
        let v: Id = send1(send0::<Id>(class("NSView"), "alloc"), "initWithFrame:", rect(0.0, 0.0, HEADER_W, HEADER_H));
        send1::<usize, ()>(v, "setAutoresizingMask:", NS_VIEW_WIDTH_SIZABLE);
        let img: Id = send1(send0::<Id>(class("NSImageView"), "alloc"), "initWithFrame:", rect((HEADER_W - PORTRAIT_PT) / 2.0, HEADER_H - 14.0 - PORTRAIT_PT, PORTRAIT_PT, PORTRAIT_PT));
        send1::<usize, ()>(img, "setAutoresizingMask:", NS_VIEW_MIN_X_MARGIN | NS_VIEW_MAX_X_MARGIN);
        send1::<Id, ()>(v, "addSubview:", img);
        let menu_size: f64 = send0(class("NSFont"), "systemFontSize");
        let bold: Id = send1(class("NSFont"), "boldSystemFontOfSize:", menu_size);
        let regular: Id = send1(class("NSFont"), "menuFontOfSize:", 0.0f64);
        let title_y = HEADER_H - (14.0 + PORTRAIT_PT + 6.0) - TITLE_H;
        let title = label(bold, rect(0.0, title_y, HEADER_W, TITLE_H));
        send1::<Id, ()>(title, "setStringValue:", nsstring("SONdpi"));
        send1::<Id, ()>(title, "setTextColor:", send0::<Id>(class("NSColor"), "labelColor"));
        send1::<Id, ()>(v, "addSubview:", title);
        let line_y = title_y - 1.0 - LINE_H;
        let state = label(regular, rect(0.0, line_y, HEADER_W, LINE_H));
        send1::<Id, ()>(v, "addSubview:", state);
        let sw: Id = send1(send0::<Id>(switch_class(), "alloc"), "initWithFrame:", rect((HEADER_W - SWITCH_W) / 2.0, line_y - SWITCH_GAP - SWITCH_H, SWITCH_W, SWITCH_H));
        send1::<usize, ()>(sw, "setAutoresizingMask:", NS_VIEW_MIN_X_MARGIN | NS_VIEW_MAX_X_MARGIN);
        send1::<Id, ()>(sw, "setToolTip:", nsstring("Aç / kapat"));
        send1::<Id, ()>(v, "addSubview:", sw);
        (v, img, state, sw)
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
        send1::<Id, ()>(menu, "setDelegate:", target);

        // As tray::menu_entries.
        let header = menu_item(menu, target, "SONdpi", None);
        let (hv, portrait, state, switch) = header_view();
        send1::<Id, ()>(header, "setView:", hv);
        // Enabled so the switch in its view gets the clicks (a view item has no action).
        send1::<bool, ()>(header, "setEnabled:", true);
        let header_sep = separator(menu);
        let toggle = menu_item(menu, target, "Açık", Some("toggle:"));
        let stats = [
            menu_item(menu, target, "Korunan bağlantı: –", None),
            menu_item(menu, target, "Kurtarılan bağlantı: –", None),
            menu_item(menu, target, "DNS yanıtı: –", None),
        ];
        let error = menu_item(menu, target, "", None);
        separator(menu);
        let autostart = menu_item(menu, target, "Mac açılışında başlat", Some("autostart:"));
        let mascot = menu_item(menu, target, "Maskot simgesi", Some("mascot:"));
        menu_item(menu, target, "SONdpi'yi kaldır…", Some("uninstall:"));
        separator(menu);
        menu_item(menu, target, "Çıkış", Some("quit:"));
        // On macOS a left click opens it (the only difference from the Windows tray).
        send1::<Id, ()>(item, "setMenu:", menu);

        Ui {
            item,
            header,
            header_sep,
            portrait,
            state,
            switch,
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
        let l = look(&v);
        let k = l as usize;
        // SAFETY: all objects are retained by `Ui`; strings and colours are autoreleased inside
        // the caller's pool.
        unsafe {
            let button: Id = send0(ui.item, "button");
            let icon = if v.mascot { ui.icons[k] } else { ui.symbols[k] };
            send1::<Id, ()>(button, "setImage:", icon);
            send1::<Id, ()>(button, "setToolTip:", nsstring(&tooltip(&v)));

            send1::<bool, ()>(ui.header, "setHidden:", !v.mascot);
            send1::<bool, ()>(ui.header_sep, "setHidden:", !v.mascot);
            send1::<Id, ()>(ui.portrait, "setImage:", ui.portraits[k]);
            send1::<Id, ()>(ui.state, "setStringValue:", nsstring(state_line(l)));
            let (r, g, b) = state_line_color(l);
            let color: Id = send4(class("NSColor"), "colorWithSRGBRed:green:blue:alpha:", r as f64 / 255.0, g as f64 / 255.0, b as f64 / 255.0, 1.0f64);
            send1::<Id, ()>(ui.state, "setTextColor:", color);
            SWITCH_ON.store(v.enabled, Ordering::Relaxed);
            SWITCH_BUSY.store(v.busy, Ordering::Relaxed);
            send1::<bool, ()>(ui.switch, "setNeedsDisplay:", true);

            send1::<isize, ()>(ui.toggle, "setState:", v.enabled as isize);
            send1::<bool, ()>(ui.toggle, "setEnabled:", !v.busy);
            for (i, t) in counter_lines(&v).iter().enumerate() {
                send1::<Id, ()>(ui.stats[i], "setTitle:", nsstring(t));
            }
            match &v.error {
                Some(e) => {
                    send1::<Id, ()>(ui.error, "setTitle:", nsstring(e));
                    send1::<bool, ()>(ui.error, "setHidden:", false);
                }
                None => send1::<bool, ()>(ui.error, "setHidden:", true),
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
        // Say so: the icon may be hidden behind the notch or other menu-bar items.
        with_pool(|| {
            // SAFETY: shared application before showing an alert from a fresh process.
            unsafe {
                let app: Id = send0(class("NSApplication"), "sharedApplication");
                let _: bool = send1(app, "setActivationPolicy:", NS_ACTIVATION_POLICY_ACCESSORY);
            }
            info("SONdpi zaten çalışıyor", "Menü çubuğundaki maskota tıklayın. Görünmüyorsa menü çubuğu dolu ya da çentiğin arkasında kalmış olabilir.");
        });
        return 0;
    }
    let c = Core::start(dir, super::new_resolver());
    let _ = CORE.set(c.clone());
    install_signals(c);

    let methods: [(&str, *const c_void, &str); 8] = [
        ("toggle:", on_toggle as *const c_void, "v@:@"),
        ("autostart:", on_autostart as *const c_void, "v@:@"),
        ("mascot:", on_mascot as *const c_void, "v@:@"),
        ("uninstall:", on_uninstall as *const c_void, "v@:@"),
        ("quit:", on_quit as *const c_void, "v@:@"),
        ("menuWillOpen:", menu_will_open as *const c_void, "v@:@"),
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
            has_stats: active,
            mascot: true,
            autostart: false,
        }
    }

    #[test]
    fn looks_and_texts_match_the_windows_tray() {
        assert_eq!(look(&v(false, false, false, None, 0)), Look::Off);
        assert_eq!(look(&v(true, true, false, None, 0)), Look::On);
        assert_eq!(look(&v(true, false, false, None, 0)), Look::Problem);
        assert_eq!(look(&v(true, false, true, None, 0)), Look::On); // switching on
        assert_eq!(look(&v(false, false, false, Some("x"), 0)), Look::Problem);
        assert_eq!(tooltip(&v(true, true, false, None, 0)), "SONdpi: açık, hazır");
        assert_eq!(tooltip(&v(true, true, false, None, 5)), "SONdpi: açık, 5 bağlantı korundu");
        assert_eq!(tooltip(&v(false, false, false, None, 0)), "SONdpi: kapalı");
        assert_eq!(tooltip(&v(true, false, false, None, 0)), "SONdpi: açık ama motor çalışmıyor");
        assert_eq!(tooltip(&v(false, false, false, Some("Açılamadı: x"), 0)), "SONdpi: sorun, Açılamadı: x");
        assert_eq!(state_line(Look::On), "Açık");
        assert_eq!(state_line(Look::Off), "Kapalı");
        assert_eq!(state_line(Look::Problem), "Sorun var");
        assert_eq!(state_line_color(Look::On), (36, 168, 96));
        assert_eq!(counter_lines(&v(true, true, false, None, 3))[0], "Korunan bağlantı: 3");
        assert_eq!(counter_lines(&v(false, false, false, None, 0))[2], "DNS yanıtı: –");
    }

    #[test]
    fn switch_knob_sits_inside_the_track() {
        for on in [false, true] {
            let (t, k) = switch_geometry(on);
            assert!(k.x >= t.x + 1.0 && k.x + k.w <= t.x + t.w - 1.0 && k.y >= 1.0 && k.y + k.h <= t.h - 1.0);
        }
        assert!(switch_geometry(true).1.x > switch_geometry(false).1.x);
    }

    /// Draws the header (both switch positions) to PNGs for a look by eye:
    /// `SONDPI_HEADER_PNG=/tmp/h cargo test --lib header_png -- --ignored` writes /tmp/h-on.png
    /// and /tmp/h-off.png.
    #[test]
    #[ignore]
    fn header_png() {
        let Ok(base) = std::env::var("SONDPI_HEADER_PNG") else { return };
        with_pool(|| unsafe {
            let (v, img, state, _) = header_view();
            for (on, name) in [(true, "on"), (false, "off")] {
                let l = if on { Look::On } else { Look::Off };
                send1::<Id, ()>(img, "setImage:", image_png(PORTRAITS[l as usize], PORTRAIT_PT));
                send1::<Id, ()>(state, "setStringValue:", nsstring(state_line(l)));
                let (r, g, b) = state_line_color(l);
                let color: Id = send4(class("NSColor"), "colorWithSRGBRed:green:blue:alpha:", r as f64 / 255.0, g as f64 / 255.0, b as f64 / 255.0, 1.0f64);
                send1::<Id, ()>(state, "setTextColor:", color);
                SWITCH_ON.store(on, Ordering::Relaxed);
                let bounds = rect(0.0, 0.0, HEADER_W, HEADER_H);
                let rep: Id = send1(v, "bitmapImageRepForCachingDisplayInRect:", bounds);
                send2::<NSRect, Id, ()>(v, "cacheDisplayInRect:toBitmapImageRep:", bounds, rep);
                let dict: Id = send0(class("NSDictionary"), "dictionary");
                let data: Id = send2(rep, "representationUsingType:properties:", 4usize, dict);
                let ok: bool = send2(data, "writeToFile:atomically:", nsstring(&format!("{base}-{name}.png")), true);
                assert!(ok);
            }
        });
    }
}
