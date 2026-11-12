//! Notification-area switch: one icon, left click toggles, right click opens the menu.
//!
//! The tray never touches the engine itself; it talks to the service over the control pipe
//! ([`crate::ipc`]) from short-lived helper threads, so the UI thread never waits on the pipe.
//!
//! Hidden developer commands (no UI): `sondpi ctl status|on|off` talks to the pipe and prints the
//! status; `sondpi ctl click` / `ctl menu` click / right-click the icon of the running tray (the menu opens at the cursor); `sondpi ctl tip` prints its
//! tooltip. `sondpi --no-setup` skips the first-run install offer.

use crate::api::{self, Status};
use crate::install::{self, wide};
use crate::ipc::{self, ReqError};
use std::cell::{Cell, RefCell};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, GENERIC_WRITE, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateBitmap, CreateDIBSection, DeleteObject, GetDC, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DeleteObject as DeleteGdi, DrawTextW, FillRect, GetTextMetricsW, MonitorFromPoint,
    SelectObject, SetBkMode, SetTextColor, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, MONITOR_DEFAULTTONEAREST,
    TEXTMETRICW, TRANSPARENT,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, SystemParametersInfoForDpi, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DrawIconEx, DI_NORMAL, MF_DISABLED, MF_OWNERDRAW, NONCLIENTMETRICSW, WM_DRAWITEM, WM_MEASUREITEM,
};
use windows_sys::Win32::Graphics::Gdi::{GetSysColor, GetSysColorBrush, COLOR_MENU, COLOR_MENUTEXT};
use windows_sys::Win32::UI::Controls::{DRAWITEMSTRUCT, MEASUREITEMSTRUCT};
use windows_sys::Win32::Graphics::Gdi::{GetDC as GetDcGdi, ReleaseDC as ReleaseDcGdi};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi, SetProcessDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_ERROR,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CheckMenuItem, CreateIconIndirect, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW, DestroyMenu, DestroyWindow, DispatchMessageW, FindWindowW,
    GetCursorPos, GetMessageW, GetWindowTextW, KillTimer, MessageBoxW,
    ModifyMenuW, PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW,
    SetForegroundWindow, SetTimer, SetWindowTextW, TrackPopupMenu, TranslateMessage, HICON,
    HMENU, ICONINFO, MB_ICONQUESTION, MB_YESNO, MF_BYCOMMAND, MF_CHECKED, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MF_UNCHECKED, MSG, SM_CXSMICON, TPM_BOTTOMALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DESTROY, WM_DISPLAYCHANGE, WM_ENDSESSION,
    WM_LBUTTONUP, WM_NULL, WM_SETTINGCHANGE, WM_TIMER, WNDCLASSEXW, IDYES,
};

const WM_TRAY: u32 = WM_APP + 1;
const WM_REPLY: u32 = WM_APP + 2;
const WM_FIRST_RUN: u32 = WM_APP + 3;
const WM_INSTALL_DONE: u32 = WM_APP + 4;
const NIN_SELECT: u32 = 0x400;
const NIN_KEYSELECT: u32 = 0x401;
const TIMER_POLL: usize = 1;
const POLL_MS: u32 = 2000;
const POLL_TIMEOUT_MS: u32 = 1500;
const TOGGLE_TIMEOUT_MS: u32 = 20_000;
const CLICK_DEBOUNCE_MS: u64 = 400;
/// Window class; a development pipe (`SONDPI_PIPE`) gets its own, so a test tray never meets the
/// real one.
fn class_name() -> String {
    format!("{}{}", install::TRAY_WINDOW_CLASS, dev_suffix())
}

fn dev_suffix() -> String {
    let n = ipc::default_pipe_name();
    if n == api::PIPE_NAME {
        String::new()
    } else {
        format!("-{}", n.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>())
    }
}

const ID_TOGGLE: usize = 1;
const ID_INFO_BASE: usize = 2; // 2, 3, 4
const ID_ERROR: usize = 5;
const ID_AUTOSTART: usize = 6;
const ID_UNINSTALL: usize = 7;
const ID_EXIT: usize = 8;
const ID_MASCOT: usize = 9;
const ID_HEADER: usize = 10;

// ---------------------------------------------------------------------------------------------
// What the user sees (pure logic)
// ---------------------------------------------------------------------------------------------

/// What the tray currently knows about the service.
#[derive(Clone, Debug, PartialEq)]
pub enum View {
    /// Nothing heard yet.
    Connecting,
    /// The pipe did not answer. `installed`: the service exists but is not reachable.
    Unreachable { installed: bool, reason: String },
    Live(Status),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconState {
    On,
    Off,
    Problem,
}

pub fn icon_state(v: &View) -> IconState {
    match v {
        View::Connecting => IconState::Off,
        View::Unreachable { .. } => IconState::Problem,
        View::Live(s) => {
            if s.error.is_some() || (s.enabled && !s.active) {
                IconState::Problem
            } else if s.enabled {
                IconState::On
            } else {
                IconState::Off
            }
        }
    }
}

fn truncate_utf16(s: &str, max_units: usize) -> String {
    let mut out = String::new();
    let mut n = 0;
    for c in s.chars() {
        n += c.len_utf16();
        if n > max_units {
            break;
        }
        out.push(c);
    }
    out
}

/// Tooltip text (at most 127 UTF-16 units, the Win32 limit with room for the terminator).
pub fn tooltip(v: &View) -> String {
    let t = match v {
        View::Connecting => "SONdpi: bağlanılıyor…".to_string(),
        View::Unreachable { installed: false, .. } => "SONdpi: kurulu değil, kurmak için tıklayın".to_string(),
        View::Unreachable { reason, .. } => format!("SONdpi: servise ulaşılamıyor ({reason})"),
        View::Live(s) => {
            if let Some(e) = &s.error {
                format!("SONdpi: sorun, {e}")
            } else if s.enabled && !s.active {
                "SONdpi: açık ama motor çalışmıyor".to_string()
            } else if s.enabled {
                if s.desynced == 0 && s.redialed == 0 {
                    "SONdpi: açık, hazır".to_string()
                } else {
                    format!("SONdpi: açık, {} bağlantı korundu", s.desynced)
                }
            } else {
                "SONdpi: kapalı".to_string()
            }
        }
    };
    truncate_utf16(&t, 127)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuModel {
    pub checked: bool,
    pub lines: [String; 3],
    pub error: Option<String>,
}

pub fn menu_model(v: &View) -> MenuModel {
    let (checked, nums, error) = match v {
        View::Live(s) => (s.enabled, Some((s.desynced, s.redialed, s.dns_answered)), s.error.clone()),
        View::Unreachable { installed: false, .. } => (false, None, Some("SONdpi kurulu değil".to_string())),
        View::Unreachable { reason, .. } => (false, None, Some(reason.clone())),
        View::Connecting => (false, None, None),
    };
    let f = |label: &str, n: Option<u64>| match n {
        Some(n) => format!("{label}: {n}"),
        None => format!("{label}: –"),
    };
    MenuModel {
        checked,
        lines: [
            f("Korunan bağlantı", nums.map(|n| n.0)),
            f("Kurtarılan bağlantı", nums.map(|n| n.1)),
            f("DNS yanıtı", nums.map(|n| n.2)),
        ],
        error: error.map(|e| truncate_utf16(&e, 120)),
    }
}

/// Per-user setting (HKCU `Software\SONdpi`, DWORD `Mascot`): use the mascot icons. Default on.
pub const MASCOT_VALUE: &str = "Mascot";

pub fn parse_mascot(v: Option<u32>) -> bool {
    v.map(|x| x != 0).unwrap_or(true)
}

fn mascot_enabled() -> bool {
    parse_mascot(install::reg_get_dword(HKEY_CURRENT_USER, install::USER_KEY, MASCOT_VALUE))
}

fn set_mascot(on: bool) -> Result<(), String> {
    install::reg_set_dword(HKEY_CURRENT_USER, install::USER_KEY, MASCOT_VALUE, on as u32)
}

/// Icon resource linked into the executable (see assets/sondpi.rc): 1 on, 2 off, 3 problem.
pub fn resource_id(s: IconState) -> u16 {
    match s {
        IconState::On => 1,
        IconState::Off => 2,
        IconState::Problem => 3,
    }
}

/// One line of the right-click menu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuEntry {
    pub id: usize,
    pub text: String,
    pub grayed: bool,
    pub checked: Option<bool>,
    pub separator: bool,
    /// The mascot header (owner-drawn); 	ext is then its state line.
    pub header: Option<IconState>,
}

/// Portrait icon resource (no corner badge): 11 on, 12 off, 13 problem.
pub fn portrait_resource_id(s: IconState) -> u16 {
    resource_id(s) + 10
}

/// The state line under the mascot's name.
pub fn state_line(s: IconState) -> &'static str {
    match s {
        IconState::On => "Açık",
        IconState::Off => "Kapalı",
        IconState::Problem => "Sorun var",
    }
}

/// Colour of the state line (RGB): green, grey, amber; readable on light and dark menus.
pub fn state_line_color(s: IconState) -> (u8, u8, u8) {
    match s {
        IconState::On => (36, 168, 96),
        IconState::Off => (128, 135, 148),
        IconState::Problem => (224, 150, 0),
    }
}

/// Where things go in the header, in device pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderMetrics {
    pub width: i32,
    pub height: i32,
    pub icon_y: i32,
    pub title_y: i32,
    pub line_y: i32,
}

fn scale(dpi: u32, v: i32) -> i32 {
    (v as i64 * dpi.max(96) as i64 / 96) as i32
}

/// portrait is the portrait size in device pixels; 	itle_h/line_h the text heights.
pub fn header_metrics(dpi: u32, portrait: i32, title_h: i32, line_h: i32) -> HeaderMetrics {
    let icon_y = scale(dpi, 14);
    let title_y = icon_y + portrait + scale(dpi, 6);
    let line_y = title_y + title_h + scale(dpi, 1);
    HeaderMetrics { width: portrait + scale(dpi, 40), height: line_y + line_h + scale(dpi, 14), icon_y, title_y, line_y }
}

/// The whole menu, in order.
pub fn menu_entries(v: &View, autostart: bool, mascot: bool) -> Vec<MenuEntry> {
    let m = menu_model(v);
    let item = |id: usize, text: &str, grayed: bool, checked: Option<bool>| MenuEntry { id, text: text.to_string(), grayed, checked, separator: false, header: None };
    let sep = || MenuEntry { id: 0, text: String::new(), grayed: false, checked: None, separator: true, header: None };
    let mut out = Vec::new();
    if mascot {
        let st = icon_state(v);
        out.push(MenuEntry { id: ID_HEADER, text: state_line(st).to_string(), grayed: true, checked: None, separator: false, header: Some(st) });
        out.push(sep());
    }
    out.push(item(ID_TOGGLE, "Açık", false, Some(m.checked)));
    for (i, l) in m.lines.iter().enumerate() {
        out.push(item(ID_INFO_BASE + i, l, true, None));
    }
    if let Some(e) = &m.error {
        out.push(item(ID_ERROR, e, true, None));
    }
    out.push(sep());
    out.push(item(ID_AUTOSTART, "Windows açılışında başlat", false, Some(autostart)));
    out.push(item(ID_MASCOT, "Maskot simgesi", false, Some(mascot)));
    out.push(item(ID_UNINSTALL, "SONdpi'yi kaldır…", false, None));
    out.push(sep());
    out.push(item(ID_EXIT, "Çıkış", false, None));
    out
}

/// Merge an error the last toggle produced into what the service reported.
fn effective(v: &View, sticky: &Option<String>) -> View {
    match (v, sticky) {
        (View::Live(s), Some(e)) if s.error.is_none() => {
            let mut s = s.clone();
            s.error = Some(e.clone());
            View::Live(s)
        }
        _ => v.clone(),
    }
}

// ---------------------------------------------------------------------------------------------
// Icon drawing
// ---------------------------------------------------------------------------------------------

type Rgb = (f32, f32, f32);

fn state_color(s: IconState) -> Rgb {
    match s {
        IconState::On => (47.0, 191.0, 113.0),
        IconState::Off => (140.0, 147.0, 160.0),
        IconState::Problem => (242.0, 169.0, 0.0),
    }
}

fn dist_segment(px: f32, py: f32, ax: f32, bx: f32, y: f32) -> f32 {
    let cx = px.clamp(ax, bx);
    ((px - cx).powi(2) + (py - y).powi(2)).sqrt()
}

/// Colour at a point of the unit square, or `None` where the icon is transparent.
///
/// On and off are a toggle switch (pill with a knob: right = on, left = off); a problem is an
/// amber round badge with an exclamation mark, so the silhouette differs as well as the colour.
fn glyph_at(s: IconState, x: f32, y: f32) -> Option<Rgb> {
    const R: f32 = 0.32; // pill radius
    const RIM: f32 = 0.075;
    const WHITE: Rgb = (255.0, 255.0, 255.0);
    let fill = state_color(s);
    let rim = (fill.0 * 0.55, fill.1 * 0.55, fill.2 * 0.55);
    let dist = |cx: f32, cy: f32| ((x - cx).powi(2) + (y - cy).powi(2)).sqrt();
    match s {
        IconState::On | IconState::Off => {
            let d = dist_segment(x, y, 0.03 + R, 0.97 - R, 0.5) - R;
            if d > 0.0 {
                return None;
            }
            let kx = if s == IconState::On { 0.97 - R } else { 0.03 + R };
            if dist(kx, 0.5) <= 0.205 {
                return Some(WHITE);
            }
            Some(if d > -RIM { rim } else { fill })
        }
        IconState::Problem => {
            let d = dist(0.5, 0.5) - 0.46;
            if d > 0.0 {
                return None;
            }
            let bar = (x - 0.5).abs() <= 0.065 && (0.27..=0.54).contains(&y);
            let caps = dist(0.5, 0.27) <= 0.065 || dist(0.5, 0.54) <= 0.065;
            if bar || caps || dist(0.5, 0.71) <= 0.075 {
                return Some(WHITE);
            }
            Some(if d > -RIM { rim } else { fill })
        }
    }
}
/// `size` x `size` pixels, BGRA with straight alpha, top row first, 4x4 supersampled.
pub fn render_icon(s: IconState, size: usize) -> Vec<u8> {
    const SS: usize = 4;
    let mut out = vec![0u8; size * size * 4];
    for py in 0..size {
        for px in 0..size {
            let (mut r, mut g, mut b, mut a) = (0.0f32, 0.0, 0.0, 0.0);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32) / size as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) / size as f32;
                    if let Some(c) = glyph_at(s, x, y) {
                        r += c.0;
                        g += c.1;
                        b += c.2;
                        a += 1.0;
                    }
                }
            }
            let i = (py * size + px) * 4;
            if a > 0.0 {
                out[i] = (b / a).round() as u8;
                out[i + 1] = (g / a).round() as u8;
                out[i + 2] = (r / a).round() as u8;
                out[i + 3] = (a / (SS * SS) as f32 * 255.0).round() as u8;
            }
        }
    }
    out
}

fn make_hicon(s: IconState, size: usize) -> HICON {
    let px = render_icon(s, size);
    let mut bi: BITMAPINFO = unsafe { std::mem::zeroed() }; // SAFETY: all-zero is a valid BITMAPINFO.
    bi.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: size as i32,
        biHeight: -(size as i32),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    let mut bits: *mut std::ffi::c_void = null_mut();
    // SAFETY: screen DC for the call only; DIB section memory is written within its size.
    unsafe {
        let dc = GetDC(null_mut());
        let color = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        ReleaseDC(null_mut(), dc);
        if color.is_null() || bits.is_null() {
            return null_mut();
        }
        std::ptr::copy_nonoverlapping(px.as_ptr(), bits as *mut u8, px.len());
        let mask_bytes = vec![0u8; size.div_ceil(16) * 2 * size];
        let mask = CreateBitmap(size as i32, size as i32, 1, 1, mask_bytes.as_ptr() as *const _);
        let info = ICONINFO { fIcon: 1, xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
        let icon = CreateIconIndirect(&info);
        DeleteObject(color);
        DeleteObject(mask);
        icon
    }
}

/// The mascot icon from the executable's resources at size, or null (library and test builds
/// carry no resources).
fn load_resource_icon(s: IconState, size: usize) -> HICON {
    // SAFETY: MAKEINTRESOURCE(id) as the name; the icon is ours and destroyed with DestroyIcon.
    unsafe {
        let hinst = GetModuleHandleW(null());
        LoadImageW(hinst, resource_id(s) as usize as *const u16, IMAGE_ICON, size as i32, size as i32, LR_DEFAULTCOLOR) as HICON
    }
}

/// Small-icon size for the monitor the taskbar is on.
fn tray_icon_size() -> usize {
    let class = wide("Shell_TrayWnd");
    // SAFETY: plain lookups with valid strings.
    let dpi = unsafe {
        let tb = FindWindowW(class.as_ptr(), null());
        let d = if tb.is_null() { 0 } else { GetDpiForWindow(tb) };
        if d == 0 { GetDpiForSystem() } else { d }
    };
    // SAFETY: trivial metric query.
    let n = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi.max(96)) };
    n.clamp(16, 64) as usize
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Poll,
    Toggle,
}

struct Reply {
    kind: Kind,
    epoch: u64,
    result: Result<Status, ReqError>,
    /// For failures: is the service registered with the SCM?
    installed: bool,
}

struct Tray {
    view: View,
    sticky_error: Option<String>,
    /// Polls left before `sticky_error` is forgotten (about 10 s).
    sticky_ttl: u8,
    icons: [HICON; 3],
    icon_size: usize,
    /// The setting the current icons were built for.
    icons_mascot: bool,
    mascot: bool,
    /// The open menu has the mascot header.
    header: bool,
    shown: Option<(IconState, String)>,
    added: bool,
    polling: bool,
    toggling: bool,
    installing: bool,
    /// Bumped on every toggle; a poll that started before it is stale.
    epoch: u64,
    last_click: u64,
    menu: HMENU,
    taskbar_created: u32,
    no_setup: bool,
}

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

/// Run `f` on the tray state. Never call this re-entrantly and never hold it across a call that
/// can pump messages.
fn with<R>(f: impl FnOnce(&mut Tray) -> R) -> Option<R> {
    TRAY.with(|t| t.try_borrow_mut().ok().and_then(|mut b| b.as_mut().map(f)))
}

fn icon_index(s: IconState) -> usize {
    match s {
        IconState::On => 0,
        IconState::Off => 1,
        IconState::Problem => 2,
    }
}

fn rebuild_icons(t: &mut Tray) {
    let size = tray_icon_size();
    if size == t.icon_size && t.icons_mascot == t.mascot && t.icons.iter().all(|i| !i.is_null()) {
        return;
    }
    for i in t.icons.iter_mut() {
        if !i.is_null() {
            // SAFETY: icons were created by CreateIconIndirect and are replaced right here.
            unsafe { DestroyIcon(*i) };
        }
    }
    t.icon_size = size;
    t.icons_mascot = t.mascot;
    let mascot = t.mascot;
    t.icons = [IconState::On, IconState::Off, IconState::Problem].map(|s| {
        let m = if mascot { load_resource_icon(s, size) } else { null_mut() };
        if m.is_null() { make_hicon(s, size) } else { m }
    });
    t.shown = None; // force the next update to push the new icon
}

fn notify_data(hwnd: HWND, icon: HICON, tip: &str, flags: u32) -> NOTIFYICONDATAW {
    // SAFETY: all-zero is a valid NOTIFYICONDATAW; fields are set below.
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = flags;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = icon;
    for (i, u) in tip.encode_utf16().take(127).enumerate() {
        nid.szTip[i] = u;
    }
    nid
}

fn add_icon(hwnd: HWND, t: &mut Tray) {
    rebuild_icons(t);
    let ev = effective(&t.view, &t.sticky_error);
    let st = icon_state(&ev);
    let tip = tooltip(&ev);
    let mut nid = notify_data(hwnd, t.icons[icon_index(st)], &tip, NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP);
    // SAFETY: nid is fully initialised.
    t.added = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) } != 0;
    if t.added {
        nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_SETVERSION, &nid) };
        t.shown = Some((st, tip));
    }
}

/// Push the current view to the icon, the hidden window title (for `ctl tip`) and an open menu.
fn refresh_ui(hwnd: HWND) {
    with(|t| {
        let ev = effective(&t.view, &t.sticky_error);
        let st = icon_state(&ev);
        let tip = tooltip(&ev);
        if !t.added {
            return;
        }
        if t.shown.as_ref() != Some(&(st, tip.clone())) {
            let nid = notify_data(hwnd, t.icons[icon_index(st)], &tip, NIF_ICON | NIF_TIP | NIF_SHOWTIP);
            // SAFETY: nid is fully initialised.
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
            let w = wide(&tip);
            // SAFETY: valid window and string.
            unsafe { SetWindowTextW(hwnd, w.as_ptr()) };
            t.shown = Some((st, tip));
        }
        if !t.menu.is_null() {
            update_menu(t.menu, &menu_model(&ev), if t.header { Some(st) } else { None });
        }
    });
}

fn balloon(hwnd: HWND, text: &str) {
    with(|t| {
        if !t.added {
            return;
        }
        let mut nid = notify_data(hwnd, null_mut(), "", NIF_INFO);
        for (i, u) in "SONdpi".encode_utf16().enumerate() {
            nid.szInfoTitle[i] = u;
        }
        for (i, u) in text.encode_utf16().take(250).enumerate() {
            nid.szInfo[i] = u;
        }
        nid.dwInfoFlags = NIIF_ERROR;
        // SAFETY: nid is fully initialised.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
    });
}

// ---------------------------------------------------------------------------------------------
// Talking to the service without blocking the UI thread
// ---------------------------------------------------------------------------------------------

fn spawn_request(hwnd: HWND, kind: Kind, cmd: &'static str, timeout_ms: u32, epoch: u64) {
    let h = hwnd as usize;
    let spawned = std::thread::Builder::new().name("sondpi-tray-req".into()).spawn(move || {
        let result = ipc::request_ex(cmd, timeout_ms);
        let installed = match &result {
            Err(ReqError::Unreachable(_)) => install::service_installed(),
            _ => true,
        };
        let b = Box::into_raw(Box::new(Reply { kind, epoch, result, installed }));
        // SAFETY: the window may be gone; on failure the reply is reclaimed below.
        if unsafe { PostMessageW(h as HWND, WM_REPLY, 0, b as LPARAM) } == 0 {
            // SAFETY: the pointer was just created by Box::into_raw and not delivered.
            drop(unsafe { Box::from_raw(b) });
        }
    });
    if spawned.is_err() {
        with(|t| {
            t.polling = false;
            t.toggling = false;
        });
    }
}

fn poll(hwnd: HWND) {
    let epoch = with(|t| {
        if t.polling || t.installing {
            None
        } else {
            t.polling = true;
            Some(t.epoch)
        }
    })
    .flatten();
    if let Some(e) = epoch {
        spawn_request(hwnd, Kind::Poll, "status", POLL_TIMEOUT_MS, e);
    }
}

fn toggle(hwnd: HWND) {
    enum Act {
        Send(&'static str, u64),
        Install,
        Poll,
        Nothing,
    }
    let act = with(|t| {
        if t.toggling || t.installing {
            return Act::Nothing;
        }
        match &t.view {
            View::Live(s) => {
                t.toggling = true;
                t.epoch += 1;
                Act::Send(if s.enabled { "off" } else { "on" }, t.epoch)
            }
            View::Unreachable { installed: false, .. } => Act::Install,
            _ => Act::Poll,
        }
    })
    .unwrap_or(Act::Nothing);
    match act {
        Act::Send(cmd, epoch) => spawn_request(hwnd, Kind::Toggle, cmd, TOGGLE_TIMEOUT_MS, epoch),
        Act::Install => offer_install(hwnd),
        Act::Poll => poll(hwnd),
        Act::Nothing => {}
    }
}

fn on_reply(hwnd: HWND, r: Reply) {
    let mut failure: Option<String> = None;
    let applied = with(|t| {
        match r.kind {
            Kind::Poll => {
                t.polling = false;
                if r.epoch != t.epoch {
                    return false; // a toggle happened meanwhile; this answer is stale
                }
                if t.sticky_ttl > 0 {
                    t.sticky_ttl -= 1;
                    if t.sticky_ttl == 0 {
                        t.sticky_error = None;
                    }
                }
            }
            Kind::Toggle => t.toggling = false,
        }
        match r.result {
            Ok(s) => {
                if r.kind == Kind::Toggle {
                    t.sticky_error = None;
                }
                t.view = View::Live(s);
            }
            Err(ReqError::Service(m)) if r.kind == Kind::Toggle => {
                t.sticky_error = Some(m.clone());
                t.sticky_ttl = 5;
                failure = Some(m);
            }
            Err(ReqError::Timeout) => {
                t.view = View::Unreachable { installed: true, reason: "servis yanıt vermiyor".into() };
            }
            Err(e) => {
                let installed = r.installed;
                let reason = if installed { e.to_string() } else { "kurulu değil".into() };
                t.view = View::Unreachable { installed, reason };
            }
        }
        true
    });
    if applied == Some(true) {
        refresh_ui(hwnd);
    }
    if let Some(m) = failure {
        balloon(hwnd, &format!("Anahtar çevrilemedi: {m}"));
        poll(hwnd);
    }
}

// ---------------------------------------------------------------------------------------------
// Install offer
// ---------------------------------------------------------------------------------------------

fn message_yes_no(hwnd: HWND, text: &str) -> bool {
    let t = wide(text);
    let title = wide(api::APP_NAME);
    // SAFETY: both strings NUL-terminated.
    unsafe { MessageBoxW(hwnd, t.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONQUESTION) == IDYES }
}

fn offer_install(hwnd: HWND) {
    let ok = with(|t| {
        if t.installing {
            false
        } else {
            t.installing = true;
            true
        }
    })
    .unwrap_or(false);
    if !ok {
        return;
    }
    let yes = message_yes_no(
        hwnd,
        "SONdpi bu bilgisayara kurulacak: arka planda çalışan bir hizmet ve bu anahtar eklenecek. Windows yönetici onayı isteyecek. Kurulsun mu?",
    );
    if !yes {
        with(|t| t.installing = false);
        return;
    }
    let h = hwnd as usize;
    let spawned = std::thread::Builder::new().name("sondpi-tray-install".into()).spawn(move || {
        // Elevates itself, waits, registers the autostart for this user and shows its own errors.
        let code = install::install(&["--no-tray".to_string()]);
        // SAFETY: the window may be gone; nothing to reclaim.
        unsafe { PostMessageW(h as HWND, WM_INSTALL_DONE, code as WPARAM, 0) };
    });
    if spawned.is_err() {
        with(|t| t.installing = false);
    }
}

// ---------------------------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------------------------

// ----- the owner-drawn mascot header -----

#[derive(Clone, Copy)]
struct HeaderGeom {
    dpi: u32,
    px: i32,
    /// Portrait icons per state (index as icon_index), 0 when not loaded.
    icons: [usize; 3],
}

thread_local! {
    /// Kept apart from the tray state: Windows asks for the item's size synchronously while the
    /// menu is being changed under a state borrow.
    static HEADER: Cell<HeaderGeom> = const { Cell::new(HeaderGeom { dpi: 96, px: 128, icons: [0; 3] }) };
}

fn state_from_data(d: usize) -> IconState {
    match d {
        1 => IconState::On,
        3 => IconState::Problem,
        _ => IconState::Off,
    }
}

fn rgb(c: (u8, u8, u8)) -> u32 {
    c.0 as u32 | (c.1 as u32) << 8 | (c.2 as u32) << 16
}

fn monitor_dpi(at: POINT) -> u32 {
    // SAFETY: plain queries; falls back to the system DPI.
    unsafe {
        let mon = MonitorFromPoint(at, MONITOR_DEFAULTTONEAREST);
        let (mut x, mut y) = (0u32, 0u32);
        if !mon.is_null() && GetDpiForMonitor(mon, MDT_EFFECTIVE_DPI, &mut x, &mut y) == 0 && x != 0 {
            x
        } else {
            GetDpiForSystem().max(96)
        }
    }
}

/// Portraits of all three states at 128 dip scaled to dpi.
fn load_portraits(dpi: u32) -> HeaderGeom {
    let px = scale(dpi, 128);
    let mut icons = [0usize; 3];
    for s in [IconState::On, IconState::Off, IconState::Problem] {
        // SAFETY: MAKEINTRESOURCE(id); the icon is ours and freed in free_portraits.
        let h = unsafe {
            LoadImageW(GetModuleHandleW(null()), portrait_resource_id(s) as usize as *const u16, IMAGE_ICON, px, px, LR_DEFAULTCOLOR)
        };
        icons[icon_index(s)] = h as usize;
    }
    HeaderGeom { dpi, px, icons }
}

fn free_portraits(g: &HeaderGeom) {
    for h in g.icons {
        if h != 0 {
            // SAFETY: created by LoadImageW in load_portraits.
            unsafe { DestroyIcon(h as HICON) };
        }
    }
}

/// Menu fonts (regular, bold) at dpi; free both with DeleteGdi.
fn menu_fonts(dpi: u32) -> (*mut std::ffi::c_void, *mut std::ffi::c_void) {
    // SAFETY: all-zero is a valid NONCLIENTMETRICSW; cbSize is set before the call.
    let mut ncm: NONCLIENTMETRICSW = unsafe { std::mem::zeroed() };
    ncm.cbSize = std::mem::size_of::<NONCLIENTMETRICSW>() as u32;
    // SAFETY: valid struct of the declared size.
    unsafe { SystemParametersInfoForDpi(0x29, ncm.cbSize, &mut ncm as *mut _ as *mut std::ffi::c_void, 0, dpi) };
    let mut bold = ncm.lfMenuFont;
    bold.lfWeight = 700;
    // SAFETY: fonts are deleted by the caller.
    unsafe { (CreateFontIndirectW(&ncm.lfMenuFont), CreateFontIndirectW(&bold)) }
}

fn text_height(hdc: *mut std::ffi::c_void, font: *mut std::ffi::c_void) -> i32 {
    // SAFETY: all-zero is a valid TEXTMETRICW; the font stays selected only for the query.
    unsafe {
        let mut tm: TEXTMETRICW = std::mem::zeroed();
        let old = SelectObject(hdc, font);
        GetTextMetricsW(hdc, &mut tm);
        SelectObject(hdc, old);
        tm.tmHeight
    }
}

fn on_measure_item(hwnd: HWND, mi: &mut MEASUREITEMSTRUCT) {
    let g = HEADER.get();
    let (reg, bold) = menu_fonts(g.dpi);
    // SAFETY: DC of our window for the measurement only; fonts freed.
    let m = unsafe {
        let hdc = GetDcGdi(hwnd);
        let m = header_metrics(g.dpi, g.px, text_height(hdc, bold), text_height(hdc, reg));
        ReleaseDcGdi(hwnd, hdc);
        DeleteGdi(reg);
        DeleteGdi(bold);
        m
    };
    mi.itemWidth = m.width as u32;
    mi.itemHeight = m.height as u32;
}

fn on_draw_item(dis: &DRAWITEMSTRUCT) {
    let g = HEADER.get();
    let st = state_from_data(dis.itemData);
    let (reg, bold) = menu_fonts(g.dpi);
    let hdc = dis.hDC;
    let rc = dis.rcItem;
    // SAFETY: drawing into the DC Windows handed us; everything selected is restored, fonts freed.
    unsafe {
        FillRect(hdc, &rc, GetSysColorBrush(COLOR_MENU));
        let m = header_metrics(g.dpi, g.px, text_height(hdc, bold), text_height(hdc, reg));
        let icon = g.icons[icon_index(st)];
        if icon != 0 {
            let x = rc.left + ((rc.right - rc.left) - g.px) / 2;
            DrawIconEx(hdc, x, rc.top + m.icon_y, icon as HICON, g.px, g.px, 0, null_mut(), DI_NORMAL);
        }
        SetBkMode(hdc, TRANSPARENT as i32);
        let old = SelectObject(hdc, bold);
        SetTextColor(hdc, GetSysColor(COLOR_MENUTEXT));
        let mut r = RECT { left: rc.left, top: rc.top + m.title_y, right: rc.right, bottom: rc.top + m.title_y + text_height(hdc, bold) };
        let t = wide("SONdpi");
        DrawTextW(hdc, t.as_ptr(), -1, &mut r, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, reg);
        SetTextColor(hdc, rgb(state_line_color(st)));
        let mut r = RECT { left: rc.left, top: rc.top + m.line_y, right: rc.right, bottom: rc.top + m.line_y + text_height(hdc, reg) };
        let t = wide(state_line(st));
        DrawTextW(hdc, t.as_ptr(), -1, &mut r, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, old);
        DeleteGdi(reg);
        DeleteGdi(bold);
    }
}

fn append_header(menu: HMENU, st: IconState) {
    // SAFETY: owner-drawn item; the app value carries the state (1 on, 2 off, 3 problem).
    unsafe { AppendMenuW(menu, MF_OWNERDRAW | MF_DISABLED, ID_HEADER, resource_id(st) as usize as *const u16) };
}

fn item_flags(grayed: bool, checked: Option<bool>) -> u32 {
    let mut f = MF_STRING;
    if grayed {
        f |= MF_GRAYED;
    }
    match checked {
        Some(true) => f |= MF_CHECKED,
        Some(false) => f |= MF_UNCHECKED,
        None => {}
    }
    f
}

fn update_menu(menu: HMENU, m: &MenuModel, header: Option<IconState>) {
    if let Some(st) = header {
        // SAFETY: re-sets the owner-drawn item so it is redrawn with the new state.
        unsafe { ModifyMenuW(menu, ID_HEADER as u32, MF_BYCOMMAND | MF_OWNERDRAW | MF_DISABLED, ID_HEADER, resource_id(st) as usize as *const u16) };
    }
    for (i, line) in m.lines.iter().enumerate() {
        let id = ID_INFO_BASE + i;
        let w = wide(line);
        // SAFETY: menu handle is alive while stored in the state; the string outlives the call.
        unsafe { ModifyMenuW(menu, id as u32, MF_BYCOMMAND | item_flags(true, None), id, w.as_ptr()) };
    }
    if let Some(e) = &m.error {
        let w = wide(e);
        // SAFETY: as above; fails harmlessly when the item does not exist.
        unsafe { ModifyMenuW(menu, ID_ERROR as u32, MF_BYCOMMAND | item_flags(true, None), ID_ERROR, w.as_ptr()) };
    }
    // SAFETY: as above.
    unsafe { CheckMenuItem(menu, ID_TOGGLE as u32, MF_BYCOMMAND | if m.checked { MF_CHECKED } else { MF_UNCHECKED }) };
}

fn append(menu: HMENU, flags: u32, id: usize, text: &str) {
    let w = wide(text);
    // SAFETY: valid popup menu and string.
    unsafe { AppendMenuW(menu, flags, id, w.as_ptr()) };
}

fn show_menu(hwnd: HWND, at: POINT) {
    let Some(ev) = with(|t| effective(&t.view, &t.sticky_error)) else { return };
    // Refresh while the menu is open: the answer updates the items in place.
    poll(hwnd);
    let auto = install::autostart_enabled();
    let mascot = with(|t| t.mascot).unwrap_or(true);
    // SAFETY: creates a popup menu we destroy below.
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }
    let mut entries = menu_entries(&ev, auto, mascot);
    let mut geom = None;
    if entries.first().map(|e| e.header.is_some()).unwrap_or(false) {
        let g = load_portraits(monitor_dpi(at));
        if g.icons[icon_index(icon_state(&ev))] == 0 {
            // No portrait (no resources): the menu is the plain one.
            free_portraits(&g);
            entries.drain(..2);
        } else {
            HEADER.set(g);
            geom = Some(g);
        }
    }
    with(|t| t.header = geom.is_some());
    for e in entries {
        if let Some(st) = e.header {
            append_header(menu, st);
        } else if e.separator {
            // SAFETY: valid menu.
            unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, null()) };
        } else {
            append(menu, item_flags(e.grayed, e.checked), e.id, &e.text);
        }
    }
    with(|t| t.menu = menu);

    // SAFETY: standard tray-menu sequence; the menu loop pumps messages, so no state borrow is held.
    let cmd = unsafe {
        SetForegroundWindow(hwnd);
        let c = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, at.x, at.y, 0, hwnd, null());
        PostMessageW(hwnd, WM_NULL, 0, 0);
        c
    };
    with(|t| {
        t.menu = null_mut();
        t.header = false;
    });
    // SAFETY: menu created above and no longer tracked.
    unsafe { DestroyMenu(menu) };
    if let Some(g) = geom {
        free_portraits(&g);
        HEADER.set(HeaderGeom { dpi: 96, px: 128, icons: [0; 3] });
    }

    match cmd as usize {
        ID_TOGGLE => toggle(hwnd),
        ID_AUTOSTART => {
            if let Err(e) = install::autostart_set(!auto) {
                balloon(hwnd, &format!("Başlangıç ayarı değiştirilemedi: {e}"));
            }
        }
        ID_MASCOT => match set_mascot(!mascot) {
            Ok(()) => {
                with(|t| {
                    t.mascot = !mascot;
                    rebuild_icons(t);
                });
                refresh_ui(hwnd);
            }
            Err(e) => balloon(hwnd, &format!("Ayar değiştirilemedi: {e}")),
        },
        ID_UNINSTALL => uninstall_from_menu(hwnd),
        ID_EXIT => {
            // SAFETY: closes our own window.
            unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
        }
        _ => {}
    }
}

fn uninstall_from_menu(hwnd: HWND) {
    if !message_yes_no(hwnd, "SONdpi bu bilgisayardan kaldırılsın mı? Windows yönetici onayı isteyecek.") {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return balloon(hwnd, &format!("Kaldırılamadı: {e}")),
    };
    match install::shell_run(&exe, "uninstall", true, false, true) {
        Ok(_) => {
            let _ = install::autostart_set(false);
            install::remove_user_settings();
            // SAFETY: closes our own window; the elevated uninstaller carries on without us.
            unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
        }
        Err(e) => balloon(hwnd, &format!("Kaldırılamadı: {e}")),
    }
}

// ---------------------------------------------------------------------------------------------
// Window procedure and entry point
// ---------------------------------------------------------------------------------------------

fn loword(v: isize) -> u32 {
    (v as usize & 0xFFFF) as u32
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let tc = with(|t| t.taskbar_created).unwrap_or(0);
    if tc != 0 && msg == tc {
        // Explorer restarted: the icon is gone, put it back.
        with(|t| {
            t.added = false;
            t.icon_size = 0;
            add_icon(hwnd, t);
        });
        refresh_ui(hwnd);
        return 0;
    }
    match msg {
        WM_TRAY => {
            let ev = loword(lp);
            match ev {
                NIN_SELECT | NIN_KEYSELECT | WM_LBUTTONUP => {
                    // SAFETY: trivial.
                    let now = unsafe { GetTickCount64() };
                    let go = with(|t| {
                        if now.saturating_sub(t.last_click) < CLICK_DEBOUNCE_MS {
                            false
                        } else {
                            t.last_click = now;
                            true
                        }
                    })
                    .unwrap_or(false);
                    if go {
                        toggle(hwnd);
                    }
                }
                WM_CONTEXTMENU => {
                    let mut pt = POINT { x: (wp & 0xFFFF) as i16 as i32, y: ((wp >> 16) & 0xFFFF) as i16 as i32 };
                    if pt.x == 0 && pt.y == 0 {
                        // SAFETY: valid out pointer.
                        unsafe { GetCursorPos(&mut pt) };
                    }
                    show_menu(hwnd, pt);
                }
                _ => {}
            }
            0
        }
        WM_REPLY => {
            // SAFETY: lp was produced by Box::into_raw in spawn_request and is delivered once.
            let r = unsafe { Box::from_raw(lp as *mut Reply) };
            on_reply(hwnd, *r);
            0
        }
        WM_MEASUREITEM => {
            // SAFETY: for owner-drawn menu items lp points to a MEASUREITEMSTRUCT.
            let mi = unsafe { &mut *(lp as *mut MEASUREITEMSTRUCT) };
            if mi.CtlType == 1 && mi.CtlID as usize == ID_HEADER || mi.itemID as usize == ID_HEADER {
                on_measure_item(hwnd, mi);
                return 1;
            }
            // SAFETY: default handling.
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }
        WM_DRAWITEM => {
            // SAFETY: for owner-drawn menu items lp points to a DRAWITEMSTRUCT.
            let dis = unsafe { &*(lp as *const DRAWITEMSTRUCT) };
            if dis.itemID as usize == ID_HEADER {
                on_draw_item(dis);
                return 1;
            }
            // SAFETY: default handling.
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }
        WM_TIMER if wp == TIMER_POLL => {
            poll(hwnd);
            0
        }
        WM_FIRST_RUN => {
            let need = with(|t| !t.no_setup).unwrap_or(false) && !install::service_installed();
            if need {
                offer_install(hwnd);
            }
            0
        }
        WM_INSTALL_DONE => {
            with(|t| {
                t.installing = false;
                t.view = View::Connecting;
            });
            poll(hwnd);
            0
        }
        WM_DISPLAYCHANGE | WM_SETTINGCHANGE => {
            let changed = with(|t| {
                let before = t.icon_size;
                rebuild_icons(t);
                before != t.icon_size
            })
            .unwrap_or(false);
            if changed {
                refresh_ui(hwnd);
            }
            // SAFETY: default handling.
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }
        WM_CLOSE => {
            // SAFETY: destroys our own window.
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_ENDSESSION | WM_DESTROY => {
            with(|t| {
                if t.added {
                    let nid = notify_data(hwnd, null_mut(), "", 0);
                    // SAFETY: nid is fully initialised.
                    unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
                    t.added = false;
                }
            });
            if msg == WM_DESTROY {
                // SAFETY: ends the message loop.
                unsafe {
                    KillTimer(hwnd, TIMER_POLL);
                    PostQuitMessage(0);
                }
            }
            0
        }
        // SAFETY: default handling.
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

fn attach_console() {
    // SAFETY: best effort so `ctl` output shows up when started from a console in a GUI build.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() || h as isize == -1 {
            let name = wide("CONOUT$");
            let out = CreateFileW(name.as_ptr(), GENERIC_WRITE, FILE_SHARE_WRITE, null(), OPEN_EXISTING, 0, null_mut());
            if out as isize != -1 {
                SetStdHandle(STD_OUTPUT_HANDLE, out);
            }
        }
    }
}

fn find_tray_window() -> HWND {
    let class = wide(&class_name());
    // SAFETY: valid class name.
    unsafe { FindWindowW(class.as_ptr(), null()) }
}

fn format_status(s: &Status) -> String {
    format!(
        "enabled={} active={} strategy={} desynced={} redialed={} dns_answered={} error={}",
        s.enabled,
        s.active,
        s.strategy,
        s.desynced,
        s.redialed,
        s.dns_answered,
        s.error.as_deref().unwrap_or("-")
    )
}

/// `sondpi ctl ...`: developer commands.
fn run_ctl(args: &[String]) -> i32 {
    attach_console();
    match args.first().map(String::as_str) {
        Some(c @ ("status" | "on" | "off")) => match ipc::request_ex(c, 20_000) {
            Ok(s) => {
                println!("{}", format_status(&s));
                0
            }
            Err(e) => {
                eprintln!("hata: {e}");
                1
            }
        },
        Some(c @ ("click" | "menu")) => {
            let h = find_tray_window();
            if h.is_null() {
                eprintln!("tepsi çalışmıyor");
                return 1;
            }
            let ev = if c == "click" { NIN_SELECT } else { WM_CONTEXTMENU };
            // SAFETY: posts to another window of this program.
            unsafe { PostMessageW(h, WM_TRAY, 0, ev as LPARAM) };
            0
        }
        Some("tip") => {
            let h = find_tray_window();
            if h.is_null() {
                eprintln!("tepsi çalışmıyor");
                return 1;
            }
            let mut buf = [0u16; 256];
            // SAFETY: buffer length passed.
            let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
            println!("{}", String::from_utf16_lossy(&buf[..n.max(0) as usize]));
            0
        }
        _ => {
            eprintln!("kullanım: sondpi ctl status|on|off|click|tip");
            2
        }
    }
}

/// Entry point for plain `sondpi`; returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    if args.first().map(String::as_str) == Some("ctl") {
        return run_ctl(&args[1..]);
    }
    let no_setup = args.iter().any(|a| a == "--no-setup");
    // A leftover of an earlier upgrade (best effort; needs write access to the install folder).
    install::cleanup_installed_leftovers();

    // SAFETY: process-wide setting, must precede window creation; failure just leaves defaults.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };

    let mname = wide(&format!("Local\\SONdpi.Tray.Instance{}", dev_suffix()));
    // SAFETY: valid name; the handle lives until the process exits.
    let mutex = unsafe { CreateMutexW(null(), 0, mname.as_ptr()) };
    // SAFETY: trivial.
    if mutex.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return 0;
    }

    // SAFETY: null module name = this executable.
    let hinst = unsafe { GetModuleHandleW(null()) };
    let class = wide(&class_name());
    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: 0,
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinst,
        hIcon: null_mut(),
        hCursor: null_mut(),
        hbrBackground: null_mut(),
        lpszMenuName: null(),
        lpszClassName: class.as_ptr(),
        hIconSm: null_mut(),
    };
    // SAFETY: wc is fully initialised.
    if unsafe { RegisterClassExW(&wc) } == 0 {
        eprintln!("pencere sınıfı kaydedilemedi");
        return 1;
    }
    let created = wide("TaskbarCreated");
    // SAFETY: valid string.
    let taskbar_created = unsafe { RegisterWindowMessageW(created.as_ptr()) };
    TRAY.with(|t| {
        *t.borrow_mut() = Some(Tray {
            view: View::Connecting,
            sticky_error: None,
            sticky_ttl: 0,
            icons: [null_mut(); 3],
            icon_size: 0,
            icons_mascot: false,
            mascot: mascot_enabled(),
            header: false,
            shown: None,
            added: false,
            polling: false,
            toggling: false,
            installing: false,
            epoch: 0,
            last_click: 0,
            menu: null_mut(),
            taskbar_created,
            no_setup,
        });
    });
    let title = wide("SONdpi");
    // A hidden top-level window (not message-only: those never get the TaskbarCreated broadcast).
    // SAFETY: valid class and title strings.
    let hwnd = unsafe { CreateWindowExW(0x80, class.as_ptr(), title.as_ptr(), 0, 0, 0, 0, 0, null_mut(), null_mut(), hinst, null()) };
    if hwnd.is_null() {
        eprintln!("pencere oluşturulamadı");
        return 1;
    }
    with(|t| add_icon(hwnd, t));
    refresh_ui(hwnd);
    // SAFETY: valid window; the timer drives the status refresh.
    unsafe {
        SetTimer(hwnd, TIMER_POLL, POLL_MS, None);
        PostMessageW(hwnd, WM_FIRST_RUN, 0, 0);
    }
    poll(hwnd);

    // SAFETY: all-zero is a valid MSG.
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    // SAFETY: standard message loop on the thread that owns the window.
    unsafe {
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    with(|t| {
        for i in t.icons.iter() {
            if !i.is_null() {
                // SAFETY: icons created by make_hicon; the window is gone.
                unsafe { DestroyIcon(*i) };
            }
        }
    });
    // SAFETY: closes the mutex handle; the instance guard ends with the process anyway.
    unsafe { CloseHandle(mutex) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(enabled: bool, active: bool) -> Status {
        Status { enabled, active, strategy: "fake".into(), desynced: 12, redialed: 3, dns_answered: 40, error: None }
    }

    #[test]
    fn icon_states() {
        assert_eq!(icon_state(&View::Connecting), IconState::Off);
        assert_eq!(icon_state(&View::Live(live(true, true))), IconState::On);
        assert_eq!(icon_state(&View::Live(live(false, false))), IconState::Off);
        assert_eq!(icon_state(&View::Live(live(true, false))), IconState::Problem);
        let mut e = live(true, true);
        e.error = Some("sürücü".into());
        assert_eq!(icon_state(&View::Live(e)), IconState::Problem);
        assert_eq!(icon_state(&View::Unreachable { installed: true, reason: "x".into() }), IconState::Problem);
    }

    #[test]
    fn tooltips() {
        assert_eq!(tooltip(&View::Live(live(true, true))), "SONdpi: açık, 12 bağlantı korundu");
        assert_eq!(tooltip(&View::Live(live(false, false))), "SONdpi: kapalı");
        let mut fresh = live(true, true);
        fresh.desynced = 0;
        fresh.redialed = 0;
        assert_eq!(tooltip(&View::Live(fresh)), "SONdpi: açık, hazır");
        assert!(tooltip(&View::Unreachable { installed: false, reason: String::new() }).contains("kurulu değil"));
        assert!(tooltip(&View::Unreachable { installed: true, reason: "servis çalışmıyor".into() }).contains("servis çalışmıyor"));
        let mut e = live(true, true);
        e.error = Some("ç".repeat(500));
        let t = tooltip(&View::Live(e));
        assert!(t.encode_utf16().count() <= 127);
    }

    #[test]
    fn menu_lines() {
        let m = menu_model(&View::Live(live(true, true)));
        assert!(m.checked);
        assert_eq!(m.lines, ["Korunan bağlantı: 12", "Kurtarılan bağlantı: 3", "DNS yanıtı: 40"]);
        assert_eq!(m.error, None);
        let mut e = live(false, false);
        e.error = Some("boom".into());
        let m = menu_model(&View::Live(e));
        assert!(!m.checked);
        assert_eq!(m.error.as_deref(), Some("boom"));
        let m = menu_model(&View::Unreachable { installed: true, reason: "servis çalışmıyor".into() });
        assert_eq!(m.lines[0], "Korunan bağlantı: –");
        assert_eq!(m.error.as_deref(), Some("servis çalışmıyor"));
    }

    #[test]
    fn mascot_setting_default_and_parse() {
        assert!(parse_mascot(None));
        assert!(parse_mascot(Some(1)));
        assert!(parse_mascot(Some(7)));
        assert!(!parse_mascot(Some(0)));
    }

    #[test]
    fn resource_ids_per_state() {
        assert_eq!(resource_id(IconState::On), 1);
        assert_eq!(resource_id(IconState::Off), 2);
        assert_eq!(resource_id(IconState::Problem), 3);
    }

    #[test]
    fn menu_order_and_mascot_item() {
        let ids = |m: &[MenuEntry]| m.iter().map(|e| e.text.clone()).collect::<Vec<_>>();
        let m = menu_entries(&View::Live(live(true, true)), true, false);
        assert_eq!(
            ids(&m),
            ["Açık", "Korunan bağlantı: 12", "Kurtarılan bağlantı: 3", "DNS yanıtı: 40", "", "Windows açılışında başlat", "Maskot simgesi", "SONdpi'yi kaldır…", "", "Çıkış"]
        );
        let at = |t: &str| m.iter().find(|e| e.text == t).unwrap();
        assert_eq!(at("Açık").checked, Some(true));
        assert_eq!(at("Windows açılışında başlat").checked, Some(true));
        assert_eq!(at("Maskot simgesi").checked, Some(false));
        assert!(!at("Maskot simgesi").grayed && !at("Maskot simgesi").separator);
        assert!(m[1..4].iter().all(|e| e.grayed));
        assert_eq!(m.iter().filter(|e| e.separator).count(), 2);
        // An error adds one disabled line after the counters; the mascot item stays under autostart.
        let mut e = live(false, false);
        e.error = Some("boom".into());
        let m = menu_entries(&View::Live(e), false, true);
        // Mascot on: header and its separator come first.
        assert_eq!(m[0].header, Some(IconState::Problem));
        assert!(m[1].separator);
        assert_eq!(m[6].text, "boom");
        assert!(m[6].grayed);
        let pos = |t: &str| m.iter().position(|x| x.text == t).unwrap();
        assert_eq!(pos("Maskot simgesi"), pos("Windows açılışında başlat") + 1);
        assert_eq!(m[pos("Maskot simgesi")].checked, Some(true));
    }

    #[test]
    fn header_only_with_mascot() {
        let v = View::Live(live(true, true));
        let on = menu_entries(&v, false, true);
        assert_eq!(on[0].header, Some(IconState::On));
        assert_eq!(on[0].id, ID_HEADER);
        assert_eq!(on[0].text, "Açık");
        assert!(on[0].grayed && !on[0].separator);
        assert!(on[1].separator);
        assert_eq!(on[2].text, "Açık");
        assert_eq!(on[2].checked, Some(true));
        let off = menu_entries(&v, false, false);
        assert!(off.iter().all(|e| e.header.is_none()));
        assert_eq!(off[0].id, ID_TOGGLE);
        assert_eq!(on.len(), off.len() + 2);
        assert_eq!(menu_entries(&View::Live(live(false, false)), false, true)[0].header, Some(IconState::Off));
    }

    #[test]
    fn portrait_resources_and_state_lines() {
        assert_eq!(portrait_resource_id(IconState::On), 11);
        assert_eq!(portrait_resource_id(IconState::Off), 12);
        assert_eq!(portrait_resource_id(IconState::Problem), 13);
        assert_eq!(state_line(IconState::On), "Açık");
        assert_eq!(state_line(IconState::Off), "Kapalı");
        assert_eq!(state_line(IconState::Problem), "Sorun var");
        let (g, k, a) = (state_line_color(IconState::On), state_line_color(IconState::Off), state_line_color(IconState::Problem));
        assert!(g.1 > g.0 && g.1 > g.2, "green");
        assert!(k.0.abs_diff(k.2) < 40 && k.0 > 90, "grey");
        assert!(a.0 > 200 && a.1 > 120 && a.2 < 60, "amber");
        assert!(g != k && k != a && g != a);
        assert_eq!(state_from_data(resource_id(IconState::On) as usize), IconState::On);
        assert_eq!(state_from_data(resource_id(IconState::Off) as usize), IconState::Off);
        assert_eq!(state_from_data(resource_id(IconState::Problem) as usize), IconState::Problem);
    }

    #[test]
    fn header_metrics_scale_with_dpi() {
        let at = |dpi: u32| header_metrics(dpi, 128 * dpi as i32 / 96, 16 * dpi as i32 / 96, 16 * dpi as i32 / 96);
        let (a, b, c) = (at(96), at(144), at(192));
        assert_eq!(a.width, 168);
        assert!(b.height * 2 == a.height * 3 || (b.height * 2 - a.height * 3).abs() <= 3);
        assert!(c.height * 1 >= a.height * 2 - 4 && c.height <= a.height * 2 + 4);
        for m in [a, b, c] {
            assert!(m.icon_y > 0 && m.title_y > m.icon_y && m.line_y > m.title_y && m.height > m.line_y);
        }
    }

    #[test]
    fn sticky_error_merges_only_when_service_has_none() {
        let v = View::Live(live(false, false));
        let merged = effective(&v, &Some("açılamadı".into()));
        assert_eq!(icon_state(&merged), IconState::Problem);
        assert_eq!(effective(&v, &None), v);
        let mut own = live(false, false);
        own.error = Some("kendi".into());
        match effective(&View::Live(own), &Some("öteki".into())) {
            View::Live(s) => assert_eq!(s.error.as_deref(), Some("kendi")),
            _ => panic!(),
        }
    }

    #[test]
    fn icons_render_distinctly_at_all_sizes() {
        for size in [16usize, 20, 24, 32, 48] {
            let mut centers = Vec::new();
            for s in [IconState::On, IconState::Off, IconState::Problem] {
                let px = render_icon(s, size);
                assert_eq!(px.len(), size * size * 4);
                // Corner is transparent, pill body is opaque.
                assert_eq!(px[3], 0);
                let mid = (size / 2 * size + size / 6) * 4;
                assert_eq!(px[mid + 3], 255, "state {s:?} size {size}");
                centers.push((px[mid], px[mid + 1], px[mid + 2]));
                let opaque = px.chunks(4).filter(|p| p[3] > 0).count();
                assert!(opaque > size * size / 3, "glyph too small at {size}");
            }
            assert_ne!(centers[0], centers[1]);
            assert_ne!(centers[1], centers[2]);
            assert_ne!(centers[0], centers[2]);
        }
        // The knob is on the right when on and on the left when off.
        let on = render_icon(IconState::On, 32);
        let off = render_icon(IconState::Off, 32);
        let white = |px: &[u8], x: usize| px[(16 * 32 + x) * 4 + 2] > 240;
        assert!(white(&on, 24) && !white(&on, 8));
        assert!(white(&off, 8) && !white(&off, 24));
    }
}
