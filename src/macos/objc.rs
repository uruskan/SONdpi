//! The few pieces of the Objective-C runtime the menu-bar app needs, declared by hand.
//!
//! `objc_msgSend` has no fixed signature: every call casts it to the exact C signature of the
//! method being called (`send0`..`send3`). Only scalar, pointer and small-struct arguments and
//! scalar/pointer returns are used, which `objc_msgSend` handles on arm64 and x86_64 alike.

use std::ffi::{c_char, c_void, CString};

pub type Id = *mut c_void;
pub type Sel = *mut c_void;
pub const NIL: Id = std::ptr::null_mut();

#[link(name = "objc")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    fn objc_allocateClassPair(superclass: Id, name: *const c_char, extra: usize) -> Id;
    fn objc_registerClassPair(cls: Id);
    fn class_addMethod(cls: Id, name: Sel, imp: *const c_void, types: *const c_char) -> bool;
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);
}

#[link(name = "AppKit", kind = "framework")]
extern "C" {}
#[link(name = "Foundation", kind = "framework")]
extern "C" {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NSSize {
    pub width: f64,
    pub height: f64,
}

pub fn cstr(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

pub fn class(name: &str) -> Id {
    let n = cstr(name);
    // SAFETY: `n` is a valid NUL-terminated string for the duration of the call.
    unsafe { objc_getClass(n.as_ptr()) }
}

pub fn sel(name: &str) -> Sel {
    let n = cstr(name);
    // SAFETY: as above; selectors are interned by the runtime.
    unsafe { sel_registerName(n.as_ptr()) }
}

/// `[obj sel]`.
///
/// # Safety
/// `obj` must be an object (or nil) that responds to `sel` with signature `R (void)`.
pub unsafe fn send0<R>(obj: Id, s: &str) -> R {
    // SAFETY: the caller guarantees the method signature this cast assumes.
    let f: unsafe extern "C" fn(Id, Sel) -> R = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(s)) }
}

/// `[obj sel:a]`.
///
/// # Safety
/// As [`send0`], for signature `R (A)`.
pub unsafe fn send1<A, R>(obj: Id, s: &str, a: A) -> R {
    // SAFETY: the caller guarantees the method signature this cast assumes.
    let f: unsafe extern "C" fn(Id, Sel, A) -> R = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(s), a) }
}

/// `[obj sel:a b:b]`.
///
/// # Safety
/// As [`send0`], for signature `R (A, B)`.
pub unsafe fn send2<A, B, R>(obj: Id, s: &str, a: A, b: B) -> R {
    // SAFETY: the caller guarantees the method signature this cast assumes.
    let f: unsafe extern "C" fn(Id, Sel, A, B) -> R = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(s), a, b) }
}

/// `[obj sel:a b:b c:c]`.
///
/// # Safety
/// As [`send0`], for signature `R (A, B, C)`.
pub unsafe fn send3<A, B, C, R>(obj: Id, s: &str, a: A, b: B, c: C) -> R {
    // SAFETY: the caller guarantees the method signature this cast assumes.
    let f: unsafe extern "C" fn(Id, Sel, A, B, C) -> R = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(s), a, b, c) }
}

/// `[obj sel:a b:b c:c d:d e:e]`.
///
/// # Safety
/// As [`send0`], for signature `R (A, B, C, D, E)`.
pub unsafe fn send5<A, B, C, D, E, R>(obj: Id, s: &str, a: A, b: B, c: C, d: D, e: E) -> R {
    // SAFETY: the caller guarantees the method signature this cast assumes.
    let f: unsafe extern "C" fn(Id, Sel, A, B, C, D, E) -> R = unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { f(obj, sel(s), a, b, c, d, e) }
}

/// An autoreleased `NSString`.
pub fn nsstring(s: &str) -> Id {
    let c = cstr(s);
    // SAFETY: `stringWithUTF8String:` copies the NUL-terminated UTF-8 bytes.
    unsafe { send1(class("NSString"), "stringWithUTF8String:", c.as_ptr()) }
}

/// An autoreleased `NSData` copy of `bytes`.
pub fn nsdata(bytes: &[u8]) -> Id {
    // SAFETY: `dataWithBytes:length:` copies `len` bytes from a live slice.
    unsafe { send2(class("NSData"), "dataWithBytes:length:", bytes.as_ptr() as *const c_void, bytes.len()) }
}

/// A new subclass of `superclass` with the given instance methods
/// (selector, implementation, type encoding). Nil if the name is taken.
pub fn make_class(name: &str, superclass: &str, methods: &[(&str, *const c_void, &str)]) -> Id {
    let n = cstr(name);
    // SAFETY: the superclass exists (AppKit/Foundation are linked); the name is NUL-terminated.
    let cls = unsafe { objc_allocateClassPair(class(superclass), n.as_ptr(), 0) };
    if cls.is_null() {
        return NIL;
    }
    for (s, imp, types) in methods {
        let t = cstr(types);
        // SAFETY: `cls` is a class under construction; `imp` matches `types` (caller's duty).
        unsafe { class_addMethod(cls, sel(s), *imp, t.as_ptr()) };
    }
    // SAFETY: `cls` was allocated above and is registered once.
    unsafe { objc_registerClassPair(cls) };
    cls
}

/// Run `f` inside an autorelease pool.
pub fn with_pool<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: push and pop are paired on this thread.
    let pool = unsafe { objc_autoreleasePoolPush() };
    let r = f();
    // SAFETY: pops the pool pushed above.
    unsafe { objc_autoreleasePoolPop(pool) };
    r
}
