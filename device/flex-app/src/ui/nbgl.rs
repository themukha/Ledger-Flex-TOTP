use core::ffi::CStr;
use core::ffi::{c_char, c_int};
use core::fmt::Write;
use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;
use ledger_device_sdk::sys::{
    nbgl_icon_details_t, nbgl_layoutAddExtendedFooter, nbgl_layoutDescription_t, nbgl_layoutDraw,
    nbgl_layoutFooter_t, nbgl_layoutGet, nbgl_layoutRelease, nbgl_layout_t, nbgl_refresh,
    nbgl_screenRedraw, FOOTER_SIMPLE_TEXT, TUNE_TAP_CASUAL,
};

pub const TOKEN_SETTINGS: u8 = 1;
pub const TOKEN_NAV: u8 = 2;
pub const TOKEN_ROW: u8 = 3;
pub const TOKEN_BACK: u8 = 4;
pub const TOKEN_DELETE: u8 = 5;
pub const TOKEN_HOLD: u8 = 6;
pub const TOKEN_CANCEL: u8 = 7;

pub const SLOT_LEN: usize = 96;
pub const SLOTS: usize = 12;
static mut TEXT: [[u8; SLOT_LEN]; SLOTS] = [[0; SLOT_LEN]; SLOTS];

pub fn put(slot: usize, args: core::fmt::Arguments) -> *const c_char {
    struct W<'a> {
        buf: &'a mut [u8],
        len: usize,
        full: bool,
    }
    impl Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for c in s.chars() {
                let n = c.len_utf8();
                if self.full || self.len + n + 1 > self.buf.len() {
                    self.full = true;
                    return Ok(());
                }
                c.encode_utf8(&mut self.buf[self.len..self.len + n]);
                self.len += n;
            }
            Ok(())
        }
    }
    let buf = unsafe { &mut (*(&raw mut TEXT))[slot] };
    let mut w = W {
        buf,
        len: 0,
        full: false,
    };
    let _ = w.write_fmt(args);
    let end = w.len;
    buf[end] = 0;
    buf.as_ptr() as *const c_char
}

const TRASH: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/Trash_64px.gif", NBGL));
const CHECK: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/Check_Circle_64px.gif", NBGL));

#[derive(Clone, Copy)]
pub enum Icon {
    Trash,
    Check,
}

static mut ICONS: [nbgl_icon_details_t; 2] = unsafe { core::mem::zeroed() };

pub fn icon(icon: Icon) -> *const nbgl_icon_details_t {
    let glyph = match icon {
        Icon::Trash => &TRASH,
        Icon::Check => &CHECK,
    };
    unsafe {
        let slot = &mut (*(&raw mut ICONS))[icon as usize];
        *slot = glyph.into();
        slot
    }
}

static mut PENDING: Option<(u8, u8)> = None;
static mut CURRENT: *mut nbgl_layout_t = core::ptr::null_mut();

unsafe extern "C" fn on_action(token: c_int, index: u8) {
    unsafe { PENDING = Some((token as u8, index)) };
}

pub fn take_action() -> Option<(u8, u8)> {
    unsafe { (*(&raw mut PENDING)).take() }
}

pub fn begin() -> Option<*mut nbgl_layout_t> {
    unsafe {
        if !CURRENT.is_null() {
            nbgl_layoutRelease(CURRENT);
            CURRENT = core::ptr::null_mut();
        }
        PENDING = None;
        let mut desc: nbgl_layoutDescription_t = core::mem::zeroed();
        desc.modal = false;
        desc.onActionCallback = Some(on_action);
        let layout = nbgl_layoutGet(&desc);
        if layout.is_null() {
            return None;
        }
        CURRENT = layout;
        Some(layout)
    }
}

pub fn finish(layout: *mut nbgl_layout_t) {
    unsafe {
        nbgl_layoutDraw(layout);
        nbgl_refresh();
    }
}

pub fn redraw_in_place() {
    unsafe {
        nbgl_screenRedraw();
        nbgl_refresh();
    }
}

pub fn add_footer_text(layout: *mut nbgl_layout_t, text: &'static CStr, token: u8) {
    unsafe {
        let mut footer: nbgl_layoutFooter_t = core::mem::zeroed();
        footer.type_ = FOOTER_SIMPLE_TEXT;
        footer.separationLine = true;
        let simple = &mut footer.__bindgen_anon_1.simpleText;
        simple.text = text.as_ptr();
        simple.token = token;
        simple.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddExtendedFooter(layout, &footer);
    }
}
