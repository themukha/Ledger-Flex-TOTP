use super::nbgl::{
    add_footer_text, begin, finish, icon, put, Icon, TOKEN_BACK, TOKEN_CANCEL, TOKEN_DELETE,
    TOKEN_HOLD, TOKEN_QUIT,
};
use core::ffi::{c_char, CStr};
use ledger_device_sdk::sys::{
    nbgl_contentCenter_t, nbgl_contentTagValueList_t, nbgl_contentTagValue_t, nbgl_icon_details_t,
    nbgl_layoutAddContentCenter, nbgl_layoutAddHeader, nbgl_layoutAddTagValueList,
    nbgl_layoutAddUpFooter, nbgl_layoutHeader_t, nbgl_layoutUpFooter_t, nbgl_layout_t,
    HEADER_EXTENDED_BACK, NBGL_INVALID_TOKEN, TUNE_TAP_CASUAL, UP_FOOTER_BUTTON,
    UP_FOOTER_LONG_PRESS, WHITE_BACKGROUND,
};
use otp_core::record::{Algorithm, Record};

const MAX_PAIRS: usize = 3;
const SLOT_CONFIRM_DESC: usize = 2 * MAX_PAIRS;
const SLOT_CONFIRM_SUB: usize = SLOT_CONFIRM_DESC + 1;

static mut PAIRS: [nbgl_contentTagValue_t; MAX_PAIRS] = unsafe { core::mem::zeroed() };

fn add_back_header(layout: *mut nbgl_layout_t, title: &'static CStr) {
    unsafe {
        let mut header: nbgl_layoutHeader_t = core::mem::zeroed();
        header.type_ = HEADER_EXTENDED_BACK;
        header.separationLine = true;
        let ext = &mut header.__bindgen_anon_1.extendedBack;
        ext.text = title.as_ptr();
        ext.backToken = TOKEN_BACK;
        ext.textToken = NBGL_INVALID_TOKEN as u8;
        ext.actionToken = NBGL_INVALID_TOKEN as u8;
        ext.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddHeader(layout, &header);
    }
}

fn add_pairs(layout: *mut nbgl_layout_t, n: usize) {
    unsafe {
        let pairs = &mut *(&raw mut PAIRS);
        let mut list: nbgl_contentTagValueList_t = core::mem::zeroed();
        list.pairs = pairs.as_ptr();
        list.nbPairs = n.min(MAX_PAIRS) as u8;
        list.smallCaseForValue = true;
        list.wrapping = true;
        list.nbMaxLinesForValue = 2;
        list.hideEndOfLastLine = true;
        list.token = NBGL_INVALID_TOKEN as u8;
        nbgl_layoutAddTagValueList(layout, &list);
    }
}

fn set_pair(i: usize, tag: &'static CStr, value: core::fmt::Arguments) {
    unsafe {
        let pairs = &mut *(&raw mut PAIRS);
        pairs[i] = core::mem::zeroed();
        pairs[i].item = tag.as_ptr();
        pairs[i].value = put(2 * i + 1, value);
    }
}

fn algorithm_name(a: Algorithm) -> &'static str {
    match a {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
    }
}

pub fn draw_details(r: &Record) {
    let Some(layout) = begin() else { return };
    add_back_header(layout, c"Account");
    set_pair(0, c"Issuer", format_args!("{}", r.issuer));
    set_pair(1, c"Account", format_args!("{}", r.account));
    set_pair(
        2,
        c"Algorithm, digits, period",
        format_args!(
            "{}, {} digits, {} s",
            algorithm_name(r.algo),
            r.digits,
            r.period
        ),
    );
    add_pairs(layout, 3);
    add_footer_text(layout, c"Delete account", TOKEN_DELETE);
    finish(layout);
}

pub fn draw_settings(version: (u8, u8, u8), count: usize, capacity: usize) {
    let Some(layout) = begin() else { return };
    add_back_header(layout, c"Settings");
    set_pair(
        0,
        c"Version",
        format_args!("{}.{}.{}", version.0, version.1, version.2),
    );
    set_pair(1, c"Accounts", format_args!("{} of {}", count, capacity));
    add_pairs(layout, 2);
    unsafe {
        let mut up: nbgl_layoutUpFooter_t = core::mem::zeroed();
        up.type_ = UP_FOOTER_BUTTON;
        let button = &mut up.__bindgen_anon_1.button;
        button.text = c"Quit app".as_ptr();
        button.token = TOKEN_QUIT;
        button.style = WHITE_BACKGROUND;
        button.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddUpFooter(layout, &up);
    }
    add_footer_text(layout, c"Delete all accounts", TOKEN_DELETE);
    finish(layout);
}

fn draw_confirm(
    icon: *const nbgl_icon_details_t,
    title: &'static CStr,
    description: *const c_char,
    sub_text: *const c_char,
    hold_text: &'static CStr,
) {
    let Some(layout) = begin() else { return };
    unsafe {
        let mut center: nbgl_contentCenter_t = core::mem::zeroed();
        center.icon = icon;
        center.title = title.as_ptr();
        center.description = description;
        center.subText = sub_text;
        nbgl_layoutAddContentCenter(layout, &center);

        let mut up: nbgl_layoutUpFooter_t = core::mem::zeroed();
        up.type_ = UP_FOOTER_LONG_PRESS;
        let long_press = &mut up.__bindgen_anon_1.longPress;
        long_press.text = hold_text.as_ptr();
        long_press.token = TOKEN_HOLD;
        long_press.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddUpFooter(layout, &up);
    }
    add_footer_text(layout, c"Cancel", TOKEN_CANCEL);
    finish(layout);
}

pub fn draw_confirm_delete(r: &Record) {
    let desc = put(SLOT_CONFIRM_DESC, format_args!("{}", r.issuer));
    let sub = put(SLOT_CONFIRM_SUB, format_args!("{}", r.account));
    draw_confirm(
        icon(Icon::Trash),
        c"Delete account?",
        desc,
        sub,
        c"Hold to delete",
    );
}

pub fn draw_confirm_delete_all() {
    let desc = put(
        SLOT_CONFIRM_DESC,
        format_args!("Every account on this device will be removed."),
    );
    draw_confirm(
        icon(Icon::Trash),
        c"Delete all accounts?",
        desc,
        core::ptr::null(),
        c"Hold to delete",
    );
}

pub fn draw_confirm_export() {
    let desc = put(
        SLOT_CONFIRM_DESC,
        format_args!("Only a device with the same recovery phrase can read it."),
    );
    draw_confirm(
        core::ptr::null(),
        c"Export encrypted backup?",
        desc,
        core::ptr::null(),
        c"Hold to export",
    );
}
