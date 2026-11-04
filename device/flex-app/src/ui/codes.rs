use super::nbgl::{
    add_footer_text, begin, finish, icon, put, redraw_in_place, Icon, TOKEN_NAV, TOKEN_QUIT,
    TOKEN_ROW, TOKEN_SETTINGS, TOKEN_SHOW,
};
use arrayvec::ArrayString;
use core::ffi::CStr;
use ledger_device_sdk::sys::{
    nbgl_contentCenter_t, nbgl_contentTagValueList_t, nbgl_contentTagValue_t, nbgl_icon_details_t,
    nbgl_layoutAddContentCenter, nbgl_layoutAddExtendedFooter, nbgl_layoutAddHeader,
    nbgl_layoutAddTagValueList, nbgl_layoutFooter_t, nbgl_layoutHeader_t, nbgl_layout_t,
    FOOTER_TEXT_AND_NAV, HEADER_EXTENDED_BACK, NBGL_INVALID_TOKEN, TUNE_TAP_CASUAL,
};

pub const ROWS_PER_PAGE: usize = 4;

pub struct CodeRow {
    pub issuer: ArrayString<32>,
    pub code: ArrayString<9>,
    pub remaining: u8,
    pub period: u8,
}

const SLOT_HEADER: usize = 0;
const SLOT_ROWS: usize = 1;

static mut PAIRS: [nbgl_contentTagValue_t; ROWS_PER_PAGE] = unsafe { core::mem::zeroed() };

fn add_home_header(layout: *mut nbgl_layout_t, text: *const core::ffi::c_char) {
    unsafe {
        let mut header: nbgl_layoutHeader_t = core::mem::zeroed();
        header.type_ = HEADER_EXTENDED_BACK;
        header.separationLine = true;
        let ext = &mut header.__bindgen_anon_1.extendedBack;
        ext.text = text;
        ext.actionIcon = icon(Icon::Close);
        ext.actionToken = TOKEN_QUIT;
        ext.backToken = NBGL_INVALID_TOKEN as u8;
        ext.textToken = NBGL_INVALID_TOKEN as u8;
        ext.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddHeader(layout, &header);
    }
}

fn add_header(layout: *mut nbgl_layout_t, time: &str) {
    add_home_header(layout, put(SLOT_HEADER, format_args!("Codes  {}", time)));
}

fn add_center(
    layout: *mut nbgl_layout_t,
    icon: *const nbgl_icon_details_t,
    title: &'static CStr,
    description: Option<&'static CStr>,
) {
    unsafe {
        let mut center: nbgl_contentCenter_t = core::mem::zeroed();
        center.icon = icon;
        center.title = title.as_ptr();
        center.description = description.map_or(core::ptr::null(), |d| d.as_ptr());
        nbgl_layoutAddContentCenter(layout, &center);
    }
}

fn fill(rows: &[CodeRow], header_time: &str) {
    put(SLOT_HEADER, format_args!("Codes  {}", header_time));
    let pairs = unsafe { &mut *(&raw mut PAIRS) };
    for (i, row) in rows.iter().enumerate() {
        pairs[i].item = put(SLOT_ROWS + 2 * i, format_args!("{}", row.issuer));
        pairs[i].value = put(
            SLOT_ROWS + 2 * i + 1,
            format_args!("{}   {}s", row.code, row.remaining),
        );
    }
}

pub fn draw_codes_page(rows: &[CodeRow], page: u8, pages: u8, header_time: &str) {
    if rows.is_empty() || rows.len() > ROWS_PER_PAGE || pages == 0 || page >= pages {
        return;
    }
    let Some(layout) = begin() else { return };
    add_header(layout, header_time);
    unsafe {
        let pairs = &mut *(&raw mut PAIRS);
        for pair in pairs.iter_mut() {
            *pair = core::mem::zeroed();
            pair.set_aliasValue(1);
        }
        fill(rows, header_time);

        let mut list: nbgl_contentTagValueList_t = core::mem::zeroed();
        list.pairs = pairs.as_ptr();
        list.nbPairs = rows.len() as u8;
        list.smallCaseForValue = true;
        list.token = TOKEN_ROW;
        nbgl_layoutAddTagValueList(layout, &list);

        let mut footer: nbgl_layoutFooter_t = core::mem::zeroed();
        footer.type_ = FOOTER_TEXT_AND_NAV;
        footer.separationLine = true;
        let text_nav = &mut footer.__bindgen_anon_1.textAndNav;
        text_nav.text = c"Settings".as_ptr();
        text_nav.token = TOKEN_SETTINGS;
        text_nav.tuneId = TUNE_TAP_CASUAL;
        let nav = &mut text_nav.navigation;
        nav.token = TOKEN_NAV;
        nav.nbPages = pages;
        nav.activePage = page;
        nav.withBackKey = true;
        nav.withPageIndicator = true;
        nav.visibleIndicator = true;
        nav.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddExtendedFooter(layout, &footer);
    }
    finish(layout);
}

pub fn update_codes_page(rows: &[CodeRow], header_time: &str) {
    if rows.len() > ROWS_PER_PAGE {
        return;
    }
    fill(rows, header_time);
    let code_changed = rows.iter().any(|row| row.remaining == row.period);
    redraw_in_place(code_changed);
}

pub fn draw_no_accounts(header_time: &str) {
    let Some(layout) = begin() else { return };
    add_header(layout, header_time);
    add_center(layout, core::ptr::null(), c"No accounts yet", None);
    add_footer_text(layout, c"Settings", TOKEN_SETTINGS);
    finish(layout);
}

pub fn draw_hidden() {
    let Some(layout) = begin() else { return };
    add_home_header(layout, c"Authenticator".as_ptr());
    add_center(
        layout,
        core::ptr::null(),
        c"Codes hidden",
        Some(c"Hidden after a minute without a touch."),
    );
    add_footer_text(layout, c"Show codes", TOKEN_SHOW);
    finish(layout);
}

pub fn draw_unsynced() {
    let Some(layout) = begin() else { return };
    add_home_header(layout, c"Authenticator".as_ptr());
    add_center(
        layout,
        core::ptr::null(),
        c"Sync time from iPhone",
        Some(c"Open the Authenticator app on your iPhone and tap Sync Time."),
    );
    add_footer_text(layout, c"Settings", TOKEN_SETTINGS);
    finish(layout);
}

pub fn draw_time_synced() {
    let Some(layout) = begin() else { return };
    add_center(layout, icon(Icon::Check), c"Time synced", None);
    finish(layout);
}
