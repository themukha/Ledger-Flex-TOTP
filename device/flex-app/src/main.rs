#![no_std]
#![no_main]

extern crate alloc;

mod keys;
mod storage;
mod ui {
    pub mod account;
    pub mod codes;
    pub mod nbgl;
    pub mod review;
}

use alloc::vec::Vec;
use arrayvec::{ArrayString, ArrayVec};
use core::fmt::Write;
use ledger_device_sdk::io::{init_comm, ApduHeader, Comm, Event, Reply};
use otp_core::clock::Clock;
use otp_core::import::{ImportSession, LastOutcome, Store};
use otp_core::protocol::{encode_info, encode_list, parse, Command, StatusWord, MAX_LIST_BYTES};
use otp_core::record::Record;
use otp_core::totp::{format_code, seconds_remaining, totp};
use otp_core::vault::encode_backup_header;
use storage::AppStorageStore;
use ui::account::{
    draw_confirm_delete, draw_confirm_delete_all, draw_confirm_export, draw_details, draw_settings,
};
use ui::codes::{
    draw_codes_page, draw_no_accounts, draw_time_synced, draw_unsynced, update_codes_page, CodeRow,
    ROWS_PER_PAGE,
};
use ui::nbgl::{
    take_action, TOKEN_BACK, TOKEN_CANCEL, TOKEN_DELETE, TOKEN_HOLD, TOKEN_NAV, TOKEN_ROW,
    TOKEN_SETTINGS,
};
use ui::review::review_import;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

const CLA: u8 = 0xE0;
const INS_IMPORT_COMMIT: u8 = 0x12;
const INS_EXPORT_BACKUP: u8 = 0x20;
const VERSION: (u8, u8, u8) = (0, 1, 0);

const TOAST_TICKS: u64 = 15;

struct Header {
    ins: u8,
    p1: u8,
    p2: u8,
}

impl TryFrom<ApduHeader> for Header {
    type Error = Reply;

    fn try_from(h: ApduHeader) -> Result<Self, Reply> {
        Ok(Header {
            ins: h.ins,
            p1: h.p1,
            p2: h.p2,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Details(usize),
    ConfirmDelete(usize),
    Settings,
    ConfirmDeleteAll,
    ConfirmExport,
    Toast { until: u64 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HomeDrawn {
    Codes { page: u8, pages: u8, rows: usize },
    Empty,
}

struct State {
    ticks: u64,
    clock: Option<Clock>,
    store: AppStorageStore,
    session: Option<ImportSession>,
    session_restoring: Option<bool>,
    export_approved: bool,
    export_decision: Option<bool>,
    last_outcome: Option<LastOutcome>,
    screen: Screen,
    page: u8,
    home_drawn: Option<HomeDrawn>,
    shown_sec: u64,
    needs_draw: bool,
}

type Response = ArrayVec<u8, MAX_LIST_BYTES>;

impl State {
    fn handle(&mut self, h: &Header, data: &[u8]) -> Option<(Response, u16)> {
        let mut out = Response::new();
        let sw = match parse(h.ins, h.p1, h.p2, data) {
            Err(sw) => sw,
            Ok(Command::GetInfo) => {
                let (synced, now, tz) = match self.clock {
                    Some(c) => (true, c.utc(self.ticks), c.tz_offset_min),
                    None => (false, 0, 0),
                };
                let info = encode_info(
                    VERSION,
                    self.store.len() as u8,
                    self.store.capacity() as u8,
                    synced,
                    now,
                    tz,
                );
                out.try_extend_from_slice(&info).unwrap();
                StatusWord::Ok
            }
            Ok(Command::SetTime {
                unix,
                tz_offset_min,
            }) => {
                self.clock = Some(Clock {
                    unix_at_sync: unix,
                    tz_offset_min,
                    ticks_at_sync: self.ticks,
                });
                self.screen = Screen::Toast {
                    until: self.ticks + TOAST_TICKS,
                };
                self.needs_draw = true;
                StatusWord::Ok
            }
            Ok(Command::ListAccounts { start }) => {
                self.list(start, &mut out);
                StatusWord::Ok
            }
            Ok(Command::ImportBegin { batch_id, expected }) => {
                match ImportSession::begin(batch_id, expected) {
                    Ok(s) => {
                        self.session = Some(s);
                        self.session_restoring = None;
                        StatusWord::Ok
                    }
                    Err(sw) => sw,
                }
            }
            Ok(Command::ImportAccount(bytes)) => match self.session.as_mut() {
                None => StatusWord::NoBatch,
                Some(_) if self.session_restoring == Some(true) => StatusWord::InvalidData,
                Some(s) => match Record::decode(bytes) {
                    Err(_) => StatusWord::InvalidData,
                    Ok(r) => match s.add(r) {
                        Ok(()) => {
                            self.session_restoring = Some(false);
                            StatusWord::Ok
                        }
                        Err(sw) => sw,
                    },
                },
            },
            Ok(Command::RestoreAccount(payload)) => match self.session.as_mut() {
                None => StatusWord::NoBatch,
                Some(_) if self.session_restoring == Some(false) => StatusWord::InvalidData,
                Some(s) => match self.store.open_payload(payload) {
                    Err(_) => {
                        self.session = None;
                        self.session_restoring = None;
                        StatusWord::DecryptFailed
                    }
                    Ok(r) => match s.add(r) {
                        Ok(()) => {
                            self.session_restoring = Some(true);
                            StatusWord::Ok
                        }
                        Err(sw) => sw,
                    },
                },
            },
            Ok(Command::ExportBackup { chunk: 0 }) => {
                self.export_approved = false;
                self.screen = Screen::ConfirmExport;
                self.needs_draw = true;
                return None;
            }
            Ok(Command::ExportBackup { chunk }) => {
                if !self.export_approved {
                    StatusWord::ExportNotApproved
                } else if chunk as usize > self.store.len() {
                    StatusWord::WrongP1P2
                } else {
                    match self.store.payload(chunk as usize - 1) {
                        Some(p) => {
                            out.try_extend_from_slice(&p).unwrap();
                            StatusWord::Ok
                        }
                        None => StatusWord::InvalidData,
                    }
                }
            }
            Ok(Command::ImportStatus { batch_id }) => {
                match &self.last_outcome {
                    Some(o) => out.try_extend_from_slice(&o.status_for(&batch_id)).unwrap(),
                    None => out.push(0),
                }
                StatusWord::Ok
            }
            Ok(Command::ImportCommit { .. }) => StatusWord::InsNotSupported,
        };
        Some((out, sw as u16))
    }

    fn commit(&mut self, comm: &mut Comm, h: &Header, data: &[u8]) -> (Response, u16) {
        let mut out = Response::new();
        let batch_id = match parse(h.ins, h.p1, h.p2, data) {
            Ok(Command::ImportCommit { batch_id }) => batch_id,
            Ok(_) => return (out, StatusWord::InsNotSupported as u16),
            Err(sw) => return (out, sw as u16),
        };
        let ready = match &self.session {
            Some(s) if s.batch_id == batch_id => s.records.len() == s.expected as usize,
            _ => return (out, StatusWord::NoBatch as u16),
        };
        if !ready {
            return (out, StatusWord::InvalidData as u16);
        }
        let session = self.session.take().unwrap();
        let restoring = self.session_restoring == Some(true);
        let approved = review_import(comm, &session.records, restoring);
        self.clock = None;
        if !approved {
            self.last_outcome = Some(LastOutcome {
                batch_id,
                approved: false,
                results: Vec::new(),
            });
            return (out, StatusWord::Denied as u16);
        }
        let results = session.commit(&mut self.store);
        out.extend(results.iter().map(|r| *r as u8));
        self.last_outcome = Some(LastOutcome {
            batch_id,
            approved: true,
            results,
        });
        (out, StatusWord::Ok as u16)
    }

    fn list(&self, start: u8, out: &mut Response) {
        let total = self.store.len();
        let mut names: ArrayVec<(u8, ArrayString<32>, ArrayString<64>), 16> = ArrayVec::new();
        let mut used = 1;
        for i in (start as usize)..total {
            let Some(r) = self.store.get(i) else { continue };
            used += 3 + r.issuer.len() + r.account.len();
            if names.is_full() || used > MAX_LIST_BYTES {
                break;
            }
            names.push((i as u8, r.issuer, r.account));
        }
        encode_list(
            total as u8,
            start,
            names
                .iter()
                .map(|(i, iss, acc)| (*i, iss.as_str(), acc.as_str())),
            out,
        );
    }
}

impl State {
    fn pages(&self) -> u8 {
        self.store.len().div_ceil(ROWS_PER_PAGE).max(1) as u8
    }

    fn page_rows(&self, utc: u64) -> ArrayVec<CodeRow, ROWS_PER_PAGE> {
        let first = self.page as usize * ROWS_PER_PAGE;
        let last = (first + ROWS_PER_PAGE).min(self.store.len());
        (first..last)
            .map(|i| match self.store.get(i) {
                Some(r) => CodeRow {
                    issuer: r.issuer,
                    code: format_code(totp(&r.secret, r.algo, r.digits, r.period, utc), r.digits),
                    remaining: seconds_remaining(r.period, utc),
                    period: r.period,
                },
                None => CodeRow {
                    issuer: ArrayString::from("Unreadable account").unwrap_or_default(),
                    code: ArrayString::from("------").unwrap_or_default(),
                    remaining: 0,
                    period: 0,
                },
            })
            .collect()
    }

    fn show(&mut self) {
        self.needs_draw = false;
        self.home_drawn = None;
        match self.screen {
            Screen::Home => self.show_home(),
            Screen::Details(i) | Screen::ConfirmDelete(i) => match self.store.get(i) {
                Some(r) if self.screen == Screen::Details(i) => draw_details(&r),
                Some(r) => draw_confirm_delete(&r),
                None => {
                    self.screen = Screen::Home;
                    self.show_home();
                }
            },
            Screen::Settings => draw_settings(VERSION, self.store.len(), self.store.capacity()),
            Screen::ConfirmDeleteAll => draw_confirm_delete_all(),
            Screen::ConfirmExport => draw_confirm_export(),
            Screen::Toast { .. } => draw_time_synced(),
        }
    }

    fn show_home(&mut self) {
        let Some(clock) = self.clock else {
            draw_unsynced();
            return;
        };
        let utc = clock.utc(self.ticks);
        let time = hms(&clock, self.ticks);
        self.shown_sec = utc;
        self.page = self.page.min(self.pages() - 1);
        if self.store.len() == 0 {
            draw_no_accounts(&time);
            self.home_drawn = Some(HomeDrawn::Empty);
            return;
        }
        let rows = self.page_rows(utc);
        let pages = self.pages();
        draw_codes_page(&rows, self.page, pages, &time);
        self.home_drawn = Some(HomeDrawn::Codes {
            page: self.page,
            pages,
            rows: rows.len(),
        });
    }

    fn tick(&mut self) {
        self.ticks += 1;
        match self.screen {
            Screen::Toast { until } if self.ticks >= until => {
                self.screen = Screen::Home;
                self.show();
            }
            Screen::Home => {
                let Some(clock) = self.clock else { return };
                let utc = clock.utc(self.ticks);
                if utc == self.shown_sec {
                    return;
                }
                let time = hms(&clock, self.ticks);
                let rows = if self.store.len() == 0 {
                    ArrayVec::new()
                } else {
                    self.page_rows(utc)
                };
                let now = if rows.is_empty() {
                    HomeDrawn::Empty
                } else {
                    HomeDrawn::Codes {
                        page: self.page,
                        pages: self.pages(),
                        rows: rows.len(),
                    }
                };
                if self.home_drawn == Some(now) {
                    update_codes_page(&rows, &time);
                    self.shown_sec = utc;
                } else {
                    self.show();
                }
            }
            _ => {}
        }
    }

    fn on_action(&mut self, token: u8, index: u8) {
        self.screen = match (self.screen, token) {
            (Screen::Home, TOKEN_NAV) if index < self.pages() => {
                self.page = index;
                Screen::Home
            }
            (Screen::Home, TOKEN_ROW) if self.clock.is_some() => {
                let i = self.page as usize * ROWS_PER_PAGE + index as usize;
                if i >= self.store.len() {
                    return;
                }
                Screen::Details(i)
            }
            (Screen::Home, TOKEN_SETTINGS) => Screen::Settings,
            (Screen::Details(_), TOKEN_BACK) | (Screen::Settings, TOKEN_BACK) => Screen::Home,
            (Screen::Details(i), TOKEN_DELETE) => Screen::ConfirmDelete(i),
            (Screen::ConfirmDelete(i), TOKEN_CANCEL) => Screen::Details(i),
            (Screen::ConfirmDelete(i), TOKEN_HOLD) => {
                self.store.remove(i);
                Screen::Home
            }
            (Screen::Settings, TOKEN_DELETE) => Screen::ConfirmDeleteAll,
            (Screen::ConfirmDeleteAll, TOKEN_CANCEL) => Screen::Settings,
            (Screen::ConfirmDeleteAll, TOKEN_HOLD) => {
                self.store.clear();
                self.page = 0;
                Screen::Home
            }
            (Screen::ConfirmExport, TOKEN_HOLD) => {
                self.export_approved = true;
                self.export_decision = Some(true);
                Screen::Home
            }
            (Screen::ConfirmExport, TOKEN_CANCEL) => {
                self.export_decision = Some(false);
                Screen::Home
            }
            _ => return,
        };
        self.show();
    }
}

fn hms(clock: &Clock, ticks: u64) -> ArrayString<8> {
    let (h, m, s) = clock.local_hms(ticks);
    let mut out = ArrayString::new();
    let _ = write!(out, "{:02}:{:02}:{:02}", h, m, s);
    out
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(CLA);

    let mut state = State {
        ticks: 0,
        clock: None,
        store: AppStorageStore::new(keys::vault_key()),
        session: None,
        session_restoring: None,
        export_approved: false,
        export_decision: None,
        last_outcome: None,
        screen: Screen::Home,
        page: 0,
        home_drawn: None,
        shown_sec: 0,
        needs_draw: false,
    };
    state.show();

    loop {
        match comm.next_event() {
            Event::Command(command) => {
                let header = command.decode::<Header>();
                if header.as_ref().map_or(true, |h| h.ins != INS_EXPORT_BACKUP) {
                    state.export_approved = false;
                }
                if let Some(h) = header.as_ref().ok().filter(|h| h.ins == INS_IMPORT_COMMIT) {
                    let data: ArrayVec<u8, 255> =
                        command.get_data().iter().copied().take(255).collect();
                    let comm = command.into_comm();
                    let (resp, sw) = state.commit(comm, h, &data);
                    let _ = comm.send(&resp, Reply(sw));
                    state.screen = Screen::Home;
                    state.show();
                    continue;
                }
                let answer = match header {
                    Ok(h) => state.handle(&h, command.get_data()),
                    Err(Reply(sw)) => Some((Response::new(), sw)),
                };
                match answer {
                    Some((resp, sw)) => {
                        let _ = command.reply(&resp, Reply(sw));
                    }
                    None => {
                        let _ = command.into_comm();
                    }
                }
            }
            Event::Ticker => state.tick(),
            _ => {}
        }
        if let Some((token, index)) = take_action() {
            state.on_action(token, index);
        }
        if let Some(approved) = state.export_decision.take() {
            let header = encode_backup_header(state.store.len() as u8);
            let _ = if approved {
                comm.send(&header, Reply(StatusWord::Ok as u16))
            } else {
                comm.send(&[], Reply(StatusWord::Denied as u16))
            };
        }
        if state.needs_draw {
            state.show();
        }
    }
}
