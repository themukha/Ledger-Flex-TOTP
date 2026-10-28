use crate::record::MAX_ENCODED_LEN;
use crate::vault::MAX_PAYLOAD_LEN;
use arrayvec::ArrayVec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusWord {
    Ok = 0x9000,
    Denied = 0x6985,
    InvalidData = 0x6A80,
    WrongP1P2 = 0x6A86,
    InsNotSupported = 0x6D00,
    WrongCla = 0x6E00,
    NoBatch = 0xB001,
    BatchFull = 0xB002,
    DecryptFailed = 0xB003,
    ExportNotApproved = 0xB004,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    GetInfo,
    SetTime { unix: u64, tz_offset_min: i16 },
    ListAccounts { start: u8 },
    ImportBegin { batch_id: [u8; 16], expected: u8 },
    ImportAccount(&'a [u8]),
    ImportCommit { batch_id: [u8; 16] },
    ImportStatus { batch_id: [u8; 16] },
    RestoreAccount(&'a [u8]),
    ExportBackup { chunk: u8 },
}

pub const MAX_SET_TIME_UNIX: u64 = 1 << 40;
pub const MAX_LIST_BYTES: usize = 250;

pub fn parse<'a>(ins: u8, p1: u8, p2: u8, data: &'a [u8]) -> Result<Command<'a>, StatusWord> {
    use StatusWord::{InsNotSupported, InvalidData, WrongP1P2};
    let p1_used = matches!(ins, 0x03 | 0x20);
    if !matches!(ins, 0x01..=0x03 | 0x10..=0x14 | 0x20) {
        return Err(InsNotSupported);
    }
    if p2 != 0 || (!p1_used && p1 != 0) {
        return Err(WrongP1P2);
    }
    let id = |d: &[u8]| -> [u8; 16] {
        let mut a = [0u8; 16];
        a.copy_from_slice(&d[..16]);
        a
    };
    match ins {
        0x01 | 0x03 | 0x20 if !data.is_empty() => Err(InvalidData),
        0x01 => Ok(Command::GetInfo),
        0x03 => Ok(Command::ListAccounts { start: p1 }),
        0x20 => Ok(Command::ExportBackup { chunk: p1 }),
        0x02 => {
            if data.len() != 10 {
                return Err(InvalidData);
            }
            let mut u = [0u8; 8];
            u.copy_from_slice(&data[..8]);
            let unix = u64::from_be_bytes(u);
            if unix > MAX_SET_TIME_UNIX {
                return Err(InvalidData);
            }
            let tz_offset_min = i16::from_be_bytes([data[8], data[9]]);
            Ok(Command::SetTime {
                unix,
                tz_offset_min,
            })
        }
        0x10 => {
            if data.len() != 17 {
                return Err(InvalidData);
            }
            Ok(Command::ImportBegin {
                batch_id: id(data),
                expected: data[16],
            })
        }
        0x11 | 0x14 => {
            let max = if ins == 0x11 {
                MAX_ENCODED_LEN
            } else {
                MAX_PAYLOAD_LEN
            };
            if data.is_empty() || data.len() > max {
                return Err(InvalidData);
            }
            Ok(if ins == 0x11 {
                Command::ImportAccount(data)
            } else {
                Command::RestoreAccount(data)
            })
        }
        0x12 | 0x13 => {
            if data.len() != 16 {
                return Err(InvalidData);
            }
            let batch_id = id(data);
            Ok(if ins == 0x12 {
                Command::ImportCommit { batch_id }
            } else {
                Command::ImportStatus { batch_id }
            })
        }
        _ => Err(InsNotSupported),
    }
}

pub fn encode_info(
    version: (u8, u8, u8),
    count: u8,
    capacity: u8,
    synced: bool,
    now_unix: u64,
    tz_offset_min: i16,
) -> ArrayVec<u8, 16> {
    let (now, tz) = if synced {
        (now_unix, tz_offset_min)
    } else {
        (0, 0)
    };
    let mut v = ArrayVec::new();
    v.try_extend_from_slice(&[
        version.0,
        version.1,
        version.2,
        count,
        capacity,
        synced as u8,
    ])
    .unwrap();
    v.try_extend_from_slice(&now.to_be_bytes()).unwrap();
    v.try_extend_from_slice(&tz.to_be_bytes()).unwrap();
    v
}

pub fn encode_list<'a>(
    total: u8,
    start: u8,
    names: impl Iterator<Item = (u8, &'a str, &'a str)>,
    out: &mut ArrayVec<u8, MAX_LIST_BYTES>,
) {
    out.clear();
    out.push(total);
    for (index, issuer, account) in names {
        if index < start {
            continue;
        }
        let need = 3 + issuer.len() + account.len();
        if issuer.len() > 255 || account.len() > 255 || out.remaining_capacity() < need {
            break;
        }
        out.push(index);
        out.push(issuer.len() as u8);
        out.try_extend_from_slice(issuer.as_bytes()).unwrap();
        out.push(account.len() as u8);
        out.try_extend_from_slice(account.as_bytes()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_set_time() {
        let mut d = [0u8; 10];
        d[..8].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        d[8..].copy_from_slice(&(-120i16).to_be_bytes());
        assert_eq!(
            parse(0x02, 0, 0, &d),
            Ok(Command::SetTime {
                unix: 1_700_000_000,
                tz_offset_min: -120
            })
        );
    }

    #[test]
    fn parse_set_time_short() {
        assert_eq!(parse(0x02, 0, 0, &[0; 9]), Err(StatusWord::InvalidData));
        assert_eq!(parse(0x02, 0, 0, &[0; 11]), Err(StatusWord::InvalidData));
    }

    #[test]
    fn parse_set_time_absurd() {
        let mut d = [0u8; 10];
        d[..8].copy_from_slice(&((1u64 << 40) + 1).to_be_bytes());
        assert_eq!(parse(0x02, 0, 0, &d), Err(StatusWord::InvalidData));
        d[..8].copy_from_slice(&(1u64 << 40).to_be_bytes());
        assert!(parse(0x02, 0, 0, &d).is_ok());
    }

    #[test]
    fn parse_unknown_ins() {
        assert_eq!(parse(0x99, 0, 0, &[]), Err(StatusWord::InsNotSupported));
    }

    #[test]
    fn parse_bad_p1() {
        assert_eq!(parse(0x01, 1, 0, &[]), Err(StatusWord::WrongP1P2));
        assert_eq!(parse(0x01, 0, 1, &[]), Err(StatusWord::WrongP1P2));
        assert_eq!(parse(0x01, 0, 0, &[]), Ok(Command::GetInfo));
        assert_eq!(parse(0x01, 0, 0, &[1]), Err(StatusWord::InvalidData));
    }

    #[test]
    fn parse_p1_carriers() {
        assert_eq!(
            parse(0x03, 7, 0, &[]),
            Ok(Command::ListAccounts { start: 7 })
        );
        assert_eq!(
            parse(0x20, 3, 0, &[]),
            Ok(Command::ExportBackup { chunk: 3 })
        );
        assert_eq!(parse(0x03, 7, 1, &[]), Err(StatusWord::WrongP1P2));
    }

    #[test]
    fn parse_import_family() {
        let id = [7u8; 16];
        let mut d = [0u8; 17];
        d[..16].copy_from_slice(&id);
        d[16] = 64;
        assert_eq!(
            parse(0x10, 0, 0, &d),
            Ok(Command::ImportBegin {
                batch_id: id,
                expected: 64
            })
        );
        assert_eq!(parse(0x10, 0, 0, &d[..16]), Err(StatusWord::InvalidData));
        assert_eq!(
            parse(0x12, 0, 0, &id),
            Ok(Command::ImportCommit { batch_id: id })
        );
        assert_eq!(
            parse(0x13, 0, 0, &id),
            Ok(Command::ImportStatus { batch_id: id })
        );
        assert_eq!(parse(0x13, 0, 0, &id[..15]), Err(StatusWord::InvalidData));
        assert_eq!(
            parse(0x11, 0, 0, &[1, 2, 3]),
            Ok(Command::ImportAccount(&[1, 2, 3]))
        );
        assert_eq!(parse(0x11, 0, 0, &[]), Err(StatusWord::InvalidData));
        assert_eq!(parse(0x14, 0, 0, &[9]), Ok(Command::RestoreAccount(&[9])));
        assert_eq!(parse(0x11, 1, 0, &[1]), Err(StatusWord::WrongP1P2));
    }

    #[test]
    fn status_word_values() {
        assert_eq!(StatusWord::Ok as u16, 0x9000);
        assert_eq!(StatusWord::Denied as u16, 0x6985);
        assert_eq!(StatusWord::ExportNotApproved as u16, 0xB004);
    }

    #[test]
    fn info_layout() {
        let v = encode_info((1, 2, 3), 5, 64, true, 0x0102030405060708, -90);
        assert_eq!(
            v.as_slice(),
            &[1, 2, 3, 5, 64, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xA6]
        );
        let v = encode_info((1, 2, 3), 0, 64, false, 99, 60);
        assert_eq!(&v[5..], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn list_encodes_entries() {
        let mut out = ArrayVec::new();
        let names = [(0u8, "GitHub", "alice"), (1, "AWS", "bob")];
        encode_list(2, 0, names.iter().copied(), &mut out);
        assert_eq!(out[0], 2);
        assert_eq!(
            &out[1..],
            &[
                0, 6, b'G', b'i', b't', b'H', b'u', b'b', 5, b'a', b'l', b'i', b'c', b'e', 1, 3,
                b'A', b'W', b'S', 3, b'b', b'o', b'b'
            ]
        );
    }

    #[test]
    fn list_stops_at_first_that_does_not_fit() {
        let issuer = "I".repeat(32);
        let account = "a".repeat(64);
        let names: std::vec::Vec<(u8, &str, &str)> = (0..5)
            .map(|i| (i, issuer.as_str(), account.as_str()))
            .collect();
        let mut out = ArrayVec::new();
        encode_list(5, 0, names.iter().copied(), &mut out);
        assert_eq!(out.len(), 1 + 2 * 99);
        assert_eq!(out[0], 5);
    }

    #[test]
    fn list_entry_exactly_filling_250_is_included() {
        let (i, a) = ("I".repeat(100), "a".repeat(146));
        let mut out = ArrayVec::new();
        encode_list(1, 0, [(0u8, i.as_str(), a.as_str())].into_iter(), &mut out);
        assert_eq!(out.len(), 250);
    }

    #[test]
    fn list_entry_reaching_251_is_dropped() {
        let (i, a) = ("I".repeat(100), "a".repeat(147));
        let mut out = ArrayVec::new();
        encode_list(1, 0, [(0u8, i.as_str(), a.as_str())].into_iter(), &mut out);
        assert_eq!(out.as_slice(), &[1]);
    }
}
