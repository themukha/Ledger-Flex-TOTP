use crate::record::Algorithm;
use arrayvec::ArrayString;
use core::fmt::Write;
use hmac::{digest::KeyInit, Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

fn hmac_into<M: Mac + KeyInit>(key: &[u8], msg: &[u8], out: &mut [u8; 64]) -> usize {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let mut res = mac.finalize().into_bytes();
    out[..res.len()].copy_from_slice(&res);
    let n = res.len();
    res.as_mut_slice().zeroize();
    n
}

pub fn totp(secret: &[u8], algo: Algorithm, digits: u8, period: u8, unix: u64) -> u32 {
    let counter = (unix / period.max(1) as u64).to_be_bytes();
    let mut h = Zeroizing::new([0u8; 64]);
    let len = match algo {
        Algorithm::Sha1 => hmac_into::<Hmac<Sha1>>(secret, &counter, &mut h),
        Algorithm::Sha256 => hmac_into::<Hmac<Sha256>>(secret, &counter, &mut h),
        Algorithm::Sha512 => hmac_into::<Hmac<Sha512>>(secret, &counter, &mut h),
    };
    let off = (h[len - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits.clamp(1, 9) as u32)
}

pub fn seconds_remaining(period: u8, unix: u64) -> u8 {
    let p = period.max(1) as u64;
    (p - unix % p) as u8
}

pub fn format_code(code: u32, digits: u8) -> ArrayString<9> {
    let digits = digits.clamp(1, 9) as usize;
    let mut raw = ArrayString::<9>::new();
    write!(raw, "{:0width$}", code, width = digits).unwrap();
    let raw = if raw.len() > digits {
        &raw[raw.len() - digits..]
    } else {
        &raw[..]
    };
    let mut out = ArrayString::<9>::new();
    let split = digits / 2;
    if digits > 1 && split > 0 && digits < 9 {
        out.push_str(&raw[..split]);
        out.push(' ');
        out.push_str(&raw[split..]);
    } else {
        out.push_str(raw);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_state_zeroizes_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<sha1::block_api::Sha1Core>();
        assert_zod::<sha2::block_api::Sha256VarCore>();
        assert_zod::<sha2::block_api::Sha512VarCore>();
    }
    const S1: &[u8] = b"12345678901234567890";
    const S256: &[u8] = b"12345678901234567890123456789012";
    const S512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
    #[test]
    fn rfc6238_sha1() {
        assert_eq!(totp(S1, Algorithm::Sha1, 8, 30, 59), 94287082);
        assert_eq!(totp(S1, Algorithm::Sha1, 8, 30, 1111111109), 7081804);
        assert_eq!(totp(S1, Algorithm::Sha1, 8, 30, 1234567890), 89005924);
        assert_eq!(totp(S1, Algorithm::Sha1, 8, 30, 2000000000), 69279037);
    }
    #[test]
    fn rfc6238_sha256() {
        assert_eq!(totp(S256, Algorithm::Sha256, 8, 30, 59), 46119246);
    }
    #[test]
    fn rfc6238_sha512() {
        assert_eq!(totp(S512, Algorithm::Sha512, 8, 30, 59), 90693936);
    }
    #[test]
    fn six_digits_is_mod() {
        assert_eq!(totp(S1, Algorithm::Sha1, 6, 30, 59), 287082);
    }
    #[test]
    fn remaining_at_boundary() {
        assert_eq!(seconds_remaining(30, 60), 30);
        assert_eq!(seconds_remaining(30, 59), 1);
        assert_eq!(seconds_remaining(60, 61), 59);
    }
    #[test]
    fn formats() {
        assert_eq!(format_code(7081804, 8).as_str(), "0708 1804");
        assert_eq!(format_code(482913, 6).as_str(), "482 913");
        assert_eq!(format_code(42, 6).as_str(), "000 042");
    }
}
