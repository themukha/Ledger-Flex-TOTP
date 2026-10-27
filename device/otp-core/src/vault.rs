use crate::record::{CodecError, Record, MAX_ENCODED_LEN};
use arrayvec::ArrayVec;
use chacha20poly1305::{aead::AeadInOut, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const AAD: &[u8] = b"ledger-otp/v1";
const KDF_INFO: &[u8] = b"ledger-otp vault v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const MAX_PAYLOAD_LEN: usize = 1 + NONCE_LEN + MAX_ENCODED_LEN + TAG_LEN;

const MAGIC: &[u8; 4] = b"LOTP";
const BACKUP_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    Malformed,
    Decrypt,
    Codec(CodecError),
}

impl From<CodecError> for VaultError {
    fn from(e: CodecError) -> Self {
        VaultError::Codec(e)
    }
}

pub fn vault_key_from_seed_material(material: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, material);
    let mut okm = [0u8; 32];
    hk.expand(KDF_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF length");
    okm
}

fn seal_with_aad(
    aad: &[u8],
    key: &[u8; 32],
    nonce: [u8; 12],
    record: &Record,
    out: &mut ArrayVec<u8, MAX_PAYLOAD_LEN>,
) {
    let mut plain: ArrayVec<u8, MAX_ENCODED_LEN> = ArrayVec::new();
    record.encode(&mut plain);

    out.clear();
    out.push((plain.len() + TAG_LEN) as u8);
    out.try_extend_from_slice(&nonce).unwrap();
    out.try_extend_from_slice(&plain).unwrap();
    plain.zeroize();

    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(nonce), aad, (&mut out[1 + NONCE_LEN..]).into())
        .expect("encryption of a bounded buffer cannot fail");
    out.try_extend_from_slice(&tag).unwrap();
}

pub fn seal(
    key: &[u8; 32],
    nonce: [u8; 12],
    record: &Record,
    out: &mut ArrayVec<u8, MAX_PAYLOAD_LEN>,
) {
    seal_with_aad(AAD, key, nonce, record, out)
}

pub fn open(key: &[u8; 32], payload: &[u8]) -> Result<Record, VaultError> {
    if payload.len() < 1 + NONCE_LEN + TAG_LEN {
        return Err(VaultError::Malformed);
    }
    let ct_len = payload[0] as usize;
    if payload.len() != 1 + NONCE_LEN + ct_len
        || ct_len < TAG_LEN
        || ct_len - TAG_LEN > MAX_ENCODED_LEN
    {
        return Err(VaultError::Malformed);
    }
    let nonce: [u8; 12] = payload[1..1 + NONCE_LEN].try_into().unwrap();
    let (ct, tag) = payload[1 + NONCE_LEN..].split_at(ct_len - TAG_LEN);
    let tag: [u8; 16] = tag.try_into().unwrap();

    let mut buf: ArrayVec<u8, MAX_ENCODED_LEN> = ArrayVec::new();
    buf.try_extend_from_slice(ct)
        .map_err(|_| VaultError::Malformed)?;

    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let res = cipher.decrypt_inout_detached(
        &Nonce::from(nonce),
        AAD,
        buf.as_mut_slice().into(),
        &Tag::from(tag),
    );
    let out = match res {
        Ok(()) => Record::decode(&buf).map_err(VaultError::from),
        Err(_) => Err(VaultError::Decrypt),
    };
    buf.zeroize();
    out
}

pub fn encode_backup_header(count: u8) -> [u8; 6] {
    [
        MAGIC[0],
        MAGIC[1],
        MAGIC[2],
        MAGIC[3],
        BACKUP_VERSION,
        count,
    ]
}

pub fn decode_backup_header(b: &[u8]) -> Result<u8, VaultError> {
    if b.len() != 6 || &b[..4] != MAGIC || b[4] != BACKUP_VERSION {
        return Err(VaultError::Malformed);
    }
    Ok(b[5])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Algorithm;
    use arrayvec::{ArrayString, ArrayVec};

    fn rec(issuer: &str, account: &str, secret: &[u8]) -> Record {
        Record {
            algo: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: ArrayString::from(issuer).unwrap(),
            account: ArrayString::from(account).unwrap(),
            secret: ArrayVec::try_from(secret).unwrap(),
        }
    }

    const KEY: [u8; 32] = [7u8; 32];
    const NONCE: [u8; 12] = [9u8; 12];

    #[test]
    fn seal_open_roundtrip() {
        let r = rec("GitHub", "me@x.io", b"12345678901234567890");
        let mut out = ArrayVec::new();
        seal(&KEY, NONCE, &r, &mut out);
        assert_eq!(out[0] as usize, out.len() - 13);
        assert_eq!(&out[1..13], &NONCE);
        assert_eq!(open(&KEY, &out).unwrap(), r);
    }

    #[test]
    fn wrong_key_fails() {
        let r = rec("a", "b", b"secret");
        let mut out = ArrayVec::new();
        seal(&KEY, NONCE, &r, &mut out);
        assert_eq!(open(&[8u8; 32], &out), Err(VaultError::Decrypt));
    }

    #[test]
    fn tampered_fails() {
        let r = rec("a", "b", b"secret");
        let mut out = ArrayVec::new();
        seal(&KEY, NONCE, &r, &mut out);
        out[14] ^= 1;
        assert_eq!(open(&KEY, &out), Err(VaultError::Decrypt));
    }

    #[test]
    fn aad_bound() {
        let r = rec("a", "b", b"secret");
        let mut out = ArrayVec::new();
        seal_with_aad(b"other-aad", &KEY, NONCE, &r, &mut out);
        assert_eq!(open(&KEY, &out), Err(VaultError::Decrypt));
    }

    #[test]
    fn malformed_rejected() {
        assert_eq!(open(&KEY, &[]), Err(VaultError::Malformed));
        let r = rec("a", "b", b"secret");
        let mut out = ArrayVec::new();
        seal(&KEY, NONCE, &r, &mut out);
        assert_eq!(
            open(&KEY, &out[..out.len() - 1]),
            Err(VaultError::Malformed)
        );
    }

    #[test]
    fn payload_max_195() {
        let issuer = "i".repeat(32);
        let account = "a".repeat(64);
        let r = rec(&issuer, &account, &[0x55u8; 64]);
        let mut out = ArrayVec::new();
        seal(&KEY, NONCE, &r, &mut out);
        assert_eq!(out.len(), 195);
        assert_eq!(open(&KEY, &out).unwrap(), r);
    }

    #[test]
    fn kdf_known_answer() {
        let expected = "4d4bef7c53d3f0747311eb6aa967fff71957c423852f4b797d2d78eb07173443";
        let key = vault_key_from_seed_material(&[0u8; 32]);
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn backup_header_roundtrip() {
        let h = encode_backup_header(5);
        assert_eq!(&h, b"LOTP\x01\x05");
        assert_eq!(decode_backup_header(&h), Ok(5));
    }

    #[test]
    fn backup_header_rejects_version_2() {
        assert_eq!(
            decode_backup_header(b"LOTP\x02\x05"),
            Err(VaultError::Malformed)
        );
        assert_eq!(
            decode_backup_header(b"XOTP\x01\x05"),
            Err(VaultError::Malformed)
        );
        assert_eq!(
            decode_backup_header(b"LOTP\x01"),
            Err(VaultError::Malformed)
        );
    }
}
