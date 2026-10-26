#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    Sha1 = 0,
    Sha256 = 1,
    Sha512 = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAlgorithm;

impl TryFrom<u8> for Algorithm {
    type Error = InvalidAlgorithm;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Algorithm::Sha1),
            1 => Ok(Algorithm::Sha256),
            2 => Ok(Algorithm::Sha512),
            _ => Err(InvalidAlgorithm),
        }
    }
}

use arrayvec::{ArrayString, ArrayVec};
use core::fmt;
use zeroize::Zeroize;

pub const MAX_ENCODED_LEN: usize = 166;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    TrailingBytes,
    BadAlgorithm,
    BadDigits,
    BadPeriod,
    TooLong,
    EmptySecret,
    NotUtf8,
}

impl From<InvalidAlgorithm> for CodecError {
    fn from(_: InvalidAlgorithm) -> Self {
        CodecError::BadAlgorithm
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    pub algo: Algorithm,
    pub digits: u8,
    pub period: u8,
    pub issuer: ArrayString<32>,
    pub account: ArrayString<64>,
    pub secret: ArrayVec<u8, 64>,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.secret.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("algo", &self.algo)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .finish()
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, CodecError> {
        let (&b, rest) = self.0.split_first().ok_or(CodecError::Truncated)?;
        self.0 = rest;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.0.len() < n {
            return Err(CodecError::Truncated);
        }
        let (a, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(a)
    }

    fn field(&mut self, max: usize) -> Result<&'a [u8], CodecError> {
        let n = self.u8()? as usize;
        if n > max {
            return Err(CodecError::TooLong);
        }
        self.take(n)
    }
}

fn utf8(b: &[u8]) -> Result<&str, CodecError> {
    core::str::from_utf8(b).map_err(|_| CodecError::NotUtf8)
}

impl Record {
    pub fn decode(buf: &[u8]) -> Result<Record, CodecError> {
        let mut r = Reader(buf);
        let algo = Algorithm::try_from(r.u8()?)?;
        let digits = r.u8()?;
        let period = r.u8()?;
        let issuer = r.field(32)?;
        let account = r.field(64)?;
        let secret = r.field(64)?;
        if !r.0.is_empty() {
            return Err(CodecError::TrailingBytes);
        }
        if digits != 6 && digits != 8 {
            return Err(CodecError::BadDigits);
        }
        if period != 30 && period != 60 {
            return Err(CodecError::BadPeriod);
        }
        if secret.is_empty() {
            return Err(CodecError::EmptySecret);
        }
        let issuer = ArrayString::from(utf8(issuer)?).map_err(|_| CodecError::TooLong)?;
        let account = ArrayString::from(utf8(account)?).map_err(|_| CodecError::TooLong)?;
        let mut sec = ArrayVec::new();
        sec.try_extend_from_slice(secret)
            .map_err(|_| CodecError::TooLong)?;
        Ok(Record {
            algo,
            digits,
            period,
            issuer,
            account,
            secret: sec,
        })
    }

    pub fn encode(&self, out: &mut ArrayVec<u8, 166>) {
        out.push(self.algo as u8);
        out.push(self.digits);
        out.push(self.period);
        out.push(self.issuer.len() as u8);
        out.try_extend_from_slice(self.issuer.as_bytes()).unwrap();
        out.push(self.account.len() as u8);
        out.try_extend_from_slice(self.account.as_bytes()).unwrap();
        out.push(self.secret.len() as u8);
        out.try_extend_from_slice(&self.secret).unwrap();
    }

    pub fn same_identity(&self, other: &Record) -> bool {
        self.secret == other.secret && self.issuer == other.issuer && self.account == other.account
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Record {
        let mut secret = ArrayVec::new();
        secret
            .try_extend_from_slice(b"12345678901234567890")
            .unwrap();
        Record {
            algo: Algorithm::Sha256,
            digits: 8,
            period: 30,
            issuer: ArrayString::from("Example").unwrap(),
            account: ArrayString::from("alice@example.com").unwrap(),
            secret,
        }
    }

    fn enc(r: &Record) -> ArrayVec<u8, 166> {
        let mut out = ArrayVec::new();
        r.encode(&mut out);
        out
    }

    #[test]
    fn roundtrip() {
        let r = sample();
        let bytes = enc(&r);
        assert_eq!(Record::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn max_len_roundtrip() {
        let mut r = sample();
        r.issuer = ArrayString::from(&"i".repeat(32)).unwrap();
        r.account = ArrayString::from(&"a".repeat(64)).unwrap();
        r.secret.clear();
        r.secret.try_extend_from_slice(&[7u8; 64]).unwrap();
        let bytes = enc(&r);
        assert_eq!(bytes.len(), 166);
        assert_eq!(Record::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn test_record_rejects_long_issuer() {
        let mut b = std::vec![0u8, 6, 30, 33];
        b.extend_from_slice(&[b'x'; 33]);
        b.extend_from_slice(&[0, 1, 1]);
        assert_eq!(Record::decode(&b), Err(CodecError::TooLong));
    }

    #[test]
    fn rejects_digits_7() {
        let mut b = enc(&sample());
        b[1] = 7;
        assert_eq!(Record::decode(&b), Err(CodecError::BadDigits));
    }

    #[test]
    fn rejects_period_45() {
        let mut b = enc(&sample());
        b[2] = 45;
        assert_eq!(Record::decode(&b), Err(CodecError::BadPeriod));
    }

    #[test]
    fn rejects_bad_algorithm() {
        let mut b = enc(&sample());
        b[0] = 9;
        assert_eq!(Record::decode(&b), Err(CodecError::BadAlgorithm));
    }

    #[test]
    fn rejects_empty_secret() {
        let b = [0u8, 6, 30, 0, 0, 0];
        assert_eq!(Record::decode(&b), Err(CodecError::EmptySecret));
    }

    #[test]
    fn rejects_trailing() {
        let mut b = enc(&sample());
        b.push(0);
        assert_eq!(Record::decode(&b), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn rejects_truncated() {
        let b = enc(&sample());
        for n in 0..b.len() {
            assert_eq!(Record::decode(&b[..n]), Err(CodecError::Truncated), "n={n}");
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        let b = [0u8, 6, 30, 1, 0xff, 0, 1, 1];
        assert_eq!(Record::decode(&b), Err(CodecError::NotUtf8));
    }

    #[test]
    fn duplicate_rule() {
        let a = sample();
        let mut b = sample();
        b.period = 60;
        b.digits = 6;
        b.algo = Algorithm::Sha1;
        assert!(a.same_identity(&b));
        b.account = ArrayString::from("bob@example.com").unwrap();
        assert!(!a.same_identity(&b));
    }

    #[test]
    fn debug_redacts_secret() {
        let s = std::format!("{:?}", sample());
        assert!(!s.contains("49") && !s.contains("12345678901234567890"));
        assert!(s.contains("redacted"));
    }
}
