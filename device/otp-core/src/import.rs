use crate::protocol::StatusWord;
use crate::record::Record;
use alloc::vec::Vec;
use arrayvec::ArrayVec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

pub trait Store {
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
    fn get(&self, i: usize) -> Option<Record>;
    fn push(&mut self, r: &Record) -> Result<(), Full>;
    fn remove(&mut self, i: usize);
    fn clear(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ImportResult {
    Saved = 0,
    Duplicate = 1,
    NoSpace = 2,
}

pub struct ImportSession {
    pub batch_id: [u8; 16],
    pub expected: u8,
    pub records: Vec<Record>,
}

impl ImportSession {
    pub fn begin(batch_id: [u8; 16], expected: u8) -> Result<Self, StatusWord> {
        if expected == 0 || expected > 64 {
            return Err(StatusWord::InvalidData);
        }
        Ok(Self {
            batch_id,
            expected,
            records: Vec::with_capacity(expected as usize),
        })
    }

    pub fn add(&mut self, r: Record) -> Result<(), StatusWord> {
        if self.records.len() >= self.expected as usize {
            return Err(StatusWord::BatchFull);
        }
        self.records.push(r);
        Ok(())
    }

    pub fn commit<S: Store>(self, store: &mut S) -> Vec<ImportResult> {
        let mut in_store = [false; 64];
        for j in 0..store.len() {
            if let Some(s) = store.get(j) {
                for (i, r) in self.records.iter().enumerate() {
                    if !in_store[i] && s.same_identity(r) {
                        in_store[i] = true;
                    }
                }
            }
        }
        let mut results = Vec::with_capacity(self.records.len());
        for (i, r) in self.records.iter().enumerate() {
            let dup = in_store[i] || self.records[..i].iter().any(|p| p.same_identity(r));
            let res = if dup {
                ImportResult::Duplicate
            } else if store.len() >= store.capacity() || store.push(r).is_err() {
                ImportResult::NoSpace
            } else {
                ImportResult::Saved
            };
            results.push(res);
        }
        results
    }
}

pub struct LastOutcome {
    pub batch_id: [u8; 16],
    pub approved: bool,
    pub results: Vec<ImportResult>,
}

impl LastOutcome {
    pub fn status_for(&self, id: &[u8; 16]) -> ArrayVec<u8, 66> {
        let mut v = ArrayVec::new();
        if *id != self.batch_id {
            v.push(0);
        } else if self.approved {
            v.push(1);
            v.extend(self.results.iter().take(64).map(|r| *r as u8));
        } else {
            v.push(2);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Algorithm;
    use arrayvec::ArrayString;

    struct VecStore {
        items: Vec<Record>,
        cap: usize,
    }

    impl Store for VecStore {
        fn len(&self) -> usize {
            self.items.len()
        }
        fn capacity(&self) -> usize {
            self.cap
        }
        fn get(&self, i: usize) -> Option<Record> {
            self.items.get(i).cloned()
        }
        fn push(&mut self, r: &Record) -> Result<(), Full> {
            if self.items.len() >= self.cap {
                return Err(Full);
            }
            self.items.push(r.clone());
            Ok(())
        }
        fn remove(&mut self, i: usize) {
            self.items.remove(i);
        }
        fn clear(&mut self) {
            self.items.clear();
        }
    }

    fn rec(n: u8) -> Record {
        let mut secret = ArrayVec::new();
        secret.push(n);
        secret.push(1);
        Record {
            algo: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: ArrayString::from("Issuer").unwrap(),
            account: ArrayString::from("acct").unwrap(),
            secret,
        }
    }

    fn empty() -> VecStore {
        VecStore {
            items: Vec::new(),
            cap: 64,
        }
    }

    fn session(recs: &[Record]) -> ImportSession {
        let mut s = ImportSession::begin([1; 16], recs.len() as u8).unwrap();
        for r in recs {
            s.add(r.clone()).unwrap();
        }
        s
    }

    #[test]
    fn import_saves_in_order() {
        let mut st = empty();
        let res = session(&[rec(1), rec(2), rec(3)]).commit(&mut st);
        assert_eq!(res, [ImportResult::Saved; 3]);
        assert_eq!(st.items.len(), 3);
        assert_eq!(st.items[0].secret[0], 1);
        assert_eq!(st.items[2].secret[0], 3);
    }

    #[test]
    fn import_dedupes_against_store() {
        let mut st = empty();
        st.push(&rec(1)).unwrap();
        let res = session(&[rec(1), rec(2)]).commit(&mut st);
        assert_eq!(res, [ImportResult::Duplicate, ImportResult::Saved]);
        assert_eq!(st.items.len(), 2);
    }

    #[test]
    fn import_dedupes_within_batch() {
        let mut st = empty();
        let res = session(&[rec(1), rec(1)]).commit(&mut st);
        assert_eq!(res, [ImportResult::Saved, ImportResult::Duplicate]);
        assert_eq!(st.items.len(), 1);
    }

    #[test]
    fn import_partial_when_full() {
        let mut st = empty();
        for i in 0..61 {
            st.push(&rec(100 + i)).unwrap();
        }
        let batch: Vec<Record> = (0..10).map(rec).collect();
        let res = session(&batch).commit(&mut st);
        assert_eq!(&res[..3], &[ImportResult::Saved; 3]);
        assert_eq!(&res[3..], &[ImportResult::NoSpace; 7]);
        assert_eq!(st.items.len(), 64);
    }

    #[test]
    fn add_beyond_expected() {
        let mut s = ImportSession::begin([0; 16], 1).unwrap();
        s.add(rec(1)).unwrap();
        assert_eq!(s.add(rec(2)), Err(StatusWord::BatchFull));
    }

    #[test]
    fn begin_bounds() {
        assert_eq!(
            ImportSession::begin([0; 16], 0).err(),
            Some(StatusWord::InvalidData)
        );
        assert_eq!(
            ImportSession::begin([0; 16], 65).err(),
            Some(StatusWord::InvalidData)
        );
        assert!(ImportSession::begin([0; 16], 64).is_ok());
    }

    #[test]
    fn status_unknown_batch() {
        let o = LastOutcome {
            batch_id: [1; 16],
            approved: true,
            results: Vec::new(),
        };
        assert_eq!(o.status_for(&[2; 16]).as_slice(), &[0]);
    }

    #[test]
    fn status_approved() {
        let o = LastOutcome {
            batch_id: [1; 16],
            approved: true,
            results: alloc::vec![
                ImportResult::Saved,
                ImportResult::Duplicate,
                ImportResult::NoSpace
            ],
        };
        assert_eq!(o.status_for(&[1; 16]).as_slice(), &[1, 0, 1, 2]);
    }

    #[test]
    fn status_rejected() {
        let o = LastOutcome {
            batch_id: [1; 16],
            approved: false,
            results: Vec::new(),
        };
        assert_eq!(o.status_for(&[1; 16]).as_slice(), &[2]);
    }

    struct CountingStore {
        inner: VecStore,
        gets: core::cell::RefCell<Vec<usize>>,
    }

    impl Store for CountingStore {
        fn len(&self) -> usize {
            self.inner.len()
        }
        fn capacity(&self) -> usize {
            self.inner.capacity()
        }
        fn get(&self, i: usize) -> Option<Record> {
            self.gets.borrow_mut().push(i);
            self.inner.get(i)
        }
        fn push(&mut self, r: &Record) -> Result<(), Full> {
            self.inner.push(r)
        }
        fn remove(&mut self, i: usize) {
            self.inner.remove(i)
        }
        fn clear(&mut self) {
            self.inner.clear()
        }
    }

    #[test]
    fn commit_fetches_each_stored_index_once() {
        let mut inner = empty();
        for i in 0..10 {
            inner.push(&rec(100 + i)).unwrap();
        }
        let mut st = CountingStore {
            inner,
            gets: Default::default(),
        };
        let batch: Vec<Record> = (0..20)
            .map(|i| rec(if i % 2 == 0 { 100 + i / 2 } else { i }))
            .collect();
        let res = session(&batch).commit(&mut st);
        assert_eq!(
            res.iter()
                .filter(|r| **r == ImportResult::Duplicate)
                .count(),
            10
        );
        let mut gets = st.gets.borrow().clone();
        gets.sort();
        assert_eq!(gets, (0..10).collect::<Vec<_>>());
    }
}
