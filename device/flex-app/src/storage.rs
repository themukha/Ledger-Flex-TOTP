use arrayvec::ArrayVec;
use ledger_device_sdk::app_storage;
use ledger_device_sdk::random::rand_bytes;
use otp_core::import::{Full, Store};
use otp_core::record::Record;
use otp_core::vault::{open, seal, VaultError, MAX_PAYLOAD_LEN};
use zeroize::Zeroizing;

pub const SLOT_SIZE: usize = 200;
pub const APP_STORAGE_SIZE: usize = 12_800;
pub const SLOT_COUNT: usize = APP_STORAGE_SIZE / SLOT_SIZE;

pub struct AppStorageStore {
    key: Zeroizing<[u8; 32]>,
    count: usize,
}

impl AppStorageStore {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        let mut s = Self { key, count: 0 };
        s.count = s.scan_used();
        s
    }

    pub fn payload(&self, i: usize) -> Option<ArrayVec<u8, MAX_PAYLOAD_LEN>> {
        if i >= self.count {
            return None;
        }
        let mut buf = [0u8; SLOT_SIZE];
        let n = Self::read_slot(i, &mut buf)?;
        let mut out = ArrayVec::new();
        out.try_extend_from_slice(&buf[1..n]).ok()?;
        Some(out)
    }

    pub fn open_payload(&self, payload: &[u8]) -> Result<Record, VaultError> {
        open(&self.key, payload)
    }

    fn offset(i: usize) -> u32 {
        (i * SLOT_SIZE) as u32
    }

    fn is_used(i: usize) -> bool {
        let mut used = [0u8; 1];
        app_storage::read(&mut used, Self::offset(i)).is_ok() && used[0] == 1
    }

    fn scan_used(&self) -> usize {
        (0..SLOT_COUNT).take_while(|&i| Self::is_used(i)).count()
    }

    fn read_slot(i: usize, buf: &mut [u8; SLOT_SIZE]) -> Option<usize> {
        let base = Self::offset(i);
        app_storage::read(&mut buf[..2], base).ok()?;
        if buf[0] != 1 {
            return None;
        }
        let total = 2 + 12 + buf[1] as usize;
        if total > SLOT_SIZE {
            return None;
        }
        app_storage::read(&mut buf[2..total], base + 2).ok()?;
        Some(total)
    }
}

impl Store for AppStorageStore {
    fn len(&self) -> usize {
        self.count
    }

    fn capacity(&self) -> usize {
        SLOT_COUNT
    }

    fn get(&self, i: usize) -> Option<Record> {
        if i >= self.count {
            return None;
        }
        let mut buf = Zeroizing::new([0u8; SLOT_SIZE]);
        let n = Self::read_slot(i, &mut buf)?;
        open(&self.key, &buf[1..n]).ok()
    }

    fn push(&mut self, r: &Record) -> Result<(), Full> {
        if self.count >= SLOT_COUNT {
            return Err(Full);
        }
        let mut nonce = [0u8; 12];
        rand_bytes(&mut nonce);
        let mut payload: ArrayVec<u8, MAX_PAYLOAD_LEN> = ArrayVec::new();
        seal(&self.key, nonce, r, &mut payload);
        let mut slot: ArrayVec<u8, { MAX_PAYLOAD_LEN + 1 }> = ArrayVec::new();
        slot.push(1);
        slot.try_extend_from_slice(&payload).map_err(|_| Full)?;
        app_storage::write(&slot, Self::offset(self.count)).map_err(|_| Full)?;
        self.count += 1;
        Ok(())
    }

    fn remove(&mut self, i: usize) {
        if i >= self.count {
            return;
        }
        let mut buf = Zeroizing::new([0u8; SLOT_SIZE]);
        for j in i + 1..self.count {
            let ok = match Self::read_slot(j, &mut buf) {
                Some(n) => app_storage::write(&buf[..n], Self::offset(j - 1)).is_ok(),
                None => false,
            };
            if !ok {
                self.count = self.scan_used();
                return;
            }
        }
        if app_storage::write(&[0u8], Self::offset(self.count - 1)).is_ok() {
            self.count -= 1;
        } else {
            self.count = self.scan_used();
        }
    }

    fn clear(&mut self) {
        app_storage::reset();
        self.count = 0;
    }
}
