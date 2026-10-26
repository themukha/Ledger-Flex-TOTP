#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    pub unix_at_sync: u64,
    pub tz_offset_min: i16,
    pub ticks_at_sync: u64,
}

impl Clock {
    pub fn utc(&self, ticks_now: u64) -> u64 {
        self.unix_at_sync + ticks_now.saturating_sub(self.ticks_at_sync) / 10
    }

    pub fn local_hms(&self, ticks_now: u64) -> (u8, u8, u8) {
        let local =
            (self.utc(ticks_now) as i64 + self.tz_offset_min as i64 * 60).rem_euclid(86_400);
        (
            (local / 3600) as u8,
            (local % 3600 / 60) as u8,
            (local % 60) as u8,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_advances() {
        let c = Clock {
            unix_at_sync: 1000,
            tz_offset_min: 180,
            ticks_at_sync: 50,
        };
        assert_eq!(c.utc(80), 1003);
    }

    #[test]
    fn clock_local_wraps_midnight() {
        let c = Clock {
            unix_at_sync: 86399,
            tz_offset_min: 60,
            ticks_at_sync: 0,
        };
        assert_eq!(c.local_hms(0), (0, 59, 59));
    }

    #[test]
    fn clock_local_negative_tz() {
        let c = Clock {
            unix_at_sync: 60,
            tz_offset_min: -120,
            ticks_at_sync: 0,
        };
        assert_eq!(c.local_hms(0), (22, 1, 0));
    }
}
