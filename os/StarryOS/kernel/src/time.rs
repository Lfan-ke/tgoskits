use ax_runtime::hal::time::{NANOS_PER_SEC, TimeValue};
use linux_raw_sys::general::{
    __kernel_old_timespec, __kernel_old_timeval, __kernel_sock_timeval, __kernel_timespec,
    timespec, timeval,
};

use crate::{StarryError, StarryResult};

/// Tick rate of the `clock_t` unit reported by times(2), /proc/[pid]/stat and
/// getrusage. Linux fixes USER_HZ at 100 (`sysconf(_SC_CLK_TCK)`), so one tick
/// is 10 ms.
pub const USER_HZ: u64 = 100;

/// Convert an elapsed [`TimeValue`] to `clock_t` ticks, mirroring Linux
/// `nsec_to_clock_t` (kernel/time/time.c). Sharing one conversion across
/// times(2) and the /proc CPU-time fields keeps the kernel on a single tick
/// unit.
pub fn clock_t_ticks(elapsed: TimeValue) -> u64 {
    (elapsed.as_nanos() / (NANOS_PER_SEC as u128 / USER_HZ as u128)) as u64
}

/// A helper trait for converting from and to `TimeValue`.
pub trait TimeValueLike {
    /// Converts from `TimeValue`.
    fn from_time_value(tv: TimeValue) -> Self;

    /// Tries to convert into `TimeValue`.
    fn try_into_time_value(self) -> StarryResult<TimeValue>;
}

impl TimeValueLike for TimeValue {
    fn from_time_value(tv: TimeValue) -> Self {
        tv
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        Ok(self)
    }
}

impl TimeValueLike for timespec {
    fn from_time_value(tv: TimeValue) -> Self {
        Self {
            tv_sec: tv.as_secs() as _,
            tv_nsec: tv.subsec_nanos() as _,
        }
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        if self.tv_nsec < 0 || self.tv_nsec > 999_999_999 || self.tv_sec < 0 {
            return Err(StarryError::InvalidInput);
        }
        Ok(TimeValue::new(self.tv_sec as u64, self.tv_nsec as u32))
    }
}

impl TimeValueLike for __kernel_timespec {
    fn from_time_value(tv: TimeValue) -> Self {
        Self {
            tv_sec: tv.as_secs() as _,
            tv_nsec: tv.subsec_nanos() as _,
        }
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        if self.tv_nsec < 0 || self.tv_nsec > 999_999_999 || self.tv_sec < 0 {
            return Err(StarryError::InvalidInput);
        }
        Ok(TimeValue::new(self.tv_sec as u64, self.tv_nsec as u32))
    }
}

impl TimeValueLike for __kernel_old_timespec {
    fn from_time_value(tv: TimeValue) -> Self {
        Self {
            tv_sec: tv.as_secs() as _,
            tv_nsec: tv.subsec_nanos() as _,
        }
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        if self.tv_nsec < 0 || self.tv_nsec > 999_999_999 || self.tv_sec < 0 {
            return Err(StarryError::InvalidInput);
        }
        Ok(TimeValue::new(self.tv_sec as u64, self.tv_nsec as u32))
    }
}

impl TimeValueLike for timeval {
    fn from_time_value(tv: TimeValue) -> Self {
        Self {
            tv_sec: tv.as_secs() as _,
            tv_usec: tv.subsec_micros() as _,
        }
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        if self.tv_usec < 0 || self.tv_usec > 999_999 || self.tv_sec < 0 {
            return Err(StarryError::InvalidInput);
        }
        Ok(TimeValue::new(
            self.tv_sec as u64,
            self.tv_usec as u32 * 1000,
        ))
    }
}

impl TimeValueLike for __kernel_old_timeval {
    fn from_time_value(tv: TimeValue) -> Self {
        Self {
            tv_sec: tv.as_secs() as _,
            tv_usec: tv.subsec_micros() as _,
        }
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        if self.tv_usec < 0 || self.tv_usec > 999_999 || self.tv_sec < 0 {
            return Err(StarryError::InvalidInput);
        }
        Ok(TimeValue::new(
            self.tv_sec as u64,
            self.tv_usec as u32 * 1000,
        ))
    }
}

impl TimeValueLike for __kernel_sock_timeval {
    fn from_time_value(tv: TimeValue) -> Self {
        Self {
            tv_sec: tv.as_secs() as _,
            tv_usec: tv.subsec_micros() as _,
        }
    }

    fn try_into_time_value(self) -> StarryResult<TimeValue> {
        if self.tv_usec < 0 || self.tv_usec > 999_999 || self.tv_sec < 0 {
            return Err(StarryError::InvalidInput);
        }
        Ok(TimeValue::new(
            self.tv_sec as u64,
            self.tv_usec as u32 * 1000,
        ))
    }
}

#[cfg(axtest)]
pub(crate) fn time_value_conversion_rules_hold_for_test() -> bool {
    let tv = TimeValue::new(5, 123_456_789);
    let ts = timespec::from_time_value(tv);
    let kernel_ts = __kernel_timespec::from_time_value(tv);
    let old_ts = __kernel_old_timespec::from_time_value(tv);
    let timeval = timeval::from_time_value(tv);
    let old_timeval = __kernel_old_timeval::from_time_value(tv);
    let sock_timeval = __kernel_sock_timeval::from_time_value(tv);

    ts.tv_sec == 5
        && ts.tv_nsec == 123_456_789
        && matches!(kernel_ts.try_into_time_value(), Ok(value) if value == tv)
        && matches!(old_ts.try_into_time_value(), Ok(value) if value == tv)
        && timeval.tv_usec == 123_456
        && matches!(
            timeval.try_into_time_value(),
            Ok(value) if value == TimeValue::new(5, 123_456_000)
        )
        && matches!(
            old_timeval.try_into_time_value(),
            Ok(value) if value == TimeValue::new(5, 123_456_000)
        )
        && matches!(
            sock_timeval.try_into_time_value(),
            Ok(value) if value == TimeValue::new(5, 123_456_000)
        )
        && (timespec {
            tv_sec: -1,
            tv_nsec: 0,
        })
        .try_into_time_value()
        .is_err()
        && (__kernel_timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        })
        .try_into_time_value()
        .is_err()
        && (__kernel_old_timeval {
            tv_sec: 0,
            tv_usec: 1_000_000,
        })
        .try_into_time_value()
        .is_err()
        && (__kernel_sock_timeval {
            tv_sec: 0,
            tv_usec: -1,
        })
        .try_into_time_value()
        .is_err()
}
