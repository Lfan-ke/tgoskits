//! Time: the clocks, and the calendar a `time_t` turns into.
//!
//! The host keeps two clocks, the wall and one that only moves forward, and
//! every Darwin clock is one or the other. There is no time zone database
//! here, so local time is UTC and says so in `tm_zone`.

use ax_abi_port::{Host, SysResult};

use crate::{
    system::{Library, PRIVATE_TEXT_UTC},
    user,
};

/// `EINVAL`.
const EINVAL: i32 = 22;
/// `ENOSYS`, in Darwin's numbering.
const ENOSYS: i32 = 78;

/// Darwin's `clockid_t` values, from `<time.h>`.
mod id {
    pub const REALTIME: usize = 0;
    pub const MONOTONIC_RAW: usize = 4;
    pub const MONOTONIC_RAW_APPROX: usize = 5;
    pub const MONOTONIC: usize = 6;
    pub const UPTIME_RAW: usize = 8;
    pub const UPTIME_RAW_APPROX: usize = 9;
}

const NANOS: u64 = 1_000_000_000;

fn now(host: &dyn Host, clock: usize) -> Result<u64, i32> {
    let clocks = host.clock().ok_or(ENOSYS)?;
    match clock {
        id::REALTIME => Ok(clocks.wall_ns()),
        id::MONOTONIC
        | id::MONOTONIC_RAW
        | id::MONOTONIC_RAW_APPROX
        | id::UPTIME_RAW
        | id::UPTIME_RAW_APPROX => Ok(clocks.monotonic_ns()),
        // The processor-time clocks have no port to read yet.
        _ => Err(EINVAL),
    }
}

fn put_timespec(host: &dyn Host, at: usize, ns: u64) -> Result<(), i32> {
    user::put_u64(host, at, ns / NANOS)?;
    user::put_u64(host, at + 8, ns % NANOS)
}

/// `clock_gettime(clock, ts)`.
pub fn gettime(host: &dyn Host, clock: usize, ts: usize) -> SysResult {
    put_timespec(host, ts, now(host, clock)?)?;
    Ok(0)
}

/// `clock_getres(clock, ts)`: both clocks count nanoseconds.
pub fn getres(host: &dyn Host, clock: usize, ts: usize) -> SysResult {
    now(host, clock)?;
    if ts != 0 {
        put_timespec(host, ts, 1)?;
    }
    Ok(0)
}

/// `mach_absolute_time()`: the forward-only clock in ticks, and a tick here
/// is a nanosecond, which is what `mach_timebase_info` says.
pub fn absolute(host: &dyn Host) -> SysResult {
    Ok(host.clock().ok_or(ENOSYS)?.monotonic_ns() as isize)
}

/// `mach_timebase_info(info)`: one tick is one nanosecond.
pub fn timebase(host: &dyn Host, info: usize) -> SysResult {
    user::put_u32(host, info, 1)?;
    user::put_u32(host, info + 4, 1)?;
    Ok(0)
}

/// `time(t)`.
pub fn time(host: &dyn Host, t: usize) -> SysResult {
    let seconds = host.clock().ok_or(ENOSYS)?.wall_ns() / NANOS;
    if t != 0 {
        user::put_u64(host, t, seconds)?;
    }
    Ok(seconds as isize)
}

/// `gettimeofday(tv, tz)`: seconds and microseconds; the zone is long obsolete
/// and left alone.
pub fn gettimeofday(host: &dyn Host, tv: usize) -> SysResult {
    let now = host.clock().ok_or(ENOSYS)?.wall_ns();
    if tv != 0 {
        user::put_u64(host, tv, now / NANOS)?;
        user::put_u64(host, tv + 8, now % NANOS / 1000)?;
    }
    Ok(0)
}

/// `nanosleep(request, remaining)`.
pub fn nanosleep(host: &dyn Host, request: usize, remaining: usize) -> SysResult {
    let seconds = user::u64_at(host, request)?;
    let nanos = user::u64_at(host, request + 8)?;
    if nanos >= NANOS {
        return Err(EINVAL);
    }
    let asked = seconds.saturating_mul(NANOS).saturating_add(nanos);
    match host.clock().ok_or(ENOSYS)?.sleep_ns(asked) {
        ax_abi_port::Slept::Full => Ok(0),
        ax_abi_port::Slept::Short { errno, elapsed_ns } => {
            if remaining != 0 {
                put_timespec(host, remaining, asked.saturating_sub(elapsed_ns))?;
            }
            Err(errno)
        }
    }
}

/// A calendar date and time, as `struct tm` counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
}

fn leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const MONTH_DAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// What `seconds` since the epoch is on the calendar, in UTC.
pub fn civil(seconds: i64) -> Tm {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let mut year = 1970i64;
    let mut left = days;
    loop {
        let len = if leap(year) { 366 } else { 365 };
        if left < 0 {
            year -= 1;
            left += if leap(year) { 366 } else { 365 };
        } else if left >= len {
            left -= len;
            year += 1;
        } else {
            break;
        }
    }
    let yday = left;
    let mut mon = 0;
    for (index, days) in MONTH_DAYS.iter().enumerate() {
        let len = days + i64::from(index == 1 && leap(year));
        if left < len {
            mon = index;
            break;
        }
        left -= len;
    }
    Tm {
        sec: (rest % 60) as i32,
        min: (rest / 60 % 60) as i32,
        hour: (rest / 3600) as i32,
        mday: left as i32 + 1,
        mon: mon as i32,
        year: (year - 1900) as i32,
        // The epoch was a Thursday.
        wday: (days + 4).rem_euclid(7) as i32,
        yday: yday as i32,
    }
}

/// The seconds since the epoch a calendar time names, with out-of-range
/// fields carried the way `mktime` carries them.
pub fn seconds_of(tm: &Tm) -> i64 {
    let months = tm.year as i64 * 12 + tm.mon as i64;
    let year = 1900 + months.div_euclid(12);
    let mon = months.rem_euclid(12) as usize;
    let mut days = 0i64;
    if year >= 1970 {
        for y in 1970..year {
            days += if leap(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if leap(y) { 366 } else { 365 };
        }
    }
    for (index, len) in MONTH_DAYS.iter().enumerate().take(mon) {
        days += len + i64::from(index == 1 && leap(year));
    }
    days += tm.mday as i64 - 1;
    days * 86_400 + tm.hour as i64 * 3600 + tm.min as i64 * 60 + tm.sec as i64
}

/// Darwin's `struct tm`: nine ints, then `tm_gmtoff` and `tm_zone`.
const TM_LEN: usize = 56;

fn put_tm(host: &dyn Host, library: &Library, at: usize, tm: &Tm) -> Result<(), i32> {
    let mut out = [0u8; TM_LEN];
    for (index, field) in [
        tm.sec, tm.min, tm.hour, tm.mday, tm.mon, tm.year, tm.wday, tm.yday, 0,
    ]
    .into_iter()
    .enumerate()
    {
        out[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
    }
    let zone = library.private() + PRIVATE_TEXT_UTC;
    out[48..56].copy_from_slice(&zone.to_le_bytes());
    user::put(host, at, &out)
}

fn read_tm(host: &dyn Host, at: usize) -> Result<Tm, i32> {
    let raw = user::bytes(host, at, 36)?;
    let field = |index: usize| {
        i32::from_le_bytes([
            raw[index * 4],
            raw[index * 4 + 1],
            raw[index * 4 + 2],
            raw[index * 4 + 3],
        ])
    };
    Ok(Tm {
        sec: field(0),
        min: field(1),
        hour: field(2),
        mday: field(3),
        mon: field(4),
        year: field(5),
        wday: field(6),
        yday: field(7),
    })
}

/// `gmtime_r(t, tm)` and `localtime_r(t, tm)`, which are the same here.
pub fn gmtime(host: &dyn Host, library: &Library, t: usize, tm: usize) -> SysResult {
    let seconds = user::u64_at(host, t)? as i64;
    put_tm(host, library, tm, &civil(seconds))?;
    Ok(tm as isize)
}

/// `mktime(tm)`: the time, with the structure's fields brought into range.
pub fn mktime(host: &dyn Host, library: &Library, tm: usize) -> SysResult {
    let seconds = seconds_of(&read_tm(host, tm)?);
    put_tm(host, library, tm, &civil(seconds))?;
    Ok(seconds as isize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_a_leap_day_land_on_the_right_dates() {
        let epoch = civil(0);
        assert_eq!(
            (epoch.year, epoch.mon, epoch.mday, epoch.wday, epoch.yday),
            (70, 0, 1, 4, 0)
        );
        // 2024-02-29 12:34:56 UTC.
        let leap_day = civil(1_709_210_096);
        assert_eq!(
            (
                leap_day.year,
                leap_day.mon,
                leap_day.mday,
                leap_day.hour,
                leap_day.min,
                leap_day.sec
            ),
            (124, 1, 29, 12, 34, 56)
        );
        assert_eq!(leap_day.wday, 4);
        assert_eq!(leap_day.yday, 59);
        // The last second before the epoch.
        let before = civil(-1);
        assert_eq!(
            (before.year, before.mon, before.mday, before.hour),
            (69, 11, 31, 23)
        );
    }

    #[test]
    fn a_calendar_time_goes_back_to_the_seconds_it_came_from() {
        for seconds in [
            0,
            86_399,
            951_782_400,
            1_709_210_096,
            4_102_444_800,
            -86_400,
        ] {
            assert_eq!(seconds_of(&civil(seconds)), seconds);
        }
        // Month 12 of a year is January of the next.
        let carried = Tm {
            sec: 0,
            min: 0,
            hour: 0,
            mday: 1,
            mon: 12,
            year: 99,
            wday: 0,
            yday: 0,
        };
        assert_eq!(seconds_of(&carried), 946_684_800);
    }
}
