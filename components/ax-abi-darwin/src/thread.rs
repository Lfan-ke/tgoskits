//! The pthread family, for a process with one thread.
//!
//! Nothing here creates a thread yet, and what the rest of the family means
//! with only one is narrow: a mutex is taken or it is not, a condition has
//! nobody to signal it, and thread-specific data is one table. That narrow
//! meaning is implemented in full rather than faked: locking a mutex this
//! thread already holds is the deadlock it would be, and waiting on a
//! condition returns the spurious wakeup POSIX allows, since no other thread
//! exists to deliver a real one. `pthread_create` says it cannot, and the
//! host's log says why.
//!
//! These report failure the pthread way: the error number is the return
//! value and `errno` is left alone.

use ax_abi_port::{Host, SysResult};

use crate::{
    libc::Frame,
    start::{TSD_KEY_LIMIT, TSD_KEYS, TSD_SIGMASK, TSD_STACK_LEN, TSD_STACK_TOP},
    system::{Library, PRIVATE_NEXT_KEY},
    user,
};

const EINVAL: isize = 22;
const EBUSY: isize = 16;
const EDEADLK: isize = 11;
const EAGAIN: isize = 35;
const ETIMEDOUT: isize = 60;

/// Where a `pthread_mutex_t` keeps whether it is held. The first word is
/// Darwin's signature, which a static initializer fills in and this layer
/// leaves alone.
const HELD: usize = 8;
/// Where it keeps its type, as `pthread_mutexattr_settype` named it.
const KIND: usize = 12;
/// `PTHREAD_MUTEX_RECURSIVE`.
const RECURSIVE: u32 = 2;

/// `pthread_mutex_init(mutex, attr)`.
pub fn mutex_init(host: &dyn Host, mutex: usize, attr: usize) -> SysResult {
    let kind = if attr == 0 {
        0
    } else {
        user::u32_at(host, attr + 8)?
    };
    user::put_u32(host, mutex + HELD, 0)?;
    user::put_u32(host, mutex + KIND, kind)?;
    Ok(0)
}

/// `pthread_mutex_lock(mutex)` and `pthread_mutex_trylock(mutex)`.
pub fn mutex_lock(host: &dyn Host, mutex: usize, try_only: bool) -> SysResult {
    let held = user::u32_at(host, mutex + HELD)?;
    if held != 0 && user::u32_at(host, mutex + KIND)? != RECURSIVE {
        if try_only {
            return Ok(EBUSY);
        }
        host.platform()
            .trace("pthread_mutex_lock: the only thread already holds this mutex");
        return Ok(EDEADLK);
    }
    user::put_u32(host, mutex + HELD, held + 1)?;
    Ok(0)
}

/// `pthread_mutex_unlock(mutex)`.
pub fn mutex_unlock(host: &dyn Host, mutex: usize) -> SysResult {
    let held = user::u32_at(host, mutex + HELD)?;
    user::put_u32(host, mutex + HELD, held.saturating_sub(1))?;
    Ok(0)
}

/// `pthread_cond_wait(cond, mutex)`: a spurious wakeup, after giving the
/// processor up once.
pub fn cond_wait(host: &dyn Host) -> SysResult {
    if let Some(tasks) = host.tasks() {
        tasks.sched_yield()?;
    }
    Ok(0)
}

/// `pthread_cond_timedwait(cond, mutex, abstime)`: nobody can signal, so the
/// wait runs to its deadline.
pub fn cond_timedwait(host: &dyn Host, deadline: usize) -> SysResult {
    let Some(clock) = host.clock() else {
        return Ok(ETIMEDOUT);
    };
    let seconds = user::u64_at(host, deadline)?;
    let nanos = user::u64_at(host, deadline + 8)?;
    let until = seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
    let _ = clock.sleep_ns(until.saturating_sub(clock.wall_ns()));
    Ok(ETIMEDOUT)
}

/// `pthread_cond_timedwait_relative_np(cond, mutex, reltime)`.
pub fn cond_timedwait_relative(host: &dyn Host, interval: usize) -> SysResult {
    let Some(clock) = host.clock() else {
        return Ok(ETIMEDOUT);
    };
    let seconds = user::u64_at(host, interval)?;
    let nanos = user::u64_at(host, interval + 8)?;
    let _ = clock.sleep_ns(seconds.saturating_mul(1_000_000_000).saturating_add(nanos));
    Ok(ETIMEDOUT)
}

/// `pthread_key_create(key, destructor)`. Keys are a process's, values a
/// thread's; the destructor would run when a thread exits, and none does.
pub fn key_create(host: &dyn Host, library: &Library, key: usize) -> SysResult {
    let counter = (library.private() + PRIVATE_NEXT_KEY) as usize;
    let next = user::u64_at(host, counter)?;
    if next >= TSD_KEY_LIMIT {
        return Ok(EAGAIN);
    }
    user::put_u64(host, counter, next + 1)?;
    user::put_u64(host, key, next)?;
    Ok(0)
}

fn slot(frame: &Frame, key: usize) -> Option<usize> {
    ((key as u64) < TSD_KEY_LIMIT).then(|| frame.tsd + TSD_KEYS as usize + key * 8)
}

/// `pthread_getspecific(key)`.
pub fn getspecific(host: &dyn Host, frame: &Frame, key: usize) -> SysResult {
    match slot(frame, key) {
        Some(at) => Ok(user::u64_at(host, at)? as isize),
        None => Ok(0),
    }
}

/// `pthread_setspecific(key, value)`.
pub fn setspecific(host: &dyn Host, frame: &Frame, key: usize, value: usize) -> SysResult {
    match slot(frame, key) {
        Some(at) => {
            user::put_u64(host, at, value as u64)?;
            Ok(0)
        }
        None => Ok(EINVAL),
    }
}

/// `pthread_get_stackaddr_np(thread)`: the high end of the stack.
pub fn stack_top(host: &dyn Host, thread: usize) -> SysResult {
    Ok(user::u64_at(host, thread + TSD_STACK_TOP as usize)? as isize)
}

/// `pthread_get_stacksize_np(thread)`.
pub fn stack_len(host: &dyn Host, thread: usize) -> SysResult {
    Ok(user::u64_at(host, thread + TSD_STACK_LEN as usize)? as isize)
}

/// `pthread_threadid_np(thread, id)`.
pub fn thread_id(host: &dyn Host, id: usize) -> SysResult {
    let tid = host.tasks().map_or(1, |tasks| tasks.gettid());
    user::put_u64(host, id, u64::from(tid))?;
    Ok(0)
}

/// `pthread_sigmask(how, set, old)`. The mask is kept; nothing is delivered
/// against it yet, so it has nothing to hold back.
pub fn sigmask(host: &dyn Host, frame: &Frame, how: usize, set: usize, old: usize) -> SysResult {
    let at = frame.tsd + TSD_SIGMASK as usize;
    let now = user::u32_at(host, at)?;
    if old != 0 {
        user::put_u32(host, old, now)?;
    }
    if set != 0 {
        let asked = user::u32_at(host, set)?;
        let next = match how {
            1 => now | asked,
            2 => now & !asked,
            3 => asked,
            _ => return Ok(EINVAL),
        };
        user::put_u32(host, at, next)?;
    }
    Ok(0)
}

/// `pthread_getname_np(thread, name, len)`: the one thread has no name.
pub fn name(host: &dyn Host, at: usize, len: usize) -> SysResult {
    if len != 0 {
        user::put(host, at, &[0])?;
    }
    Ok(0)
}

/// `pthread_create`: there is no second thread to make yet.
pub fn create(host: &dyn Host) -> SysResult {
    host.platform()
        .trace("pthread_create: this personality does not create threads yet");
    Ok(EAGAIN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockHost;

    fn ready() -> (MockHost, Library, Frame) {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1_0000, 0);
        let frame = Frame {
            a: [0; 6],
            sp: 0,
            tsd: 0x4000,
        };
        (host, Library::new(0x8000), frame)
    }

    #[test]
    fn a_mutex_held_by_the_only_thread_reports_the_deadlock() {
        let (host, ..) = ready();
        assert_eq!(mutex_init(&host, 0x200, 0), Ok(0));
        assert_eq!(mutex_lock(&host, 0x200, false), Ok(0));
        assert_eq!(mutex_lock(&host, 0x200, true), Ok(EBUSY));
        assert_eq!(mutex_lock(&host, 0x200, false), Ok(EDEADLK));
        assert_eq!(mutex_unlock(&host, 0x200), Ok(0));
        assert_eq!(mutex_lock(&host, 0x200, true), Ok(0));
    }

    #[test]
    fn a_recursive_mutex_counts_its_holds() {
        let (host, ..) = ready();
        host.mem.borrow_mut()[0x308..0x30C].copy_from_slice(&RECURSIVE.to_le_bytes());
        assert_eq!(mutex_init(&host, 0x200, 0x300), Ok(0));
        assert_eq!(mutex_lock(&host, 0x200, false), Ok(0));
        assert_eq!(mutex_lock(&host, 0x200, false), Ok(0));
        assert_eq!(mutex_unlock(&host, 0x200), Ok(0));
        assert_eq!(user::u32_at(&host, 0x200 + HELD), Ok(1));
    }

    #[test]
    fn keys_are_handed_out_in_order_and_hold_what_was_stored() {
        let (host, library, frame) = ready();
        assert_eq!(key_create(&host, &library, 0x200), Ok(0));
        assert_eq!(key_create(&host, &library, 0x208), Ok(0));
        assert_eq!(user::u64_at(&host, 0x208), Ok(1));
        assert_eq!(getspecific(&host, &frame, 1), Ok(0));
        assert_eq!(setspecific(&host, &frame, 1, 0xABCD), Ok(0));
        assert_eq!(getspecific(&host, &frame, 1), Ok(0xABCD));
        assert_eq!(setspecific(&host, &frame, 4096, 1), Ok(EINVAL));
    }

    #[test]
    fn the_signal_mask_is_kept_per_thread() {
        let (host, _, frame) = ready();
        host.mem.borrow_mut()[0x200..0x204].copy_from_slice(&0b110u32.to_le_bytes());
        assert_eq!(sigmask(&host, &frame, 3, 0x200, 0), Ok(0));
        host.mem.borrow_mut()[0x200..0x204].copy_from_slice(&0b010u32.to_le_bytes());
        assert_eq!(sigmask(&host, &frame, 2, 0x200, 0x300), Ok(0));
        assert_eq!(user::u32_at(&host, 0x300), Ok(0b110));
        assert_eq!(sigmask(&host, &frame, 1, 0, 0x300), Ok(0));
        assert_eq!(user::u32_at(&host, 0x300), Ok(0b100));
    }
}
