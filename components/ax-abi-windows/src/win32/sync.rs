//! Locks, condition variables, events, semaphores and mutexes.
//!
//! Each one is a word - or a small block - of the program's own memory, and
//! all of them are built from the same two host steps: an atomic update of a
//! shared word, and blocking on one until another thread changes it. That is
//! what [`ax_abi_port::Wait`] provides, and it is deliberately all it
//! provides: the protocols below are Windows's, not the host's.
//!
//! The lock word has three states, which is what lets an uncontended release
//! avoid waking anyone: 0 free, 1 held with nobody waiting, 2 held with
//! someone waiting. A thread that fails to take a free lock marks it 2 before
//! parking, so the release that follows knows it owes a wake.

use ax_abi_port::Wait;
use ax_dispatch::Dispatch;

use super::{Call, FALSE, TRUE, heap};
use crate::teb_peb::PEB_PROCESS_HEAP;

/// The lock word's three states.
const FREE: u32 = 0;
const HELD: u32 = 1;
const CONTENDED: u32 = 2;

/// `INFINITE`: a wait with no deadline.
pub const INFINITE: u32 = 0xFFFF_FFFF;

/// What a wait returns: `WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_FAILED`.
pub const WAIT_OBJECT_0: usize = 0;
pub const WAIT_TIMEOUT: usize = 0x102;
pub const WAIT_FAILED: usize = 0xFFFF_FFFF;

/// The word a synchronisation object begins with, so a handle that is really a
/// pointer into the process heap can be told from one that is not.
const MAGIC: u64 = 0x434E_5953_5952_5241; // "ARRYSYNC"

/// A synchronisation object's fields, from the start of its block.
const KIND: usize = 8;
/// The word threads park on: an event's signal, a semaphore's count, a
/// mutex's lock.
const STATE: usize = 16;
/// A mutex's owner, and below it the depth it has been taken to. A
/// semaphore uses the same word past its count as the lock that guards it,
/// and a timer keeps the moment it comes due where a mutex keeps its depth.
const OWNER: usize = 20;
const GUARD: usize = 20;
const DEPTH: usize = 24;
const DUE: usize = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Kind {
    ManualEvent = 1,
    AutoEvent   = 2,
    Semaphore   = 3,
    Mutex       = 4,
    Timer       = 5,
}

impl Kind {
    fn from(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::ManualEvent,
            2 => Self::AutoEvent,
            3 => Self::Semaphore,
            4 => Self::Mutex,
            5 => Self::Timer,
            _ => return None,
        })
    }
}

/// The host's synchronisation steps, or nothing if this host has none.
fn port<'a>(c: &'a Call<'_>) -> Option<&'a dyn Wait> {
    c.host.wait()
}

fn swap(c: &Call<'_>, at: usize, value: u32) -> Option<u32> {
    port(c)?.swap(at, value).ok()
}

fn add(c: &Call<'_>, at: usize, value: u32) -> Option<u32> {
    port(c)?.fetch_add(at, value).ok()
}

/// Park until the word at `at` stops holding `expected`, or the deadline
/// passes. A word that already changed counts as woken: the caller looks
/// again either way.
fn park(c: &Call<'_>, at: usize, expected: u32, timeout_ms: u32) -> bool {
    let Some(wait) = port(c) else { return false };
    let timeout = (timeout_ms != INFINITE).then(|| timeout_ms as u64 * 1_000_000);
    // An error is the word having moved between the caller's read and the
    // park, which is a reason to look again - the same as being woken.
    wait.wait(at, expected, timeout).unwrap_or(true)
}

fn unpark(c: &Call<'_>, at: usize, count: u32) {
    if let Some(wait) = port(c) {
        let _ = wait.wake(at, count);
    }
}

/// Take the lock at `at`, blocking until it is free.
///
/// A host with no blocking of its own cannot be waited on, so the lock is
/// taken rather than waited for: without the port nothing could ever wake this
/// thread, and spinning would only hang the one thread that might release it.
pub(super) fn lock(c: &Call<'_>, at: usize) {
    if port(c).is_none() {
        c.write_u32(at, HELD);
        return;
    }
    if swap(c, at, HELD) == Some(FREE) {
        return;
    }
    // Every later attempt claims it as contended, so whoever releases it
    // knows to wake this thread even if it took the lock in between.
    while swap(c, at, CONTENDED) != Some(FREE) {
        park(c, at, CONTENDED, INFINITE);
    }
}

/// Release the lock at `at`, waking one waiter if the lock says there is one.
pub(super) fn unlock(c: &Call<'_>, at: usize) {
    if swap(c, at, FREE) == Some(CONTENDED) {
        unpark(c, at, 1);
    }
}

/// Take the lock only if it is free.
pub(super) fn try_lock_word(c: &Call<'_>, at: usize) -> bool {
    if port(c).is_none() {
        let free = c.read_u32(at) == Some(FREE);
        c.write_u32(at, HELD);
        return free;
    }
    match swap(c, at, HELD) {
        Some(FREE) => true,
        // Putting HELD in lost the record that someone is waiting; put it
        // back so the holder still owes them a wake.
        Some(CONTENDED) => {
            swap(c, at, CONTENDED);
            false
        }
        _ => false,
    }
}

/// InitializeSRWLock / InitializeConditionVariable: both start at zero.
pub fn init(c: &mut Call<'_>) -> Dispatch {
    c.write_u32(c.arg(0), 0);
    c.finish(0)
}

pub fn acquire_exclusive(c: &mut Call<'_>) -> Dispatch {
    lock(c, c.arg(0));
    c.finish(0)
}

pub fn release_exclusive(c: &mut Call<'_>) -> Dispatch {
    unlock(c, c.arg(0));
    c.finish(0)
}

pub fn try_acquire_exclusive(c: &mut Call<'_>) -> Dispatch {
    let taken = try_lock_word(c, c.arg(0));
    c.finish(if taken { TRUE } else { FALSE })
}

/// A shared lock is taken exclusively here. Readers serialise where Windows
/// would let them run together, which is slower but never wrong; a reader
/// count would need its own protocol to keep writers from starving.
pub fn acquire_shared(c: &mut Call<'_>) -> Dispatch {
    lock(c, c.arg(0));
    c.finish(0)
}

pub fn release_shared(c: &mut Call<'_>) -> Dispatch {
    unlock(c, c.arg(0));
    c.finish(0)
}

pub fn try_acquire_shared(c: &mut Call<'_>) -> Dispatch {
    let taken = try_lock_word(c, c.arg(0));
    c.finish(if taken { TRUE } else { FALSE })
}

/// WakeConditionVariable / WakeAllConditionVariable: move the variable on so
/// a sleeper's parked value no longer matches, then wake.
pub fn wake_condition(c: &mut Call<'_>, all: bool) -> Dispatch {
    let at = c.arg(0);
    add(c, at, 1);
    unpark(c, at, if all { u32::MAX } else { 1 });
    c.finish(0)
}

/// SleepConditionVariableSRW(cond, lock, ms, flags) and the CS form.
///
/// The variable is read before the lock goes, so a wake that lands in the gap
/// changes the value the park compares against and the park returns at once -
/// which is the whole reason the value is read first.
pub fn sleep_condition(c: &mut Call<'_>, lock_at: usize, timeout_ms: u32) -> bool {
    let cond = c.arg(0);
    let Some(seen) = c.read_u32(cond) else {
        return false;
    };
    unlock(c, lock_at);
    let woken = park(c, cond, seen, timeout_ms);
    lock(c, lock_at);
    woken
}

/// When a wait that was given `timeout_ms` must give up, in monotonic
/// nanoseconds, or nothing for a wait with no deadline.
///
/// Every waiting loop keeps its own deadline rather than trusting the port to
/// say which of its outcomes ended the park: a wait that was told to time out
/// has to, whatever the park reports.
fn deadline_for(c: &Call<'_>, timeout_ms: u32) -> Option<u64> {
    if timeout_ms == INFINITE {
        return None;
    }
    Some(c.host.clock().map_or(0, |clock| clock.monotonic_ns()) + timeout_ms as u64 * 1_000_000)
}

/// What is left of a deadline, in milliseconds, or nothing once it has passed.
fn left_of(c: &Call<'_>, deadline: Option<u64>) -> Option<u32> {
    let Some(deadline) = deadline else {
        return Some(INFINITE);
    };
    let now = c
        .host
        .clock()
        .map_or(deadline, |clock| clock.monotonic_ns());
    (now < deadline).then(|| ((deadline - now) / 1_000_000) as u32)
}

/// How many times anything in this process has been signalled.
///
/// A thread waiting on several objects parks on this rather than on any one
/// of them; every signal moves it, so no wake is missed and every waiter gets
/// to look over its own objects again.
pub(super) fn signal_count(c: &Call<'_>) -> Option<u32> {
    c.read_u32(c.peb()? + super::PEB_SIGNAL_SEQ)
}

/// Record a signal and wake everyone waiting on several objects at once.
fn announce(c: &Call<'_>) {
    let Some(peb) = c.peb() else { return };
    let at = peb + super::PEB_SIGNAL_SEQ;
    add(c, at, 1);
    unpark(c, at, u32::MAX);
}

/// Park until the signal counter leaves `seen`, or the deadline passes.
pub(super) fn wait_for_signal(c: &Call<'_>, seen: u32, timeout_ms: u32) -> bool {
    let Some(peb) = c.peb() else { return false };
    park(c, peb + super::PEB_SIGNAL_SEQ, seen, timeout_ms)
}

/// The process heap a new object is carved from.
fn heap_of(c: &Call<'_>) -> Option<usize> {
    c.peb()
        .and_then(|peb| c.read_u64(peb + PEB_PROCESS_HEAP))
        .map(|heap| heap as usize)
}

/// Lay out a new object and answer with the handle naming it: the block
/// itself, which the magic word identifies on the way back in.
fn create(c: &mut Call<'_>, kind: Kind, state: u32) -> Option<usize> {
    let heap = heap_of(c)?;
    let block = heap::alloc(c, heap, 32)?;
    super::zero(c, block, 32).then_some(())?;
    c.write_u64(block, MAGIC);
    c.write_u32(block + KIND, kind as u32);
    c.write_u32(block + STATE, state);
    Some(block)
}

/// The object a handle names, if it names one.
fn object(c: &Call<'_>, handle: usize) -> Option<(usize, Kind)> {
    if handle == 0 || !handle.is_multiple_of(8) {
        return None;
    }
    (c.read_u64(handle)? == MAGIC)
        .then(|| Kind::from(c.read_u32(handle + KIND)?).map(|kind| (handle, kind)))?
}

/// Release an object's block. A handle that names one is closed here; any
/// other handle is left to the caller to make sense of.
pub(super) fn close(c: &mut Call<'_>, handle: usize) -> bool {
    let Some((block, _)) = object(c, handle) else {
        return false;
    };
    // Anyone still parked on it is woken rather than left waiting on memory
    // that is about to be handed out again.
    unpark(c, block + STATE, u32::MAX);
    announce(c);
    c.write_u64(block, 0);
    if let Some(heap) = heap_of(c) {
        heap::mark_free(c, heap, block);
    }
    true
}

/// CreateEventA/W(attributes, manual reset, initial state, name).
pub fn create_event(c: &mut Call<'_>) -> Dispatch {
    let kind = if c.arg(1) != 0 {
        Kind::ManualEvent
    } else {
        Kind::AutoEvent
    };
    let signalled = u32::from(c.arg(2) != 0);
    match create(c, kind, signalled) {
        Some(handle) => {
            c.set_last_error(0);
            c.finish(handle)
        }
        None => c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// SetEvent(handle): signal it. A manual-reset event stays signalled and
/// releases everyone; an auto-reset event releases one thread, which takes
/// the signal with it.
pub fn set_event(c: &mut Call<'_>) -> Dispatch {
    let Some((block, kind)) = object(c, c.arg(0)) else {
        return c.finish(TRUE);
    };
    swap(c, block + STATE, 1);
    unpark(
        c,
        block + STATE,
        if kind == Kind::ManualEvent {
            u32::MAX
        } else {
            1
        },
    );
    c.finish(TRUE)
}

/// ResetEvent(handle): back to unsignalled, waking nobody.
pub fn reset_event(c: &mut Call<'_>) -> Dispatch {
    if let Some((block, _)) = object(c, c.arg(0)) {
        swap(c, block + STATE, 0);
    }
    c.finish(TRUE)
}

/// CreateWaitableTimerExW(attributes, name, flags, access): a timer a thread
/// can wait on. It starts unarmed; `SetWaitableTimerEx` says when it comes due.
pub fn create_timer(c: &mut Call<'_>) -> Dispatch {
    match create(c, Kind::Timer, 0) {
        Some(handle) => {
            c.set_last_error(0);
            c.finish(handle)
        }
        None => c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// SetWaitableTimer(handle, due time, ...): arm it. A negative due time is
/// relative, in hundreds of nanoseconds, which is how a sleep asks for one.
pub fn set_timer(c: &mut Call<'_>) -> Dispatch {
    let Some((block, Kind::Timer)) = object(c, c.arg(0)) else {
        return c.finish(TRUE);
    };
    let due = c.read_u64(c.arg(1)).unwrap_or(0) as i64;
    let now = c.host.clock().map_or(0, |clock| clock.monotonic_ns());
    // A positive due time is an absolute file time, which this has no way to
    // relate to the monotonic clock; treat it as due at once, as a timer set
    // to a moment already past would be.
    let at = if due < 0 {
        now + due.unsigned_abs() * 100
    } else {
        now
    };
    swap(c, block + STATE, 0);
    c.write_u64(block + DUE, at);
    announce(c);
    c.finish(TRUE)
}

/// CancelWaitableTimer(handle): unarm it, leaving it unsignalled.
pub fn cancel_timer(c: &mut Call<'_>) -> Dispatch {
    if let Some((block, Kind::Timer)) = object(c, c.arg(0)) {
        swap(c, block + STATE, 0);
        c.write_u64(block + DUE, 0);
    }
    c.finish(TRUE)
}

/// How long until `handle` comes due, in milliseconds, for a timer that is
/// armed and has not fired. A wait on several objects has to wake for it.
pub(super) fn due_in_ms(c: &Call<'_>, handle: usize) -> Option<u32> {
    let (block, Kind::Timer) = object(c, handle)? else {
        return None;
    };
    let due = c.read_u64(block + DUE)?;
    if due == 0 || c.read_u32(block + STATE) == Some(1) {
        return None;
    }
    let now = c.host.clock().map_or(due, |clock| clock.monotonic_ns());
    Some(((due.saturating_sub(now)) / 1_000_000) as u32)
}

/// CreateSemaphoreA/W(attributes, initial count, maximum, name).
pub fn create_semaphore(c: &mut Call<'_>) -> Dispatch {
    let initial = c.arg(1) as u32;
    match create(c, Kind::Semaphore, initial) {
        Some(handle) => {
            c.set_last_error(0);
            c.finish(handle)
        }
        None => c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// ReleaseSemaphore(handle, count, previous out): raise the count and wake as
/// many threads as were added, since each one can take exactly one.
pub fn release_semaphore(c: &mut Call<'_>) -> Dispatch {
    let (handle, count, previous_out) = (c.arg(0), c.arg(1) as u32, c.arg(2));
    let Some((block, Kind::Semaphore)) = object(c, handle) else {
        if previous_out != 0 {
            c.write_u32(previous_out, 0);
        }
        return c.finish(TRUE);
    };
    lock(c, block + GUARD);
    let previous = c.read_u32(block + STATE).unwrap_or(0);
    c.write_u32(block + STATE, previous.saturating_add(count));
    unlock(c, block + GUARD);
    if previous_out != 0 {
        c.write_u32(previous_out, previous);
    }
    // One thread can take each count that was added.
    unpark(c, block + STATE, count.max(1));
    announce(c);
    c.finish(TRUE)
}

/// CreateMutexA/W(attributes, initial owner, name).
pub fn create_mutex(c: &mut Call<'_>) -> Dispatch {
    let owned = c.arg(1) != 0;
    match create(c, Kind::Mutex, if owned { HELD } else { FREE }) {
        Some(handle) => {
            if owned {
                let tid = c.host.tasks().map_or(1, |t| t.gettid());
                c.write_u32(handle + OWNER, tid);
                c.write_u32(handle + DEPTH, 1);
            }
            c.set_last_error(0);
            c.finish(handle)
        }
        None => c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// ReleaseMutex(handle): unwind one level; the last one hands it on.
pub fn release_mutex(c: &mut Call<'_>) -> Dispatch {
    let Some((block, Kind::Mutex)) = object(c, c.arg(0)) else {
        return c.finish(TRUE);
    };
    let depth = c.read_u32(block + DEPTH).unwrap_or(1);
    if depth > 1 {
        c.write_u32(block + DEPTH, depth - 1);
        return c.finish(TRUE);
    }
    c.write_u32(block + DEPTH, 0);
    c.write_u32(block + OWNER, 0);
    unlock(c, block + STATE);
    announce(c);
    c.finish(TRUE)
}

/// Wait on one object until it is signalled or the deadline passes.
///
/// Which state the wait consumes is what tells the objects apart: a
/// manual-reset event leaves its signal for everyone, an auto-reset event and
/// a semaphore each take one, and a mutex is a lock that remembers its owner.
pub(super) fn wait_object(c: &mut Call<'_>, handle: usize, timeout_ms: u32) -> Option<usize> {
    let (block, kind) = object(c, handle)?;
    if port(c).is_none() {
        // Nothing can signal it, so a wait would never end; report it taken,
        // which is what this layer did before it could block at all.
        return Some(WAIT_OBJECT_0);
    }
    let state = block + STATE;
    let deadline = deadline_for(c, timeout_ms);
    // A mutex the calling thread already holds is taken again without waiting,
    // which is the one case that never looks at the state word.
    if kind == Kind::Mutex {
        let tid = c.host.tasks().map_or(1, |t| t.gettid());
        if c.read_u32(block + OWNER) == Some(tid) && c.read_u32(block + DEPTH).unwrap_or(0) > 0 {
            let depth = c.read_u32(block + DEPTH).unwrap_or(0);
            c.write_u32(block + DEPTH, depth + 1);
            return Some(WAIT_OBJECT_0);
        }
    }
    loop {
        let taken = match kind {
            // A manual reset event holds its signal for everyone.
            Kind::ManualEvent => c.read_u32(state) == Some(1),
            // An auto reset event and a semaphore each hand out one.
            Kind::AutoEvent => swap(c, state, 0) == Some(1),
            Kind::Semaphore => {
                lock(c, block + GUARD);
                let count = c.read_u32(state).unwrap_or(0);
                if count > 0 {
                    c.write_u32(state, count - 1);
                }
                unlock(c, block + GUARD);
                count > 0
            }
            Kind::Mutex => try_lock_word(c, state),
            // An armed timer is signalled once its moment has passed, and
            // stays that way until it is set again.
            Kind::Timer => {
                let due = c.read_u64(block + DUE).unwrap_or(0);
                let now = c.host.clock().map_or(due, |clock| clock.monotonic_ns());
                let fired = c.read_u32(state) == Some(1) || (due != 0 && now >= due);
                if fired {
                    swap(c, state, 1);
                }
                fired
            }
        };
        if taken {
            if kind == Kind::Mutex {
                let tid = c.host.tasks().map_or(1, |t| t.gettid());
                c.write_u32(block + OWNER, tid);
                c.write_u32(block + DEPTH, 1);
            }
            return Some(WAIT_OBJECT_0);
        }
        // A poll asks whether it is ready now, so it never parks.
        let Some(left) = left_of(c, deadline).filter(|_| timeout_ms != 0) else {
            return Some(WAIT_TIMEOUT);
        };
        // Nothing signals a timer, so the park has to end when it comes due.
        let left = match due_in_ms(c, handle) {
            Some(due) => left.min(due),
            None => left,
        };
        park(c, state, 0, left);
    }
}
