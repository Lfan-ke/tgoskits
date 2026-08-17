//! System V semaphores (semget/semop/semtimedop/semctl).
//!
//! Mirrors Linux `ipc/sem.c`: sets of counting semaphores identified by a key,
//! atomic all-or-nothing multi-operation `semop`, SEM_UNDO adjustment lists
//! applied when a process exits, and the full `semctl` command surface. The
//! IPC permission model, id allocation and namespace scoping are shared with
//! the message-queue and shared-memory implementations (see `super`).

use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::time::Duration;

use ax_runtime::hal::time::monotonic_time_nanos;
use ax_task::current;
use bytemuck::AnyBitPattern;
use linux_raw_sys::general::{__kernel_long_t, __kernel_timespec, __kernel_ulong_t};
use starry_vm::{VmMutPtr, VmPtr, vm_load, vm_write_slice};

use super::{
    IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, IpcPerm,
    has_ipc_permission, next_ipc_id,
};
use crate::{
    Errno, StarryError, StarryResult,
    sync::Mutex,
    task::{AsThread, PidIdentityId, PidSnapshot, WaitQueue},
};

// semop() sem_flg bits (shared with the other IPC families).
const IPC_NOWAIT: i32 = 0o4000;
/// sem_flg bit requesting an undo entry that is reverted at process exit.
const SEM_UNDO: i32 = 0x1000;
/// `IPC_64` flag some libcs OR into the semctl command word.
const IPC_64: i32 = 0x100;

// semctl(2) commands beyond the IPC_* set shared in `super`.
const GETPID: i32 = 11;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;
const SEM_STAT: i32 = 18;
const SEM_INFO: i32 = 19;
const SEM_STAT_ANY: i32 = 20;

// Linux default tunables (`ipc/sem.c`, `include/uapi/linux/sem.h`).
/// Maximum value a semaphore may hold.
const SEMVMX: i32 = 32767;
/// Maximum semaphores per set.
const SEMMSL: usize = 32000;
/// Maximum number of semaphore sets.
const SEMMNI: usize = 32000;
/// Maximum semaphores system-wide.
const SEMMNS: usize = SEMMNI * SEMMSL;
/// Maximum operations per semop() call.
const SEMOPM: usize = 500;
/// Maximum adjust-on-exit value.
const SEMAEM: i32 = SEMVMX;

/// A single semop operation as passed by userspace.
#[repr(C)]
#[derive(Clone, Copy, AnyBitPattern)]
#[allow(non_camel_case_types)]
pub struct sembuf {
    /// Index of the semaphore within the set.
    sem_num: u16,
    /// Operation: `>0` post, `<0` wait, `==0` wait-for-zero.
    sem_op: i16,
    /// Operation flags (IPC_NOWAIT, SEM_UNDO).
    sem_flg: i16,
}

impl sembuf {
    fn nowait(&self) -> bool {
        (self.sem_flg as i32 & IPC_NOWAIT) != 0
    }
    fn undo(&self) -> bool {
        (self.sem_flg as i32 & SEM_UNDO) != 0
    }
}

// Linux `semid64_ds` differs by architecture: x86_64 keeps two reserved words
// interleaved with the timestamps (historically the 32-bit time high halves),
// while the asm-generic layout used by aarch64/riscv64/loongarch64 drops them.
// `sem_nsems` is a full word in the kernel struct; musl exposes only its low
// `unsigned short` on little-endian, which is all four target arches.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, AnyBitPattern)]
#[allow(non_camel_case_types)]
struct semid_ds {
    sem_perm: IpcPerm,
    sem_otime: __kernel_long_t,
    _unused1: __kernel_ulong_t,
    sem_ctime: __kernel_long_t,
    _unused2: __kernel_ulong_t,
    sem_nsems: __kernel_ulong_t,
    _unused3: __kernel_ulong_t,
    _unused4: __kernel_ulong_t,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy, AnyBitPattern)]
#[allow(non_camel_case_types)]
struct semid_ds {
    sem_perm: IpcPerm,
    sem_otime: __kernel_long_t,
    sem_ctime: __kernel_long_t,
    sem_nsems: __kernel_ulong_t,
    _unused3: __kernel_ulong_t,
    _unused4: __kernel_ulong_t,
}

impl semid_ds {
    #[cfg(target_arch = "x86_64")]
    fn build(perm: IpcPerm, otime: i64, ctime: i64, nsems: usize) -> Self {
        Self {
            sem_perm: perm,
            sem_otime: otime as __kernel_long_t,
            _unused1: 0,
            sem_ctime: ctime as __kernel_long_t,
            _unused2: 0,
            sem_nsems: nsems as __kernel_ulong_t,
            _unused3: 0,
            _unused4: 0,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn build(perm: IpcPerm, otime: i64, ctime: i64, nsems: usize) -> Self {
        Self {
            sem_perm: perm,
            sem_otime: otime as __kernel_long_t,
            sem_ctime: ctime as __kernel_long_t,
            sem_nsems: nsems as __kernel_ulong_t,
            _unused3: 0,
            _unused4: 0,
        }
    }
}

/// System-wide and per-set limits, returned by IPC_INFO/SEM_INFO.
#[repr(C)]
#[derive(Clone, Copy, AnyBitPattern)]
#[allow(non_camel_case_types)]
struct seminfo {
    semmap: i32,
    semmni: i32,
    semmns: i32,
    semmnu: i32,
    semmsl: i32,
    semopm: i32,
    semume: i32,
    semusz: i32,
    semvmx: i32,
    semaem: i32,
}

/// One semaphore within a set.
struct Sem {
    val: i32,
    /// PID of the last process to operate on this semaphore (GETPID).
    pid: Option<PidSnapshot>,
}

/// A blocked semop, tracked so GETNCNT/GETZCNT can report waiter counts.
struct Pending {
    token: u64,
    ops: Vec<(u16, i16)>,
}

/// Outcome of attempting a semop against the current semaphore values.
enum SemopStatus {
    Applied,
    Blocked,
    Failed(Errno),
}

/// A System V semaphore set.
struct SemSet {
    id: i32,
    perm: IpcPerm,
    sem_otime: i64,
    sem_ctime: i64,
    sems: Vec<Sem>,
    wait_queue: Arc<WaitQueue>,
    pending: Vec<Pending>,
    next_token: u64,
    mark_removed: bool,
    ns_id: u64,
}

impl SemSet {
    fn new(id: i32, key: i32, mode: u32, uid: u32, gid: u32, nsems: usize, ns_id: u64) -> Self {
        let now = monotonic_time_nanos() as i64;
        let mut sems = Vec::with_capacity(nsems);
        sems.resize_with(nsems, || Sem { val: 0, pid: None });
        SemSet {
            id,
            perm: IpcPerm {
                key,
                uid,
                gid,
                cuid: uid,
                cgid: gid,
                mode,
                seq: 0,
                pad: 0,
                unused0: 0,
                unused1: 0,
            },
            sem_otime: 0,
            sem_ctime: now,
            sems,
            wait_queue: Arc::new(WaitQueue::new()),
            pending: Vec::new(),
            next_token: 0,
            mark_removed: false,
            ns_id,
        }
    }

    fn status(&self) -> semid_ds {
        semid_ds::build(self.perm, self.sem_otime, self.sem_ctime, self.sems.len())
    }

    /// True while `ops` cannot make progress against the current values, so a
    /// waiter must keep sleeping. Overflow of a post is not a blocking
    /// condition - it surfaces as ERANGE on the real attempt.
    fn blocked(&self, ops: &[sembuf]) -> bool {
        let mut scratch: BTreeMap<usize, i32> = BTreeMap::new();
        for op in ops {
            let idx = op.sem_num as usize;
            let cur = *scratch.entry(idx).or_insert(self.sems[idx].val);
            let delta = op.sem_op as i32;
            if delta == 0 {
                if cur != 0 {
                    return true;
                }
            } else {
                let next = cur + delta;
                if next < 0 {
                    return true;
                }
                scratch.insert(idx, next.min(SEMVMX));
            }
        }
        false
    }

    /// Atomically apply `ops`, committing SEM_UNDO adjustments. Values are
    /// rolled back if any operation cannot proceed or would overflow.
    fn apply(&mut self, ops: &[sembuf], pid_id: PidIdentityId, pid: &PidSnapshot) -> SemopStatus {
        let mut rollback: Vec<(usize, i32)> = Vec::new();
        for op in ops {
            let idx = op.sem_num as usize;
            let delta = op.sem_op as i32;
            if delta == 0 {
                if self.sems[idx].val != 0 {
                    self.revert(&rollback);
                    return if op.nowait() {
                        SemopStatus::Failed(Errno::EAGAIN)
                    } else {
                        SemopStatus::Blocked
                    };
                }
            } else {
                let next = self.sems[idx].val + delta;
                if next < 0 {
                    self.revert(&rollback);
                    return if op.nowait() {
                        SemopStatus::Failed(Errno::EAGAIN)
                    } else {
                        SemopStatus::Blocked
                    };
                }
                if next > SEMVMX {
                    self.revert(&rollback);
                    return SemopStatus::Failed(Errno::ERANGE);
                }
                self.sems[idx].val = next;
                rollback.push((idx, delta));
            }
        }

        if ops.iter().any(sembuf::undo) && !self.commit_undo(ops, pid_id) {
            self.revert(&rollback);
            return SemopStatus::Failed(Errno::ERANGE);
        }

        for op in ops {
            self.sems[op.sem_num as usize].pid = Some(pid.clone());
        }
        SemopStatus::Applied
    }

    fn revert(&mut self, rollback: &[(usize, i32)]) {
        for &(idx, delta) in rollback.iter().rev() {
            self.sems[idx].val -= delta;
        }
    }

    /// Update this process's undo list for the set. Returns false (no mutation)
    /// if any adjustment would exceed the permitted magnitude.
    fn commit_undo(&self, ops: &[sembuf], pid_id: PidIdentityId) -> bool {
        let mut registry = SEM_UNDO_REGISTRY.lock();
        let entry = registry
            .entry((pid_id, self.id))
            .or_insert_with(|| vec![0i32; self.sems.len()]);
        let mut next = entry.clone();
        for op in ops {
            if !op.undo() {
                continue;
            }
            let idx = op.sem_num as usize;
            match next[idx].checked_sub(op.sem_op as i32) {
                Some(v) if v.abs() <= SEMVMX => next[idx] = v,
                _ => return false,
            }
        }
        *entry = next;
        true
    }

    fn register_pending(&mut self, ops: &[sembuf]) -> u64 {
        let token = self.next_token;
        self.next_token += 1;
        self.pending.push(Pending {
            token,
            ops: ops.iter().map(|op| (op.sem_num, op.sem_op)).collect(),
        });
        token
    }

    fn remove_pending(&mut self, token: u64) {
        self.pending.retain(|p| p.token != token);
    }

    fn semncnt(&self, num: u16) -> usize {
        self.pending
            .iter()
            .filter(|p| p.ops.iter().any(|&(n, op)| n == num && op < 0))
            .count()
    }

    fn semzcnt(&self, num: u16) -> usize {
        self.pending
            .iter()
            .filter(|p| p.ops.iter().any(|&(n, op)| n == num && op == 0))
            .count()
    }
}

/// Registry of semaphore sets, keyed like the message-queue manager.
struct SemManager {
    key_id: BTreeMap<(i32, u64), i32>,
    sets: BTreeMap<i32, Arc<Mutex<SemSet>>>,
}

impl SemManager {
    const fn new() -> Self {
        SemManager {
            key_id: BTreeMap::new(),
            sets: BTreeMap::new(),
        }
    }

    fn id_by_key(&self, key: i32, ns_id: u64) -> Option<i32> {
        self.key_id.get(&(key, ns_id)).copied()
    }

    fn get(&self, id: i32, ns_id: u64) -> Option<Arc<Mutex<SemSet>>> {
        self.sets
            .get(&id)
            .filter(|s| s.lock().ns_id == ns_id)
            .cloned()
    }

    fn insert(&mut self, key: i32, ns_id: u64, id: i32, set: Arc<Mutex<SemSet>>) {
        if key != IPC_PRIVATE {
            self.key_id.insert((key, ns_id), id);
        }
        self.sets.insert(id, set);
    }

    fn remove(&mut self, id: i32) {
        self.key_id.retain(|_, &mut v| v != id);
        self.sets.remove(&id);
    }

    fn count(&self, ns_id: u64) -> usize {
        self.sets.values().filter(|s| s.lock().ns_id == ns_id).count()
    }

    fn total_sems(&self, ns_id: u64) -> usize {
        self.sets
            .values()
            .filter(|s| s.lock().ns_id == ns_id)
            .map(|s| s.lock().sems.len())
            .sum()
    }

    fn nth(&self, ns_id: u64, index: usize) -> Option<(i32, Arc<Mutex<SemSet>>)> {
        self.sets
            .iter()
            .filter(|(_, s)| s.lock().ns_id == ns_id && !s.lock().mark_removed)
            .nth(index)
            .map(|(&id, set)| (id, set.clone()))
    }
}

static SEM_MANAGER: Mutex<SemManager> = Mutex::new(SemManager::new());

/// Per-process SEM_UNDO adjustment lists, keyed by (owner pid identity, semid).
/// Global and pid-keyed like the fcntl lock table, so the process-exit hook can
/// find and revert them without threading state through `ProcessData`.
static SEM_UNDO_REGISTRY: Mutex<BTreeMap<(PidIdentityId, i32), Vec<i32>>> =
    Mutex::new(BTreeMap::new());

fn current_uid_gid() -> (u32, u32) {
    let current = current();
    let cred = current.as_thread().cred();
    (cred.euid, cred.egid)
}

fn current_ipc_ns() -> u64 {
    let current = current();
    let ns = current.as_thread().proc_data.nsproxy.lock();
    ns.ipc_ns.lock().ns_id
}

/// `semget(key, nsems, semflg)`.
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> StarryResult<isize> {
    let (uid, gid) = current_uid_gid();
    let ns_id = current_ipc_ns();
    let nsems = nsems as usize;

    let mut manager = SEM_MANAGER.lock();

    if key != IPC_PRIVATE
        && let Some(id) = manager.id_by_key(key, ns_id)
    {
        let set = manager.get(id, ns_id).ok_or(StarryError::from(Errno::ENOENT))?;
        let set = set.lock();
        if set.mark_removed {
            return Err(StarryError::from(Errno::EIDRM));
        }
        if !has_ipc_permission(&set.perm, uid, gid, false) {
            return Err(StarryError::from(Errno::EACCES));
        }
        if (semflg & IPC_CREAT) != 0 && (semflg & IPC_EXCL) != 0 {
            return Err(StarryError::from(Errno::EEXIST));
        }
        // An existing set must be at least as large as requested.
        if nsems != 0 && nsems > set.sems.len() {
            return Err(StarryError::from(Errno::EINVAL));
        }
        return Ok(id as isize);
    }

    if key != IPC_PRIVATE && (semflg & IPC_CREAT) == 0 {
        return Err(StarryError::from(Errno::ENOENT));
    }

    // Creating a set requires a valid semaphore count.
    if nsems == 0 || nsems > SEMMSL {
        return Err(StarryError::from(Errno::EINVAL));
    }
    if manager.count(ns_id) >= SEMMNI {
        return Err(StarryError::from(Errno::ENOSPC));
    }

    let id = next_ipc_id();
    let set = SemSet::new(id, key, (semflg & 0o777) as u32, uid, gid, nsems, ns_id);
    manager.insert(key, ns_id, id, Arc::new(Mutex::new(set)));
    Ok(id as isize)
}

/// `semop(semid, sops, nsops)` - a `semtimedop` with no timeout.
pub fn sys_semop(semid: i32, sops: *const sembuf, nsops: usize) -> StarryResult<isize> {
    sys_semtimedop(semid, sops, nsops, core::ptr::null())
}

/// `semtimedop(semid, sops, nsops, timeout)`.
pub fn sys_semtimedop(
    semid: i32,
    sops: *const sembuf,
    nsops: usize,
    timeout: *const __kernel_timespec,
) -> StarryResult<isize> {
    if nsops == 0 {
        return Err(StarryError::from(Errno::EINVAL));
    }
    if nsops > SEMOPM {
        return Err(StarryError::from(Errno::E2BIG));
    }

    let deadline = load_relative_deadline(timeout)?;
    let ops: Vec<sembuf> = vm_load(sops, nsops)?;
    let alter = ops.iter().any(|op| op.sem_op != 0);

    let (uid, gid) = current_uid_gid();
    let ns_id = current_ipc_ns();
    let (pid_id, pid_snapshot) = {
        let current = current();
        let identity = current.as_thread().proc_data.identity();
        (identity.id(), identity.snapshot())
    };

    let set_ref = SEM_MANAGER
        .lock()
        .get(semid, ns_id)
        .ok_or(StarryError::from(Errno::EINVAL))?;

    {
        let set = set_ref.lock();
        if set.mark_removed {
            return Err(StarryError::from(Errno::EIDRM));
        }
        if !has_ipc_permission(&set.perm, uid, gid, alter) {
            return Err(StarryError::from(Errno::EACCES));
        }
        for op in &ops {
            if op.sem_num as usize >= set.sems.len() {
                return Err(StarryError::from(Errno::EFBIG));
            }
        }
    }

    loop {
        let mut set = set_ref.lock();
        if set.mark_removed {
            return Err(StarryError::from(Errno::EIDRM));
        }
        match set.apply(&ops, pid_id, &pid_snapshot) {
            SemopStatus::Applied => {
                set.sem_otime = monotonic_time_nanos() as i64;
                let wait_queue = set.wait_queue.clone();
                drop(set);
                if alter {
                    wait_queue.wake(usize::MAX, u32::MAX);
                }
                return Ok(0);
            }
            SemopStatus::Failed(errno) => return Err(StarryError::from(errno)),
            SemopStatus::Blocked => {
                let remaining = match deadline {
                    Some(dl) => {
                        let now = monotonic_time_nanos();
                        if now >= dl {
                            return Err(StarryError::from(Errno::EAGAIN));
                        }
                        Some(Duration::from_nanos(dl - now))
                    }
                    None => None,
                };
                let token = set.register_pending(&ops);
                let wait_queue = set.wait_queue.clone();
                drop(set);

                let waited = wait_queue.wait_if(u32::MAX, remaining, || {
                    let set = set_ref.lock();
                    !set.mark_removed && set.blocked(&ops)
                });

                set_ref.lock().remove_pending(token);

                match waited {
                    Ok(_) => {}
                    Err(err) if err.linux_errno() == Errno::ETIMEDOUT => {
                        return Err(StarryError::from(Errno::EAGAIN));
                    }
                    Err(err) => return Err(err),
                }
            }
        }
    }
}

/// `semctl(semid, semnum, cmd, arg)`.
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> StarryResult<isize> {
    let cmd = cmd & !IPC_64;
    let (uid, gid) = current_uid_gid();
    let ns_id = current_ipc_ns();
    let is_privileged = uid == 0;

    match cmd {
        IPC_INFO | SEM_INFO => return sem_info(cmd, ns_id, arg),
        SEM_STAT | SEM_STAT_ANY => return sem_stat(cmd, ns_id, semid, uid, gid, arg),
        _ => {}
    }

    let set_ref = SEM_MANAGER
        .lock()
        .get(semid, ns_id)
        .ok_or(StarryError::from(Errno::EINVAL))?;

    let observer = {
        let current = current();
        current.as_thread().active_pid_namespace().id()
    };

    let mut set = set_ref.lock();
    if set.mark_removed {
        return Err(StarryError::from(Errno::EIDRM));
    }

    // GETVAL/GETPID/GETNCNT/GETZCNT/SETVAL address a single semaphore.
    let needs_index = matches!(cmd, GETVAL | GETPID | GETNCNT | GETZCNT | SETVAL);
    if needs_index && (semnum < 0 || semnum as usize >= set.sems.len()) {
        return Err(StarryError::from(Errno::EINVAL));
    }
    let idx = semnum as usize;

    let read_ok = has_ipc_permission(&set.perm, uid, gid, false);
    let write_ok = has_ipc_permission(&set.perm, uid, gid, true);

    match cmd {
        IPC_STAT => {
            require(read_ok)?;
            let status = set.status();
            (arg as *mut semid_ds).vm_write(status)?;
            Ok(0)
        }
        GETVAL => {
            require(read_ok)?;
            Ok(set.sems[idx].val as isize)
        }
        GETPID => {
            require(read_ok)?;
            let pid = set.sems[idx]
                .pid
                .as_ref()
                .and_then(|p| p.visible_number(observer))
                .map_or(0, |n| n.get() as isize);
            Ok(pid)
        }
        GETNCNT => {
            require(read_ok)?;
            Ok(set.semncnt(semnum as u16) as isize)
        }
        GETZCNT => {
            require(read_ok)?;
            Ok(set.semzcnt(semnum as u16) as isize)
        }
        GETALL => {
            require(read_ok)?;
            let vals: Vec<u16> = set.sems.iter().map(|s| s.val as u16).collect();
            vm_write_slice(arg as *mut u16, &vals)?;
            Ok(0)
        }
        SETVAL => {
            require(write_ok)?;
            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                return Err(StarryError::from(Errno::ERANGE));
            }
            set.sems[idx].val = val;
            set.sems[idx].pid = current_pid_snapshot();
            set.sem_ctime = monotonic_time_nanos() as i64;
            let id = set.id;
            let wait_queue = set.wait_queue.clone();
            drop(set);
            clear_undo_slot(id, Some(idx));
            wait_queue.wake(usize::MAX, u32::MAX);
            Ok(0)
        }
        SETALL => {
            require(write_ok)?;
            let nsems = set.sems.len();
            let vals: Vec<u16> = vm_load(arg as *const u16, nsems)?;
            if vals.iter().any(|&v| v as i32 > SEMVMX) {
                return Err(StarryError::from(Errno::ERANGE));
            }
            let pid = current_pid_snapshot();
            for (sem, &v) in set.sems.iter_mut().zip(vals.iter()) {
                sem.val = v as i32;
                sem.pid = pid.clone();
            }
            set.sem_ctime = monotonic_time_nanos() as i64;
            let id = set.id;
            let wait_queue = set.wait_queue.clone();
            drop(set);
            clear_undo_slot(id, None);
            wait_queue.wake(usize::MAX, u32::MAX);
            Ok(0)
        }
        IPC_SET => {
            require(is_privileged || uid == set.perm.uid || uid == set.perm.cuid)?;
            let user: semid_ds = (arg as *const semid_ds).vm_read()?;
            set.perm.update_from_user(&user.sem_perm);
            set.sem_ctime = monotonic_time_nanos() as i64;
            Ok(0)
        }
        IPC_RMID => {
            require(is_privileged || uid == set.perm.uid || uid == set.perm.cuid)?;
            set.mark_removed = true;
            let id = set.id;
            let wait_queue = set.wait_queue.clone();
            drop(set);
            SEM_MANAGER.lock().remove(id);
            clear_undo_set(id);
            wait_queue.wake(usize::MAX, u32::MAX);
            Ok(0)
        }
        _ => Err(StarryError::from(Errno::EINVAL)),
    }
}

fn sem_info(cmd: i32, ns_id: u64, arg: usize) -> StarryResult<isize> {
    let manager = SEM_MANAGER.lock();
    let (used_sets, used_sems) = if cmd == SEM_INFO {
        (manager.count(ns_id) as i32, manager.total_sems(ns_id) as i32)
    } else {
        (SEMMNS as i32, SEMAEM)
    };
    let info = seminfo {
        semmap: SEMMNS as i32,
        semmni: SEMMNI as i32,
        semmns: SEMMNS as i32,
        semmnu: SEMMNS as i32,
        semmsl: SEMMSL as i32,
        semopm: SEMOPM as i32,
        semume: SEMOPM as i32,
        semusz: used_sets,
        semvmx: SEMVMX,
        semaem: used_sems,
    };
    (arg as *mut seminfo).vm_write(info)?;
    Ok(manager.count(ns_id) as isize)
}

fn sem_stat(cmd: i32, ns_id: u64, index: i32, uid: u32, gid: u32, arg: usize) -> StarryResult<isize> {
    if index < 0 {
        return Err(StarryError::from(Errno::EINVAL));
    }
    let (id, set_ref) = SEM_MANAGER
        .lock()
        .nth(ns_id, index as usize)
        .ok_or(StarryError::from(Errno::EINVAL))?;
    let set = set_ref.lock();
    if cmd == SEM_STAT && !has_ipc_permission(&set.perm, uid, gid, false) {
        return Err(StarryError::from(Errno::EACCES));
    }
    (arg as *mut semid_ds).vm_write(set.status())?;
    Ok(id as isize)
}

fn require(ok: bool) -> StarryResult<()> {
    if ok {
        Ok(())
    } else {
        Err(StarryError::from(Errno::EACCES))
    }
}

fn current_pid_snapshot() -> Option<PidSnapshot> {
    let current = current();
    Some(current.as_thread().proc_data.identity().snapshot())
}

fn load_relative_deadline(timeout: *const __kernel_timespec) -> StarryResult<Option<u64>> {
    if timeout.is_null() {
        return Ok(None);
    }
    // linux_raw_sys' __kernel_timespec is not AnyBitPattern, so read via the
    // uninit path (same as the POSIX mqueue timeout parsing).
    let ts: __kernel_timespec = unsafe { timeout.vm_read_uninit()?.assume_init() };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(StarryError::from(Errno::EINVAL));
    }
    let rel = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    Ok(Some(monotonic_time_nanos().saturating_add(rel)))
}

/// Zero the SEM_UNDO adjustments for one semaphore (or all with `slot = None`)
/// across every process, matching Linux clearing semadj on SETVAL/SETALL.
fn clear_undo_slot(id: i32, slot: Option<usize>) {
    let mut registry = SEM_UNDO_REGISTRY.lock();
    for ((_, semid), adj) in registry.iter_mut() {
        if *semid != id {
            continue;
        }
        match slot {
            Some(i) if i < adj.len() => adj[i] = 0,
            Some(_) => {}
            None => adj.iter_mut().for_each(|v| *v = 0),
        }
    }
}

fn clear_undo_set(id: i32) {
    SEM_UNDO_REGISTRY.lock().retain(|(_, semid), _| *semid != id);
}

/// Apply and drop a process's SEM_UNDO adjustments when it exits. Called from
/// the process teardown path alongside the shared-memory cleanup.
pub fn clear_proc_sem_undo(owner: PidIdentityId) {
    let entries: Vec<(i32, Vec<i32>)> = {
        let mut registry = SEM_UNDO_REGISTRY.lock();
        let taken: Vec<(i32, Vec<i32>)> = registry
            .iter()
            .filter(|((pid, _), _)| *pid == owner)
            .map(|((_, semid), adj)| (*semid, adj.clone()))
            .collect();
        registry.retain(|(pid, _), _| *pid != owner);
        taken
    };

    for (semid, adj) in entries {
        let set_ref = { SEM_MANAGER.lock().sets.get(&semid).cloned() };
        let Some(set_ref) = set_ref else { continue };
        let mut set = set_ref.lock();
        if set.mark_removed {
            continue;
        }
        for (sem, &delta) in set.sems.iter_mut().zip(adj.iter()) {
            if delta == 0 {
                continue;
            }
            sem.val = (sem.val + delta).clamp(0, SEMVMX);
        }
        let wait_queue = set.wait_queue.clone();
        drop(set);
        wait_queue.wake(usize::MAX, u32::MAX);
    }
}
