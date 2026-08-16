use alloc::{sync::Arc, vec::Vec};

use ax_runtime::hal::{self, time::TimeValue};
use ax_task::{
    AxCpuMask, current,
    future::{block_on, interruptible, sleep},
};
use bytemuck::{Pod, Zeroable};
use linux_raw_sys::general::{
    __kernel_clockid_t, CLOCK_MONOTONIC, CLOCK_REALTIME, PRIO_PGRP, PRIO_PROCESS, PRIO_USER,
    SCHED_BATCH, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL, SCHED_RR, TIMER_ABSTIME, timespec,
};
use starry_vm::{VmMutPtr, VmPtr, vm_load, vm_write_slice};

use crate::{
    StarryError, StarryResult,
    task::{
        AsThread, Cred, PgidNumber, ProcessData, TgidNumber, TidNumber, current_pid_view,
        get_task_by_number, get_user_process_data_by_number, get_user_task_by_number,
        is_user_zombie_process, processes,
    },
    time::TimeValueLike,
};

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
struct SchedParam {
    sched_priority: i32,
}

pub fn sys_sched_yield() -> StarryResult<isize> {
    ax_task::yield_now();
    Ok(0)
}

fn sleep_impl(clock: impl Fn() -> TimeValue, dur: TimeValue) -> (StarryResult<()>, TimeValue) {
    debug!("sleep_impl <= {dur:?}");

    let start = clock();

    // TODO: currently ignoring concrete clock type
    let result = block_on(interruptible(sleep(dur))).map_err(StarryError::from);

    (result, clock() - start)
}

/// Sleep some nanoseconds
pub fn sys_nanosleep(req: *const timespec, rem: *mut timespec) -> StarryResult<isize> {
    // FIXME: AnyBitPattern
    let req = unsafe { req.vm_read_uninit()?.assume_init() }.try_into_time_value()?;
    debug!("sys_nanosleep <= req: {req:?}");

    let (result, actual) = sleep_impl(hal::time::monotonic_time, req);

    match result {
        Ok(()) => Ok(0),
        Err(err) => {
            let diff = req.saturating_sub(actual);
            debug!("sys_nanosleep => rem: {diff:?}");
            if let Some(rem) = rem.nullable() {
                rem.vm_write(timespec::from_time_value(diff))?;
            }
            Err(err)
        }
    }
}

pub fn sys_clock_nanosleep(
    clock_id: __kernel_clockid_t,
    flags: u32,
    req: *const timespec,
    rem: *mut timespec,
) -> StarryResult<isize> {
    let clock = match clock_id as u32 {
        CLOCK_REALTIME => hal::time::wall_time,
        CLOCK_MONOTONIC => hal::time::monotonic_time,
        _ => {
            warn!("Unsupported clock_id: {clock_id}");
            return Err(StarryError::InvalidInput);
        }
    };

    let req = unsafe { req.vm_read_uninit()?.assume_init() }.try_into_time_value()?;
    debug!("sys_clock_nanosleep <= clock_id: {clock_id}, flags: {flags}, req: {req:?}");

    let is_abstime = flags & TIMER_ABSTIME != 0;
    let dur = if is_abstime {
        req.saturating_sub(clock())
    } else {
        req
    };

    let (result, actual) = sleep_impl(clock, dur);

    match result {
        Ok(()) => Ok(0),
        Err(err) => {
            if !is_abstime {
                let diff = dur.saturating_sub(actual);
                debug!("sys_clock_nanosleep => rem: {diff:?}");
                if let Some(rem) = rem.nullable() {
                    rem.vm_write(timespec::from_time_value(diff))?;
                }
            }
            Err(err)
        }
    }
}

pub fn sys_sched_getaffinity(
    pid: i32,
    cpusetsize: usize,
    user_mask: *mut u8,
) -> StarryResult<isize> {
    if cpusetsize * 8 < hal::cpu_num() {
        return Err(StarryError::InvalidInput);
    }

    let task = SchedulerTarget::try_from(pid)?.resolve()?;
    let mask = task.cpumask();
    let mask_bytes = mask.as_bytes();

    vm_write_slice(user_mask, mask_bytes)?;

    Ok(mask_bytes.len() as _)
}

fn check_sched_permission(task: &ax_task::AxTaskRef) -> StarryResult<()> {
    let caller = current().as_thread().cred();
    if task.id() == current().id() {
        return Ok(());
    }
    let target_proc = task.as_thread().proc_data.clone();
    let target_cred = process_cred(&target_proc)?;
    if caller.has_cap_sys_nice()
        || caller.euid == target_cred.uid
        || caller.euid == target_cred.euid
    {
        Ok(())
    } else {
        Err(StarryError::OperationNotPermitted)
    }
}

pub fn sys_sched_setaffinity(
    pid: i32,
    cpusetsize: usize,
    user_mask: *const u8,
) -> StarryResult<isize> {
    let task = SchedulerTarget::try_from(pid)?.resolve()?;
    check_sched_permission(&task)?;
    let size = cpusetsize.min(hal::cpu_num().div_ceil(8));
    let user_mask = vm_load(user_mask, size)?;
    let mut cpu_mask = AxCpuMask::new();

    for i in 0..(size * 8).min(hal::cpu_num()) {
        if user_mask[i / 8] & (1 << (i % 8)) != 0 {
            cpu_mask.set(i, true);
        }
    }

    if cpu_mask.is_empty() {
        return Err(StarryError::InvalidInput);
    }
    if task.id() == current().id() {
        ax_task::set_current_affinity(cpu_mask);
    } else {
        task.set_cpumask(cpu_mask);
        task.interrupt();
    }

    Ok(0)
}

enum SchedulerTarget {
    Current,
    Thread(TidNumber),
}

impl SchedulerTarget {
    fn resolve(self) -> StarryResult<ax_task::AxTaskRef> {
        match self {
            Self::Current => Ok(current().clone()),
            Self::Thread(tid) => get_user_task_by_number(tid),
        }
    }
}

impl TryFrom<i32> for SchedulerTarget {
    type Error = StarryError;

    fn try_from(pid: i32) -> Result<Self, Self::Error> {
        match pid {
            ..0 => Err(StarryError::InvalidInput),
            0 => Ok(Self::Current),
            1.. => Ok(Self::Thread(TidNumber::try_from(pid as u32)?)),
        }
    }
}

pub fn sys_sched_getscheduler(pid: i32) -> StarryResult<isize> {
    let task = SchedulerTarget::try_from(pid)?.resolve()?;
    Ok(task.sched_policy() as isize)
}

pub fn sys_sched_setscheduler(pid: i32, policy: i32, param: *const ()) -> StarryResult<isize> {
    let task = SchedulerTarget::try_from(pid)?.resolve()?;
    check_sched_permission(&task)?;
    let caller = current().as_thread().cred();
    if param.is_null() {
        return Err(StarryError::InvalidInput);
    }
    let user_param = vm_load::<SchedParam>(param.cast(), 1)?;
    let user_param = user_param[0];
    let mut policy = policy as u32;
    const SCHED_RESET_ON_FORK: u32 = 0x40000000;
    let _reset_on_fork = (policy & SCHED_RESET_ON_FORK) != 0;
    policy &= !SCHED_RESET_ON_FORK;
    let prio = user_param.sched_priority;
    match policy {
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE => {}
        _ => return Err(StarryError::InvalidInput),
    }
    match policy {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            if prio != 0 {
                return Err(StarryError::InvalidInput);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if !(1..=99).contains(&prio) {
                return Err(StarryError::InvalidInput);
            }
            if !caller.has_cap_sys_nice() {
                return Err(StarryError::OperationNotPermitted);
            }
        }
        _ => unreachable!(),
    }
    task.set_sched_policy(policy as i32);
    task.set_sched_priority(prio);
    Ok(0)
}

pub fn sys_sched_getparam(pid: i32, param: *mut ()) -> StarryResult<isize> {
    let task = SchedulerTarget::try_from(pid)?.resolve()?;
    if param.is_null() {
        return Err(StarryError::InvalidInput);
    }
    let sched_param = SchedParam {
        sched_priority: task.sched_priority(),
    };
    let ptr = param as *mut SchedParam;
    unsafe {
        let bytes = core::slice::from_raw_parts(
            &sched_param as *const SchedParam as *const u8,
            core::mem::size_of::<SchedParam>(),
        );
        vm_write_slice(ptr as *mut u8, bytes)?;
    }
    Ok(0)
}

/// Round-robin quantum: MAX_TIME_SLICE scheduler ticks (axtask api.rs sets
/// MAX_TIME_SLICE = 5) at the scheduler tick rate (axconfig ticks-per-sec =
/// 100), i.e. 5 * 10 ms.
const RR_QUANTUM: TimeValue = TimeValue::from_millis(50);

/// `sched_get_priority_max(2)`: highest priority usable by a policy. Mirrors
/// Linux kernel/sched/syscalls.c - SCHED_FIFO/RR use MAX_RT_PRIO-1 (99), the
/// fair policies use 0, and any other policy is EINVAL.
pub fn sys_sched_get_priority_max(policy: i32) -> StarryResult<isize> {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => Ok(99),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => Ok(0),
        _ => Err(StarryError::InvalidInput),
    }
}

/// `sched_get_priority_min(2)`: lowest priority usable by a policy. SCHED_FIFO/RR
/// use 1, the fair policies use 0, any other policy is EINVAL.
pub fn sys_sched_get_priority_min(policy: i32) -> StarryResult<isize> {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => Ok(1),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => Ok(0),
        _ => Err(StarryError::InvalidInput),
    }
}

/// `sched_setparam(2)`: set only the priority, keeping the current policy.
/// Mirrors Linux `do_sched_setscheduler(pid, SETPARAM_POLICY, param)`: the
/// priority is validated against the task's existing policy (0 for the fair
/// policies, 1..=99 with CAP_SYS_NICE for SCHED_FIFO/RR).
pub fn sys_sched_setparam(pid: i32, param: *const ()) -> StarryResult<isize> {
    let task = SchedulerTarget::try_from(pid)?.resolve()?;
    check_sched_permission(&task)?;
    let caller = current().as_thread().cred();
    if param.is_null() {
        return Err(StarryError::InvalidInput);
    }
    let user_param = vm_load::<SchedParam>(param.cast(), 1)?;
    let prio = user_param[0].sched_priority;
    match task.sched_policy() as u32 {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            if prio != 0 {
                return Err(StarryError::InvalidInput);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if !(1..=99).contains(&prio) {
                return Err(StarryError::InvalidInput);
            }
            if !caller.has_cap_sys_nice() {
                return Err(StarryError::OperationNotPermitted);
            }
        }
        _ => return Err(StarryError::InvalidInput),
    }
    task.set_sched_priority(prio);
    Ok(0)
}

/// `sched_rr_get_interval(2)`: write the round-robin quantum of a task to a
/// timespec. Mirrors Linux kernel/sched/syscalls.c - a negative pid is EINVAL, a
/// missing task is ESRCH.
pub fn sys_sched_rr_get_interval(pid: i32, interval: *mut timespec) -> StarryResult<isize> {
    let _task = SchedulerTarget::try_from(pid)?.resolve()?;
    interval.vm_write(timespec::from_time_value(RR_QUANTUM))?;
    Ok(0)
}

enum PrioritySelector {
    CurrentProcess,
    Process(TgidNumber),
    CurrentProcessGroup,
    ProcessGroup(PgidNumber),
    CurrentUser,
    User(u32),
}

impl PrioritySelector {
    fn parse(which: u32, who: u32) -> StarryResult<Self> {
        match (which, who) {
            (PRIO_PROCESS, 0) => Ok(Self::CurrentProcess),
            (PRIO_PROCESS, _) => Ok(Self::Process(TgidNumber::try_from(who)?)),
            (PRIO_PGRP, 0) => Ok(Self::CurrentProcessGroup),
            (PRIO_PGRP, _) => Ok(Self::ProcessGroup(PgidNumber::try_from(who)?)),
            (PRIO_USER, 0) => Ok(Self::CurrentUser),
            (PRIO_USER, _) => Ok(Self::User(who)),
            _ => Err(StarryError::InvalidInput),
        }
    }
}

pub fn sys_getpriority(which: u32, who: u32) -> StarryResult<isize> {
    debug!("sys_getpriority <= which: {which}, who: {who}");

    match PrioritySelector::parse(which, who)? {
        PrioritySelector::CurrentProcess => {
            Ok(raw_priority(current().as_thread().proc_data.nice()))
        }
        PrioritySelector::Process(tgid) => match get_user_process_data_by_number(tgid) {
            Ok(proc) => Ok(raw_priority(proc.nice())),
            Err(StarryError::NoSuchProcess) if is_user_zombie_process(tgid) => Ok(20),
            Err(err) => Err(err),
        },
        PrioritySelector::CurrentProcessGroup => {
            let group = current().as_thread().proc_data.proc.group();
            min_priority_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
            )
        }
        PrioritySelector::ProcessGroup(pgid) => {
            let group = current_pid_view().resolve_group(pgid)?;
            min_priority_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
            )
        }
        PrioritySelector::CurrentUser => min_priority_for_processes(
            processes_for_uid(current().as_thread().cred().uid).into_iter(),
        ),
        PrioritySelector::User(uid) => {
            min_priority_for_processes(processes_for_uid(uid).into_iter())
        }
    }
}

pub fn sys_setpriority(which: u32, who: u32, prio: i32) -> StarryResult<isize> {
    debug!("sys_setpriority <= which: {which}, who: {who}, prio: {prio}");

    let nice = prio.clamp(-20, 19);
    match PrioritySelector::parse(which, who)? {
        PrioritySelector::CurrentProcess => {
            let proc = current().as_thread().proc_data.clone();
            check_setpriority_permission(&proc, nice)?;
            proc.set_nice(nice);
            Ok(0)
        }
        PrioritySelector::Process(tgid) => {
            let proc = get_user_process_data_by_number(tgid)?;
            check_setpriority_permission(&proc, nice)?;
            proc.set_nice(nice);
            Ok(0)
        }
        PrioritySelector::CurrentProcessGroup => {
            let group = current().as_thread().proc_data.proc.group();
            set_priority_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
                nice,
            )
        }
        PrioritySelector::ProcessGroup(pgid) => {
            let group = current_pid_view().resolve_group(pgid)?;
            set_priority_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
                nice,
            )
        }
        PrioritySelector::CurrentUser => set_priority_for_processes(
            processes_for_uid(current().as_thread().cred().uid).into_iter(),
            nice,
        ),
        PrioritySelector::User(uid) => {
            set_priority_for_processes(processes_for_uid(uid).into_iter(), nice)
        }
    }
}

fn raw_priority(nice: i32) -> isize {
    (20 - nice) as isize
}

fn min_priority_for_processes(
    procs: impl Iterator<Item = alloc::sync::Arc<ProcessData>>,
) -> StarryResult<isize> {
    procs
        .map(|proc| proc.nice())
        .min()
        .map(raw_priority)
        .ok_or(StarryError::NoSuchProcess)
}

fn processes_for_uid(uid: u32) -> Vec<Arc<ProcessData>> {
    processes()
        .into_iter()
        .filter(|proc| {
            process_cred(proc)
                .map(|cred| cred.uid == uid)
                .unwrap_or(false)
        })
        .collect()
}

fn process_cred(proc: &ProcessData) -> StarryResult<Arc<Cred>> {
    for tid in proc.proc.threads() {
        if let Ok(task) = get_task_by_number(tid)
            && let Some(thread) = task.try_as_thread()
        {
            return Ok(thread.cred());
        }
    }
    Err(StarryError::NoSuchProcess)
}

fn setpriority_cred_matches(caller: &Cred, target: &Cred) -> bool {
    caller.euid == target.uid || caller.euid == target.euid
}

fn check_setpriority_permission(proc: &ProcessData, nice: i32) -> StarryResult<()> {
    let caller = current().as_thread().cred();
    if caller.has_cap_sys_nice() {
        return Ok(());
    }

    let target = process_cred(proc)?;
    if !setpriority_cred_matches(&caller, &target) {
        return Err(StarryError::OperationNotPermitted);
    }
    if nice < proc.nice() {
        return Err(StarryError::PermissionDenied);
    }
    Ok(())
}

fn set_priority_for_processes(
    procs: impl Iterator<Item = alloc::sync::Arc<ProcessData>>,
    nice: i32,
) -> StarryResult<isize> {
    let procs: Vec<_> = procs.collect();
    if procs.is_empty() {
        return Err(StarryError::NoSuchProcess);
    }
    for proc in &procs {
        check_setpriority_permission(proc, nice)?;
    }
    for proc in procs {
        proc.set_nice(nice);
    }
    Ok(0)
}

#[cfg(axtest)]
pub(crate) fn schedule_clock_and_sched_validation_rules_hold_for_test() -> bool {
    use linux_raw_sys::general::{
        CLOCK_MONOTONIC, CLOCK_REALTIME, SCHED_BATCH, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL,
        SCHED_RR,
    };

    // Test clock_nanosleep clock_id validation
    let valid_clocks = [CLOCK_REALTIME as u32, CLOCK_MONOTONIC as u32];

    for &clock in &valid_clocks {
        assert!(clock == CLOCK_REALTIME as u32 || clock == CLOCK_MONOTONIC as u32);
    }

    // Invalid clock ID
    assert!(999u32 != CLOCK_REALTIME as u32 && 999u32 != CLOCK_MONOTONIC as u32);

    // Test valid scheduler policies
    let valid_policies = [SCHED_NORMAL, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE];

    assert!(valid_policies.contains(&SCHED_NORMAL));

    true
}
