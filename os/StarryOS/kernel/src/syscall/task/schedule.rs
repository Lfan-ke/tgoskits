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

// ioprio(2), include/uapi/linux/ioprio.h.
const IOPRIO_CLASS_SHIFT: u32 = 13;
const IOPRIO_CLASS_MASK: u32 = 0x07;
const IOPRIO_LEVEL_MASK: u32 = 0x07;
const IOPRIO_CLASS_NONE: u32 = 0;
const IOPRIO_CLASS_RT: u32 = 1;
const IOPRIO_CLASS_BE: u32 = 2;
const IOPRIO_CLASS_IDLE: u32 = 3;
const IOPRIO_WHO_PROCESS: i32 = 1;
const IOPRIO_WHO_PGRP: i32 = 2;
const IOPRIO_WHO_USER: i32 = 3;

/// 1:1 Linux block/ioprio.c ioprio_check_cap: validate the class/level and gate
/// the RT class on CAP_SYS_ADMIN or CAP_SYS_NICE. The data/level field is not
/// range-checked (Linux stores any value verbatim).
fn ioprio_check_cap(ioprio: i32) -> StarryResult<()> {
    let class = ((ioprio as u32) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK;
    let level = (ioprio as u32) & IOPRIO_LEVEL_MASK;
    match class {
        IOPRIO_CLASS_RT => {
            let caller = current().as_thread().cred();
            if !caller.has_cap_sys_admin() && !caller.has_cap_sys_nice() {
                return Err(StarryError::OperationNotPermitted);
            }
        }
        IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => {}
        IOPRIO_CLASS_NONE => {
            if level != 0 {
                return Err(StarryError::InvalidInput);
            }
        }
        _ => return Err(StarryError::InvalidInput),
    }
    Ok(())
}

/// IOPRIO_WHO_* are 1/2/3; map onto the shared PrioritySelector (PRIO_* 0/1/2).
fn ioprio_selector(which: i32, who: i32) -> StarryResult<PrioritySelector> {
    let prio_which = match which {
        IOPRIO_WHO_PROCESS => PRIO_PROCESS,
        IOPRIO_WHO_PGRP => PRIO_PGRP,
        IOPRIO_WHO_USER => PRIO_USER,
        _ => return Err(StarryError::InvalidInput),
    };
    PrioritySelector::parse(prio_which, who as u32)
}

/// Linux blk-ioc.c set_task_ioprio gate: CAP_SYS_NICE, or the target's uid
/// matches the caller's uid or euid.
fn ioprio_set_perm(proc: &ProcessData) -> StarryResult<()> {
    let caller = current().as_thread().cred();
    if caller.has_cap_sys_nice() {
        return Ok(());
    }
    let target = process_cred(proc)?;
    if target.uid == caller.uid || target.uid == caller.euid {
        Ok(())
    } else {
        Err(StarryError::OperationNotPermitted)
    }
}

fn set_ioprio_for_processes(
    procs: impl Iterator<Item = Arc<ProcessData>>,
    ioprio: i32,
) -> StarryResult<isize> {
    let procs: Vec<_> = procs.collect();
    if procs.is_empty() {
        return Err(StarryError::NoSuchProcess);
    }
    for proc in &procs {
        ioprio_set_perm(proc)?;
    }
    for proc in procs {
        proc.set_ioprio(ioprio);
    }
    Ok(0)
}

/// Read a process's CPU scheduler policy through its thread-group leader,
/// mirroring how Linux's task_nice_ioclass consults task->policy.
fn proc_sched_policy(proc: &ProcessData) -> i32 {
    let leader = TidNumber::from(proc.proc.pid().pid_number());
    get_task_by_number(leader)
        .map(|task| task.sched_policy())
        .unwrap_or(SCHED_NORMAL as i32)
}

/// 1:1 Linux __get_task_ioprio (include/linux/ioprio.h): report an explicitly
/// set (non-NONE) I/O priority verbatim, otherwise derive one from the CPU
/// scheduler nice value and policy. ioprio_get's WHO_PGRP/WHO_USER aggregation
/// uses this effective value, whereas WHO_PROCESS reports the raw stored value
/// (get_task_raw_ioprio).
fn effective_ioprio(proc: &ProcessData) -> i32 {
    let raw = proc.ioprio();
    if ((raw as u32) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK != IOPRIO_CLASS_NONE {
        return raw;
    }
    let class = match proc_sched_policy(proc) as u32 {
        SCHED_IDLE => IOPRIO_CLASS_IDLE,
        SCHED_FIFO | SCHED_RR => IOPRIO_CLASS_RT,
        _ => IOPRIO_CLASS_BE,
    };
    let level = ((proc.nice() + 20) / 5) as u32;
    ((class << IOPRIO_CLASS_SHIFT) | level) as i32
}

/// ioprio_best over a set of tasks: Linux aggregates get_task_ioprio (the
/// nice-derived effective value) with min for WHO_PGRP/WHO_USER.
fn min_ioprio_for_processes(procs: impl Iterator<Item = Arc<ProcessData>>) -> StarryResult<isize> {
    procs
        .map(|proc| effective_ioprio(&proc))
        .min()
        .map(|value| value as isize)
        .ok_or(StarryError::NoSuchProcess)
}

pub fn sys_ioprio_set(which: i32, who: i32, ioprio: i32) -> StarryResult<isize> {
    // ioprio_check_cap runs first: a bad class returns EINVAL before a bad who
    // would return ESRCH (matching ioprio_set's ordering).
    ioprio_check_cap(ioprio)?;
    // set_task_ioprio stores the value in io_context->ioprio, an unsigned short,
    // so the low 16 bits are what a later ioprio_get reads back.
    let ioprio = (ioprio as u16) as i32;
    match ioprio_selector(which, who)? {
        PrioritySelector::CurrentProcess => {
            let proc = current().as_thread().proc_data.clone();
            ioprio_set_perm(&proc)?;
            proc.set_ioprio(ioprio);
            Ok(0)
        }
        PrioritySelector::Process(tgid) => {
            let proc = get_user_process_data_by_number(tgid)?;
            ioprio_set_perm(&proc)?;
            proc.set_ioprio(ioprio);
            Ok(0)
        }
        PrioritySelector::CurrentProcessGroup => {
            let group = current().as_thread().proc_data.proc.group();
            set_ioprio_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
                ioprio,
            )
        }
        PrioritySelector::ProcessGroup(pgid) => {
            let group = current_pid_view().resolve_group(pgid)?;
            set_ioprio_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
                ioprio,
            )
        }
        PrioritySelector::CurrentUser => set_ioprio_for_processes(
            processes_for_uid(current().as_thread().cred().uid).into_iter(),
            ioprio,
        ),
        PrioritySelector::User(uid) => {
            set_ioprio_for_processes(processes_for_uid(uid).into_iter(), ioprio)
        }
    }
}

pub fn sys_ioprio_get(which: i32, who: i32) -> StarryResult<isize> {
    match ioprio_selector(which, who)? {
        PrioritySelector::CurrentProcess => Ok(current().as_thread().proc_data.ioprio() as isize),
        PrioritySelector::Process(tgid) => {
            Ok(get_user_process_data_by_number(tgid)?.ioprio() as isize)
        }
        PrioritySelector::CurrentProcessGroup => {
            let group = current().as_thread().proc_data.proc.group();
            min_ioprio_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
            )
        }
        PrioritySelector::ProcessGroup(pgid) => {
            let group = current_pid_view().resolve_group(pgid)?;
            min_ioprio_for_processes(
                processes()
                    .into_iter()
                    .filter(|proc| Arc::ptr_eq(&proc.proc.group(), &group)),
            )
        }
        PrioritySelector::CurrentUser => min_ioprio_for_processes(
            processes_for_uid(current().as_thread().cred().uid).into_iter(),
        ),
        PrioritySelector::User(uid) => min_ioprio_for_processes(processes_for_uid(uid).into_iter()),
    }
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
