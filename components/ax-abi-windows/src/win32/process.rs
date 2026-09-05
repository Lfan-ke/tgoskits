//! Creating a process: what `CreateProcessW` does, and what waits on the
//! result.
//!
//! Windows starts a program in a fresh process; this host forks and execs.
//! So the caller is forked, and the child - a copy of the caller - starts
//! inside the stub of a private entry point, `_StarrySpawnExec`, right at its
//! trap, with a block describing the program as the argument. The trap makes
//! the block's handles the child's standard descriptors and replaces its image
//! with the program, the way `execve` does, so the new process is loaded by
//! whichever personality claims the file. The block lives in the caller's
//! heap; the fork copies it along with everything else.
//!
//! A process handle is a pseudo-handle carrying the pid. Waiting on one reaps
//! the child and keeps its exit code for `GetExitCodeProcess`.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use ax_dispatch::Dispatch;
use ax_sync::SpinLock;

use super::{
    Call, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, FALSE, TRUE, Win32Call, file, runtime,
};
use crate::{
    dll,
    nt::Ntstatus,
    teb_peb::{PARAMS_ENVIRONMENT, PEB_PROCESS_HEAP},
    thunk,
};

/// The high bits that mark a process or thread pseudo-handle; the low bits
/// are the pid.
pub(super) const PROCESS_TAG: usize = 0x2000_0000;
pub(super) const THREAD_TAG: usize = 0x3000_0000;
const TAG_MASK: usize = 0xF000_0000;
/// What `GetExitCodeProcess` reports for a process still running.
const STILL_ACTIVE: u32 = 259;
/// `WAIT_OBJECT_0`, `WAIT_TIMEOUT` and `WAIT_FAILED`, as a wait on a process
/// reports them.
const WAIT_OBJECT_0: usize = 0;
const WAIT_TIMEOUT: usize = super::sync::WAIT_TIMEOUT;
const WAIT_FAILED: usize = 0xFFFF_FFFF;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `STARTF_USESTDHANDLES`: the three handles in the startup info apply.
const STARTF_USESTDHANDLES: u32 = 0x100;
/// The private entry point the child starts in.
const SPAWN_ENTRY: &str = "_StarrySpawnExec";

/// Exit codes of children already reaped, by pid.
static EXITED: SpinLock<BTreeMap<u32, u32>> = SpinLock::new(BTreeMap::new());

/// Whether `handle` is one of the pseudo-handles made here, and its pid.
pub(super) fn pid_of(handle: usize) -> Option<u32> {
    let tag = handle & TAG_MASK;
    (handle != 0 && (tag == PROCESS_TAG || tag == THREAD_TAG))
        .then_some((handle & !TAG_MASK) as u32)
}

/// A Windows command line as `CommandLineToArgvW` splits it: whitespace
/// separates arguments, double quotes group, and a run of backslashes before
/// a quote halves, an odd one escaping the quote.
pub(super) fn split_command_line(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(' ' | '\t')) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    let mut slashes = 1;
                    while chars.peek() == Some(&'\\') {
                        chars.next();
                        slashes += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        for _ in 0..slashes / 2 {
                            arg.push('\\');
                        }
                        if slashes % 2 == 1 {
                            chars.next();
                            arg.push('"');
                        }
                    } else {
                        for _ in 0..slashes {
                            arg.push('\\');
                        }
                    }
                }
                '"' => quoted = !quoted,
                ' ' | '\t' if !quoted => break,
                other => arg.push(other),
            }
        }
        args.push(arg);
    }
    args
}

/// The environment block at `at` - `NAME=value` entries as UTF-16, each NUL
/// terminated, the block ended by one more - as strings.
fn environment(c: &Call<'_>, at: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = at;
    while at != 0 {
        let Some(units) = c.read_wstr(at) else { break };
        if units.is_empty() {
            break;
        }
        at += (units.len() + 1) * 2;
        if let Ok(text) = String::from_utf16(&units) {
            out.push(text);
        }
    }
    out
}

/// Lay the exec block out in the process heap: the three standard
/// descriptors, then pointers to the path, the argument vector and the
/// environment vector, then the strings and vectors themselves.
fn exec_block(
    c: &Call<'_>,
    stdio: [i32; 3],
    path: &str,
    args: &[String],
    envs: &[String],
) -> Option<usize> {
    let heap = c.read_u64(c.peb()? + PEB_PROCESS_HEAP)? as usize;
    let strings: Vec<&str> = core::iter::once(path)
        .chain(args.iter().map(String::as_str))
        .chain(envs.iter().map(String::as_str))
        .collect();
    let header = 16 + 3 * 8;
    let vectors = (args.len() + 1 + envs.len() + 1) * 8;
    let text: usize = strings.iter().map(|s| s.len() + 1).sum();
    let block = super::heap::alloc(c, heap, header + vectors + text)?;
    let argv_at = block + header;
    let envp_at = argv_at + (args.len() + 1) * 8;
    let mut cursor = envp_at + (envs.len() + 1) * 8;
    let mut addresses = Vec::with_capacity(strings.len());
    for s in &strings {
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
        if !c.write(cursor, &bytes) {
            return None;
        }
        addresses.push(cursor as u64);
        cursor += bytes.len();
    }
    for (i, fd) in stdio.iter().enumerate() {
        c.write_u32(block + i * 4, *fd as u32);
    }
    c.write_u64(block + 16, addresses[0]);
    c.write_u64(block + 24, argv_at as u64);
    c.write_u64(block + 32, envp_at as u64);
    for (i, at) in addresses[1..1 + args.len()].iter().enumerate() {
        c.write_u64(argv_at + i * 8, *at);
    }
    c.write_u64(argv_at + args.len() * 8, 0);
    for (i, at) in addresses[1 + args.len()..].iter().enumerate() {
        c.write_u64(envp_at + i * 8, *at);
    }
    c.write_u64(envp_at + envs.len() * 8, 0);
    Some(block)
}

/// Where the child starts: the private entry's stub, at its trap.
fn spawn_entry(c: &Call<'_>) -> Option<usize> {
    let call = Win32Call::named(SPAWN_ENTRY)?;
    let (lib, index) = call.place();
    let base = runtime::module_named(c, dll::SYSTEM_NAMES[lib])?;
    Some(base + thunk::MODULE_HEADER + index * thunk::STUB_LEN + thunk::STUB_TRAP_OFFSET)
}

/// CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
/// lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
/// lpCurrentDirectory, lpStartupInfo, lpProcessInformation).
pub fn create_process(c: &mut Call<'_>) -> Dispatch {
    let (app, line) = (c.arg(0), c.arg(1));
    let (Some(env), Some(cwd), Some(si), Some(pi)) = (
        super::arg_n(c, 6),
        super::arg_n(c, 7),
        super::arg_n(c, 8),
        super::arg_n(c, 9),
    ) else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let text = if line != 0 {
        c.read_wstr(line)
    } else {
        c.read_wstr(app)
    };
    let Some(text) = text.and_then(|u| String::from_utf16(&u).ok()) else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let mut args = split_command_line(&text);
    if app != 0
        && let Some(name) = c.read_wstr(app).and_then(|u| String::from_utf16(&u).ok())
    {
        if args.is_empty() {
            args.push(name.clone());
        } else {
            args[0] = name;
        }
    }
    let Some(exe) = args.first().cloned() else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let Some(path) = file::host_path(c, &exe) else {
        return c.fail(ERROR_FILE_NOT_FOUND, FALSE);
    };
    let mut envs = if env != 0 {
        environment(c, env)
    } else {
        c.params()
            .and_then(|p| c.read_u64(p + PARAMS_ENVIRONMENT))
            .map_or_else(Vec::new, |at| environment(c, at as usize))
    };
    // Where the child starts: the directory the caller named, or this
    // process's, which is what a child inherits when none is named. It rides
    // with the environment under the `=X:` name Windows keeps a drive's
    // current directory under, since the C runtime hides those from the
    // program and the loader is the only reader.
    let here = match cwd {
        0 => file::current_directory(c),
        at => c
            .read_wstr(at)
            .and_then(|u| String::from_utf16(&u).ok())
            .and_then(|name| file::full_windows_path(c, &name)),
    };
    if let Some(here) = here {
        // Spelled the way Windows keeps it: no trailing separator unless the
        // directory is the root of the drive.
        let here = match here.trim_end_matches('\\') {
            "" | "Z:" => String::from("Z:\\"),
            trimmed if trimmed.len() == 2 => alloc::format!("{trimmed}\\"),
            trimmed => String::from(trimmed),
        };
        let drive = here.chars().next().unwrap_or('Z');
        let name = alloc::format!("={drive}:=");
        envs.retain(|entry| !entry.starts_with(&name));
        envs.push(alloc::format!("{name}{here}"));
    }
    // The startup info: dwFlags at 60, then hStdInput, hStdOutput and
    // hStdError at 80, 88 and 96 of STARTUPINFOW.
    let mut stdio = [-1i32; 3];
    let flags = if si != 0 {
        c.read_u32(si + 60).unwrap_or(0)
    } else {
        0
    };
    if flags & STARTF_USESTDHANDLES != 0 {
        for (i, slot) in stdio.iter_mut().enumerate() {
            let handle = c.read_u64(si + 80 + i * 8).unwrap_or(0) as usize;
            if handle != 0 {
                *slot = match file::descriptor(handle) {
                    Ok(fd) => fd,
                    Err(status) => return c.fail_status(status, FALSE),
                };
            }
        }
    }
    let (Some(block), Some(entry)) = (exec_block(c, stdio, &path, &args, &envs), spawn_entry(c))
    else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, FALSE);
    };
    let pid = match c.env.spawn(entry, block) {
        Ok(pid) => pid,
        Err(errno) => return c.fail_status(super::nt::status_from_errno(errno), FALSE),
    };
    // This child has the number, so whatever the last one to hold it exited
    // with is no longer an answer about this one.
    forget(pid);
    // PROCESS_INFORMATION: hProcess, hThread, dwProcessId, dwThreadId.
    if !c.write_u64(pi, (PROCESS_TAG | pid as usize) as u64)
        || !c.write_u64(pi + 8, (THREAD_TAG | pid as usize) as u64)
        || !c.write_u32(pi + 16, pid)
        || !c.write_u32(pi + 20, pid)
    {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.set_last_error(0);
    c.finish(TRUE)
}

/// The child's first and only call in the caller's image: take the block
/// `CreateProcessW` left and become the program. Failing that, the child
/// ends, since there is no caller to return to.
pub fn spawn_exec(c: &mut Call<'_>) -> Dispatch {
    let block = c.arg(0);
    let mut stdio = [-1i32; 3];
    for (i, slot) in stdio.iter_mut().enumerate() {
        *slot = c.read_u32(block + i * 4).unwrap_or(u32::MAX) as i32;
    }
    let (Some(path), Some(argv), Some(envp)) = (
        c.read_u64(block + 16),
        c.read_u64(block + 24),
        c.read_u64(block + 32),
    ) else {
        exit_child(c, 127);
        return c.finish(0);
    };
    if c.env
        .exec_with_stdio(stdio, path as usize, argv as usize, envp as usize)
        .is_err()
    {
        exit_child(c, 127);
    }
    c.finish(0)
}

fn exit_child(c: &Call<'_>, code: i32) {
    if let Some(tasks) = c.host.tasks() {
        let _ = tasks.exit_group(code);
    }
}

/// Forget what a pid exited with, because a new process now has it.
///
/// The table below remembers an exit code until someone asks for it, and the
/// host hands pids out again once they are free. Without this, a child that
/// takes the number of one that has been reaped is reported as having already
/// exited - with the other one's code - the moment it starts.
pub(super) fn forget(pid: u32) {
    EXITED.lock().remove(&pid);
    TERMINATED.lock().remove(&pid);
}

/// What a look at a child found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Child {
    /// It has ended and its code is in the table.
    Ended,
    /// It is still running.
    Running,
    /// There is no such child of ours to wait for.
    Gone,
}

/// Reap `pid` if it has ended, recording its exit code; `block` waits for it.
fn reap(c: &Call<'_>, pid: u32, block: bool) -> Child {
    if EXITED.lock().contains_key(&pid) {
        return Child::Ended;
    }
    let (Some(tasks), Some(peb)) = (c.host.tasks(), c.peb()) else {
        return Child::Gone;
    };
    let Some(heap) = c.read_u64(peb + PEB_PROCESS_HEAP) else {
        return Child::Gone;
    };
    let Some(status_at) = super::heap::alloc(c, heap as usize, 4) else {
        return Child::Gone;
    };
    c.write_u32(status_at, 0);
    let waited = tasks.wait(pid, status_at, !block);
    let status = c.read_u32(status_at).unwrap_or(0);
    super::heap::mark_free(c, heap as usize, status_at);
    match waited {
        Ok(reaped) if reaped == pid => {
            // A Linux wait status: the exit code above the low byte, or the
            // terminating signal in it, reported the way a shell would.
            let code = match TERMINATED.lock().remove(&pid) {
                Some(code) => code,
                None if status & 0x7F == 0 => (status >> 8) & 0xFF,
                None => 128 + (status & 0x7F),
            };
            EXITED.lock().insert(pid, code);
            Child::Ended
        }
        // Asked not to block, a child that has not ended answers with zero.
        Ok(_) => Child::Running,
        Err(_) => Child::Gone,
    }
}

/// OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId): a handle for a
/// process that is running. There is one process table here and no access
/// checks in it, so what the handle carries is the number itself; whether the
/// process is there is asked by signalling it with nothing.
pub fn open_process(c: &mut Call<'_>) -> Dispatch {
    let pid = c.arg(2) as u32;
    if pid == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let alive = match c.host.signals() {
        Some(signals) => signals
            .kill(ax_abi_port::SignalTarget::Process(pid), 0)
            .is_ok(),
        // A host that cannot ask takes the caller's word for it.
        None => true,
    };
    // A process that has ended still has a handle while its exit code is
    // there to be read, which is what a parent opens one for.
    if !alive && !EXITED.lock().contains_key(&pid) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    c.set_last_error(0);
    c.finish(PROCESS_TAG | pid as usize)
}

/// What a child was told to exit with, until it has.
///
/// `TerminateProcess` names the code the process is to report, and the host
/// ends it with a signal, which is a different thing to report; this is what
/// keeps the two apart.
static TERMINATED: SpinLock<BTreeMap<u32, u32>> = SpinLock::new(BTreeMap::new());

/// TerminateProcess on a child: end it, and remember what it is to be
/// reported as having exited with.
pub(super) fn terminate(c: &mut Call<'_>, pid: u32, code: u32) -> Dispatch {
    /// `SIGKILL`, which is what ending a process without its cooperation is.
    const SIGKILL: u32 = 9;
    let Some(signals) = c.host.signals() else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    match signals.kill(ax_abi_port::SignalTarget::Process(pid), SIGKILL) {
        Ok(_) => {
            TERMINATED.lock().insert(pid, code);
            c.set_last_error(0);
            c.finish(TRUE)
        }
        Err(errno) => c.fail_status(super::nt::status_from_errno(errno), FALSE),
    }
}

/// How long a wait on a child sleeps before looking again. A child ending
/// signals nothing in this process, so the wait has to come back and ask.
const POLL_MS: u32 = 10;

/// Whether `pid` has ended, without waiting for it: `None` when it is no
/// child of ours to ask about.
pub(super) fn ended(c: &Call<'_>, pid: u32) -> Option<bool> {
    match reap(c, pid, false) {
        Child::Ended => Some(true),
        Child::Running => Some(false),
        Child::Gone => None,
    }
}

/// WaitForSingleObject on a process handle: the child ending, or the timeout.
pub fn wait_process(c: &mut Call<'_>, pid: u32, timeout_ms: u32) -> Dispatch {
    let deadline = super::sync::deadline_for(c, timeout_ms);
    loop {
        match reap(c, pid, false) {
            Child::Ended => return c.finish(WAIT_OBJECT_0),
            // The child could not be waited for, which is not the same as it
            // having ended; saying otherwise sends the caller off to collect
            // an exit code that does not exist yet.
            Child::Gone => return c.fail(ERROR_INVALID_HANDLE, WAIT_FAILED),
            Child::Running => {}
        }
        let Some(left) = super::sync::left_of(c, deadline) else {
            return c.finish(WAIT_TIMEOUT);
        };
        let seen = super::sync::signal_count(c).unwrap_or(0);
        super::sync::wait_for_signal(c, seen, left.min(POLL_MS));
    }
}

/// GetExitCodeProcess(hProcess, lpExitCode): the code once the child has
/// ended, STILL_ACTIVE until then.
pub fn get_exit_code_process(c: &mut Call<'_>) -> Dispatch {
    let (handle, out) = (c.arg(0), c.arg(1));
    let Some(pid) = pid_of(handle) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    reap(c, pid, false);
    let code = EXITED.lock().get(&pid).copied().unwrap_or(STILL_ACTIVE);
    if !c.write_u32(out, code) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.finish(TRUE)
}

/// InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount,
/// dwFlags, lpSize): asked for the size with a NULL list, as the API is used;
/// the list itself is accepted and never read, since the only attribute a
/// runtime sets - which handles the child inherits - is answered by the
/// standard handles alone.
pub fn init_proc_thread_attribute_list(c: &mut Call<'_>) -> Dispatch {
    let (list, size_out) = (c.arg(0), c.arg(3));
    if list == 0 {
        if size_out != 0 {
            c.write_u64(size_out, 64);
        }
        return c.fail(ERROR_INSUFFICIENT_BUFFER, FALSE);
    }
    c.finish(TRUE)
}
