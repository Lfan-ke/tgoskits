//! Threads: `CreateThread` starts one, `ExitThread` ends one.
//!
//! A thread shares the address space, descriptors and signal handlers of the
//! process, so it is a clone with the thread flags. Windows keeps a thread's
//! own state - its last error, its TLS slots, its stack bounds - in a TEB the
//! thread reads through `gs`, so each thread gets a fresh one and the clone
//! carries its address in the child's `gs` base. The thread starts in a
//! trampoline that calls the thread procedure and, when it returns, exits the
//! thread with what it returned (see [`crate::thunk::thread_trampoline`]).

use ax_abi_port::{MapRequest, MapSource, Prot};
use ax_dispatch::Dispatch;

use super::{Call, mapped, process::THREAD_TAG, runtime};
use crate::{
    dll,
    nt::Ntstatus,
    teb_peb::{TEB_PEB, TEB_SELF, TEB_SIZE, TEB_STACK_BASE, TEB_STACK_LIMIT, TEB_TLS_POINTER},
    thunk,
};

/// The default stack a thread gets when the caller asks for none - the reserve
/// a Windows thread starts with.
const DEFAULT_STACK: usize = 0x100_000;

/// CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
/// dwCreationFlags, lpThreadId).
pub fn create_thread(c: &mut Call<'_>) -> Dispatch {
    let (size, proc, param, thread_id_out) = (c.arg(1), c.arg(2), c.arg(3), c.arg(5));
    if proc == 0 {
        return c.fail(super::ERROR_INVALID_PARAMETER, 0);
    }
    let Some(mem) = c.host.mem() else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    let stack_len = if size == 0 {
        DEFAULT_STACK
    } else {
        size.next_multiple_of(0x1000)
    };
    let Ok(stack) = mem.map(&MapRequest {
        addr: 0,
        len: stack_len,
        prot: Prot::READ | Prot::WRITE,
        fixed: false,
        shared: false,
        source: MapSource::Anonymous,
    }) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    let stack = stack as usize;
    let stack_top = (stack + stack_len) & !0xF;

    // The thread's own TEB, from the process heap, pointing at the shared PEB.
    let peb = c.read_u64(c.teb + TEB_PEB).unwrap_or(0);
    let Some(heap) = c
        .peb()
        .and_then(|p| c.read_u64(p + crate::teb_peb::PEB_PROCESS_HEAP))
        .map(|h| h as usize)
    else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    let (Some(teb), Some(block)) = (
        super::heap::alloc(c, heap, TEB_SIZE),
        super::heap::alloc(c, heap, 24),
    ) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    if !super::zero(c, teb, TEB_SIZE) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }
    c.write_u64(teb + TEB_SELF, teb as u64);
    c.write_u64(teb + TEB_PEB, peb);
    c.write_u64(teb + TEB_STACK_BASE, stack_top as u64);
    c.write_u64(teb + TEB_STACK_LIMIT, stack as u64);
    // Thread locals: a block per module that has them, in load order, since
    // the slot a module was given is its position in that order. Without this
    // the first `__declspec(thread)` read in the thread goes through a null
    // pointer, which is where a thread that had none died.
    let Some((array, callbacks)) = thread_locals(c, heap) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    c.write_u64(teb + TEB_TLS_POINTER, array as u64);

    // The trampoline's argument: the procedure, its parameter, and the
    // callbacks the loader owes this thread.
    if !c.write_u64(block, proc as u64)
        || !c.write_u64(block + 8, param as u64)
        || !c.write_u64(block + 16, callbacks as u64)
    {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }

    let Some(kernel32) = runtime::module_named(c, dll::SYSTEM_NAMES[0]) else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    let entry = kernel32 + thunk::thread_trampoline_offset();
    let tid = match c.env.spawn_thread(entry, stack_top, block, teb) {
        Ok(tid) => tid,
        Err(errno) => return c.fail_status(super::nt::status_from_errno(errno), 0),
    };
    if thread_id_out != 0 {
        c.write_u32(thread_id_out, tid);
    }
    c.set_last_error(0);
    c.finish(THREAD_TAG | tid as usize)
}

/// FreeLibraryAndExitThread(hLibModule, dwExitCode): let go of the library the
/// thread is running in and end the thread in one step, so the thread cannot be
/// left executing code that was unmapped out from under it. Libraries are never
/// unmapped here, so there is no reference to let go of and this is the exit.
pub fn free_library_and_exit_thread(c: &mut Call<'_>) -> Dispatch {
    exit_with(c, c.arg(1) as i32)
}

/// ExitThread(dwExitCode): end the calling thread.
pub fn exit_thread(c: &mut Call<'_>) -> Dispatch {
    exit_with(c, c.arg(0) as i32)
}

/// End the calling thread with `code`. The task does not come back from this;
/// the finish is what the trap layer needs to see if it ever did.
fn exit_with(c: &mut Call<'_>, code: i32) -> Dispatch {
    if let Some(tasks) = c.host.tasks() {
        let _ = tasks.exit(code);
    }
    c.finish(0)
}

/// The thread-local blocks a starting thread needs, and the callbacks to run
/// in it before its procedure.
///
/// A module's slot is its position among the modules that have a thread-local
/// directory, so the array is built by walking the modules in load order - the
/// same order the slots were handed out in when the process was loaded. Each
/// block is the module's template followed by its zero fill, which is what the
/// template's own initialisers expect to find.
fn thread_locals(c: &Call<'_>, heap: usize) -> Option<(usize, usize)> {
    let images = super::modules(c);
    let dirs: alloc::vec::Vec<mapped::Tls> = images
        .iter()
        .filter_map(|base| mapped::tls(c, *base))
        .collect();
    // Even a process with no thread locals gets an array, so the pointer in
    // the TEB names something a read can land on.
    let array = super::heap::alloc(c, heap, dirs.len().max(1) * 8)?;
    if !super::zero(c, array, dirs.len().max(1) * 8) {
        return None;
    }
    for (slot, dir) in dirs.iter().enumerate() {
        let block = super::heap::alloc(c, heap, dir.len.max(1))?;
        if !super::zero(c, block, dir.len.max(1)) || !copy(c, dir.template, block, dir.raw) {
            return None;
        }
        c.write_u64(array + slot * 8, block as u64);
    }
    // The callbacks, paired with the module they belong to, ending in a null
    // entry the trampoline stops at.
    let mut pairs = alloc::vec::Vec::new();
    for (base, dir) in images.iter().zip(dirs.iter()) {
        let mut at = dir.callbacks;
        while at != 0 {
            match c.read_u64(at) {
                Some(0) | None => break,
                Some(callback) => pairs.push((callback as usize, *base)),
            }
            at += 8;
        }
    }
    if pairs.is_empty() {
        return Some((array, 0));
    }
    let list = super::heap::alloc(c, heap, (pairs.len() + 1) * 16)?;
    if !super::zero(c, list, (pairs.len() + 1) * 16) {
        return None;
    }
    for (at, (callback, base)) in pairs.iter().enumerate() {
        c.write_u64(list + at * 16, *callback as u64);
        c.write_u64(list + at * 16 + 8, *base as u64);
    }
    Some((array, list))
}

/// Copy `len` bytes of user memory from `from` to `to`, in the chunks the
/// platform port reads and writes in.
fn copy(c: &Call<'_>, from: usize, to: usize, len: usize) -> bool {
    let mut chunk = [0u8; 256];
    let mut moved = 0;
    while moved < len {
        let n = (len - moved).min(chunk.len());
        if c.host
            .platform()
            .read_user(from + moved, &mut chunk[..n])
            .is_err()
            || !c.write(to + moved, &chunk[..n])
        {
            return false;
        }
        moved += n;
    }
    true
}
