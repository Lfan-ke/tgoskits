//! Kernel-side seam for the ArceOS ABI personalities.
//!
//! A personality (`ax-abi-linux` and its siblings) implements a foreign syscall
//! ABI against the abstract ports in `ax-abi-port`, never against a kernel type.
//! This module is StarryOS's end of that contract:
//!
//! - [`TrapCtx`] presents an arch [`UserContext`] as the ABI-neutral `TrapEnv` a
//!   domain reads the call number and arguments from;
//! - [`KernelHost`] implements the capability ports over what the kernel already
//!   has, and binds itself as the process-wide `CurrentHost`.
//!
//! The ports carry primitives, so each one either reaches straight for a kernel
//! object (the fd table, the address space, the thread) or reuses the existing
//! `sys_*` implementation of that same primitive. Reuse is deliberate: while
//! syscalls migrate into the domain one family at a time, a migrated call must
//! behave exactly as the kernel's own did.

mod port;

use ax_abi_port::{Clock, Creds, CurrentHost, Files, Host, Mem, Platform, Random, Signals, System, Tasks};
use ax_binfmt::{Abi, TrapEnv};
use ax_crate_interface::call_interface;
use ax_runtime::hal::cpu::uspace::UserContext;

use ax_task::current;

use crate::{StarryError, StarryResult, task::AsThread};

/// Borrows a trapped [`UserContext`] and presents it as the ABI-neutral
/// [`TrapEnv`] the personality domains consume.
pub struct TrapCtx<'a> {
    uctx: &'a mut UserContext,
    entry_ip: usize,
    abi: Option<Abi>,
}

impl<'a> TrapCtx<'a> {
    pub fn new(uctx: &'a mut UserContext) -> Self {
        let entry_ip = uctx.ip();
        let abi = Abi::from_tag(
            current()
                .as_thread()
                .proc_data
                .abi_tag
                .load(core::sync::atomic::Ordering::Relaxed),
        );
        Self {
            uctx,
            entry_ip,
            abi,
        }
    }
}

impl TrapEnv for TrapCtx<'_> {
    fn nr(&self) -> usize {
        self.uctx.sysno()
    }

    fn arg(&self, i: usize) -> usize {
        match i {
            0 => self.uctx.arg0(),
            1 => self.uctx.arg1(),
            2 => self.uctx.arg2(),
            3 => self.uctx.arg3(),
            4 => self.uctx.arg4(),
            _ => self.uctx.arg5(),
        }
    }

    fn abi(&self) -> Option<Abi> {
        self.abi
    }

    fn set_result(&mut self, value: usize) {
        // A syscall that got a signal delivered has already moved the frame on.
        // Where the return value shares a register with the first argument,
        // writing it now would clobber the signal number.
        if self.uctx.ip() == self.entry_ip {
            self.uctx.set_retval(value);
        }
    }
}

/// StarryOS's implementation of the personality capability ports.
///
/// Stateless: every port method reaches the current task, its address space or
/// the fd table when it runs, so one `'static` instance serves every CPU.
pub struct KernelHost;

/// The instance [`CurrentHost`] hands to a domain.
static HOST: KernelHost = KernelHost;

impl Host for KernelHost {
    fn platform(&self) -> &dyn Platform {
        self
    }
    fn tasks(&self) -> Option<&dyn Tasks> {
        Some(self)
    }
    fn files(&self) -> Option<&dyn Files> {
        Some(self)
    }
    fn mem(&self) -> Option<&dyn Mem> {
        Some(self)
    }
    fn signals(&self) -> Option<&dyn Signals> {
        Some(self)
    }
    fn clock(&self) -> Option<&dyn Clock> {
        Some(self)
    }
    fn random(&self) -> Option<&dyn Random> {
        Some(self)
    }
    fn system(&self) -> Option<&dyn System> {
        Some(self)
    }
    fn creds(&self) -> Option<&dyn Creds> {
        Some(self)
    }
}

#[ax_crate_interface::impl_interface]
impl CurrentHost for KernelHost {
    fn current() -> &'static dyn Host {
        &HOST
    }
}

/// Offer a trapped syscall to the Linux personality first.
///
/// `Some(result)` when a personality owns the call; `None` leaves it to the
/// kernel's own table. The kernel does not name the personality: the ABI layer
/// answers, so which ABI this system speaks is a dependency of that layer.
///
/// Returning the outcome rather than writing the trap frame keeps one epilogue
/// for both paths, so a migrated syscall still goes through the signal-redirect
/// check and the retval encoding the kernel already applies.
pub fn dispatch_syscall(uctx: &mut UserContext) -> bool {
    call_interface!(
        ax_binfmt::TrapDispatch::dispatch,
        &mut TrapCtx::new(uctx)
    ) == ax_binfmt::Dispatch::Handled
}

/// Translate a kernel failure into the errno a personality reports to userspace,
/// the same mapping `handle_syscall` applies to its own results.
fn errno(err: StarryError) -> i32 {
    err.linux_errno().into_raw()
}

/// Carry a kernel syscall result over to a port result.
fn port_result(result: StarryResult<isize>) -> ax_abi_port::SysResult {
    result.map_err(errno)
}
