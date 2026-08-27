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
use ax_binfmt::TrapEnv;
use ax_runtime::hal::cpu::uspace::UserContext;

use crate::{Errno, StarryError, StarryResult};

/// Borrows a trapped [`UserContext`] and presents it as the ABI-neutral
/// [`TrapEnv`] the personality domains consume.
pub struct TrapCtx<'a>(pub &'a mut UserContext);

impl TrapEnv for TrapCtx<'_> {
    fn nr(&self) -> usize {
        self.0.sysno()
    }

    fn arg(&self, i: usize) -> usize {
        match i {
            0 => self.0.arg0(),
            1 => self.0.arg1(),
            2 => self.0.arg2(),
            3 => self.0.arg3(),
            4 => self.0.arg4(),
            _ => self.0.arg5(),
        }
    }

    fn set_result(&mut self, value: usize) {
        self.0.set_retval(value);
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
/// `Some(result)` when the domain owns the call; `None` leaves it to the
/// kernel's own table. Returning the outcome rather than writing the trap frame
/// keeps one epilogue for both paths, so a migrated syscall still goes through
/// the signal-redirect check and the retval encoding the kernel already applies.
pub fn route_syscall(uctx: &mut UserContext) -> Option<StarryResult<isize>> {
    ax_abi_linux::LinuxAbi::route_trapped_syscall(&TrapCtx(uctx))
        .map(|result| result.map_err(|errno| StarryError::from(Errno::new(errno))))
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
