//! Kernel-side seam for the ArceOS ABI personalities.
//!
//! A personality (`ax-abi-linux` and its siblings) reads the trapped register
//! file through `ax-binfmt`'s ABI-neutral [`TrapEnv`], never touching an arch or
//! kernel type. This adapter borrows StarryOS's arch [`UserContext`] and presents
//! it as a [`TrapEnv`], so the domain dispatch can read the syscall number and
//! arguments and write the result back. It is the first half of the kernel
//! integration; the host-service ports the domain drives are wired next.

use ax_binfmt::TrapEnv;
use ax_runtime::hal::cpu::uspace::UserContext;

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
