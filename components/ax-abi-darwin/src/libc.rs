//! The bodies behind the synthesized libSystem's stubs.
//!
//! [`crate::system`] gives every entry point a stub and a trap number; this
//! is what those numbers reach. On a real machine the same entry points are
//! ordinary user code inside libSystem, most of them a few instructions over
//! a system call, and a few - the string and stdio families - a real library.
//! There is no libSystem to load here, so the bodies live on this side of the
//! trap instead, over the same capability ports [`crate::bsd`] uses.
//!
//! An entry the table names but nothing here serves says so in the host's log
//! and fails the call. That is what keeps a half-built library honest: a
//! program reaches exactly as far as what is implemented, and the log names
//! the next thing to write.

use ax_abi_port::{Host, SysResult};
use ax_dispatch::{Dispatch, TrapEnv};

use crate::system::DarwinCall;

/// `ENOSYS`, which is what an entry point that is bound but not written yet
/// answers with.
const ENOSYS: i32 = 78;

/// Service a call that came through one of the library's stubs.
pub fn dispatch(env: &mut dyn TrapEnv, host: &dyn Host) -> Dispatch {
    let Ok(nr) = u32::try_from(env.nr()) else {
        return Dispatch::Passthrough;
    };
    let Some(call) = DarwinCall::from_nr(nr) else {
        return Dispatch::Passthrough;
    };
    let a = [
        env.arg(0),
        env.arg(1),
        env.arg(2),
        env.arg(3),
        env.arg(4),
        env.arg(5),
    ];
    let outcome = route(host, call, &a).unwrap_or_else(|| {
        host.platform()
            .trace(&alloc::format!("{} is not implemented", call.name()));
        Err(ENOSYS)
    });
    match outcome {
        Ok(value) => {
            env.set_error(false);
            env.set_result(value as usize);
        }
        Err(errno) => {
            // The C entry points report failure the way C does - a negative
            // return and `errno` set - but the carry flag costs nothing to
            // raise and is what a program reaching past this layer expects.
            env.set_error(true);
            env.set_result(errno as usize);
        }
    }
    Dispatch::Handled
}

/// What one call does, or `None` for one this layer does not serve yet.
fn route(host: &dyn Host, call: DarwinCall, a: &[usize; 6]) -> Option<SysResult> {
    let fd = a[0] as i32;
    Some(match call.name() {
        // `exit(3)`. Flushing what stdio holds belongs here once there is
        // stdio to flush; until then it is the same as leaving.
        "_exit" | "__exit" => host.tasks()?.exit_group((a[0] as i32) << 8),
        "_read" => host.files()?.read(fd, a[1], a[2]),
        "_write" => host.files()?.write(fd, a[1], a[2]),
        "_close" => host.files()?.close(fd),
        "_getpid" => host.tasks()?.getpid(),
        "_getppid" => host.tasks()?.getppid(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        system::Library,
        testing::{MockHost, Trap},
    };

    fn nr(name: &str) -> usize {
        Library::call(name).expect("the table names it").nr() as usize
    }

    #[test]
    fn a_number_from_another_layer_is_left_alone() {
        let host = MockHost::default();
        // A BSD call carries its class in the top byte and belongs to `bsd`.
        let mut env = Trap::at(2 << 24 | 4, [1, 0x200, 12, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Passthrough);
        assert_eq!(env.answer(), (None, None));
    }

    #[test]
    fn write_reaches_the_files_port() {
        let host = MockHost::default();
        let mut env = Trap::at(nr("_write"), [1, 0x200, 12, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.answer(), (Some(12), Some(false)));
        assert_eq!(*host.wrote.borrow(), Some((1, 0x200, 12)));
    }

    #[test]
    fn a_failing_call_reports_the_errno_and_raises_the_carry_flag() {
        let host = MockHost::default();
        let mut env = Trap::at(nr("_write"), [-1i32 as usize, 0x200, 4, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(
            env.answer(),
            (Some(9), Some(true)),
            "EBADF, not its negation"
        );
    }

    #[test]
    fn an_entry_point_with_no_body_yet_says_so_rather_than_answer() {
        let host = MockHost::default();
        let mut env = Trap::at(nr("_fprintf"), [0; 6]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.answer(), (Some(ENOSYS as usize), Some(true)));
    }
}
