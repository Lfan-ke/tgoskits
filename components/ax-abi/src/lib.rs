//! Umbrella crate for ArceOS personalities.
//!
//! This is the "one package that does it all" entry point: enable the `linux`,
//! `win` and/or `mac` features to compile in those personalities, `auto-dispatch`
//! to route each executed image to the right one by its magic bytes, and
//! `driver-compat`/`path-compat` to pull in the shared compatibility shims. A
//! "maker" who wants finer control can depend on the sub-crates
//! (`ax-abi-windows`, `ax-abi-path`, ...) directly instead.
//!
//! The dispatch spine and the [`SysAbi`] trait live in [`ax_dispatch`], the
//! executable formats in [`ax_binfmt`], and the capability ports a hosting OS
//! implements in [`ax_abi_port`]; all three are re-exported here so a dependant
//! needs only this crate.
//!
//! Nothing here selects anything at run time. A feature adds a crate to the
//! link, that crate registers itself, and this crate supplies the one default
//! dispatch policy the kernel calls. A host wanting another policy depends on
//! the packages directly and implements [`TrapDispatch`] itself.

#![no_std]

#[cfg(feature = "custom")]
pub use ax_abi_custom::{self, CustomSyscalls};
#[cfg(feature = "mac")]
pub use ax_abi_darwin::{self, DarwinAbi};
#[cfg(feature = "driver-compat")]
pub use ax_abi_driver;
#[cfg(feature = "embedded")]
pub use ax_abi_embedded::{self, VectorTable};
#[cfg(feature = "linux")]
pub use ax_abi_linux::{self, LinuxAbi};
#[cfg(feature = "path-compat")]
pub use ax_abi_path;
pub use ax_abi_port::{self, CurrentHost, Host};
#[cfg(feature = "win")]
pub use ax_abi_windows::{self, WindowsAbi};
pub use ax_binfmt::{self, AbiError, AbiResult, ImageFormat, detect, dispatch_image};
pub use ax_dispatch::{
    self, Abi, CustomHandler, Dispatch, SysAbi, TrapDispatch, TrapEnv, TrapOutcome, dispatch_trap,
    dispatch_trap_intercept,
};

/// Answers the hosting kernel's [`TrapDispatch`] from the registry, so neither
/// the kernel nor this crate names a personality. Swapping the ABI a system
/// speaks is a dependency change: a linked personality registers itself.
struct Dispatcher;

#[ax_crate_interface::impl_interface]
impl TrapDispatch for Dispatcher {
    fn dispatch(env: &mut dyn TrapEnv) -> Dispatch {
        // A host that resolved which implementation serves this task gets an
        // index into the registry; one that did not gets the scan.
        match env.slot() {
            Some(slot) => ax_dispatch::dispatch_at(slot, env),
            None => ax_dispatch::dispatch_registered_trap(env),
        }
    }
}

/// The ABI implementations this build linked in, in registration order.
pub fn personalities() -> impl Iterator<Item = &'static dyn SysAbi> {
    ax_dispatch::registered()
        .iter()
        .map(ax_dispatch::Registration::sysabi)
}

/// Route `image` to the first compiled-in personality that recognizes it.
///
/// # Errors
///
/// Returns [`AbiError::UnknownFormat`] when no enabled personality claims the
/// image (the caller reports `ENOEXEC`).
#[cfg(feature = "auto-dispatch")]
pub fn dispatch(image: &[u8]) -> AbiResult<&'static dyn ImageFormat> {
    ax_binfmt::dispatch_image(image)
}

#[cfg(test)]
mod tests {
    use ax_abi_port::{Platform, SysResult};

    use super::*;

    // A host with nothing but the platform port, so the registered personalities
    // have something to resolve while these tests only exercise registration.
    struct BareHost;
    impl Platform for BareHost {
        fn read_user(&self, _uaddr: usize, _out: &mut [u8]) -> SysResult {
            Ok(0)
        }
        fn write_user(&self, _uaddr: usize, _data: &[u8]) -> SysResult {
            Ok(0)
        }
    }
    impl Host for BareHost {
        fn platform(&self) -> &dyn Platform {
            self
        }
    }

    struct Binding;
    #[ax_crate_interface::impl_interface]
    impl CurrentHost for Binding {
        fn current() -> &'static dyn Host {
            static HOST: BareHost = BareHost;
            &HOST
        }
    }

    #[cfg(feature = "win")]
    #[test]
    fn a_linked_personality_registers_itself() {
        assert!(personalities().any(|p| p.abi() == Abi::Windows));
    }

    #[cfg(all(feature = "win", feature = "auto-dispatch"))]
    #[test]
    fn dispatches_a_pe_to_windows() {
        // Minimal "MZ..PE\0\0" stub that detect() routes to Windows.
        let mut pe = [0u8; 0x88];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(dispatch(&pe).unwrap().abi(), Abi::Windows);
        // A non-executable blob is refused.
        assert_eq!(dispatch(b"garbage").err(), Some(AbiError::UnknownFormat));
    }

    #[cfg(not(feature = "win"))]
    #[test]
    fn an_unlinked_personality_is_absent() {
        assert!(!personalities().any(|p| p.abi() == Abi::Windows));
    }
}
