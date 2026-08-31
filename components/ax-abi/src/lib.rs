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
        // Whether an extension may take an index the ABI also owns is a policy
        // of this crate, not a property of the extension: enabling
        // `custom-intercept` puts extensions first, which is the deliberate
        // opt-in to shadowing a base ABI.
        #[cfg(feature = "custom-intercept")]
        if ax_dispatch::dispatch_registered_custom(env) == Dispatch::Handled {
            return Dispatch::Handled;
        }
        // A host that resolved which implementation serves this task gets an
        // index into the registry; one that did not gets the scan.
        let claimed = match env.slot() {
            Some(slot) => ax_dispatch::dispatch_at(slot, env),
            None => ax_dispatch::dispatch_registered_trap(env),
        };
        if claimed == Dispatch::Handled {
            return Dispatch::Handled;
        }
        // Otherwise the index is outside the ABI's own space, which is exactly
        // what a reserved range is for.
        ax_dispatch::dispatch_registered_custom(env)
    }
}

/// The ABI implementations this build linked in, in registration order.
pub fn personalities() -> impl Iterator<Item = &'static dyn SysAbi> {
    ax_dispatch::SYSABIS.iter().map(|get| get())
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
extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

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
        fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
            // Reads one byte at a time so it stops at the terminator, which
            // is what a host with real mappings has to do anyway.
            for (i, slot) in out.iter_mut().enumerate() {
                let mut byte = [0u8; 1];
                self.read_user(uaddr + i, &mut byte)?;
                if byte[0] == 0 {
                    return Ok(i as isize);
                }
                *slot = byte[0];
            }
            Ok(out.len() as isize)
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

    #[test]
    fn a_package_registers_once_per_capability_it_provides() {
        // Servicing traps and loading images are separate capabilities with
        // separate registries, so a package appears in the one it provides -
        // both, for a package that does both. Nothing here names a package.
        let abis: Vec<Abi> = personalities().map(|p| p.abi()).collect();
        let formats: Vec<Abi> = ax_binfmt::BINFMTS.iter().map(|get| get().abi()).collect();

        #[cfg(feature = "linux")]
        {
            assert!(abis.contains(&Abi::Linux));
            // The Linux package carries ELF only when asked for it, because a
            // host may still load ELF itself.
            assert_eq!(formats.contains(&Abi::Linux), cfg!(feature = "linux-elf"));
        }
        #[cfg(feature = "win")]
        {
            assert!(abis.contains(&Abi::Windows));
            assert!(formats.contains(&Abi::Windows));
        }
        #[cfg(feature = "mac")]
        {
            assert!(abis.contains(&Abi::Darwin));
            assert!(formats.contains(&Abi::Darwin));
        }
        // An ABI nothing linked in speaks is absent from both.
        #[cfg(not(feature = "win"))]
        {
            assert!(!abis.contains(&Abi::Windows));
            assert!(!formats.contains(&Abi::Windows));
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
