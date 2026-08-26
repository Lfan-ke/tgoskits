//! Umbrella crate for ArceOS personalities.
//!
//! This is the "one package that does it all" entry point: enable the `linux`,
//! `win` and/or `mac` features to compile in those personalities, `auto-dispatch`
//! to route each executed image to the right one by its magic bytes, and
//! `driver-compat`/`path-compat` to pull in the shared compatibility shims. A
//! "maker" who wants finer control can depend on the sub-crates
//! (`ax-abi-windows`, `ax-abi-path`, ...) directly instead.
//!
//! The dispatch core and the [`Personality`] trait live in [`ax_binfmt`] and are
//! re-exported here so a dependant needs only this crate.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(feature = "mac")]
pub use ax_abi_darwin::{self, DarwinAbi};
#[cfg(feature = "driver-compat")]
pub use ax_abi_driver;
#[cfg(feature = "path-compat")]
pub use ax_abi_path;
#[cfg(feature = "win")]
pub use ax_abi_windows::{self, WindowsAbi};
pub use ax_binfmt::{self, Abi, AbiError, AbiResult, Personality, detect};

// Each compiled-in personality is a zero-sized handler with a `'static` address,
// so the assembled set holds `'static` references without allocation of the
// handlers themselves.
#[cfg(feature = "win")]
static WINDOWS: WindowsAbi = WindowsAbi;
#[cfg(feature = "mac")]
static DARWIN: DarwinAbi = DarwinAbi;

/// The personalities compiled into this build, in dispatch-priority order.
///
/// Registration order is the match priority, mirroring how the Linux binfmt list
/// is walked. Only personalities whose feature is enabled appear.
pub fn personalities() -> Vec<&'static dyn Personality> {
    // Each slot is `Some` only when its feature is enabled; `flatten` drops the
    // absent ones, so this stays clean whether zero, one or many are compiled in.
    let win: Option<&'static dyn Personality> = {
        #[cfg(feature = "win")]
        {
            Some(&WINDOWS)
        }
        #[cfg(not(feature = "win"))]
        {
            None
        }
    };
    let mac: Option<&'static dyn Personality> = {
        #[cfg(feature = "mac")]
        {
            Some(&DARWIN)
        }
        #[cfg(not(feature = "mac"))]
        {
            None
        }
    };
    [win, mac].into_iter().flatten().collect()
}

/// Route `image` to the first compiled-in personality that recognizes it.
///
/// # Errors
///
/// Returns [`AbiError::UnknownFormat`] when no enabled personality claims the
/// image (the caller reports `ENOEXEC`).
#[cfg(feature = "auto-dispatch")]
pub fn dispatch(image: &[u8]) -> AbiResult<&'static dyn Personality> {
    personalities()
        .into_iter()
        .find(|p| p.recognizes(image))
        .ok_or(AbiError::UnknownFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "win")]
    #[test]
    fn windows_personality_is_compiled_in() {
        assert!(personalities().iter().any(|p| p.abi() == Abi::Windows));
    }

    #[cfg(all(feature = "win", feature = "auto-dispatch"))]
    #[test]
    fn dispatches_a_pe_to_windows() {
        // Minimal "MZ..PE\0\0" stub that detect() routes to Windows.
        let mut pe = alloc::vec![0u8; 0x88];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(dispatch(&pe).unwrap().abi(), Abi::Windows);
        // A non-executable blob is refused.
        assert_eq!(dispatch(b"garbage").err(), Some(AbiError::UnknownFormat));
    }

    #[cfg(not(feature = "win"))]
    #[test]
    fn empty_build_has_no_personalities() {
        assert!(personalities().is_empty());
    }
}
