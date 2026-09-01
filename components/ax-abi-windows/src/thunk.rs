//! Synthesized entry points for the system libraries an image imports.
//!
//! A Windows image reaches the system through kernel32, a real DLL that ntdll
//! loads. There is no ntdll here; this package's loader is what maps an image,
//! so a system library need not be a file at all: each imported function
//! binds to a few instructions synthesized into the process, and those
//! instructions raise the trap [`crate::win32`] answers. Wine writes a stub
//! into the address table the same way when it cannot satisfy an import
//! (`allocate_stub`, `dlls/ntdll/loader.c`); here it is the ordinary path
//! rather than the failure path, which is what saves mapping a kernel32 at all.
//!
//! The instructions also move arguments. A Windows function takes its first
//! four in `rcx`, `rdx`, `r8`, `r9` and the rest above the register spill area,
//! while a trap arrives with them in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.
//! The stub is where the two conventions meet, which is why the Win32 layer
//! reads every argument from the trap frame and none from the stack.

use crate::win32::Win32Call;

/// Bytes reserved for each stub. The instructions are shorter; a fixed stride
/// makes the address of a stub its index times this.
pub const STUB_LEN: usize = 32;

/// The instructions that stand in for one imported function.
///
/// Reaching past them means something jumped into the middle of a stub, so the
/// remainder traps rather than running on into the next one.
pub fn stub(call: Win32Call) -> [u8; STUB_LEN] {
    let nr = call.nr().to_le_bytes();
    let load_nr = [0xB8, nr[0], nr[1], nr[2], nr[3]];
    let mut out = [0xCC_u8; STUB_LEN];
    let mut at = 0;
    // r9 is read before rdx is overwritten and r8 before it is reloaded, so the
    // moves need no scratch register.
    for part in [
        &[0x48, 0x89, 0xCF][..],             // mov rdi, rcx
        &[0x48, 0x89, 0xD6][..],             // mov rsi, rdx
        &[0x4D, 0x89, 0xCA][..],             // mov r10, r9
        &[0x4C, 0x89, 0xC2][..],             // mov rdx, r8
        &[0x4C, 0x8B, 0x44, 0x24, 0x28][..], // mov r8, [rsp+0x28]
        &[0x4C, 0x8B, 0x4C, 0x24, 0x30][..], // mov r9, [rsp+0x30]
        &load_nr[..],                        // mov eax, <trap number>
        &[0x0F, 0x05][..],                   // syscall
        &[0xC3][..],                         // ret
    ] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stub_moves_the_arguments_and_asks_for_its_own_number() {
        let code = stub(Win32Call::WriteFile);
        // mov eax, <nr> carries the number the trap is answered by.
        let at = code
            .windows(5)
            .position(|w| w[0] == 0xB8)
            .expect("the number is loaded");
        let nr = u32::from_le_bytes(code[at + 1..at + 5].try_into().unwrap());
        assert_eq!(nr, Win32Call::WriteFile.nr());
        // The number is loaded last, so the moves cannot clobber it.
        assert_eq!(&code[at + 5..at + 7], &[0x0F, 0x05], "syscall follows");
        assert_eq!(code[at + 7], 0xC3, "then a return");
        // Whatever the instructions leave unused must not run on.
        assert!(code[at + 8..].iter().all(|b| *b == 0xCC));
    }

    #[test]
    fn two_calls_get_different_numbers_and_so_different_stubs() {
        assert_ne!(stub(Win32Call::WriteFile), stub(Win32Call::ExitProcess));
    }
}
