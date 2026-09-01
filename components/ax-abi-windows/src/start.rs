//! The first instructions a Windows process runs.
//!
//! Between mapping and the program's entry point ntdll does three things on
//! the new thread: it gives every module with thread locals a slot and a block
//! (`alloc_tls_slot`), it calls each library's TLS callbacks and then its entry
//! point with `DLL_PROCESS_ATTACH`, dependencies first (`process_attach`,
//! `MODULE_InitDLL`), and it calls the program's entry point and ends the
//! process with whatever that returns (`RtlUserThreadStart`). The blocks are
//! laid out by the loader before the process exists; the calls are the code
//! this module emits, which becomes the process's entry point. A library whose
//! entry point returns zero has refused, and the process ends the way Windows
//! ends it, with `STATUS_DLL_INIT_FAILED`.
//!
//! The sequence keeps the stack sixteen-byte aligned at every call and leaves
//! the thirty-two bytes of spill space a Windows callee expects, so what it
//! calls sees the frame `RtlUserThreadStart` would have given it.

use alloc::vec::Vec;

/// `STATUS_DLL_INIT_FAILED`: what a process exits with when a library's entry
/// point refuses to attach.
pub const DLL_INIT_FAILED: u32 = 0xC000_0142;

/// The reason every call here passes: the process is attaching.
const DLL_PROCESS_ATTACH: u32 = 1;

/// One call made before the program's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// A TLS callback: `(base, DLL_PROCESS_ATTACH, NULL)`; what it returns is
    /// not looked at.
    Callback { base: u64, at: u64 },
    /// A library's entry point: `(base, DLL_PROCESS_ATTACH, non-NULL)`, the
    /// last argument saying this is the process starting rather than a later
    /// `LoadLibrary`. Zero back means the library refused.
    Entry { base: u64, at: u64 },
}

/// The sequence: every step in order, then the program's `entry` with `arg`
/// (Windows hands the first thread the PEB), then `ExitProcess` - reached at
/// `exit` - with what the entry returned, or with [`DLL_INIT_FAILED`] if a
/// step refused.
pub fn emit(steps: &[Step], entry: u64, arg: u64, exit: u64) -> Vec<u8> {
    let mut code = Vec::new();
    let mut to_fail = Vec::new();

    // The thread starts on a sixteen-byte boundary; taking the spill space
    // keeps it there, so each `call` below hands its callee the alignment the
    // convention promises.
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20
    for step in steps {
        let (base, at, reserved): (u64, u64, u32) = match *step {
            Step::Callback { base, at } => (base, at, 0),
            Step::Entry { base, at } => (base, at, 1),
        };
        mov_rcx(&mut code, base);
        code.push(0xBA); // mov edx, DLL_PROCESS_ATTACH
        code.extend_from_slice(&DLL_PROCESS_ATTACH.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xB8]); // mov r8d, reserved
        code.extend_from_slice(&reserved.to_le_bytes());
        call_rax(&mut code, at);
        if matches!(step, Step::Entry { .. }) {
            code.extend_from_slice(&[0x85, 0xC0, 0x0F, 0x84]); // test eax, eax; jz rel32
            to_fail.push(code.len());
            code.extend_from_slice(&[0; 4]);
        }
    }
    mov_rcx(&mut code, arg);
    call_rax(&mut code, entry);
    code.extend_from_slice(&[0x89, 0xC1, 0xE9]); // mov ecx, eax; jmp rel32
    let to_exit = code.len();
    code.extend_from_slice(&[0; 4]);

    let fail = code.len();
    code.push(0xB9); // mov ecx, DLL_INIT_FAILED
    code.extend_from_slice(&DLL_INIT_FAILED.to_le_bytes());
    let exit_at = code.len();
    call_rax(&mut code, exit);
    // ExitProcess does not return; if it did, stop rather than run on.
    code.push(0xCC);

    for at in to_fail {
        patch_rel32(&mut code, at, fail);
    }
    patch_rel32(&mut code, to_exit, exit_at);
    code
}

fn mov_rcx(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn call_rax(code: &mut Vec<u8>, at: u64) {
    code.extend_from_slice(&[0x48, 0xB8]); // mov rax, at
    code.extend_from_slice(&at.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax
}

/// A rel32 is measured from the end of the instruction that holds it.
fn patch_rel32(code: &mut [u8], at: usize, target: usize) {
    let rel = (target as i64 - (at + 4) as i64) as i32;
    code[at..at + 4].copy_from_slice(&rel.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn mov_rcx_of(value: u64) -> Vec<u8> {
        let mut v = vec![0x48, 0xB9];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }

    #[test]
    fn libraries_attach_in_order_before_the_program_starts() {
        let code = emit(
            &[
                Step::Callback {
                    base: 0x1000,
                    at: 0x1100,
                },
                Step::Entry {
                    base: 0x1000,
                    at: 0x1200,
                },
                Step::Entry {
                    base: 0x2000,
                    at: 0x2200,
                },
            ],
            0x9000,
            0x7000,
            0x8000,
        );
        let first = find(&code, &mov_rcx_of(0x1000)).expect("first library");
        let second = find(&code[first + 1..], &mov_rcx_of(0x1000)).expect("its entry") + first + 1;
        let third = find(&code, &mov_rcx_of(0x2000)).expect("second library");
        let program = find(&code, &mov_rcx_of(0x7000)).expect("the program, with the PEB");
        assert!(first < second && second < third && third < program);
        // A callback is told nothing is reserved; an entry point is told the
        // process is starting.
        assert_eq!(
            &code[first + 10..first + 20],
            &[0xBA, 1, 0, 0, 0, 0x41, 0xB8, 0, 0, 0]
        );
        assert_eq!(
            &code[second + 10..second + 20],
            &[0xBA, 1, 0, 0, 0, 0x41, 0xB8, 1, 0, 0]
        );
    }

    #[test]
    fn a_refusal_ends_the_process_with_dll_init_failed() {
        let code = emit(
            &[Step::Entry {
                base: 0x1000,
                at: 0x1200,
            }],
            0x9000,
            0,
            0x8000,
        );
        // test eax, eax; jz rel32 follows the entry's call.
        let jz = find(&code, &[0x85, 0xC0, 0x0F, 0x84]).expect("the check") + 4;
        let rel = i32::from_le_bytes(code[jz..jz + 4].try_into().unwrap());
        let fail = (jz as i64 + 4 + rel as i64) as usize;
        assert_eq!(code[fail], 0xB9, "mov ecx, status");
        assert_eq!(
            u32::from_le_bytes(code[fail + 1..fail + 5].try_into().unwrap()),
            DLL_INIT_FAILED
        );
        // And then ExitProcess, through the stub the loader placed.
        let mut exit = vec![0x48, 0xB8];
        exit.extend_from_slice(&0x8000u64.to_le_bytes());
        exit.extend_from_slice(&[0xFF, 0xD0, 0xCC]);
        assert_eq!(&code[fail + 5..], &exit[..]);
    }

    #[test]
    fn what_the_program_returns_becomes_the_exit_code() {
        let code = emit(&[], 0x9000, 0, 0x8000);
        // mov ecx, eax; jmp exit - the jump lands on the ExitProcess call.
        let at = find(&code, &[0x89, 0xC1, 0xE9]).expect("hand the return value on") + 3;
        let rel = i32::from_le_bytes(code[at..at + 4].try_into().unwrap());
        let target = (at as i64 + 4 + rel as i64) as usize;
        assert_eq!(&code[target..target + 2], &[0x48, 0xB8]);
        assert_eq!(
            u64::from_le_bytes(code[target + 2..target + 10].try_into().unwrap()),
            0x8000
        );
    }
}
