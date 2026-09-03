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

use alloc::{vec, vec::Vec};

use crate::win32::{self, Win32Call};

/// The page a synthesized system library begins with: enough PE for a
/// program that asks the loader about the module - `GetModuleHandleW` then
/// `GetProcAddress` - to be answered out of an export directory, the way it
/// would be by the real library. The stubs follow it, so every export's RVA is
/// small and positive. Four pages: the names of every entry do not fit in two.
pub const MODULE_HEADER: usize = 0x4000;

/// How much address space library `lib` takes: its header, then a stub per
/// entry, rounded to a page so the next library starts on one.
pub fn system_size(lib: usize) -> usize {
    let trampoline = if lib == 0 { ATTACH_LEN } else { 0 };
    (MODULE_HEADER + win32::LIBRARIES[lib].exports.len() * STUB_LEN + trampoline)
        .next_multiple_of(0x1000)
}

/// The room the attach trampoline takes past kernel32's last stub.
pub const ATTACH_LEN: usize = 0x80;

/// The code a `LoadLibrary` stub jumps to instead of returning: with the
/// result in `rax` and the caller's `rsi`/`rdi` still pushed, it takes the
/// list the host left in the PEB (see `PEB_PENDING_ATTACH`) and calls each
/// entry point as `DllMain(base, DLL_PROCESS_ATTACH, NULL)`, then clears the
/// slot and returns the way the stub would have. The stack is kept
/// sixteen-byte aligned at the call with a shadow space in place.
pub fn attach_trampoline() -> [u8; ATTACH_LEN] {
    let mut out = [0xCC_u8; ATTACH_LEN];
    let slot = (win32::PEB_PENDING_ATTACH as u32).to_le_bytes();
    let code: &[&[u8]] = &[
        &[0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00], // mov rcx, gs:[0x60]
        &[0x48, 0x8B, 0x89, slot[0], slot[1], slot[2], slot[3]], // mov rcx, [rcx+slot]
        &[0x48, 0x85, 0xC9],                                     // test rcx, rcx
        &[0x74, 0x49],                                           // jz done
        &[0x53],                                                 // push rbx
        &[0x41, 0x54],                                           // push r12
        &[0x48, 0x89, 0xC3],                                     // mov rbx, rax
        &[0x49, 0x89, 0xCC],                                     // mov r12, rcx
        &[0x48, 0x83, 0xEC, 0x28],                               // sub rsp, 40
        &[0x49, 0x8B, 0x04, 0x24],                               // loop: mov rax, [r12]
        &[0x48, 0x85, 0xC0],                                     // test rax, rax
        &[0x74, 0x15],                                           // jz end
        &[0x49, 0x8B, 0x4C, 0x24, 0x08],                         // mov rcx, [r12+8]
        &[0xBA, 0x01, 0x00, 0x00, 0x00],                         // mov edx, 1
        &[0x45, 0x31, 0xC0],                                     // xor r8d, r8d
        &[0xFF, 0xD0],                                           // call rax
        &[0x49, 0x83, 0xC4, 0x10],                               // add r12, 16
        &[0xEB, 0xE2],                                           // jmp loop
        &[0x48, 0x83, 0xC4, 0x28],                               // end: add rsp, 40
        &[0x48, 0x89, 0xD8],                                     // mov rax, rbx
        &[0x41, 0x5C],                                           // pop r12
        &[0x5B],                                                 // pop rbx
        &[0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00], // mov rcx, gs:[0x60]
        &[
            0x48, 0xC7, 0x81, slot[0], slot[1], slot[2], slot[3], 0, 0, 0, 0,
        ], // mov [rcx+slot], 0
        &[0x5E],                                                 // done: pop rsi
        &[0x5F],                                                 // pop rdi
        &[0xC3],                                                 // ret
    ];
    let mut at = 0;
    for part in code {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    out
}

/// How much address space every synthesized library takes together.
pub fn system_len() -> usize {
    (0..win32::LIBRARIES.len()).map(system_size).sum()
}

/// The header page of synthesized library `lib` at `base`, whose stubs begin
/// [`MODULE_HEADER`] bytes past it. Only what a reader of the export directory
/// touches is filled in: the signature, the optional header's magic and size
/// of image, and the export directory naming every entry under its ordinal.
pub fn system_header(base: u64, lib: usize) -> Vec<u8> {
    let library = &win32::LIBRARIES[lib];
    let mut img = vec![0u8; MODULE_HEADER];
    let put32 =
        |img: &mut Vec<u8>, at: usize, v: u32| img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put16 =
        |img: &mut Vec<u8>, at: usize, v: u16| img[at..at + 2].copy_from_slice(&v.to_le_bytes());
    img[..2].copy_from_slice(b"MZ");
    let pe = 0x80;
    put32(&mut img, 0x3C, pe as u32);
    img[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    put16(&mut img, coff, 0x8664); // Machine: x86-64
    put16(&mut img, coff + 16, 240); // SizeOfOptionalHeader
    put16(&mut img, coff + 18, 0x2022); // DLL, executable, large-address-aware
    let opt = coff + 20;
    put16(&mut img, opt, 0x20B); // PE32+
    img[opt + 24..opt + 32].copy_from_slice(&base.to_le_bytes());
    put32(&mut img, opt + 32, 0x1000); // SectionAlignment
    put32(&mut img, opt + 36, 0x200); // FileAlignment
    put32(&mut img, opt + 56, system_size(lib) as u32); // SizeOfImage
    put32(&mut img, opt + 60, MODULE_HEADER as u32); // SizeOfHeaders
    put16(&mut img, opt + 68, 3); // Subsystem: console
    put32(&mut img, opt + 108, 16); // NumberOfRvaAndSizes

    // The export directory and its three tables, then the names, all inside
    // this page. The function table is indexed by ordinal less the base, so
    // it spans up to the highest ordinal; the names and their ordinals run
    // in table order.
    let first = win32::Win32Call::first_of(lib);
    let calls: Vec<win32::Win32Call> = (0..library.exports.len())
        .map(|i| win32::Win32Call::from_nr(first.nr() + i as u32).expect("in the table"))
        .collect();
    let count = calls.len();
    let functions_len = calls
        .iter()
        .map(|c| usize::from(c.ordinal()))
        .max()
        .unwrap_or(0);
    let dir = 0x200;
    let functions = 0x240;
    let names = functions + functions_len * 4;
    let ordinals = names + count * 4;
    let mut strings = ordinals + count * 2;
    put32(&mut img, dir + 12, strings as u32); // Name
    let dll_name = library.name.as_bytes();
    img[strings..strings + dll_name.len()].copy_from_slice(dll_name);
    strings += dll_name.len() + 1;
    put32(&mut img, dir + 16, 1); // Base
    put32(&mut img, dir + 20, functions_len as u32); // NumberOfFunctions
    put32(&mut img, dir + 24, count as u32); // NumberOfNames
    put32(&mut img, dir + 28, functions as u32);
    put32(&mut img, dir + 32, names as u32);
    put32(&mut img, dir + 36, ordinals as u32);
    for (i, call) in calls.iter().enumerate() {
        let slot = usize::from(call.ordinal()) - 1;
        put32(
            &mut img,
            functions + slot * 4,
            (MODULE_HEADER + i * STUB_LEN) as u32,
        );
        put32(&mut img, names + i * 4, strings as u32);
        put16(&mut img, ordinals + i * 2, slot as u16);
        let name = call.symbol().as_bytes();
        img[strings..strings + name.len()].copy_from_slice(name);
        strings += name.len() + 1;
    }
    assert!(
        strings <= MODULE_HEADER,
        "the export names fit in the header page"
    );
    // DataDirectory[0]: the export directory, spanning through the strings.
    put32(&mut img, opt + 112, dir as u32);
    put32(&mut img, opt + 116, (strings - dir) as u32);
    img
}

/// Bytes reserved for each stub. The instructions are shorter; a fixed stride
/// makes the address of a stub its index times this.
pub const STUB_LEN: usize = 48;
/// Where in a stub the `mov eax, <trap number>` sits: a task started here,
/// with its first argument already in `rdi`, makes the call directly.
pub const STUB_TRAP_OFFSET: usize = 24;

/// The instructions that stand in for one imported function.
///
/// Reaching past them means something jumped into the middle of a stub, so the
/// remainder traps rather than running on into the next one.
pub fn stub(call: Win32Call) -> [u8; STUB_LEN] {
    let nr = call.nr().to_le_bytes();
    let load_nr = [0xB8, nr[0], nr[1], nr[2], nr[3]];
    let mut out = [0xCC_u8; STUB_LEN];
    let mut at = 0;
    // rdi and rsi belong to the caller on Windows - it keeps its own state in
    // them across a call - and the trap wants its first two arguments in
    // exactly those registers, so they are saved around it, as ntdll's own
    // stubs save what they clobber. The two pushes move the caller's stack
    // arguments sixteen bytes further from rsp. r9 is read before rdx is
    // overwritten and r8 before it is reloaded, so no scratch register is
    // needed for the moves.
    for part in [
        &[0x57][..],                         // push rdi
        &[0x56][..],                         // push rsi
        &[0x48, 0x89, 0xCF][..],             // mov rdi, rcx
        &[0x48, 0x89, 0xD6][..],             // mov rsi, rdx
        &[0x4D, 0x89, 0xCA][..],             // mov r10, r9
        &[0x4C, 0x89, 0xC2][..],             // mov rdx, r8
        &[0x4C, 0x8B, 0x44, 0x24, 0x38][..], // mov r8, [rsp+0x38]
        &[0x4C, 0x8B, 0x4C, 0x24, 0x40][..], // mov r9, [rsp+0x40]
        &load_nr[..],                        // mov eax, <trap number>
        &[0x0F, 0x05][..],                   // syscall
        &[0x5E][..],                         // pop rsi
        &[0x5F][..],                         // pop rdi
        &[0xC3][..],                         // ret
    ] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    // A library load returns through the attach trampoline instead, so the
    // entry points of what it brought in run before the caller goes on.
    if matches!(
        call.symbol(),
        "LoadLibraryExW" | "LoadLibraryW" | "LoadLibraryA" | "LoadLibraryExA"
    ) {
        let (lib, index) = call.place();
        debug_assert_eq!(lib, 0, "the trampoline follows kernel32's stubs");
        let tail = at - 3;
        let count = win32::LIBRARIES[0].exports.len();
        let rel = ((count - index) * STUB_LEN) as i64 - (tail + 5) as i64;
        out[tail] = 0xE9;
        out[tail + 1..tail + 5].copy_from_slice(&(rel as i32).to_le_bytes());
        out[tail + 5..].fill(0xCC);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stub_moves_the_arguments_and_asks_for_its_own_number() {
        let code = stub(Win32Call::WRITE_FILE);
        // mov eax, <nr> carries the number the trap is answered by.
        let at = code
            .windows(5)
            .position(|w| w[0] == 0xB8)
            .expect("the number is loaded");
        let nr = u32::from_le_bytes(code[at + 1..at + 5].try_into().unwrap());
        assert_eq!(nr, Win32Call::WRITE_FILE.nr());
        // The number is loaded last, so the moves cannot clobber it.
        assert_eq!(&code[at + 5..at + 7], &[0x0F, 0x05], "syscall follows");
        // The caller's rdi and rsi come back before the return.
        assert_eq!(&code[..2], &[0x57, 0x56], "pushed on entry");
        assert_eq!(
            &code[at + 7..at + 10],
            &[0x5E, 0x5F, 0xC3],
            "popped, then return"
        );
        // Whatever the instructions leave unused must not run on.
        assert!(code[at + 10..].iter().all(|b| *b == 0xCC));
    }

    #[test]
    fn the_kernel32_header_exports_every_entry_at_its_stub() {
        let base = 0x1_4000_6000u64;
        let img = system_header(base, 0);
        let u32_at = |at: usize| u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        let pe = u32_at(0x3C) as usize;
        assert_eq!(&img[pe..pe + 4], b"PE\0\0");
        let opt = pe + 24;
        assert_eq!(
            u16::from_le_bytes(img[opt..opt + 2].try_into().unwrap()),
            0x20B
        );
        let dir = u32_at(opt + 112) as usize;
        let count = u32_at(dir + 24) as usize;
        assert_eq!(count, win32::LIBRARIES[0].exports.len());
        let (functions, names, ordinals) = (
            u32_at(dir + 28) as usize,
            u32_at(dir + 32) as usize,
            u32_at(dir + 36) as usize,
        );
        // WriteFile is entry 0: its name is first, its slot is 0, and its
        // address is the first stub past the header.
        let name_at = u32_at(names) as usize;
        assert_eq!(&img[name_at..name_at + 10], b"WriteFile\0");
        assert_eq!(
            u16::from_le_bytes(img[ordinals..ordinals + 2].try_into().unwrap()),
            0
        );
        assert_eq!(u32_at(functions), MODULE_HEADER as u32);
        // The last entry's stub is where the table's length says.
        assert_eq!(
            u32_at(functions + (count - 1) * 4),
            (MODULE_HEADER + (count - 1) * STUB_LEN) as u32
        );
    }

    #[test]
    fn a_library_exported_by_ordinal_places_each_stub_under_its_ordinal() {
        let lib = win32::LIBRARIES.len() - 1;
        assert_eq!(win32::LIBRARIES[lib].name, "WS2_32.dll");
        let base = 0x1_4000_0000u64;
        let img = system_header(base, lib);
        let u32_at = |at: usize| u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        let pe = u32_at(0x3C) as usize;
        let dir = u32_at(pe + 24 + 112) as usize;
        let functions = u32_at(dir + 28) as usize;
        let highest = win32::LIBRARIES[lib]
            .exports
            .iter()
            .map(|(_, ordinal)| u32::from(*ordinal))
            .max()
            .unwrap();
        assert_eq!(
            u32_at(dir + 20),
            highest,
            "the function table spans to the highest ordinal"
        );
        // WSAGetLastError is ordinal 111; its stub is at its table position.
        let at = win32::LIBRARIES[lib]
            .exports
            .iter()
            .position(|(n, _)| *n == "WSAGetLastError")
            .unwrap();
        assert_eq!(
            u32_at(functions + (111 - 1) * 4),
            (MODULE_HEADER + at * STUB_LEN) as u32
        );
        // An ordinal nothing is exported under leads nowhere: the first gap
        // below the highest.
        let used: alloc::collections::BTreeSet<u32> = win32::LIBRARIES[lib]
            .exports
            .iter()
            .map(|(_, ordinal)| u32::from(*ordinal))
            .collect();
        let hole = (1..=highest).find(|o| !used.contains(o)).unwrap();
        assert_eq!(u32_at(functions + (hole as usize - 1) * 4), 0);
    }

    #[test]
    fn the_trap_offset_lands_on_the_number_load() {
        let bytes = stub(Win32Call::WRITE_FILE);
        assert_eq!(bytes[STUB_TRAP_OFFSET], 0xB8, "mov eax, imm32");
        assert_eq!(
            &bytes[STUB_TRAP_OFFSET + 5..STUB_TRAP_OFFSET + 7],
            &[0x0F, 0x05]
        );
    }

    #[test]
    fn two_calls_get_different_numbers_and_so_different_stubs() {
        assert_ne!(stub(Win32Call::WRITE_FILE), stub(Win32Call::EXIT_PROCESS));
    }
}
