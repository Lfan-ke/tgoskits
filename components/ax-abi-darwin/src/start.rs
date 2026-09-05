//! The initial stack and the code that runs before `main`.
//!
//! A Darwin program's entry point is `main` itself: `LC_MAIN` names it, and
//! dyld calls it with the four arguments the kernel left on the stack, then
//! calls `exit` with what it returns. Everything between - running each
//! image's `__mod_init_func` pointers, in load order - is dyld's too. There
//! is no dyld here, so this module writes that sequence out as code, with
//! every address already known and no lookup left to do at run time.
//!
//! The stack itself is the kernel's half of the same contract: `argc`, then
//! `argv`, `envp` and `apple`, each a run of pointers ending in a null, then
//! the strings they point at. `apple` is where Darwin puts what a program
//! cannot work out for itself, starting with the path it was run from, which
//! is what `_NSGetExecutablePath` answers with.

use alloc::{format, string::String, vec::Vec};

/// What `apple[0]` is named. dyld puts the program's resolved path here and
/// `_NSGetExecutablePath` reads it back.
const EXECUTABLE_PATH: &str = "executable_path=";

/// Where a thread keeps the address of its own block, so code that has `gs`
/// can get the address rather than only the contents. Darwin's own thread
/// block starts with the same self pointer, and so do Windows' TEB and
/// Linux's TCB, for the same reason: `gs` names a base, not a value.
pub const TSD_SELF: u64 = 0;

/// Where the thread's `errno` is. Darwin reaches it through `__error()`, and
/// nothing outside this package knows the offset, so the layout is this
/// package's to choose - but the stub that stores it and the entry point that
/// hands out its address must agree, which is what [`crate::system`] asserts.
pub const TSD_ERRNO: u64 = 8;

/// Where the thread keeps the address of the synthesized library. A trap
/// arrives with nothing but its number and its arguments, so the entries that
/// have state of their own - the allocator - find it from here.
pub const TSD_LIBRARY: u64 = 16;

/// How big the block is. Only three words are spoken for; the rest is room
/// for what the pthread family will need.
pub const TSD_LEN: u64 = 64;

/// The block a thread reaches through `gs`, placed at `at`, for a process
/// whose synthesized library is at `library`.
pub fn tsd(at: u64, library: u64) -> Vec<u8> {
    let mut out = alloc::vec![0u8; TSD_LEN as usize];
    for (off, value) in [(TSD_SELF, at), (TSD_LIBRARY, library)] {
        out[off as usize..off as usize + 8].copy_from_slice(&value.to_le_bytes());
    }
    out
}

/// A laid-out initial stack: where the pointer runs are, and the bytes to
/// write at [`sp`](Stack::sp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub sp: u64,
    pub argc: u64,
    pub argv: u64,
    pub envp: u64,
    pub apple: u64,
    pub bytes: Vec<u8>,
}

/// Lay out the stack a Darwin process starts on, ending at `top`.
pub fn stack(top: u64, path: &str, args: &[&str], envs: &[&str]) -> Stack {
    let apple = [format!("{EXECUTABLE_PATH}{path}")];
    let strings: Vec<&str> = args
        .iter()
        .copied()
        .chain(envs.iter().copied())
        .chain(apple.iter().map(String::as_str))
        .collect();
    // One word for argc, one per string, and one null ending each of the
    // three runs.
    let words = 1 + strings.len() + 3;
    let text: usize = strings.iter().map(|s| s.len() + 1).sum();
    let len = (words * 8 + text).div_ceil(16) * 16;
    let sp = top - len as u64;

    let mut bytes = alloc::vec![0u8; len];
    bytes[..8].copy_from_slice(&(args.len() as u64).to_le_bytes());
    // The runs are written in order and the strings appended as each pointer
    // is filled in, so a pointer is always the address of the string just put
    // down.
    let mut word = 8;
    let mut text_at = words * 8;
    let run = |bytes: &mut [u8], word: &mut usize, text_at: &mut usize, of: &[&str]| {
        let at = sp + *word as u64;
        for string in of {
            let put = sp + *text_at as u64;
            bytes[*word..*word + 8].copy_from_slice(&put.to_le_bytes());
            bytes[*text_at..*text_at + string.len()].copy_from_slice(string.as_bytes());
            *word += 8;
            *text_at += string.len() + 1;
        }
        // The null that ends the run.
        *word += 8;
        at
    };
    let argv = run(&mut bytes, &mut word, &mut text_at, args);
    let envp = run(&mut bytes, &mut word, &mut text_at, envs);
    let apple: Vec<&str> = apple.iter().map(String::as_str).collect();
    let apple = run(&mut bytes, &mut word, &mut text_at, &apple);

    Stack {
        sp,
        argc: args.len() as u64,
        argv,
        envp,
        apple,
        bytes,
    }
}

/// What the process starts on: the initializers, then `main`, then `exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The program's `LC_MAIN` entry point.
    pub main: u64,
    /// Where `exit` is, which is what a returning `main` becomes.
    pub exit: u64,
}

/// Build the code the process begins at.
///
/// `inits` are the initializer pointers of every image, in the order dyld
/// would call them: the libraries a program needs before the program itself.
pub fn code(entry: Entry, inits: &[u64], stack: &Stack) -> Vec<u8> {
    let mut out = Vec::new();
    // The kernel leaves the stack where its own layout put it; the ABI wants
    // it aligned at the call, and a call pushes eight bytes over it.
    out.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
    for target in inits.iter().chain(core::iter::once(&entry.main)) {
        for (register, value) in [
            (0xBF, stack.argc),  // rdi
            (0xBE, stack.argv),  // rsi
            (0xBA, stack.envp),  // rdx
            (0xB9, stack.apple), // rcx
        ] {
            out.extend_from_slice(&[0x48, register]);
            out.extend_from_slice(&value.to_le_bytes());
        }
        // An initializer's fifth argument is dyld's own `ProgramVars`, which
        // nothing built in the last two decades reads; it is passed as null
        // rather than left holding whatever the last call did.
        out.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d
        out.extend_from_slice(&[0x48, 0xB8]); // movabs rax, <target>
        out.extend_from_slice(&target.to_le_bytes());
        out.extend_from_slice(&[0xFF, 0xD0]); // call rax
    }
    // What `main` returned is what the process exits with.
    out.extend_from_slice(&[0x89, 0xC7]); // mov edi, eax
    out.extend_from_slice(&[0x48, 0xB8]); // movabs rax, <exit>
    out.extend_from_slice(&entry.exit.to_le_bytes());
    out.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(stack: &Stack, at: u64) -> u64 {
        let off = (at - stack.sp) as usize;
        u64::from_le_bytes(stack.bytes[off..off + 8].try_into().unwrap())
    }

    fn string(stack: &Stack, at: u64) -> &str {
        let off = (at - stack.sp) as usize;
        let rest = &stack.bytes[off..];
        let len = rest.iter().position(|b| *b == 0).unwrap();
        core::str::from_utf8(&rest[..len]).unwrap()
    }

    #[test]
    fn lays_the_runs_out_the_way_the_kernel_does() {
        let s = stack(
            0x7FFF_0000,
            "/bin/prog",
            &["/bin/prog", "-c", "x"],
            &["A=1"],
        );
        assert_eq!(s.sp % 16, 0);
        assert_eq!(s.sp + s.bytes.len() as u64, 0x7FFF_0000);
        assert_eq!(word(&s, s.sp), 3, "argc leads the stack");
        assert_eq!(s.argv, s.sp + 8, "argv follows argc");
        assert_eq!(string(&s, word(&s, s.argv)), "/bin/prog");
        assert_eq!(string(&s, word(&s, s.argv + 16)), "x");
        assert_eq!(word(&s, s.argv + 24), 0, "a null ends argv");
        assert_eq!(s.envp, s.argv + 32);
        assert_eq!(string(&s, word(&s, s.envp)), "A=1");
        assert_eq!(word(&s, s.envp + 8), 0, "a null ends envp");
        assert_eq!(s.apple, s.envp + 16);
        assert_eq!(string(&s, word(&s, s.apple)), "executable_path=/bin/prog");
        assert_eq!(word(&s, s.apple + 8), 0, "a null ends apple");
    }

    #[test]
    fn a_program_with_no_arguments_still_gets_three_runs() {
        let s = stack(0x7FFF_0000, "/bin/prog", &[], &[]);
        assert_eq!(word(&s, s.sp), 0);
        assert_eq!(word(&s, s.argv), 0);
        assert_eq!(word(&s, s.envp), 0);
        assert_eq!(string(&s, word(&s, s.apple)), "executable_path=/bin/prog");
    }

    #[test]
    fn calls_every_initializer_before_main_and_exits_with_what_it_returns() {
        let s = stack(0x7FFF_0000, "/bin/prog", &["/bin/prog"], &[]);
        let entry = Entry {
            main: 0x1_0000_1234,
            exit: 0x2_0000_5678,
        };
        let out = code(entry, &[0x3_0000_1111, 0x3_0000_2222], &s);
        // Every target the code holds, in the order it calls them.
        let targets: Vec<u64> = out
            .windows(12)
            .filter(|w| w[0] == 0x48 && w[1] == 0xB8)
            .map(|w| u64::from_le_bytes(w[2..10].try_into().unwrap()))
            .collect();
        assert_eq!(
            targets,
            [0x3_0000_1111, 0x3_0000_2222, entry.main, entry.exit]
        );
        assert_eq!(&out[..4], &[0x48, 0x83, 0xE4, 0xF0], "the stack is aligned");
        assert_eq!(&out[out.len() - 2..], &[0xFF, 0xE0], "exit is jumped to");
        // Each call is handed the same four the kernel left on the stack.
        let argcs = out
            .windows(10)
            .filter(|w| w[0] == 0x48 && w[1] == 0xBF)
            .count();
        assert_eq!(argcs, 3, "two initializers and main");
    }
}
