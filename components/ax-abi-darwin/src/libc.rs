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

use crate::{
    bsd::nr,
    system::{DarwinCall, Library},
};

/// `ENOSYS`, which is what an entry point that is bound but not written yet
/// answers with.
const ENOSYS: i32 = 78;

/// `ENAMETOOLONG`, which is what `_NSGetExecutablePath` reports for a buffer
/// that could not hold the answer.
const ENAMETOOLONG: i32 = 63;

/// The wait status of a program that aborted: killed by signal six, with no
/// exit code of its own.
const SIGABRT: i32 = 6;

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
    // The library's own address, which the thread block carries because a
    // trap arrives with nothing else that could name it.
    let mut base = [0u8; 8];
    let tsd = env.thread_pointer();
    if tsd == 0
        || host
            .platform()
            .read_user(tsd + crate::start::TSD_LIBRARY as usize, &mut base)
            .is_err()
    {
        return Dispatch::Passthrough;
    }
    let library = Library::new(u64::from_le_bytes(base));
    let outcome = route(host, library, call, &a).unwrap_or_else(|| {
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

/// The entry points that are a system call and nothing else. libSystem's own
/// are the same shape - a few instructions that move the arguments and trap -
/// so what they do is what the BSD half already does.
const CALLS: &[(&str, usize)] = &[
    ("__exit", nr::EXIT),
    ("_access", nr::ACCESS),
    ("_close", nr::CLOSE),
    ("_dup2", nr::DUP2),
    ("_faccessat", nr::FACCESSAT),
    ("_fstat$INODE64", nr::FSTAT64),
    ("_fsync", nr::FSYNC),
    ("_ftruncate", nr::FTRUNCATE),
    ("_getegid", nr::GETEGID),
    ("_geteuid", nr::GETEUID),
    ("_getgid", nr::GETGID),
    ("_getpid", nr::GETPID),
    ("_getppid", nr::GETPPID),
    ("_getuid", nr::GETUID),
    ("_lseek", nr::LSEEK),
    ("_lstat$INODE64", nr::LSTAT64),
    ("_madvise", nr::MADVISE),
    ("_mmap", nr::MMAP),
    ("_mprotect", nr::MPROTECT),
    ("_munmap", nr::MUNMAP),
    ("_open", nr::OPEN),
    ("_openat", nr::OPENAT),
    ("_pread", nr::PREAD),
    ("_pwrite", nr::PWRITE),
    ("_read", nr::READ),
    ("_readv", nr::READV),
    ("_stat$INODE64", nr::STAT64),
    ("_write", nr::WRITE),
    ("_writev", nr::WRITEV),
];

/// What one call does, or `None` for one this layer does not serve yet.
///
/// `library` is where the synthesized library was placed, which the entries
/// that keep state - the allocator - need to find their own words.
fn route(host: &dyn Host, library: Library, call: DarwinCall, a: &[usize; 6]) -> Option<SysResult> {
    let name = call.name();
    if let Ok(at) = CALLS.binary_search_by_key(&name, |entry| entry.0) {
        return crate::bsd::route(host, CALLS[at].1, a);
    }
    Some(match name {
        // `exit(3)`. Flushing what stdio holds belongs here once there is
        // stdio to flush; until then it is the same as leaving.
        "_exit" => host.tasks()?.exit_group((a[0] as i32) << 8),
        "_dup" => host.files()?.dup(a[0] as i32),
        // The allocator: the code is here, but every byte it hands out and
        // every word it remembers is the program's own.
        "_malloc" => crate::heap::malloc(host, &library, a[0]),
        "_calloc" => crate::heap::calloc(host, &library, a[0], a[1]),
        "_realloc" => crate::heap::realloc(host, &library, a[0], a[1]),
        "_free" => crate::heap::free(host, &library, a[0]),
        // Where `environ` itself is, which is what a program asks for when it
        // wants to replace the whole environment rather than read it.
        "__NSGetEnviron" => Ok(library.address("_environ")? as isize),
        "__NSGetExecutablePath" => exec_path(host, &library, a[0], a[1]),
        "_getenv" => getenv(host, &library, a[0]),
        // The stream family. Nothing is buffered, so `fflush` has nothing to
        // do and `setvbuf` has nothing to change.
        "_fwrite" => crate::stdio::fwrite(host, a),
        "_fread" => crate::stdio::fread(host, a),
        "_fputs" => crate::stdio::fputs(host, a),
        "_puts" => crate::stdio::puts(host, &library, a),
        "_fputc" => crate::stdio::fputc(host, a),
        // `putchar` is `fputc` with the stream already decided.
        "_putchar" => {
            let out = crate::stdio::standard(&library, 1) as usize;
            crate::stdio::fputc(host, &[a[0], out, 0, 0, 0, 0])
        }
        "_fileno" => crate::stdio::fileno(host, a[0]),
        "_feof" => crate::stdio::status(host, a[0], 1),
        "_ferror" => crate::stdio::status(host, a[0], 2),
        "_clearerr" => crate::stdio::clearerr(host, a[0]),
        "_fclose" => crate::stdio::fclose(host, a[0]),
        "_fopen" | "_fopen$DARWIN_EXTSN" => crate::stdio::fopen(host, &library, a[0], a[1]),
        "_fdopen$DARWIN_EXTSN" => crate::stdio::fdopen(host, &library, a[0] as i32),
        "_fflush" | "_setvbuf" | "_flockfile" | "_funlockfile" => Ok(0),
        // Both of these end the program on purpose and neither returns. The
        // status is the one a shell reports for a process killed by SIGABRT,
        // which is what a real abort turns into.
        "_abort" | "___stack_chk_fail" => {
            host.platform()
                .trace(&alloc::format!("{name} ended the program"));
            host.tasks()?.exit_group(SIGABRT)
        }
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

    /// Where the thread block goes in the mock's memory, and where the
    /// library it names goes. Every call arrives on a thread, and the ones
    /// that keep state find the library through it.
    const TSD: usize = 0x100;
    const LIBRARY: u64 = 0x8000;

    /// A trap on a thread whose block names a library, with room in the
    /// mock's memory for both.
    fn call(name: &str, host: &MockHost, args: [usize; 6]) -> Trap {
        let mut mem = host.mem.borrow_mut();
        if mem.len() < 0x1_0000 {
            mem.resize(0x1_0000, 0);
        }
        let at = TSD + crate::start::TSD_LIBRARY as usize;
        mem[at..at + 8].copy_from_slice(&LIBRARY.to_le_bytes());
        drop(mem);
        Trap::at(nr(name), args).on_thread(TSD)
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
        let mut env = call("_write", &host, [1, 0x200, 12, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.answer(), (Some(12), Some(false)));
        assert_eq!(*host.wrote.borrow(), Some((1, 0x200, 12)));
    }

    #[test]
    fn a_failing_call_reports_the_errno_and_raises_the_carry_flag() {
        let host = MockHost::default();
        let mut env = call("_write", &host, [-1i32 as usize, 0x200, 4, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(
            env.answer(),
            (Some(9), Some(true)),
            "EBADF, not its negation"
        );
    }

    #[test]
    fn the_calls_that_are_only_a_system_call_reach_the_bsd_half() {
        let host = MockHost::default();
        let mut env = call("_close", &host, [7, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(*host.closed.borrow(), Some(7));
    }

    #[test]
    fn the_delegated_table_is_sorted_so_the_search_finds_them() {
        for pair in CALLS.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} then {}", pair[0].0, pair[1].0);
        }
        for (name, _) in CALLS {
            assert!(Library::call(name).is_some(), "{name} is an entry point");
        }
    }

    #[test]
    fn the_program_can_ask_where_environ_is_and_where_it_was_run_from() {
        let host = MockHost::default();
        let library = Library::new(LIBRARY);
        // The path the loader left, and the string it points at.
        let path = b"/bin/prog\0";
        {
            let mut mem = host.mem.borrow_mut();
            mem.resize(0x1_0000, 0);
            mem[0x300..0x300 + path.len()].copy_from_slice(path);
            let at = (library.private() + crate::system::PRIVATE_EXEC_PATH) as usize;
            mem[at..at + 8].copy_from_slice(&0x300u64.to_le_bytes());
        }

        let mut environ = call("__NSGetEnviron", &host, [0; 6]);
        assert_eq!(dispatch(&mut environ, &host), Dispatch::Handled);
        assert_eq!(
            environ.result.map(|at| at as u64),
            library.address("_environ"),
            "it answers with where the variable is, not what is in it"
        );

        // A buffer that fits gets the path and a terminator.
        host.mem.borrow_mut()[0x400..0x404].copy_from_slice(&64u32.to_le_bytes());
        let mut got = call("__NSGetExecutablePath", &host, [0x500, 0x400, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut got, &host), Dispatch::Handled);
        assert_eq!(got.answer(), (Some(0), Some(false)));
        assert_eq!(&host.mem.borrow()[0x500..0x50A], path);

        // Too small a buffer is answered with how much room it needs.
        host.mem.borrow_mut()[0x400..0x404].copy_from_slice(&4u32.to_le_bytes());
        let mut small = call("__NSGetExecutablePath", &host, [0x600, 0x400, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut small, &host), Dispatch::Handled);
        assert_eq!(small.failed, Some(true));
        let asked = u32::from_le_bytes(host.mem.borrow()[0x400..0x404].try_into().unwrap());
        assert_eq!(
            asked,
            path.len() as u32,
            "the whole path and its terminator"
        );
    }

    #[test]
    fn getenv_answers_with_where_the_value_is_in_the_environment() {
        let host = MockHost::default();
        let library = Library::new(LIBRARY);
        // An environment of two entries, and the array that names them.
        {
            let mut mem = host.mem.borrow_mut();
            mem.resize(0x1_0000, 0);
            mem[0x300..0x30A].copy_from_slice(b"PATH=/bin\0");
            mem[0x320..0x32B].copy_from_slice(b"PATHEXT=.x\0");
            mem[0x200..0x208].copy_from_slice(&0x300u64.to_le_bytes());
            mem[0x208..0x210].copy_from_slice(&0x320u64.to_le_bytes());
            mem[0x210..0x218].copy_from_slice(&0u64.to_le_bytes());
            let at = library.address("_environ").unwrap() as usize;
            mem[at..at + 8].copy_from_slice(&0x200u64.to_le_bytes());
            mem[0x100..0x105].copy_from_slice(b"PATH\0");
            mem[0x110..0x115].copy_from_slice(b"NOPE\0");
        }
        let mut found = call("_getenv", &host, [0x100, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut found, &host), Dispatch::Handled);
        assert_eq!(
            found.result,
            Some(0x300 + 5),
            "it points into the entry, past the separator"
        );

        // A name that only prefixes an entry is not that entry.
        let mut missing = call("_getenv", &host, [0x110, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut missing, &host), Dispatch::Handled);
        assert_eq!(
            missing.answer(),
            (Some(0), Some(false)),
            "not there is null"
        );
    }

    #[test]
    fn abort_ends_the_program_rather_than_returning_to_it() {
        let host = MockHost::default();
        let mut env = call("_abort", &host, [0; 6]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(*host.ended.borrow(), Some(SIGABRT));
        let mut guard = call("___stack_chk_fail", &host, [0; 6]);
        assert_eq!(dispatch(&mut guard, &host), Dispatch::Handled);
        assert_eq!(*host.ended.borrow(), Some(SIGABRT));
    }

    #[test]
    fn an_entry_point_with_no_body_yet_says_so_rather_than_answer() {
        let host = MockHost::default();
        let mut env = call("_fprintf", &host, [0; 6]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.answer(), (Some(ENOSYS as usize), Some(true)));
    }
}

/// `_NSGetExecutablePath(buf, &size)`: the path the program was run by, copied
/// out. Too small a buffer is not a failure to answer - the call says how much
/// room it needs, which is what a caller is expected to loop on.
fn exec_path(host: &dyn Host, library: &Library, buf: usize, size_at: usize) -> SysResult {
    let mut word = [0u8; 8];
    host.platform().read_user(
        (library.private() + crate::system::PRIVATE_EXEC_PATH) as usize,
        &mut word,
    )?;
    let at = u64::from_le_bytes(word) as usize;
    let mut path = [0u8; 1024];
    let len = host.platform().read_user_cstr(at, &mut path)? as usize;
    let mut room = [0u8; 4];
    host.platform().read_user(size_at, &mut room)?;
    let room = u32::from_le_bytes(room) as usize;
    if room < len + 1 {
        host.platform()
            .write_user(size_at, &(len as u32 + 1).to_le_bytes())?;
        return Err(ENAMETOOLONG);
    }
    host.platform().write_user(buf, &path[..len + 1])?;
    Ok(0)
}

/// How many entries of `environ` a walk reads before it decides the array has
/// no end, which is what a corrupted one looks like.
const ENVIRON_LIMIT: usize = 4096;

/// `getenv(name)`: where the value is inside `environ`'s own string, or null.
/// The answer points into the environment rather than at a copy, which is what
/// C promises and what lets a caller compare pointers.
fn getenv(host: &dyn Host, library: &Library, name_at: usize) -> SysResult {
    let mut name = [0u8; 256];
    let len = host.platform().read_user_cstr(name_at, &mut name)? as usize;
    if len == 0 {
        return Ok(0);
    }
    let mut word = [0u8; 8];
    host.platform().read_user(
        library.address("_environ").ok_or(ENOSYS)? as usize,
        &mut word,
    )?;
    let mut array = u64::from_le_bytes(word) as usize;
    for _ in 0..ENVIRON_LIMIT {
        host.platform().read_user(array, &mut word)?;
        let entry = u64::from_le_bytes(word) as usize;
        if entry == 0 {
            return Ok(0);
        }
        let mut line = [0u8; 1024];
        let put = host.platform().read_user_cstr(entry, &mut line)? as usize;
        // The name has to match in full and be followed by the separator, so
        // that asking for PATH does not answer with PATHEXT.
        if put > len && line[..len] == name[..len] && line[len] == b'=' {
            return Ok((entry + len + 1) as isize);
        }
        array += 8;
    }
    Ok(0)
}
