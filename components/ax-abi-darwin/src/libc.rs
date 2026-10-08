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

/// What a call arrives with besides its number: the six argument registers,
/// the stack pointer, which is where a variadic call keeps the rest, and the
/// thread's block.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    pub a: [usize; 6],
    pub sp: usize,
    pub tsd: usize,
}

/// The entry points that answer with a pointer, whose failure is therefore a
/// null one with `errno` set rather than -1.
const NULL_ON_FAILURE: &[&str] = &[
    "_calloc",
    "_dlopen",
    "_dlsym",
    "_fdopen$DARWIN_EXTSN",
    "_fdopendir$INODE64",
    "_fgets",
    "_fopen",
    "_fopen$DARWIN_EXTSN",
    "_getcwd",
    "_gmtime_r",
    "_localtime_r",
    "_malloc",
    "_opendir$INODE64",
    "_readdir$INODE64",
    "_realloc",
    "_realpath$DARWIN_EXTSN",
    "_setlocale",
    "_strdup",
    "_strerror",
    "_strstr",
];

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
    let frame = Frame {
        a,
        sp: env.stack_pointer(),
        tsd,
    };
    let outcome = route(host, library, call, &frame).unwrap_or_else(|| {
        host.platform()
            .trace(&alloc::format!("{} is not implemented", call.name()));
        Err(ENOSYS)
    });
    match outcome {
        Ok(value) => {
            env.set_error(false);
            env.set_result(value as usize);
        }
        Err(errno) if NULL_ON_FAILURE.contains(&call.name()) => {
            let _ = host
                .platform()
                .write_user(tsd + crate::start::TSD_ERRNO as usize, &errno.to_le_bytes());
            env.set_error(false);
            env.set_result(0);
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
    ("_msync", nr::MSYNC),
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
fn route(host: &dyn Host, library: Library, call: DarwinCall, f: &Frame) -> Option<SysResult> {
    let name = call.name();
    let a = &f.a;
    let errno = f.tsd + crate::start::TSD_ERRNO as usize;
    if let Ok(at) = CALLS.binary_search_by_key(&name, |entry| entry.0) {
        return crate::bsd::route(host, CALLS[at].1, a);
    }
    Some(match name {
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
        "_sysconf" => sysconf(host, a[0]),
        "_setenv" => crate::environ::set(host, &library, a),
        "_unsetenv" => crate::environ::unset(host, &library, a[0]),
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
        "_CCRandomGenerateBytes" => crate::node::random(host, a[0], a[1]),
        "_getentropy" => crate::node::getentropy(host, a[0], a[1]),
        "_clock_gettime" => crate::clock::gettime(host, a[0], a[1]),
        "_clock_getres" => crate::clock::getres(host, a[0], a[1]),
        "_mach_absolute_time" => crate::clock::absolute(host),
        "_mach_timebase_info" => crate::clock::timebase(host, a[0]),
        "_time" => crate::clock::time(host, a[0]),
        "_nanosleep" => crate::clock::nanosleep(host, a[0], a[1]),
        "_gmtime_r" | "_localtime_r" => crate::clock::gmtime(host, &library, a[0], a[1]),
        "_mktime" => crate::clock::mktime(host, &library, a[0]),
        // There is one zone, so there is nothing to read.
        "_tzset" => Ok(0),
        "_pthread_mutex_init" => crate::thread::mutex_init(host, a[0], a[1]),
        "_pthread_mutex_lock" => crate::thread::mutex_lock(host, a[0], false),
        "_pthread_mutex_trylock" => crate::thread::mutex_lock(host, a[0], true),
        "_pthread_mutex_unlock" => crate::thread::mutex_unlock(host, a[0]),
        // With one thread there is nothing to tear down, nobody to wake, and
        // no second stack for an attribute to size.
        "_pthread_mutex_destroy"
        | "_pthread_cond_init"
        | "_pthread_cond_destroy"
        | "_pthread_cond_signal"
        | "_pthread_attr_init"
        | "_pthread_attr_destroy"
        | "_pthread_attr_setstacksize"
        | "_pthread_attr_setscope"
        | "_pthread_setname_np"
        | "_pthread_key_delete" => Ok(0),
        "_pthread_cond_wait" => crate::thread::cond_wait(host),
        "_pthread_cond_timedwait" => crate::thread::cond_timedwait(host, a[2]),
        "_pthread_cond_timedwait_relative_np" => crate::thread::cond_timedwait_relative(host, a[2]),
        "_pthread_key_create" => crate::thread::key_create(host, &library, a[0]),
        "_pthread_getspecific" => crate::thread::getspecific(host, f, a[0]),
        "_pthread_setspecific" => crate::thread::setspecific(host, f, a[0], a[1]),
        "_pthread_get_stackaddr_np" => crate::thread::stack_top(host, a[0]),
        "_pthread_get_stacksize_np" => crate::thread::stack_len(host, a[0]),
        "_pthread_threadid_np" => crate::thread::thread_id(host, a[1]),
        "_pthread_sigmask" => crate::thread::sigmask(host, f, a[0], a[1], a[2]),
        "_pthread_create" => crate::thread::create(host),
        "_sched_yield" => host.tasks()?.sched_yield(),
        "_sigaction" => crate::node::sigaction(host, &library, a[0], a[1], a[2]),
        "_fcntl" => crate::node::fcntl(host, a[0] as i32, a[1], a[2]),
        "_ioctl" => crate::node::ioctl(host, a[0] as i32, a[1]),
        "_isatty" => crate::node::isatty(host, errno, a[0] as i32),
        "_opendir$INODE64" => crate::node::opendir(host, &library, a[0]),
        "_fdopendir$INODE64" => crate::node::fdopendir(host, &library, a[0] as i32),
        "_readdir$INODE64" => crate::node::readdir(host, a[0]),
        "_rewinddir$INODE64" => crate::node::rewinddir(host, a[0]),
        "_closedir" => crate::node::closedir(host, &library, a[0]),
        "_getcwd" => crate::node::getcwd(host, &library, a[0], a[1]),
        "_realpath$DARWIN_EXTSN" => crate::node::realpath(host, &library, a[0], a[1]),
        "_readlink" => crate::node::readlink(host, a[0], a[1], a[2]),
        "_pthread_getname_np" => crate::thread::name(host, a[1], a[2]),
        "_uname" => crate::node::uname(host, a[0]),
        "__availability_version_check" => crate::node::available(host, a[0], a[1]),
        "_strtol" => crate::text::strtol(host, errno, a, false),
        "_strtoul" => crate::text::strtol(host, errno, a, true),
        "_wcstol" => crate::text::wcstol(host, errno, a),
        "_strstr" => crate::text::strstr(host, a[0], a[1]),
        "_strdup" => crate::text::strdup(host, &library, a[0]),
        "___strlcat_chk" => crate::text::strlcat(host, a[0], a[1], a[2]),
        "_wcsncpy" => crate::text::wcsncpy(host, a[0], a[1], a[2]),
        "_strerror" => crate::text::strerror(host, &library, a[0]),
        "_setlocale" => crate::text::setlocale(host, &library, a[1]),
        "_nl_langinfo" => crate::text::nl_langinfo(&library, a[0]),
        "_mbstowcs" => crate::text::mbstowcs(host, a[0], a[1], a[2]),
        "_wcstombs" => crate::text::wcstombs(host, a[0], a[1], a[2]),
        "_mbrtowc" => crate::text::mbrtowc(host, a[0], a[1], a[2]),
        "_snprintf" => crate::fmt::snprintf(host, f),
        "_sprintf" => crate::fmt::sprintf(host, f),
        "___sprintf_chk" => crate::fmt::sprintf_chk(host, f),
        "_vsnprintf" => crate::fmt::vsnprintf(host, f),
        "_fprintf" => crate::fmt::fprintf(host, &library, f),
        "_vfprintf" => crate::fmt::vfprintf(host, &library, f),
        "_printf" => crate::fmt::printf(host, &library, f),
        "_fgets" => crate::stdio::fgets(host, a[0], a[1], a[2]),
        "_getc" | "___srget" => crate::stdio::getc(host, a[0]),
        "_ungetc" => crate::stdio::ungetc(host, a[0], a[1]),
        "_fseek" => crate::stdio::fseek(host, a[0], a[1] as isize, a[2]),
        "_ftell" => crate::stdio::ftell(host, a[0]),
        "_rewind" => crate::stdio::fseek(host, a[0], 0, 0),
        "_dlopen" => crate::dl::dlopen(host, &library, a[0]),
        "_dlsym" => crate::dl::dlsym(host, &library, a[0], a[1]),
        "_dlerror" => crate::dl::dlerror(host, &library),
        "_dladdr" => crate::dl::dladdr(host, &library, a[0], a[1]),
        "_atexit" => crate::node::atexit(host, &library, a[0]),
        "_unlink" => crate::node::unlink(host, a[0], false),
        "_rmdir" => crate::node::unlink(host, a[0], true),
        "_rename" => crate::node::rename(host, a[0], a[1]),
        "_mkdir" => crate::node::mkdir(host, a[0], a[1] as u32),
        "_dirfd" => crate::node::dirfd(host, a[0]),
        "_gettimeofday" => crate::clock::gettimeofday(host, a[0]),
        "_strtoll" => crate::text::strtol(host, errno, a, false),
        "___strcat_chk" => crate::text::strcat(host, a[0], a[1], usize::MAX),
        "___strncat_chk" => crate::text::strcat(host, a[0], a[1], a[2]),
        // An `fd_set` holds 1024 descriptors, and this says whether one fits.
        "___darwin_check_fd_set_overflow" => Ok(isize::from(a[0] < 1024)),
        "_crc32" => crc32(host, a[0] as u32, a[1], a[2]),
        _ => return crate::math::route(host, name, a),
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
    fn sysconf_answers_the_page_size_and_leaves_the_rest_indeterminate() {
        let host = MockHost::default();
        let mut page = call("_sysconf", &host, [29, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut page, &host), Dispatch::Handled);
        assert_eq!(page.answer(), (Some(4096), Some(false)));

        // Not an error - "indeterminate" is an answer C already asks callers
        // to handle, and it does not claim the name is unknown.
        let mut other = call("_sysconf", &host, [58, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut other, &host), Dispatch::Handled);
        assert_eq!(other.answer(), (Some(-1i32 as usize), Some(false)));
    }

    #[test]
    fn crc32_matches_the_check_value_and_continues_across_calls() {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1000, 0);
        host.mem.borrow_mut()[0x100..0x109].copy_from_slice(b"123456789");
        assert_eq!(crc32(&host, 0, 0x100, 9), Ok(0xCBF4_3926));
        let first = crc32(&host, 0, 0x100, 4).unwrap() as u32;
        assert_eq!(crc32(&host, first, 0x104, 5), Ok(0xCBF4_3926));
        assert_eq!(crc32(&host, 7, 0, 9), Ok(0), "a null buffer starts over");
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
        let mut env = call("_forkpty", &host, [0; 6]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.answer(), (Some(ENOSYS as usize), Some(true)));
    }
}

/// zlib's `crc32(crc, buf, len)`. libz is one of the libraries a Darwin system
/// provides, and this is the one entry of it the shipped modules bind. A null
/// buffer asks for the starting value.
fn crc32(host: &dyn Host, crc: u32, buf: usize, len: usize) -> SysResult {
    if buf == 0 {
        return Ok(0);
    }
    let mut crc = !crc;
    let mut done = 0;
    while done < len {
        let step = (len - done).min(4096);
        for byte in crate::user::bytes(host, buf + done, step)? {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
            }
        }
        done += step;
    }
    Ok(!crc as isize)
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

/// The `_SC_*` names this layer can answer, from Darwin's `<unistd.h>`.
mod sc {
    pub const CLK_TCK: usize = 3;
    pub const PAGESIZE: usize = 29;
}

/// `sysconf(name)`.
///
/// A name this layer has no answer for is answered with -1 and no errno,
/// which C spells "indeterminate" and every caller already has to handle -
/// rather than with `EINVAL`, which would say the name is not a name. The
/// host's log names it, so the list of what is still unanswered is the log.
fn sysconf(host: &dyn Host, name: usize) -> SysResult {
    match name {
        // The page size is this personality's own, not something to ask about.
        sc::PAGESIZE => Ok(crate::PAGE as isize),
        // What `times` counts in, which on Darwin is hundredths of a second.
        sc::CLK_TCK => Ok(100),
        _ => {
            host.platform()
                .trace(&alloc::format!("sysconf({name}) has no answer here"));
            Ok(-1)
        }
    }
}
