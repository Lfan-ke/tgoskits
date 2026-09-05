//! The library a Darwin program reaches the system through.
//!
//! On a real machine dyld binds a program's imports to libSystem, and
//! libSystem reaches the kernel. There is no libSystem here, so this module
//! is one: the table below is every entry point and every variable the 3.14
//! install binds, and [`Library`] lays them out as an image - a slot per
//! variable, then a stub per entry point, each stub trapping under its own
//! number. It is the Mach-O counterpart of `ax_abi_windows::thunk`, and much
//! smaller for the same job: the Darwin C ABI already passes arguments where
//! a trap wants them, so a stub only moves `rcx` aside and traps.

/// Where this layer's trap numbers begin. Darwin's own numbering puts a class
/// in bits 24..28 - 1 Mach, 2 Unix, 3 machine-dependent, 4 diagnostic - so a
/// number outside those classes can never collide with one a program raises
/// itself.
pub const DARWIN_BASE: u32 = 0x0F00_0000;

/// How much room a stub takes. The body is eleven bytes; the rest keeps every
/// stub at an address the index alone can name.
pub const STUB_LEN: usize = 16;

/// What a variable's slot is aligned and rounded to, so one slot's size never
/// decides the next one's alignment.
const SLOT_ALIGN: u64 = 16;

/// One thing the library exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub name: &'static str,
    /// Bytes the variable occupies, or zero for an entry point.
    pub len: u16,
}

const fn text(name: &'static str) -> Entry {
    Entry { name, len: 0 }
}

const fn data(name: &'static str, len: u16) -> Entry {
    Entry { name, len }
}

/// Everything the install binds, in the order the layout follows. Sorted by
/// name so a lookup is a binary search and so the list stays reviewable.
pub const TABLE: &[Entry] = &[
    text("_CCRandomGenerateBytes"),
    data("__DefaultRuneLocale", 0xd00),
    text("__NSGetEnviron"),
    text("__NSGetExecutablePath"),
    text("____chkstk_darwin"),
    text("___bzero"),
    text("___error"),
    text("___maskrune"),
    text("___memcpy_chk"),
    text("___memmove_chk"),
    text("___memset_chk"),
    text("___sincos_stret"),
    text("___sprintf_chk"),
    text("___srget"),
    text("___stack_chk_fail"),
    data("___stack_chk_guard", 0x8),
    data("___stderrp", 0x8),
    data("___stdinp", 0x8),
    data("___stdoutp", 0x8),
    text("___strcpy_chk"),
    text("___strlcat_chk"),
    text("___tolower"),
    text("___toupper"),
    text("__availability_version_check"),
    text("__exit"),
    data("__os_log_default", 0x10),
    text("__os_log_impl"),
    text("__tlv_bootstrap"),
    text("_abort"),
    text("_access"),
    text("_alarm"),
    text("_atan2"),
    text("_atexit"),
    text("_backtrace"),
    text("_btowc"),
    text("_calloc"),
    text("_chdir"),
    text("_chflags"),
    text("_chmod"),
    text("_chown"),
    text("_chroot"),
    text("_clearerr"),
    text("_clock"),
    text("_clock_getres"),
    text("_clock_gettime"),
    text("_clock_settime"),
    text("_close"),
    text("_closedir"),
    text("_confstr"),
    text("_ctermid_r"),
    text("_dispatch_once_f"),
    text("_dladdr"),
    text("_dlerror"),
    text("_dlopen"),
    text("_dlsym"),
    text("_dup2"),
    text("_endpwent"),
    data("_environ", 0x8),
    text("_err"),
    text("_execv"),
    text("_execve"),
    text("_exit"),
    text("_exp"),
    text("_faccessat"),
    text("_fchdir"),
    text("_fchmod"),
    text("_fchmodat"),
    text("_fchown"),
    text("_fchownat"),
    text("_fclose"),
    text("_fcntl"),
    text("_fcopyfile"),
    text("_fdopen$DARWIN_EXTSN"),
    text("_fdopendir$INODE64"),
    text("_feof"),
    text("_ferror"),
    text("_fflush"),
    text("_fgets"),
    text("_fileno"),
    text("_flockfile"),
    text("_fmod"),
    text("_fopen"),
    text("_fopen$DARWIN_EXTSN"),
    text("_fork"),
    text("_forkpty"),
    text("_fpathconf"),
    text("_fprintf"),
    text("_fputc"),
    text("_fputs"),
    text("_fread"),
    text("_free"),
    text("_frexp"),
    text("_fseek"),
    text("_fstat$INODE64"),
    text("_fstatat$INODE64"),
    text("_fstatfs$INODE64"),
    text("_fsync"),
    text("_ftell"),
    text("_ftruncate"),
    text("_funlockfile"),
    text("_futimens"),
    text("_fwrite"),
    text("_getc"),
    text("_getcwd"),
    text("_getegid"),
    text("_getentropy"),
    text("_getenv"),
    text("_geteuid"),
    text("_getgid"),
    text("_getgrouplist"),
    text("_getgroups$DARWIN_EXTSN"),
    text("_getitimer"),
    text("_getloadavg"),
    text("_getlogin_r"),
    text("_getpagesize"),
    text("_getpgid"),
    text("_getpgrp"),
    text("_getpid"),
    text("_getppid"),
    text("_getpriority"),
    text("_getpwent"),
    text("_getpwnam_r"),
    text("_getpwuid_r"),
    text("_getrlimit"),
    text("_getrusage"),
    text("_getsid"),
    text("_getuid"),
    text("_gmtime_r"),
    text("_grantpt"),
    text("_hypot"),
    text("_initgroups"),
    text("_ioctl"),
    text("_isatty"),
    text("_kill"),
    text("_killpg"),
    text("_lchflags"),
    text("_lchmod"),
    text("_lchown"),
    text("_ldexp"),
    text("_linkat"),
    text("_localeconv"),
    text("_localtime_r"),
    text("_lockf"),
    text("_log"),
    text("_login_tty"),
    text("_lseek"),
    text("_lstat$INODE64"),
    text("_mach_absolute_time"),
    data("_mach_task_self_", 0x4),
    text("_mach_timebase_info"),
    text("_mach_vm_read_overwrite"),
    text("_mach_vm_region"),
    text("_mach_vm_write"),
    text("_madvise"),
    text("_malloc"),
    text("_mbrtowc"),
    text("_mbstowcs"),
    text("_memchr"),
    text("_memcmp"),
    text("_memcpy"),
    text("_memmove"),
    text("_memset"),
    text("_memset_pattern16"),
    text("_mkdir"),
    text("_mkdirat"),
    text("_mkfifo"),
    text("_mkfifoat"),
    text("_mknod"),
    text("_mknodat"),
    text("_mktime"),
    text("_mmap"),
    text("_modf"),
    text("_mprotect"),
    text("_munmap"),
    text("_nanosleep"),
    text("_nice"),
    text("_nl_langinfo"),
    text("_open"),
    text("_openat"),
    text("_opendir$INODE64"),
    text("_openpty"),
    text("_os_log_type_enabled"),
    text("_pathconf"),
    text("_pause"),
    text("_perror"),
    text("_pipe"),
    text("_posix_openpt"),
    text("_posix_spawn"),
    text("_posix_spawn_file_actions_addclose"),
    text("_posix_spawn_file_actions_adddup2"),
    text("_posix_spawn_file_actions_addopen"),
    text("_posix_spawn_file_actions_destroy"),
    text("_posix_spawn_file_actions_init"),
    text("_posix_spawnattr_destroy"),
    text("_posix_spawnattr_init"),
    text("_posix_spawnattr_setbinpref_np"),
    text("_posix_spawnattr_setflags"),
    text("_posix_spawnattr_setpgroup"),
    text("_posix_spawnattr_setsigdefault"),
    text("_posix_spawnattr_setsigmask"),
    text("_posix_spawnp"),
    text("_pow"),
    text("_pread"),
    text("_preadv"),
    text("_printf"),
    text("_proc_regionfilename"),
    text("_pthread_attr_destroy"),
    text("_pthread_attr_init"),
    text("_pthread_attr_setscope"),
    text("_pthread_attr_setstacksize"),
    text("_pthread_cond_destroy"),
    text("_pthread_cond_init"),
    text("_pthread_cond_signal"),
    text("_pthread_cond_timedwait"),
    text("_pthread_cond_timedwait_relative_np"),
    text("_pthread_cond_wait"),
    text("_pthread_create"),
    text("_pthread_detach"),
    text("_pthread_exit"),
    text("_pthread_get_stackaddr_np"),
    text("_pthread_get_stacksize_np"),
    text("_pthread_getname_np"),
    text("_pthread_getspecific"),
    text("_pthread_join"),
    text("_pthread_key_create"),
    text("_pthread_key_delete"),
    text("_pthread_kill"),
    text("_pthread_mutex_destroy"),
    text("_pthread_mutex_init"),
    text("_pthread_mutex_lock"),
    text("_pthread_mutex_trylock"),
    text("_pthread_mutex_unlock"),
    text("_pthread_self"),
    text("_pthread_setname_np"),
    text("_pthread_setspecific"),
    text("_pthread_sigmask"),
    text("_pthread_threadid_np"),
    text("_ptsname_r"),
    text("_putchar"),
    text("_puts"),
    text("_pwrite"),
    text("_pwritev"),
    text("_raise"),
    text("_read"),
    text("_readdir$INODE64"),
    text("_readlink"),
    text("_readlinkat"),
    text("_readv"),
    text("_realloc"),
    text("_realpath$DARWIN_EXTSN"),
    text("_rename"),
    text("_renameat"),
    text("_rewind"),
    text("_rewinddir$INODE64"),
    text("_rmdir"),
    text("_sched_get_priority_max"),
    text("_sched_get_priority_min"),
    text("_sched_yield"),
    text("_sendfile"),
    text("_setegid"),
    text("_setenv"),
    text("_seteuid"),
    text("_setgid"),
    text("_setgroups"),
    text("_setitimer"),
    text("_setlocale"),
    text("_setpgid"),
    text("_setpgrp"),
    text("_setpriority"),
    text("_setpwent"),
    text("_setregid"),
    text("_setreuid"),
    text("_setrlimit"),
    text("_setsid"),
    text("_setuid"),
    text("_setvbuf"),
    text("_sigaction"),
    text("_sigaltstack"),
    text("_sigpending"),
    text("_sigwait"),
    text("_snprintf"),
    text("_sprintf"),
    text("_sscanf"),
    text("_stat$INODE64"),
    text("_statfs$INODE64"),
    text("_strchr"),
    text("_strcmp"),
    text("_strcpy"),
    text("_strcspn"),
    text("_strdup"),
    text("_strerror"),
    text("_strftime"),
    text("_strlen"),
    text("_strncmp"),
    text("_strncpy"),
    text("_strpbrk"),
    text("_strrchr"),
    text("_strsignal"),
    text("_strstr"),
    text("_strtol"),
    text("_strtoul"),
    text("_symlink"),
    text("_symlinkat"),
    text("_sync"),
    text("_sysconf"),
    text("_sysctlbyname"),
    text("_system"),
    text("_task_for_pid"),
    text("_task_info"),
    text("_task_threads"),
    text("_tcgetpgrp"),
    text("_tcsetpgrp"),
    text("_time"),
    text("_times"),
    text("_truncate"),
    text("_ttyname_r"),
    text("_tzset"),
    text("_umask"),
    text("_uname"),
    text("_ungetc"),
    text("_unlink"),
    text("_unlinkat"),
    text("_unlockpt"),
    text("_unsetenv"),
    text("_utimensat"),
    text("_vfprintf"),
    text("_vsnprintf"),
    text("_wait"),
    text("_wait3"),
    text("_wait4"),
    text("_waitid"),
    text("_waitpid"),
    text("_wcschr"),
    text("_wcscmp"),
    text("_wcscoll"),
    text("_wcscpy"),
    text("_wcsftime"),
    text("_wcslen"),
    text("_wcsncmp"),
    text("_wcsncpy"),
    text("_wcsrchr"),
    text("_wcstok"),
    text("_wcstol"),
    text("_wcstombs"),
    text("_wcsxfrm"),
    text("_wmemchr"),
    text("_wmemcmp"),
    text("_write"),
    text("_writev"),
];

/// A call this layer serves: a position in [`TABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarwinCall(u32);

impl DarwinCall {
    /// The call a trap number names, or `None` for a number outside this layer.
    pub fn from_nr(nr: u32) -> Option<DarwinCall> {
        let index = nr.checked_sub(DARWIN_BASE)?;
        (index < TABLE.len() as u32).then_some(DarwinCall(index))
    }

    /// The trap number a stub for this call raises.
    pub const fn nr(self) -> u32 {
        DARWIN_BASE + self.0
    }

    /// What the call is named, as an image's bind stream spells it.
    pub const fn name(self) -> &'static str {
        TABLE[self.0 as usize].name
    }
}

/// The synthesized libSystem, placed at `base`.
///
/// Variables come first, in one writable run, because they are what the
/// program's own code stores through; the stubs follow on their own page,
/// executable and never written. Both are laid out from the table alone, so
/// an address is a function of the entry's position and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Library {
    pub base: u64,
}

impl Library {
    pub const fn new(base: u64) -> Library {
        Library { base }
    }

    /// Where the stubs begin, relative to `base`.
    pub fn code_off(&self) -> u64 {
        page_up(vars_len())
    }

    /// How much address space the whole library takes.
    pub fn extent(&self) -> u64 {
        self.code_off() + page_up((stubs() * STUB_LEN) as u64)
    }

    /// Where `symbol` is, or `None` if this library does not have it.
    pub fn address(&self, symbol: &str) -> Option<u64> {
        let at = TABLE.binary_search_by_key(&symbol, |e| e.name).ok()?;
        Some(self.base + place(at))
    }

    /// The call `symbol` names, or `None` for a variable or an unknown name.
    pub fn call(symbol: &str) -> Option<DarwinCall> {
        let at = TABLE.binary_search_by_key(&symbol, |e| e.name).ok()?;
        (TABLE[at].len == 0).then_some(DarwinCall(at as u32))
    }

    /// The variables' page, zeroed: what the program stores through, and what
    /// the kernel fills in for the handful of them that start with a value.
    pub fn vars(&self) -> alloc::vec::Vec<u8> {
        alloc::vec![0u8; self.code_off() as usize]
    }

    /// The stubs, in table order, so an entry's address is its index.
    pub fn code(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![0xCC_u8; page_up((stubs() * STUB_LEN) as u64) as usize];
        let mut at = 0;
        for (index, entry) in TABLE.iter().enumerate() {
            if entry.len != 0 {
                continue;
            }
            out[at..at + STUB_LEN].copy_from_slice(&stub(DarwinCall(index as u32)));
            at += STUB_LEN;
        }
        out
    }
}

/// One stub: the Darwin C ABI hands arguments over in the registers a trap
/// reads, except that `syscall` destroys `rcx`, so the fourth argument moves
/// to `r10` first - which is what every libSystem stub does too.
pub fn stub(call: DarwinCall) -> [u8; STUB_LEN] {
    let nr = call.nr().to_le_bytes();
    let mut out = [0xCC_u8; STUB_LEN];
    let mut at = 0;
    for part in [
        &[0x49, 0x89, 0xCA][..],                 // mov r10, rcx
        &[0xB8, nr[0], nr[1], nr[2], nr[3]][..], // mov eax, <trap number>
        &[0x0F, 0x05][..],                       // syscall
        &[0xC3][..],                             // ret
    ] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    out
}

/// Where the entry at `index` lands, relative to the library's base.
fn place(index: usize) -> u64 {
    if TABLE[index].len != 0 {
        return TABLE[..index]
            .iter()
            .filter(|e| e.len != 0)
            .map(|e| slot(e.len))
            .sum();
    }
    let before = TABLE[..index].iter().filter(|e| e.len == 0).count();
    page_up(vars_len()) + (before * STUB_LEN) as u64
}

/// How much room the variables take together.
fn vars_len() -> u64 {
    TABLE
        .iter()
        .filter(|e| e.len != 0)
        .map(|e| slot(e.len))
        .sum()
}

/// How many entry points there are, which is how many stubs a process gets.
fn stubs() -> usize {
    TABLE.iter().filter(|e| e.len == 0).count()
}

/// A variable's slot, rounded so the next one starts aligned.
fn slot(len: u16) -> u64 {
    (len as u64).div_ceil(SLOT_ALIGN) * SLOT_ALIGN
}

fn page_up(at: u64) -> u64 {
    at.div_ceil(crate::PAGE) * crate::PAGE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_has_no_repeats() {
        for pair in TABLE.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} then {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn a_variable_gets_a_slot_and_an_entry_point_gets_a_stub() {
        let lib = Library::new(0x2_0000);
        let stderr = lib.address("___stderrp").expect("a variable is exported");
        let write = lib.address("_write").expect("an entry point is exported");
        assert!(stderr < lib.base + lib.code_off(), "{stderr:#x} is a slot");
        assert!(write >= lib.base + lib.code_off(), "{write:#x} is a stub");
        assert_eq!(
            write % STUB_LEN as u64,
            0,
            "a stub starts where its index says"
        );
        assert!(write < lib.base + lib.extent());
    }

    #[test]
    fn no_two_entries_share_an_address() {
        let lib = Library::new(0);
        let mut seen: alloc::vec::Vec<u64> = TABLE
            .iter()
            .map(|e| lib.address(e.name).expect("the table exports itself"))
            .collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before);
    }

    #[test]
    fn a_stub_asks_for_its_own_number_and_the_number_names_it_back() {
        let call = Library::call("_write").expect("_write is an entry point");
        let code = stub(call);
        let at = code
            .iter()
            .position(|b| *b == 0xB8)
            .expect("the number is loaded");
        let nr = u32::from_le_bytes(code[at + 1..at + 5].try_into().unwrap());
        assert_eq!(nr, call.nr());
        assert_eq!(DarwinCall::from_nr(nr), Some(call));
        assert_eq!(DarwinCall::from_nr(nr).unwrap().name(), "_write");
        // rcx moves to r10 before the trap, because syscall destroys it.
        assert_eq!(&code[..3], &[0x49, 0x89, 0xCA]);
    }

    #[test]
    fn a_variable_is_not_a_call() {
        assert!(Library::call("___stderrp").is_none());
        assert!(Library::call("_no_such_symbol").is_none());
        assert!(Library::new(0).address("_no_such_symbol").is_none());
    }

    #[test]
    fn the_stubs_hold_one_body_per_entry_point() {
        let lib = Library::new(0x1000);
        let code = lib.code();
        let write = lib.address("_write").unwrap() - lib.base - lib.code_off();
        let call = Library::call("_write").unwrap();
        assert_eq!(
            &code[write as usize..write as usize + STUB_LEN],
            &stub(call)
        );
    }
}
