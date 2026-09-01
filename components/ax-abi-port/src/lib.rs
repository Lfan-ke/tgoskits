//! Capability ports for ArceOS ABI personalities.
//!
//! A personality (`ax-abi-linux` and its siblings) implements a foreign syscall
//! ABI without depending on `axtask`/`axfs`/`axmm`: it reaches the machine and
//! the OS only through the traits here. A hosting OS implements them once, over
//! whatever it already has, and every personality runs on that one contract -
//! rather than each domain inventing its own host interface for the same files,
//! memory and tasks.
//!
//! Two layers, mirroring gVisor's split of a swappable `Platform` from the
//! Sentry's service subsystems:
//!
//! - [`Platform`] - the minimal arch/memory primitives (copy user memory).
//! - [`Tasks`]/[`Files`]/[`Mem`]/[`Signals`]/[`Clock`]/[`Random`]/[`System`]/
//!   [`Creds`] - the OS services a syscall implementation drives.
//!
//! The ports carry primitives, not syscalls: a domain implements each syscall's
//! semantics, flags and errno itself (the zero-passthrough rule), copies user
//! memory through [`Platform`], and never forwards a call to the host. That
//! keeps every domain unit-testable against mock ports.
//!
//! [`Host`] bundles the ports, and [`CurrentHost`] is the global binding the
//! kernel provides so a trap path can reach them without threading a parameter.

#![no_std]

use ax_crate_interface::def_interface;
#[cfg(feature = "mm")]
use bitflags::bitflags;

/// A syscall outcome: `Ok(return value)` or `Err(positive errno)`. A domain
/// encodes it into the trap frame its ABI's way (`-errno` for Linux).
pub type SysResult = Result<isize, i32>;

pub use ax_io::SeekFrom;

/// `ENOSYS` - no handler for this call (yet).
pub const ENOSYS: i32 = 38;
/// `EFAULT` - a user pointer was not accessible.
pub const EFAULT: i32 = 14;
/// `EINVAL` - an argument was invalid.
pub const EINVAL: i32 = 22;
/// `EBADF` - not an open descriptor.
pub const EBADF: i32 = 9;
/// `ESRCH` - no such process.
pub const ESRCH: i32 = 3;

/// No such file or directory.
pub const ENOENT: i32 = 2;
/// `ESPIPE` - the descriptor does not admit positional io.
pub const ESPIPE: i32 = 29;
/// `EOPNOTSUPP` - the operation is not one this build carries out.
pub const EOPNOTSUPP: i32 = 95;
/// `EINTR` - a signal cut the call short.
pub const EINTR: i32 = 4;
/// `EPERM` - the operation is not permitted.
pub const EPERM: i32 = 1;
/// `EIO` - the device failed.
pub const EIO: i32 = 5;
/// `ENXIO` - no such device or address.
pub const ENXIO: i32 = 6;
/// `EAGAIN` - the resource is busy; try again.
pub const EAGAIN: i32 = 11;
/// `ENOMEM` - out of memory.
pub const ENOMEM: i32 = 12;
/// `EACCES` - permission denied.
pub const EACCES: i32 = 13;
/// `EBUSY` - the device or resource is busy.
pub const EBUSY: i32 = 16;
/// `EEXIST` - the file exists.
pub const EEXIST: i32 = 17;
/// `ENOTDIR` - a component of the path is not a directory.
pub const ENOTDIR: i32 = 20;
/// `EISDIR` - the name is a directory.
pub const EISDIR: i32 = 21;
/// `ENFILE` - the system has too many open files.
pub const ENFILE: i32 = 23;
/// `EMFILE` - the process has too many open files.
pub const EMFILE: i32 = 24;
/// `ENOTTY` - not a terminal, or an inappropriate control request.
pub const ENOTTY: i32 = 25;
/// `ENOSPC` - no space left on the device.
pub const ENOSPC: i32 = 28;
/// `EROFS` - the filesystem is read-only.
pub const EROFS: i32 = 30;
/// `EPIPE` - the other end of the pipe is gone.
pub const EPIPE: i32 = 32;
/// `ENOTEMPTY` - the directory is not empty.
pub const ENOTEMPTY: i32 = 39;
/// `ELOOP` - too many symbolic links were followed.
pub const ELOOP: i32 = 40;
/// `ETIME` - the operation timed out.
pub const ETIME: i32 = 62;
/// `ECONNRESET` - the connection was reset by the peer.
pub const ECONNRESET: i32 = 104;

/// The minimal arch/memory platform, à la gVisor's `Platform`: move bytes across
/// the user/kernel boundary. Everything a personality needs from the CPU/MMU
/// that is not a higher-level service goes here.
pub trait Platform: Sync {
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult;
    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult;

    /// Read a NUL-terminated byte string starting at `uaddr` into `out`, and
    /// report its length without the terminator.
    ///
    /// Reading `out.len()` bytes outright would fault on a string that ends
    /// near the end of a mapping, and how far it is safe to read is something
    /// only the host knows. What the bytes mean stays with the ABI: this
    /// reports them as they are, with no encoding assumed.
    ///
    /// # Errors
    ///
    /// Reports the host's fault error for an unreadable address, and its
    /// name-too-long error for a string that does not end within `out`.
    fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> SysResult;

    /// Record `message` wherever the host keeps its diagnostics. A domain
    /// says here what it could not do for a program - an entry point it binds
    /// but does not serve, a request it refused - so the reason a program
    /// failed is on record and not only in its own error code. A host with
    /// nowhere to put it drops it.
    fn trace(&self, _message: &str) {}
}

#[cfg(feature = "task")]
pub trait Tasks: Sync {
    /// The caller's process id. A host whose namespace cannot see the caller
    /// says so, so the port reports a result rather than a bare number.
    ///
    /// The identity is the host's and there is one of it, however many ABIs
    /// are linked in: the host creates processes, schedules them and reaps
    /// them, so it is the host that names them. An ABI presents that name the
    /// way its programs expect to read it - the same division as descriptors,
    /// which Windows presents as handles. A second allocator per ABI would be
    /// the thing that made two processes share a name.
    fn getpid(&self) -> SysResult;
    /// The parent's process id, or the host's error when there is no parent
    /// it can name.
    fn getppid(&self) -> SysResult;
    /// The caller's thread id, which always exists.
    fn gettid(&self) -> u32;
    fn set_tid_address(&self, tidptr: usize) -> SysResult;
    fn sched_yield(&self) -> SysResult;
    /// Terminate the calling thread. A host whose exit path returns - marking
    /// the thread and letting the trap return handle it - reports that outcome
    /// here rather than diverging.
    fn exit(&self, code: i32) -> SysResult;
    /// Terminate every thread in the process.
    fn exit_group(&self, code: i32) -> SysResult;
}

/// What a program says it will do with a range, so the host can act on it.
///
/// The numbers each ABI uses for these disagree - Darwin's `MADV_FREE` is 5
/// where Linux's is 8 - so the advice crosses the port as what it means rather
/// than as the number one of them writes it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// No expectation; undo any earlier advice.
    Normal,
    /// Access will be random, so reading ahead is wasted.
    Random,
    /// Access will be sequential, so reading ahead pays.
    Sequential,
    /// The range will be needed soon.
    WillNeed,
    /// The range is not needed; a later read may see zeroes or the file again.
    DontNeed,
    /// The range's contents may be discarded, and the pages reclaimed.
    Free,
    /// Punch the range out of whatever backs it, so a later read sees zeroes.
    /// Only a shared file-backed range can be removed this way.
    Remove,
    /// Advice the host has no action for, which is not an error to give.
    Ignored,
}

/// Where a name that is not absolute starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// The process's working directory.
    Cwd,
    /// An open directory.
    Dir(i32),
}

/// Whether a name that is not there may be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Create {
    /// Fail if it is not there.
    Never,
    /// Make it if it is not there.
    IfAbsent,
    /// Make it, and fail if it is already there.
    Exclusive,
}

/// What opening a name should do.
///
/// Each ABI spells these differently - Linux and Darwin in `O_*` bits that do
/// not agree on their values, Windows in an access mask and a disposition - so
/// the request crosses the port as what it asks for rather than as one ABI's
/// spelling of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenHow {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Writes go to the end.
    pub append: bool,
    /// Existing contents are dropped.
    pub truncate: bool,
    /// Whether a missing name may be made.
    pub create: Create,
    /// The name has to be a directory.
    pub directory: bool,
    /// Follow a symbolic link in the last component.
    pub follow: bool,
    /// The descriptor does not survive into a new image.
    pub close_on_exec: bool,
    /// Permissions for a name this call makes.
    pub mode: u32,
}

/// What a file is, as every ABI has to describe it in its own layout.
///
/// Neutral because the three lay the same facts out differently - a Linux
/// `struct stat`, an NT `FILE_BASIC_INFORMATION`, a Darwin `struct stat` whose
/// fields are in another order - while agreeing on what the facts are. The
/// times are since the epoch, which is the one origin all three count from.
#[cfg(feature = "paths")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    /// What kind of node this is.
    pub kind: NodeKind,
    /// Permission bits, in the octal form all three ultimately carry.
    pub mode: u32,
    /// Size in bytes.
    pub size: u64,
    /// Filesystem block size for I/O.
    pub block_size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// The filesystem this node lives on.
    pub device: u64,
    /// The device this node *is*, for a character or block special.
    pub rdev: u64,
    /// Inode number, or whatever serves as one.
    pub inode: u64,
    /// How many names refer to it.
    pub links: u64,
    /// Owning user and group.
    pub uid: u32,
    /// Owning group.
    pub gid: u32,
    /// Last access, since the epoch.
    pub accessed_ns: u64,
    /// Last modification, since the epoch.
    pub modified_ns: u64,
    /// Last status change, since the epoch.
    pub changed_ns: u64,
}

/// The ways a caller may want to reach a name.
///
/// All false asks only whether the name is there, which is what Linux spells
/// `F_OK`. Each ABI decodes its own bits into this; the host never sees them.
#[cfg(feature = "paths")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Access {
    /// May read its contents.
    pub read: bool,
    /// May change its contents.
    pub write: bool,
    /// May execute it, or search it when it is a directory.
    pub execute: bool,
}

/// What kind of thing a name refers to.
///
/// The set every ABI distinguishes; one that does not care about a distinction
/// simply does not look at it.
#[cfg(feature = "paths")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// An ordinary file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A named pipe.
    Fifo,
    /// A socket.
    Socket,
}

/// Reaching a file by name.
///
/// The name is the ABI's: it decodes it from user memory in whatever encoding
/// its programs write it in, and applies its own rules about which
/// combinations of request mean anything. What the host does is resolve the
/// name and install the result as a descriptor.
#[cfg(feature = "paths")]
pub trait Paths: Sync {
    /// Open `path`, relative to `at` when it is not absolute, and report the
    /// descriptor it was installed at.
    fn open(&self, at: At, path: &str, how: &OpenHow) -> SysResult;

    /// Describe what `path` refers to, without opening it.
    ///
    /// An interpreter asks this of every candidate path as it resolves an
    /// import, far more often than it opens anything, which is why it is here
    /// rather than left to open-then-describe.
    ///
    /// When `follow` is false a symbolic link describes itself rather than
    /// what it points at.
    fn attributes(&self, at: At, path: &str, follow: bool) -> Result<Attributes, i32>;

    /// Describe what an open descriptor refers to.
    fn attributes_of(&self, fd: i32) -> Result<Attributes, i32>;

    /// Whether the caller may reach `path` in the ways `wants` names.
    ///
    /// The decision is the host's, not the ABI's: it turns on mount flags, the
    /// caller's whole credential set including supplementary groups, and any
    /// capability that overrides the ordinary permission bits - none of which
    /// shows up in [`Attributes`], so a domain that answered this from the mode
    /// word alone would be a shallower check than the one it replaced.
    ///
    /// `real_ids` asks for the decision against the real user and group rather
    /// than the effective ones, which is what a set-user-ID program means when
    /// it asks whether the user who invoked it may reach a name.
    fn permitted(
        &self,
        at: At,
        path: &str,
        wants: Access,
        follow: bool,
        real_ids: bool,
    ) -> Result<(), i32>;

    /// The same question about an open descriptor.
    fn permitted_of(&self, fd: i32, wants: Access, real_ids: bool) -> Result<(), i32>;
}

/// One run of user memory. An ABI decodes its own vector layout and names the
/// runs it found this way, so the host never learns what an `iovec` looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Where the run starts in user memory.
    pub uaddr: usize,
    /// How many bytes it covers.
    pub len: usize,
}

/// File-descriptor service.
///
/// Bulk transfers name a user range rather than a kernel buffer, and each does
/// exactly one underlying read or write. That is what a pipe, socket or tty
/// needs: a second underlying read would block where the call should have
/// returned, and a bounce buffer would cap the result into a short transfer the
/// kernel would not have produced. The domain still owns the call: it decodes
/// and validates the arguments and maps the errno; the host owns moving the
/// bytes, since only it can touch user memory and the file layer together.
#[cfg(feature = "fs")]
pub trait Files: Sync {
    /// Read from `fd` into the user range at `uaddr`, returning the count read.
    fn read(&self, fd: i32, uaddr: usize, len: usize) -> SysResult;
    /// Write the user range at `uaddr` to `fd`, returning the count written.
    fn write(&self, fd: i32, uaddr: usize, len: usize) -> SysResult;
    fn close(&self, fd: i32) -> SysResult;
    fn dup(&self, fd: i32) -> SysResult;
    fn seek(&self, fd: i32, to: SeekFrom) -> SysResult;
    /// Report whether `fd` is open, without touching it.
    fn validate(&self, fd: i32) -> SysResult;
    /// Read from `fd` into `segs` in order, in one underlying transfer.
    fn readv(&self, fd: i32, segs: &[Segment]) -> SysResult;
    /// Write `segs` in order to `fd`, in one underlying transfer.
    fn writev(&self, fd: i32, segs: &[Segment]) -> SysResult;
    /// Read from `fd` at absolute `offset` into `segs`, in one transfer.
    fn preadv(&self, fd: i32, segs: &[Segment], offset: u64) -> SysResult;
    /// Write `segs` to `fd` at absolute `offset`, in one transfer.
    fn pwritev(&self, fd: i32, segs: &[Segment], offset: u64) -> SysResult;
    /// Whether `fd` can be read or written at an absolute offset. Which
    /// descriptors can is the host's property, and so is the error it reports
    /// for the ones that cannot; an ABI asks before it validates an offset,
    /// because that is the order the check falls in.
    fn seekable(&self, fd: i32) -> SysResult;
    /// Read from `fd` at absolute `offset` into the user range at `uaddr`,
    /// leaving the file position unchanged.
    fn pread(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult;
    /// Write the user range at `uaddr` to `fd` at absolute `offset`, leaving the
    /// file position unchanged.
    fn pwrite(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult;
    /// Duplicate `oldfd` onto `newfd`, closing what `newfd` held, and return
    /// `newfd`. The two are never equal here: what that means is the ABI's call,
    /// so a domain settles it before asking.
    fn dup_onto(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult;
    /// Flush `fd` to backing storage. `datasync` may skip metadata not needed
    /// for data integrity.
    fn fsync(&self, fd: i32, datasync: bool) -> SysResult;
    /// Set the size of `fd` to `len`, zero-extending on growth.
    fn ftruncate(&self, fd: i32, len: u64) -> SysResult;
}

#[cfg(feature = "mm")]
bitflags! {
    /// How a mapping may be used. The three access bits are common to every ABI;
    /// the growth hints say a region is a stack that extends one way, which some
    /// hosts track and others ignore.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Prot: u32 {
        /// Readable.
        const READ = 1 << 0;
        /// Writable.
        const WRITE = 1 << 1;
        /// Executable.
        const EXEC = 1 << 2;
        /// Grows toward lower addresses.
        const GROWS_DOWN = 1 << 3;
        /// Grows toward higher addresses.
        const GROWS_UP = 1 << 4;
    }
}

/// Where a new mapping's contents come from.
#[cfg(feature = "mm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSource {
    /// Zero-filled pages.
    Anonymous,
    /// A file, from `offset`.
    File {
        /// The descriptor to map.
        fd: i32,
        /// Where in the file the mapping starts.
        offset: usize,
    },
}

/// A request to place a new mapping.
#[cfg(feature = "mm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapRequest {
    /// Where to place it; zero asks the host to choose.
    pub addr: usize,
    /// How much to map.
    pub len: usize,
    /// What the mapping allows.
    pub prot: Prot,
    /// Place it exactly at `addr`, replacing whatever is there.
    pub fixed: bool,
    /// Writes are visible to others mapping the same object.
    pub shared: bool,
    /// What backs it.
    pub source: MapSource,
}

#[cfg(feature = "mm")]
pub trait Mem: Sync {
    /// Where the program break sits now.
    fn brk(&self) -> usize;
    /// Move the program break to `addr`, mapping or unmapping to match. Fails
    /// when the host will not place it there; what a caller reports for that is
    /// the ABI's business.
    fn set_brk(&self, addr: usize) -> SysResult;
    /// Place a mapping, returning the address it went to.
    fn map(&self, req: &MapRequest) -> SysResult;
    /// Unmap `[addr, addr+len)`. The length is rounded up to whole pages here,
    /// since the page size is the host's to know.
    fn unmap(&self, addr: usize, len: usize) -> SysResult;
    /// Change what `[addr, addr+len)` allows.
    fn protect(&self, addr: usize, len: usize, prot: Prot) -> SysResult;
    /// Advise usage of `[addr, addr+len)`. The host validates `advice`, since
    /// which hints it honours is its own property, as is page alignment.
    /// Apply `advice` to `[addr, addr+len)`. The caller has already checked the
    /// advice is one its ABI defines; whether this host acts on it is its own
    /// business.
    fn advise(&self, addr: usize, len: usize, advice: Advice) -> SysResult;
    /// Write back the file-backed parts of `[addr, addr+len)`.
    fn writeback(&self, addr: usize, len: usize) -> SysResult;
}

/// A source of randomness. Fills a kernel buffer; a domain copies it to user
/// memory. Every modern libc draws from it at startup.
#[cfg(feature = "random")]
pub trait Random: Sync {
    /// Fill `len` bytes of user memory at `uaddr` with entropy, returning how
    /// many arrived. `blocking` asks for the source that waits for entropy
    /// over the one that never does.
    fn fill(&self, uaddr: usize, len: usize, blocking: bool) -> SysResult;
}

/// Signal delivery and the blocked-signal mask. A domain moves the user
/// `sigset_t` itself; this port carries the mask as a `u64`.
/// Who a signal is aimed at, once an ABI has read its own encoding of that.
#[cfg(feature = "signal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalTarget {
    /// One process.
    Process(u32),
    /// Every process in the caller's group.
    CallerGroup,
    /// Every process the caller may signal.
    All,
    /// Every process in one group.
    Group(u32),
}

#[cfg(feature = "signal")]
pub trait Signals: Sync {
    /// Send `signo` to `target`. A zero `signo` only checks that the target
    /// exists and may be signalled.
    fn kill(&self, target: SignalTarget, signo: u32) -> SysResult;
    /// Send `signo` to thread `tid` of thread-group `tgid`.
    fn tgkill(&self, tgid: u32, tid: u32, signo: u32) -> SysResult;
    /// Send `signo` to the thread `tid`, named without its group.
    fn tkill(&self, tid: u32, signo: u32) -> SysResult;
    /// Apply `new` to the blocked-signal mask per `how` (`SIG_BLOCK`/`UNBLOCK`/
    /// `SETMASK`, already validated), returning the previous mask. `None` queries.
    fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32>;
}

/// How a sleep ended. A sleep cut short says how far it got, because an ABI
/// that hands the caller the time remaining has to work that out itself.
#[cfg(feature = "time")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slept {
    /// The whole requested span elapsed.
    Full,
    /// Something interrupted it after `elapsed_ns`.
    Short { errno: i32, elapsed_ns: u64 },
}

/// Clocks and sleeping, in nanoseconds. A domain packs the `timespec`/`timeval`
/// structs itself; this port only supplies the raw counters.
#[cfg(feature = "time")]
pub trait Clock: Sync {
    fn monotonic_ns(&self) -> u64;
    fn wall_ns(&self) -> u64;
    /// Sleep for `ns`, reporting whether it ran out or was cut short.
    fn sleep_ns(&self, ns: u64) -> Slept;
}

/// One field of the system identity a `uname`-style call reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "system")]
pub enum UtsField {
    SysName,
    NodeName,
    Release,
    Version,
    Machine,
    DomainName,
}

#[cfg(feature = "system")]
pub trait System: Sync {
    /// Report the system identity, calling `put` once per [`UtsField`].
    ///
    /// Push rather than return, because a hosting OS keeps these fields behind a
    /// lock and can then report a consistent snapshot without allocating or
    /// lending out a borrow. A domain lays the values into its own ABI struct,
    /// so the wire format stays out of this port.
    fn uname(&self, put: &mut dyn FnMut(UtsField, &str));
}

/// Process credentials. Each getter returns the `(real, effective, saved)`
/// triple; a domain projects the single ids it needs from it.
#[cfg(feature = "creds")]
pub trait Creds: Sync {
    fn uids(&self) -> (u32, u32, u32);
    fn gids(&self) -> (u32, u32, u32);
}

/// The capabilities a hosting OS registers for the personalities it runs.
///
/// Only [`platform`](Host::platform) is required - moving bytes across the user
/// boundary is what every ABI needs before anything else. The rest are optional
/// and default to absent, so a host registers the capabilities it actually has:
/// plug in a filesystem and the file-related syscalls of whichever personality
/// is loaded light up; leave it out and a domain simply does not offer them, and
/// the trap falls back to whatever the host does with an unclaimed call.
///
/// That is the same composition the rest of the system uses - a capability is a
/// part you fit, not a slot you must fill.
pub trait Host: Sync {
    fn platform(&self) -> &dyn Platform;
    #[cfg(feature = "task")]
    fn tasks(&self) -> Option<&dyn Tasks> {
        None
    }
    #[cfg(feature = "fs")]
    fn files(&self) -> Option<&dyn Files> {
        None
    }
    #[cfg(feature = "mm")]
    fn mem(&self) -> Option<&dyn Mem> {
        None
    }
    #[cfg(feature = "signal")]
    fn signals(&self) -> Option<&dyn Signals> {
        None
    }
    #[cfg(feature = "time")]
    fn clock(&self) -> Option<&dyn Clock> {
        None
    }
    #[cfg(feature = "random")]
    fn random(&self) -> Option<&dyn Random> {
        None
    }
    #[cfg(feature = "system")]
    fn system(&self) -> Option<&dyn System> {
        None
    }
    /// The name-resolution port, when the host has one.
    #[cfg(feature = "paths")]
    fn paths(&self) -> Option<&dyn Paths> {
        None
    }
    #[cfg(feature = "creds")]
    fn creds(&self) -> Option<&dyn Creds> {
        None
    }
}

/// The global binding a hosting OS provides so a trap path can reach the
/// registered [`Host`] without a parameter - ArceOS's own way to invert the
/// dependency (the kernel `#[impl_interface]`s this, a domain `call_interface!`s
/// it), which keeps this layer free of a hand-rolled registry.
#[def_interface]
pub trait CurrentHost {
    fn current() -> &'static dyn Host;
}
