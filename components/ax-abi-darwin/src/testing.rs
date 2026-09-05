//! The host the tests run a domain against.
//!
//! One trap frame and one host, shared by every module's tests, so a check
//! written for one layer reads the same as a check written for another and a
//! new layer does not bring a fourth mock with it.

use alloc::{string::String, vec::Vec};
use core::cell::RefCell;

use ax_abi_port::{
    Advice, At, Attributes, Creds, Files, Host, MapRequest, Mem, OpenHow, Paths, Platform, Prot,
    SysResult, Tasks,
};
use ax_dispatch::TrapEnv;

/// `EFAULT` and `EBADF`, the two the host itself reports.
const EFAULT: i32 = 14;
const EBADF: i32 = 9;

#[derive(Default)]
pub struct Trap {
    pub nr: usize,
    pub args: [usize; 6],
    pub result: Option<usize>,
    pub failed: Option<bool>,
}
impl Trap {
    /// A trap that arrived under `nr`.
    pub fn at(nr: usize, args: [usize; 6]) -> Self {
        Self {
            nr,
            args,
            result: None,
            failed: None,
        }
    }

    /// What the domain answered with, and whether it called it a failure.
    pub fn answer(&self) -> (Option<usize>, Option<bool>) {
        (self.result, self.failed)
    }
}

impl TrapEnv for Trap {
    fn nr(&self) -> usize {
        self.nr
    }
    fn arg(&self, i: usize) -> usize {
        self.args[i]
    }
    fn set_result(&mut self, value: usize) {
        self.result = Some(value);
    }
    fn set_error(&mut self, failed: bool) {
        self.failed = Some(failed);
    }
}

#[derive(Default)]
pub struct MockHost {
    pub wrote: RefCell<Option<(i32, usize, usize)>>,
    pub closed: RefCell<Option<i32>>,
    pub mapped: RefCell<Option<MapRequest>>,
    pub advised: RefCell<Option<Advice>>,
    /// User memory, as one flat buffer starting at address zero.
    pub mem: RefCell<Vec<u8>>,
    pub opened: RefCell<Option<(At, String, OpenHow)>>,
    pub asked: RefCell<Option<(String, bool)>>,
    pub describes: Option<Attributes>,
}
// Single-threaded tests; the ports ask for Sync on a real host.
unsafe impl Sync for MockHost {}

impl Platform for MockHost {
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
        let mem = self.mem.borrow();
        let end = uaddr + out.len();
        if end > mem.len() {
            return Err(EFAULT);
        }
        out.copy_from_slice(&mem[uaddr..end]);
        Ok(0)
    }
    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult {
        let mut mem = self.mem.borrow_mut();
        let end = uaddr + data.len();
        if end > mem.len() {
            return Err(EFAULT);
        }
        mem[uaddr..end].copy_from_slice(data);
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
impl Files for MockHost {
    fn read(&self, _fd: i32, _u: usize, len: usize) -> SysResult {
        Ok(len as isize)
    }
    fn write(&self, fd: i32, uaddr: usize, len: usize) -> SysResult {
        if fd < 0 {
            return Err(EBADF);
        }
        *self.wrote.borrow_mut() = Some((fd, uaddr, len));
        Ok(len as isize)
    }
    fn close(&self, fd: i32) -> SysResult {
        *self.closed.borrow_mut() = Some(fd);
        Ok(0)
    }
    fn dup(&self, _fd: i32) -> SysResult {
        Ok(5)
    }
    fn seek(&self, _fd: i32, to: ax_abi_port::SeekFrom) -> SysResult {
        Ok(match to {
            ax_abi_port::SeekFrom::Start(at) => at as isize,
            ax_abi_port::SeekFrom::Current(by) | ax_abi_port::SeekFrom::End(by) => by as isize,
        })
    }
    fn validate(&self, _fd: i32) -> SysResult {
        Ok(0)
    }
    fn seekable(&self, _fd: i32) -> SysResult {
        Ok(0)
    }
    fn readv(&self, _fd: i32, _segs: &[ax_abi_port::Segment]) -> SysResult {
        Ok(0)
    }
    fn preadv(&self, _fd: i32, _segs: &[ax_abi_port::Segment], _offset: u64) -> SysResult {
        Ok(0)
    }
    fn writev(&self, _fd: i32, _segs: &[ax_abi_port::Segment]) -> SysResult {
        Ok(0)
    }
    fn pwritev(&self, _fd: i32, _segs: &[ax_abi_port::Segment], _offset: u64) -> SysResult {
        Ok(0)
    }
    fn pread(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> SysResult {
        Ok(len as isize)
    }
    fn pwrite(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> SysResult {
        Ok(len as isize)
    }
    fn dup_onto(&self, _old: i32, new: i32, _cloexec: bool) -> SysResult {
        Ok(new as isize)
    }
    fn fsync(&self, _fd: i32, _datasync: bool) -> SysResult {
        Ok(0)
    }
    fn ftruncate(&self, _fd: i32, _len: u64) -> SysResult {
        Ok(0)
    }
}
impl Mem for MockHost {
    fn brk(&self) -> usize {
        0
    }
    fn set_brk(&self, _addr: usize) -> SysResult {
        Ok(0)
    }
    fn map(&self, req: &MapRequest) -> SysResult {
        *self.mapped.borrow_mut() = Some(*req);
        Ok(0x9000)
    }
    fn unmap(&self, _a: usize, _l: usize) -> SysResult {
        Ok(0)
    }
    fn protect(&self, _a: usize, _l: usize, _p: Prot) -> SysResult {
        Ok(0)
    }
    fn advise(&self, _a: usize, _l: usize, adv: Advice) -> SysResult {
        *self.advised.borrow_mut() = Some(adv);
        Ok(0)
    }
    fn writeback(&self, _a: usize, _l: usize) -> SysResult {
        Ok(0)
    }
}
impl Tasks for MockHost {
    fn getpid(&self) -> SysResult {
        Ok(77)
    }
    fn getppid(&self) -> SysResult {
        Ok(1)
    }
    fn gettid(&self) -> u32 {
        77
    }
    fn set_tid_address(&self, _t: usize) -> SysResult {
        Ok(77)
    }
    fn sched_yield(&self) -> SysResult {
        Ok(0)
    }
    fn exit(&self, _status: i32) -> SysResult {
        Ok(0)
    }
    fn exit_group(&self, _status: i32) -> SysResult {
        Ok(0)
    }
}
impl Creds for MockHost {
    fn uids(&self) -> (u32, u32, u32) {
        (501, 501, 0)
    }
    fn gids(&self) -> (u32, u32, u32) {
        (20, 20, 0)
    }
}
type SysResultAttr = Result<Attributes, i32>;

impl Paths for MockHost {
    fn open(&self, at: At, path: &str, how: &OpenHow) -> SysResult {
        *self.opened.borrow_mut() = Some((at, path.to_string(), *how));
        Ok(5)
    }
    fn attributes(&self, _at: At, path: &str, follow: bool) -> SysResultAttr {
        *self.asked.borrow_mut() = Some((path.to_string(), follow));
        self.describes.clone().ok_or(ax_abi_port::ENOENT)
    }
    fn attributes_of(&self, _fd: i32) -> SysResultAttr {
        self.describes.clone().ok_or(ax_abi_port::EBADF)
    }

    fn permitted(
        &self,
        _at: ax_abi_port::At,
        _path: &str,
        _wants: ax_abi_port::Access,
        _follow: bool,
        _real_ids: bool,
    ) -> Result<(), i32> {
        Ok(())
    }

    fn permitted_of(
        &self,
        _fd: i32,
        _wants: ax_abi_port::Access,
        _real_ids: bool,
    ) -> Result<(), i32> {
        Ok(())
    }
}

impl Host for MockHost {
    fn platform(&self) -> &dyn Platform {
        self
    }
    fn paths(&self) -> Option<&dyn Paths> {
        Some(self)
    }
    fn files(&self) -> Option<&dyn Files> {
        Some(self)
    }
    fn mem(&self) -> Option<&dyn Mem> {
        Some(self)
    }
    fn tasks(&self) -> Option<&dyn Tasks> {
        Some(self)
    }
    fn creds(&self) -> Option<&dyn Creds> {
        Some(self)
    }
}

// The personality resolves its host through the platform binding, so the
// test binary provides one; these tests pass their own host directly.
pub struct StaticHost;
impl Platform for StaticHost {
    fn read_user(&self, _u: usize, _o: &mut [u8]) -> SysResult {
        Ok(0)
    }
    fn write_user(&self, _u: usize, _d: &[u8]) -> SysResult {
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
impl Host for StaticHost {
    fn platform(&self) -> &dyn Platform {
        self
    }
}
pub struct Binding;
#[ax_crate_interface::impl_interface]
impl ax_abi_port::CurrentHost for Binding {
    fn current() -> &'static dyn Host {
        static HOST: StaticHost = StaticHost;
        &HOST
    }
}
