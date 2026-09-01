//! What a C runtime asks about the process while it sets itself up: fiber-
//! local storage, the operating system version, and the modules it can reach.
//!
//! Fiber-local storage is thread-local storage with a callback and an index
//! space that starts at one (ntdll's `RtlFlsAlloc`; index zero is refused).
//! Windows keeps the per-thread values behind `TEB.FlsSlots` and the callbacks
//! process-wide; so does this, with the tables carved from the process heap
//! on first use. A freed index's callback is not run: that would mean calling
//! back into the program from inside a trap, which nothing here can do yet.
//!
//! The version is the one the PEB carries, compared field by field the way
//! `RtlVerifyVersionInfo` compares it, condition mask and all.

use super::{
    Call, Dispatch, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER, ERROR_MOD_NOT_FOUND,
    ERROR_NOT_ENOUGH_MEMORY, FALSE, TRUE, heap,
};
use crate::{
    dll,
    teb_peb::{
        LDR_DLL_BASE, LDR_IN_LOAD_ORDER, LDR_SIZE_OF_IMAGE, PEB_IMAGE_BASE, PEB_LDR, PEB_OS_MAJOR,
        PEB_PRIVATE, PEB_PROCESS_HEAP, TEB_FLS_SLOTS,
    },
};

const ERROR_INVALID_HANDLE: u32 = 6;
/// `ERROR_OLD_WIN_VERSION`, what `STATUS_REVISION_MISMATCH` maps to.
const ERROR_OLD_WIN_VERSION: u32 = 1150;
const FLS_OUT_OF_INDEXES: usize = u32::MAX as usize;

/// Indices this process hands out; one is the first, as on Windows.
const FLS_CAP: usize = 128;
/// A callback slot holding this marks an index allocated without a callback.
const NO_CALLBACK: u64 = u64::MAX;

/// Where the process-wide FLS tables are recorded: the callback table's
/// address, in the PEB's private area.
const PEB_FLS_CALLBACKS: usize = PEB_PRIVATE + 0x20;

/// The callback table, made on first use.
fn fls_callbacks(c: &Call<'_>) -> Option<usize> {
    let peb = c.peb()?;
    match c.read_u64(peb + PEB_FLS_CALLBACKS)? {
        0 => {
            let heap = c.read_u64(peb + PEB_PROCESS_HEAP)? as usize;
            let table = heap::alloc(c, heap, FLS_CAP * 8)?;
            super::zero(c, table, FLS_CAP * 8).then_some(())?;
            c.write_u64(peb + PEB_FLS_CALLBACKS, table as u64)
                .then_some(table)
        }
        at => Some(at as usize),
    }
}

/// This thread's value table, made on first use.
fn fls_values(c: &Call<'_>) -> Option<usize> {
    if c.teb == 0 {
        return None;
    }
    match c.read_u64(c.teb + TEB_FLS_SLOTS)? {
        0 => {
            let peb = c.peb()?;
            let heap = c.read_u64(peb + PEB_PROCESS_HEAP)? as usize;
            let table = heap::alloc(c, heap, FLS_CAP * 8)?;
            super::zero(c, table, FLS_CAP * 8).then_some(())?;
            c.write_u64(c.teb + TEB_FLS_SLOTS, table as u64)
                .then_some(table)
        }
        at => Some(at as usize),
    }
}

/// Whether `index` is one that was handed out and not freed.
fn fls_live(c: &Call<'_>, index: usize) -> bool {
    (1..FLS_CAP).contains(&index)
        && fls_callbacks(c)
            .and_then(|table| c.read_u64(table + index * 8))
            .is_some_and(|slot| slot != 0)
}

/// FlsAlloc(lpCallback): the lowest free index from one upward.
pub fn fls_alloc(c: &mut Call<'_>) -> Dispatch {
    let callback = c.arg(0) as u64;
    let (Some(table), Some(_values)) = (fls_callbacks(c), fls_values(c)) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, FLS_OUT_OF_INDEXES);
    };
    for index in 1..FLS_CAP {
        if c.read_u64(table + index * 8) == Some(0) {
            let slot = if callback == 0 { NO_CALLBACK } else { callback };
            c.write_u64(table + index * 8, slot);
            return c.finish(index);
        }
    }
    c.fail(ERROR_NOT_ENOUGH_MEMORY, FLS_OUT_OF_INDEXES)
}

/// FlsGetValue(dwFlsIndex).
pub fn fls_get_value(c: &mut Call<'_>) -> Dispatch {
    let index = c.arg(0);
    if !fls_live(c, index) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let value = fls_values(c)
        .and_then(|table| c.read_u64(table + index * 8))
        .unwrap_or(0) as usize;
    c.set_last_error(0);
    c.finish(value)
}

/// FlsSetValue(dwFlsIndex, lpFlsData).
pub fn fls_set_value(c: &mut Call<'_>) -> Dispatch {
    let (index, value) = (c.arg(0), c.arg(1) as u64);
    if !fls_live(c, index) {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let Some(table) = fls_values(c) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, FALSE);
    };
    c.write_u64(table + index * 8, value);
    c.finish(TRUE)
}

/// FlsFree(dwFlsIndex): the index goes back; the value is dropped without
/// its callback, which cannot be reached from here.
pub fn fls_free(c: &mut Call<'_>) -> Dispatch {
    let index = c.arg(0);
    if !fls_live(c, index) {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    if let Some(table) = fls_callbacks(c) {
        c.write_u64(table + index * 8, 0);
    }
    if let Some(values) = fls_values(c) {
        c.write_u64(values + index * 8, 0);
    }
    c.finish(TRUE)
}

// VER_* type bits and conditions (`winnt.h`). The condition for a type sits
// at three times the type bit's index in the mask, which is how
// VerSetConditionMask and RtlVerifyVersionInfo agree without a table.
const VER_MINORVERSION: u32 = 0x1;
const VER_MAJORVERSION: u32 = 0x2;
const VER_BUILDNUMBER: u32 = 0x4;
const VER_PLATFORMID: u32 = 0x8;
const VER_SERVICEPACKMINOR: u32 = 0x10;
const VER_SERVICEPACKMAJOR: u32 = 0x20;
const VER_SUITENAME: u32 = 0x40;
const VER_PRODUCT_TYPE: u32 = 0x80;
const VER_EQUAL: u8 = 1;
const VER_GREATER: u8 = 2;
const VER_GREATER_EQUAL: u8 = 3;
const VER_LESS: u8 = 4;
const VER_LESS_EQUAL: u8 = 5;
const VER_AND: u8 = 6;
const VER_OR: u8 = 7;

/// VerSetConditionMask(ConditionMask, TypeMask, Condition): the highest type
/// bit named gets the condition, as Wine orders them.
pub fn ver_set_condition_mask(c: &mut Call<'_>) -> Dispatch {
    let (mut mask, kind, condition) = (c.arg(0) as u64, c.arg(1) as u32, (c.arg(2) & 0x7) as u64);
    let shift = [
        (VER_PRODUCT_TYPE, 7),
        (VER_SUITENAME, 6),
        (VER_SERVICEPACKMAJOR, 5),
        (VER_SERVICEPACKMINOR, 4),
        (VER_PLATFORMID, 3),
        (VER_BUILDNUMBER, 2),
        (VER_MAJORVERSION, 1),
        (VER_MINORVERSION, 0),
    ]
    .into_iter()
    .find(|(bit, _)| kind & bit != 0)
    .map(|(_, at)| at);
    if let Some(at) = shift {
        mask |= condition << (3 * at);
    }
    c.finish(mask as usize)
}

/// What the process reports as its version: what the PEB says, as
/// `RtlGetVersion` reads it, plus the fixed parts of an ordinary workstation.
struct Version {
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    sp_major: u16,
    sp_minor: u16,
    suite: u16,
    product: u8,
}

fn version(c: &Call<'_>) -> Option<Version> {
    let peb = c.peb()?;
    Some(Version {
        major: c.read_u32(peb + PEB_OS_MAJOR)?,
        minor: c.read_u32(peb + PEB_OS_MAJOR + 4)?,
        build: c.read_u32(peb + PEB_OS_MAJOR + 8)?,
        platform: c.read_u32(peb + PEB_OS_MAJOR + 12)?,
        sp_major: 0,
        sp_minor: 0,
        suite: 0x100, // VER_SUITE_SINGLEUSERTS
        product: 1,   // VER_NT_WORKSTATION
    })
}

fn compare(left: u32, right: u32, condition: u8) -> bool {
    match condition {
        VER_EQUAL => left == right,
        VER_GREATER => left > right,
        VER_GREATER_EQUAL => left >= right,
        VER_LESS => left < right,
        VER_LESS_EQUAL => left <= right,
        _ => false,
    }
}

/// `version_update_condition`: a field with no condition of its own takes
/// the one a more significant field carried, when the two can combine.
fn update_condition(last: &mut u8, condition: u8) -> u8 {
    let ok = match *last & 0xF {
        0 => false,
        VER_EQUAL => (VER_EQUAL..=VER_LESS_EQUAL).contains(&condition),
        VER_GREATER | VER_GREATER_EQUAL => (VER_EQUAL..=VER_GREATER_EQUAL).contains(&condition),
        VER_LESS | VER_LESS_EQUAL => {
            condition == VER_EQUAL || (VER_LESS..=VER_LESS_EQUAL).contains(&condition)
        }
        _ => false,
    };
    if ok {
        return condition;
    }
    if condition == 0 {
        *last |= 0x10;
    } else if *last == 0 {
        *last = condition;
    }
    *last & 0xF
}

/// VerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask):
/// `RtlVerifyVersionInfo`, with a mismatch reported as ERROR_OLD_WIN_VERSION.
pub fn verify_version_info(c: &mut Call<'_>) -> Dispatch {
    let (info, kinds, mask) = (c.arg(0), c.arg(1) as u32, c.arg(2) as u64);
    if info == 0 || kinds == 0 || mask == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let Some(ours) = version(c) else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    // RTL_OSVERSIONINFOEXW: size, major, minor, build, platform, then 128
    // wide characters of CSD version, then the service pack, suite and product.
    let want = |off: usize| c.read_u32(info + off).unwrap_or(0);
    let want16 = |off: usize| u16::from_le_bytes(c.read::<2>(info + off).unwrap_or([0, 0]));
    let cond = |at: u32| ((mask >> (3 * at)) & 0x7) as u8;
    let mismatch = |c: &mut Call<'_>| c.fail(ERROR_OLD_WIN_VERSION, FALSE);

    if kinds & VER_PRODUCT_TYPE != 0
        && !compare(
            u32::from(ours.product),
            u32::from(c.read::<1>(info + 282).unwrap_or([0])[0]),
            cond(7),
        )
    {
        return mismatch(c);
    }
    if kinds & VER_SUITENAME != 0 {
        let theirs = want16(280);
        match cond(6) {
            VER_AND if theirs & ours.suite != theirs => return mismatch(c),
            VER_OR if theirs & ours.suite == 0 && theirs != 0 => return mismatch(c),
            VER_AND | VER_OR => {}
            _ => return c.fail(ERROR_INVALID_PARAMETER, FALSE),
        }
    }
    if kinds & VER_PLATFORMID != 0 && !compare(ours.platform, want(16), cond(3)) {
        return mismatch(c);
    }
    if kinds & VER_BUILDNUMBER != 0 && !compare(ours.build, want(12), cond(2)) {
        return mismatch(c);
    }
    if kinds & (VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR)
        != 0
    {
        let mut last = 0u8;
        let mut next = true;
        let fields: [(u32, u32, u32, u32); 4] = [
            (VER_MAJORVERSION, ours.major, want(4), 1),
            (VER_MINORVERSION, ours.minor, want(8), 0),
            (
                VER_SERVICEPACKMAJOR,
                u32::from(ours.sp_major),
                u32::from(want16(276)),
                5,
            ),
            (
                VER_SERVICEPACKMINOR,
                u32::from(ours.sp_minor),
                u32::from(want16(278)),
                4,
            ),
        ];
        for (kind, mine, theirs, at) in fields {
            if kinds & kind == 0 || !next {
                continue;
            }
            let condition = update_condition(&mut last, cond(at));
            if !compare(mine, theirs, condition) {
                return mismatch(c);
            }
            next = mine == theirs && (VER_EQUAL..=VER_LESS_EQUAL).contains(&condition);
        }
    }
    c.finish(TRUE)
}

/// The base of the module `name` means, out of the loader list, with the
/// system library answering for every name that folds into it.
fn module_named(c: &Call<'_>, name: &str) -> Option<usize> {
    let peb = c.peb()?;
    // A synthesized library is in the list under its own name, as is a file.
    let canonical = dll::canonical(name);
    super::find_module(c, peb, canonical.as_bytes())
}

/// LoadLibraryExW(lpLibFileName, hFile, dwFlags): a library already in the
/// process, or the system library for a name that means it. Loading a file
/// the process has not got yet is not done from a trap here.
pub fn load_library_ex(c: &mut Call<'_>) -> Dispatch {
    let name = c.arg(0);
    if name == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(units) = c.read_wstr(name) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let text: alloc::string::String = char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    let text = text.trim_end_matches(' ');
    let stem = text.rsplit(['\\', '/']).next().unwrap_or(text);
    match module_named(c, stem) {
        Some(base) => c.finish(base),
        None => {
            c.host.platform().trace(&alloc::format!(
                "LoadLibraryExW: {text} is not loaded and cannot be loaded here"
            ));
            c.fail(ERROR_MOD_NOT_FOUND, 0)
        }
    }
}

/// FreeLibrary(hLibModule): nothing is unloaded, so a module the process has
/// stays; a null handle is refused as Windows refuses it.
pub fn free_library(c: &mut Call<'_>) -> Dispatch {
    if c.arg(0) == 0 {
        return c.fail(ERROR_INVALID_HANDLE, FALSE);
    }
    c.finish(TRUE)
}

/// GetModuleHandleExW(dwFlags, lpModuleName, phModule).
pub fn get_module_handle_ex(c: &mut Call<'_>) -> Dispatch {
    const PIN: u32 = 0x1;
    const UNCHANGED_REFCOUNT: u32 = 0x2;
    const FROM_ADDRESS: u32 = 0x4;
    let (flags, name, out) = (c.arg(0) as u32, c.arg(1), c.arg(2));
    if out == 0
        || flags & !(PIN | UNCHANGED_REFCOUNT | FROM_ADDRESS) != 0
        || flags & (PIN | UNCHANGED_REFCOUNT) == (PIN | UNCHANGED_REFCOUNT)
    {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let Some(peb) = c.peb() else {
        return c.fail(ERROR_MOD_NOT_FOUND, FALSE);
    };
    let found = if name == 0 {
        c.read_u64(peb + PEB_IMAGE_BASE).map(|b| b as usize)
    } else if flags & FROM_ADDRESS != 0 {
        module_at(c, peb, name)
    } else {
        c.read_wstr(name)
            .and_then(|units| alloc::string::String::from_utf16(&units).ok())
            .and_then(|text| module_named(c, text.rsplit(['\\', '/']).next().unwrap_or(&text)))
    };
    match found {
        Some(base) if c.write_u64(out, base as u64) => c.finish(TRUE),
        Some(_) => c.fail(ERROR_INVALID_PARAMETER, FALSE),
        None => {
            c.write_u64(out, 0);
            c.fail(ERROR_MOD_NOT_FOUND, FALSE)
        }
    }
}

/// The module whose image contains `address`, out of the loader list.
fn module_at(c: &Call<'_>, peb: usize, address: usize) -> Option<usize> {
    let ldr = c.read_u64(peb + PEB_LDR)? as usize;
    let head = ldr + LDR_IN_LOAD_ORDER;
    let mut link = c.read_u64(head)? as usize;
    for _ in 0..1024 {
        if link == head || link == 0 {
            return None;
        }
        let base = c.read_u64(link + LDR_DLL_BASE)? as usize;
        let size = c.read_u32(link + LDR_SIZE_OF_IMAGE)? as usize;
        if (base..base + size).contains(&address) {
            return Some(base);
        }
        link = c.read_u64(link)? as usize;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lower_field_inherits_the_condition_a_higher_one_set() {
        // Major >= 6 with minor given no condition: the minor check is >= too.
        let mut last = 0;
        assert_eq!(
            update_condition(&mut last, VER_GREATER_EQUAL),
            VER_GREATER_EQUAL
        );
        assert_eq!(update_condition(&mut last, 0), VER_GREATER_EQUAL);
        // A condition that cannot combine is replaced by the inherited one.
        let mut last = 0;
        assert_eq!(update_condition(&mut last, VER_LESS), VER_LESS);
        assert_eq!(update_condition(&mut last, VER_GREATER), VER_LESS);
    }
}
