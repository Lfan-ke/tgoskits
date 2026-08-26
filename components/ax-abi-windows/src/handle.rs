//! NT object handles and a per-process handle table.
//!
//! Windows names kernel objects (files, events, processes) through opaque
//! HANDLEs, not the small dense integers POSIX uses for file descriptors. A
//! handle is a 4-byte-aligned index into a per-process table whose two low bits
//! are NT tag bits (inheritance, protect-from-close), so values step by
//! `HANDLE_VALUE_INC` (4) and `0` is always the NULL handle. This module owns
//! that mapping, mirroring ReactOS `ntoskrnl/ob` + `ntoskrnl/ex/handle.c`; what
//! an entry points at is the caller's object type `T`.

use alloc::vec::Vec;

/// Handles step by 4; the two low bits are reserved as NT tag bits.
const HANDLE_VALUE_INC: u32 = 4;

/// An NT object handle: an opaque, per-process token for a kernel object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Handle(pub u32);

impl Handle {
    /// The NULL handle; never refers to an object.
    pub const NULL: Handle = Handle(0);
    /// Pseudo-handle for the current process (`NtCurrentProcess()`, `(HANDLE)-1`).
    pub const CURRENT_PROCESS: Handle = Handle(u32::MAX);
    /// Pseudo-handle for the current thread (`NtCurrentThread()`, `(HANDLE)-2`).
    pub const CURRENT_THREAD: Handle = Handle(u32::MAX - 1);

    /// Whether this is the NULL handle.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Whether this is a pseudo-handle (current process/thread), which resolves
    /// by identity rather than through a table slot.
    pub const fn is_pseudo(self) -> bool {
        self.0 == Self::CURRENT_PROCESS.0 || self.0 == Self::CURRENT_THREAD.0
    }

    /// Handle value for table slot `index`. Slot 0 maps to handle 4, keeping 0
    /// reserved as NULL.
    fn from_slot(index: usize) -> Handle {
        Handle((index as u32 + 1) * HANDLE_VALUE_INC)
    }

    /// The table slot this handle addresses, or `None` for NULL, pseudo, or
    /// misaligned values.
    fn slot(self) -> Option<usize> {
        (self.0 != 0 && self.0.is_multiple_of(HANDLE_VALUE_INC))
            .then(|| (self.0 / HANDLE_VALUE_INC - 1) as usize)
    }
}

/// A per-process handle table mapping [`Handle`]s to objects of type `T`.
///
/// Closed slots are reused so handle values stay small and dense, as the NT
/// handle table does; a stale handle to a reused slot is not detected here
/// (NT relies on higher-level object pointers for that).
pub struct HandleTable<T> {
    slots: Vec<Option<T>>,
    free: Vec<usize>,
}

impl<T> HandleTable<T> {
    /// Create an empty handle table.
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Install `object`, returning its new handle. Reuses a closed slot when one
    /// is available, otherwise grows the table.
    pub fn insert(&mut self, object: T) -> Handle {
        let index = match self.free.pop() {
            Some(index) => {
                self.slots[index] = Some(object);
                index
            }
            None => {
                self.slots.push(Some(object));
                self.slots.len() - 1
            }
        };
        Handle::from_slot(index)
    }

    /// Borrow the object a handle refers to, or `None` if the handle is NULL,
    /// pseudo, out of range, or already closed.
    pub fn get(&self, handle: Handle) -> Option<&T> {
        self.slots.get(handle.slot()?)?.as_ref()
    }

    /// Mutably borrow the object a handle refers to.
    pub fn get_mut(&mut self, handle: Handle) -> Option<&mut T> {
        self.slots.get_mut(handle.slot()?)?.as_mut()
    }

    /// Close a handle, returning the object it held so the caller can run its
    /// teardown. Returns `None` for an invalid or already-closed handle
    /// (`NtClose` reports `STATUS_INVALID_HANDLE` in that case).
    pub fn close(&mut self, handle: Handle) -> Option<T> {
        let index = handle.slot()?;
        let object = self.slots.get_mut(index)?.take()?;
        self.free.push(index);
        Some(object)
    }

    /// Number of live handles.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// Whether the table holds no live handles.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Default for HandleTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_aligned_and_nonnull() {
        let mut table = HandleTable::new();
        let a = table.insert("a");
        let b = table.insert("b");
        // First handles are 4 and 8 - aligned to HANDLE_VALUE_INC, never NULL.
        assert_eq!(a, Handle(4));
        assert_eq!(b, Handle(8));
        assert!(!a.is_null());
    }

    #[test]
    fn get_and_close_round_trip() {
        let mut table = HandleTable::new();
        let h = table.insert(42u32);
        assert_eq!(table.get(h), Some(&42));
        *table.get_mut(h).unwrap() = 7;
        assert_eq!(table.get(h), Some(&7));
        assert_eq!(table.close(h), Some(7));
        // A closed handle no longer resolves, and closing again is invalid.
        assert_eq!(table.get(h), None);
        assert_eq!(table.close(h), None);
    }

    #[test]
    fn closed_slots_are_reused() {
        let mut table = HandleTable::new();
        let a = table.insert('a');
        let _b = table.insert('b');
        table.close(a);
        // The freed slot backs the next insertion, keeping handle values dense.
        let c = table.insert('c');
        assert_eq!(c, a);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn null_and_pseudo_handles_never_resolve() {
        let table: HandleTable<u8> = HandleTable::new();
        assert!(Handle::NULL.is_null());
        assert!(Handle::CURRENT_PROCESS.is_pseudo());
        assert!(Handle::CURRENT_THREAD.is_pseudo());
        assert_eq!(table.get(Handle::NULL), None);
        assert_eq!(table.get(Handle::CURRENT_PROCESS), None);
        // A misaligned value is not a valid table handle either.
        assert_eq!(table.get(Handle(5)), None);
    }
}
