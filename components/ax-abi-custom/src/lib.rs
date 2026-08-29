//! Extensions for a reserved range of trapped indices.
//!
//! The analogue of RISC-V's reserved custom opcode space, or of a Chipyard RoCC
//! accelerator: an ABI leaves a range of indices unclaimed, and whoever wants
//! it registers for it. An extension is a peer of the ABI implementations in
//! `ax-dispatch`, registered the same way and reached by the same dispatch -
//! not a mechanism bolted onto one of them.
//!
//! What this crate adds over registering a handler directly is that its
//! registry is *runtime-mutable*: [`CustomSyscalls`] maps an index to a handler
//! and can be changed while the system runs, where `ax_abi_embedded`'s vector
//! table is a `const` decided at build time.
//!
//! Whether an extension may take an index the ABI also owns is not decided
//! here. It is a dispatch policy: the umbrella crate offers the ABI first by
//! default, so a reserved range extends an ABI and cannot shadow it, and its
//! `custom-intercept` feature reverses that as a deliberate opt-in.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;

use ax_dispatch::{CustomHandler, Dispatch, TrapEnv};

/// A handler for one custom trap index. A bare function pointer keeps the
/// registry `Sync` and closure-free; state a handler needs lives behind its own
/// synchronization, reached from within the function.
pub type Handler = fn(&mut dyn TrapEnv) -> Dispatch;

/// A runtime registry of extension handlers, keyed by trapped index.
///
/// Register with [`register`](Self::register) and drop with
/// [`remove`](Self::remove). An index with no handler passes through, so the
/// registry composes with the ABI under either dispatch order (see the crate
/// docs). An integrator owning a `'static` one registers it with
/// `ax_dispatch::register_custom!`, and it is then reached like any other
/// registered owner.
/// Registration takes `&mut self`; a kernel keeps the registry behind its own
/// lock and dispatches through a shared borrow.
#[derive(Default)]
pub struct CustomSyscalls {
    handlers: BTreeMap<usize, Handler>,
}

impl CustomSyscalls {
    /// An empty registry.
    pub const fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
        }
    }

    /// Register `handler` for trap index `nr`, returning the handler it replaced.
    pub fn register(&mut self, nr: usize, handler: Handler) -> Option<Handler> {
        self.handlers.insert(nr, handler)
    }

    /// Remove and return the handler for `nr`, if any.
    pub fn remove(&mut self, nr: usize) -> Option<Handler> {
        self.handlers.remove(&nr)
    }

    /// The number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether no handler is registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl CustomHandler for CustomSyscalls {
    fn handle(&self, env: &mut dyn TrapEnv) -> Dispatch {
        match self.handlers.get(&env.nr()) {
            Some(handler) => handler(env),
            None => Dispatch::Passthrough,
        }
    }
}

#[cfg(test)]
mod tests {
    use ax_dispatch::{Abi, SysAbi, dispatch_trap, dispatch_trap_intercept};

    use super::*;

    struct Trap {
        nr: usize,
        result: Option<usize>,
    }
    impl TrapEnv for Trap {
        fn nr(&self) -> usize {
            self.nr
        }
        fn arg(&self, _i: usize) -> usize {
            0
        }
        fn set_result(&mut self, value: usize) {
            self.result = Some(value);
        }
    }
    impl Trap {
        fn at(nr: usize) -> Self {
            Self { nr, result: None }
        }
    }

    fn answer(env: &mut dyn TrapEnv) -> Dispatch {
        env.set_result(42);
        Dispatch::Handled
    }

    #[test]
    fn registers_and_dispatches_by_index() {
        let mut reg = CustomSyscalls::new();
        assert!(reg.is_empty());
        assert!(reg.register(0x900, answer).is_none());
        assert_eq!(reg.len(), 1);

        let mut hit = Trap::at(0x900);
        assert_eq!(reg.handle(&mut hit), Dispatch::Handled);
        assert_eq!(hit.result, Some(42));

        // An unregistered index passes through.
        let mut miss = Trap::at(0x901);
        assert_eq!(reg.handle(&mut miss), Dispatch::Passthrough);
        assert_eq!(miss.result, None);
    }

    #[test]
    fn register_replaces_and_remove_clears() {
        let mut reg = CustomSyscalls::new();
        reg.register(0x900, answer);
        // Re-registering the same index returns the previous handler.
        assert!(reg.register(0x900, answer).is_some());
        assert!(reg.remove(0x900).is_some());
        assert!(reg.is_empty());
        assert_eq!(reg.handle(&mut Trap::at(0x900)), Dispatch::Passthrough);
    }

    // A base ABI that owns syscall 0x1, writing a sentinel distinct from the
    // custom handler's, so the two dispatch orders are distinguishable.
    struct Base;
    impl SysAbi for Base {
        fn abi(&self) -> Abi {
            Abi::Linux
        }
        fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch {
            env.set_result(1);
            Dispatch::Handled
        }
    }

    #[test]
    fn extends_under_default_and_overrides_under_intercept() {
        let mut reg = CustomSyscalls::new();
        reg.register(0x1, answer); // a handler for a syscall the base ABI owns
        let handlers: [&dyn CustomHandler; 1] = [&reg];
        let base = Base;

        // SysAbi-first: the base ABI keeps 0x1; the registry only extends.
        let mut extend = Trap::at(0x1);
        assert_eq!(
            dispatch_trap(&base, &handlers, &mut extend),
            Dispatch::Handled
        );
        assert_eq!(extend.result, Some(1));

        // Custom-first: the registry overrides the base ABI's 0x1.
        let mut override_ = Trap::at(0x1);
        assert_eq!(
            dispatch_trap_intercept(&base, &handlers, &mut override_),
            Dispatch::Handled
        );
        assert_eq!(override_.result, Some(42));
    }
}
