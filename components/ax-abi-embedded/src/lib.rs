//! The embedded personality: a bare interrupt-vector table.
//!
//! A syscall is, stripped of its object model, a standardized interrupt-vector
//! table - an index carried by a trap, routed to a handler. This crate is that
//! table with nothing else around it: the degenerate end of the platform's
//! dispatch spectrum, for a bare-metal target that has no processes, no files
//! and no foreign binary format, only a fixed set of traps to service.
//!
//! [`VectorTable`] is deliberately the same shape from both directions:
//!
//! - as a [`SysAbi`], it is the fourth dispatch domain alongside Linux,
//!   Windows and Darwin (an integrator installs it directly; it is never magic
//!   routed, since a bare image carries no universal header);
//! - as a [`CustomHandler`], it is the reserved-index extension a maker fills to
//!   add traps to *another* domain without forking it - the software analogue of
//!   a RISC-V custom opcode or a Chipyard RoCC accelerator.
//!
//! It borrows its vector slice and allocates nothing, so a `const` table lives in
//! ROM and the whole crate is `no_std`.

#![cfg_attr(not(test), no_std)]

use ax_binfmt::{AbiError, AbiResult, LoadEnv, LoadRequest, Loaded, Prot};
use ax_dispatch::{Abi, CustomHandler, Dispatch, SysAbi, TrapEnv};

/// A handler for one trapped index. A bare function pointer, so a vector table
/// is `const`-constructible and needs no allocation or object identity - the
/// right primitive for a fixed ROM dispatch table. Stateful extensions that need
/// captured data implement [`CustomHandler`] directly instead.
pub type Vector = fn(&mut dyn TrapEnv) -> Dispatch;

/// A bare interrupt-vector table: `(index, handler)` pairs searched in order,
/// plus the base a flat image loads at.
///
/// The vector slice is borrowed, keeping the table allocation-free; a typical
/// use is a `static` const table an integrator hands to the kernel.
pub struct VectorTable<'a> {
    vectors: &'a [(usize, Vector)],
    /// Asynchronous entries, indexed by interrupt number rather than by trap
    /// index. A machine with no interrupt controller carries none, and without
    /// the `interrupts` feature the field does not exist at all.
    #[cfg(feature = "interrupts")]
    interrupts: &'a [(usize, Vector)],
    base: u64,
}

impl<'a> VectorTable<'a> {
    /// Build a table over `vectors`, with `base` the load address a flat image
    /// is placed at (see [`load`](Self::load)). `const` so it can back a
    /// `static`.
    pub const fn new(vectors: &'a [(usize, Vector)], base: u64) -> Self {
        Self {
            vectors,
            #[cfg(feature = "interrupts")]
            interrupts: &[],
            base,
        }
    }

    /// Build a table that also carries asynchronous entries. Only a target with
    /// an interrupt controller has these, which is what the `interrupts`
    /// feature says; the ordinary MCU/MPU case, so it is on by default.
    #[cfg(feature = "interrupts")]
    pub const fn with_interrupts(
        vectors: &'a [(usize, Vector)],
        interrupts: &'a [(usize, Vector)],
        base: u64,
    ) -> Self {
        Self {
            vectors,
            interrupts,
            base,
        }
    }

    /// Deliver an asynchronous trap by interrupt number. Kept apart from
    /// [`dispatch`](Self::dispatch) because the two index spaces are unrelated:
    /// interrupt 3 and trap index 3 are different events.
    #[cfg(feature = "interrupts")]
    pub fn interrupt(&self, nr: usize, env: &mut dyn TrapEnv) -> Dispatch {
        match self.interrupts.iter().find(|(irq, _)| *irq == nr) {
            Some((_, handler)) => handler(env),
            None => Dispatch::Passthrough,
        }
    }

    /// Route one trapped index through the table: run the first handler whose
    /// index matches, else [`Dispatch::Passthrough`] so the caller can fall to
    /// the next handler or its default. The single point both the [`SysAbi`]
    /// and [`CustomHandler`] faces delegate to.
    pub fn dispatch(&self, env: &mut dyn TrapEnv) -> Dispatch {
        match self.vectors.iter().find(|(nr, _)| *nr == env.nr()) {
            Some((_, handler)) => handler(env),
            None => Dispatch::Passthrough,
        }
    }
}

impl SysAbi for VectorTable<'_> {
    fn abi(&self) -> Abi {
        Abi::Embedded
    }

    /// Always `false`: a bare image carries no universal magic, so the embedded
    /// domain is installed explicitly by an integrator, never selected by
    /// [`ax_binfmt::detect`] or [`ax_binfmt::dispatch`].
    fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch {
        self.dispatch(env)
    }
}

impl VectorTable<'_> {
    /// Load a flat image: map the opaque blob at [`base`](Self::base) and start
    /// there. Mapped read-write-execute because a flat binary interleaves code
    /// and mutable data with no section table to separate them - matching how a
    /// bootloader drops a raw blob into RAM on an MMU-less target. A maker who
    /// needs W^X separation uses a structured personality (ELF/PE/Mach-O).
    pub fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded> {
        if req.image.is_empty() {
            return Err(AbiError::MalformedImage);
        }
        env.map_region(
            self.base,
            req.image.len() as u64,
            Prot::READ | Prot::WRITE | Prot::EXEC,
            Some(req.image),
        )?;
        Ok(Loaded {
            entry: self.base,
            stack: 0,
        })
    }
}

impl CustomHandler for VectorTable<'_> {
    fn handle(&self, env: &mut dyn TrapEnv) -> Dispatch {
        self.dispatch(env)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "interrupts")]
    #[test]
    fn an_interrupt_number_is_a_different_space_from_a_trap_index() {
        fn sync(env: &mut dyn TrapEnv) -> Dispatch {
            env.set_result(0x51);
            Dispatch::Handled
        }
        fn irq(env: &mut dyn TrapEnv) -> Dispatch {
            env.set_result(0xA2);
            Dispatch::Handled
        }
        static SYNC: [(usize, Vector); 1] = [(3, sync as Vector)];
        static IRQ: [(usize, Vector); 1] = [(3, irq as Vector)];
        let table = VectorTable::with_interrupts(&SYNC, &IRQ, 0);

        // Index 3 and interrupt 3 are different events, so they answer apart.
        let mut trap = Trap::at(3);
        assert_eq!(table.dispatch(&mut trap), Dispatch::Handled);
        let mut line = Trap::at(3);
        assert_eq!(table.interrupt(3, &mut line), Dispatch::Handled);
        assert_ne!(trap.result, line.result);

        // An interrupt nobody wired up passes through rather than firing a
        // handler that happens to share the number.
        assert_eq!(table.interrupt(9, &mut Trap::at(3)), Dispatch::Passthrough);
    }

    use ax_dispatch::dispatch_trap;

    use super::*;

    // A trap frame exposing a fixed index and six arguments, recording the
    // handler's return value.
    struct Trap {
        nr: usize,
        args: [usize; 6],
        result: Option<usize>,
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
    }
    impl Trap {
        fn at(nr: usize) -> Self {
            Self {
                nr,
                args: [0; 6],
                result: None,
            }
        }
    }

    // A LoadEnv that records what a personality asked to map.
    #[derive(Default)]
    struct Recorder {
        regions: Vec<(u64, u64, Prot, usize)>,
    }
    impl LoadEnv for Recorder {
        fn map_region(
            &mut self,
            va: u64,
            len: u64,
            prot: Prot,
            init: Option<&[u8]>,
        ) -> AbiResult<()> {
            self.regions
                .push((va, len, prot, init.map_or(0, <[u8]>::len)));
            Ok(())
        }
    }

    fn put_42(env: &mut dyn TrapEnv) -> Dispatch {
        env.set_result(42);
        Dispatch::Handled
    }
    fn add01(env: &mut dyn TrapEnv) -> Dispatch {
        env.set_result(env.arg(0) + env.arg(1));
        Dispatch::Handled
    }

    const TABLE: VectorTable<'static> =
        VectorTable::new(&[(0x10, put_42), (0x20, add01)], 0x8000_0000);

    #[test]
    fn routes_each_index_to_its_vector() {
        let mut hit = Trap::at(0x10);
        assert_eq!(TABLE.dispatch(&mut hit), Dispatch::Handled);
        assert_eq!(hit.result, Some(42));

        let mut sum = Trap {
            nr: 0x20,
            args: [3, 4, 0, 0, 0, 0],
            result: None,
        };
        assert_eq!(TABLE.dispatch(&mut sum), Dispatch::Handled);
        assert_eq!(sum.result, Some(7));

        // An index the table does not own falls through untouched.
        let mut miss = Trap::at(0x99);
        assert_eq!(TABLE.dispatch(&mut miss), Dispatch::Passthrough);
        assert_eq!(miss.result, None);
    }

    #[test]
    fn is_the_fourth_dispatch_domain() {
        assert_eq!(TABLE.abi(), Abi::Embedded);
        // Its SysAbi face dispatches exactly like the table.
        let mut env = Trap::at(0x10);
        assert_eq!(TABLE.handle_syscall(&mut env), Dispatch::Handled);
        assert_eq!(env.result, Some(42));
    }

    #[test]
    fn loads_a_flat_image_at_base() {
        let image = [0x90u8; 64];
        let req = LoadRequest {
            image: &image,
            args: &[],
            envs: &[],
        };
        let mut rec = Recorder::default();
        let loaded = TABLE.load(&req, &mut rec).unwrap();
        assert_eq!(loaded.entry, 0x8000_0000);
        assert_eq!(loaded.stack, 0);
        assert_eq!(
            rec.regions,
            vec![(0x8000_0000, 64, Prot::READ | Prot::WRITE | Prot::EXEC, 64)]
        );

        // An empty image is not a flat binary.
        assert_eq!(
            TABLE.load(
                &LoadRequest {
                    image: &[],
                    args: &[],
                    envs: &[]
                },
                &mut Recorder::default(),
            ),
            Err(AbiError::MalformedImage)
        );
    }

    // A domain that owns no syscalls, so every index passes through to the
    // custom handlers - the seam a maker extends.
    struct NullDomain;
    impl SysAbi for NullDomain {
        fn abi(&self) -> Abi {
            Abi::Linux
        }
        fn handle_syscall(&self, _: &mut dyn TrapEnv) -> Dispatch {
            Dispatch::Passthrough
        }
    }

    #[test]
    fn extends_another_domain_as_a_custom_handler() {
        // The same table, now plugged in as a reserved-index extension over a
        // domain that passes 0x20 through: the maker's custom trap is serviced.
        let handlers: [&dyn CustomHandler; 1] = [&TABLE];
        let mut env = Trap {
            nr: 0x20,
            args: [10, 5, 0, 0, 0, 0],
            result: None,
        };
        assert_eq!(
            dispatch_trap(&NullDomain, &handlers, &mut env),
            Dispatch::Handled
        );
        assert_eq!(env.result, Some(15));

        // An index neither the domain nor the extension owns still passes through.
        let mut unclaimed = Trap::at(0x77);
        assert_eq!(
            dispatch_trap(&NullDomain, &handlers, &mut unclaimed),
            Dispatch::Passthrough
        );
    }
}
