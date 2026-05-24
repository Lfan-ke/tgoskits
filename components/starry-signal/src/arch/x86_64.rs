use ax_cpu::{ExtendedState, uspace::UserContext};

use crate::{SignalSet, SignalStack};

core::arch::global_asm!(
    "
.section .text
.code64
.balign 4096
.global signal_trampoline
signal_trampoline:
    mov rax, 0xf
    syscall

.fill 4096 - (. - signal_trampoline), 1, 0
"
);

// Linux x86-64 `mcontext_t` (`struct sigcontext`) has NATURAL 8-byte alignment,
// not 16. In `ucontext_t`, `uc_mcontext` sits in the MIDDLE of the struct (at
// offset 40, after uc_flags/uc_link/uc_stack), so forcing `align(16)` here would
// insert 8 bytes of padding and push `uc_mcontext` to offset 48 — shifting every
// general register (RSP@160, RIP@168), the fpregs pointer and `uc_sigmask` 8
// bytes off the Linux ABI. Runtimes that read the context by raw ABI offset —
// most notably Go's async preemption, which reads/writes
// `uc_mcontext.gregs[REG_RSP/REG_RIP]` and expects `rt_sigreturn` to honor those
// writes — then corrupt RSP/RIP (observed: `sp` loaded with adjacent non-pointer
// bytes → `unsafe.Slice: len out of range`). The kernel FP save area is
// intentionally NOT a field of `MContext` (an `ExtendedState`/FXSAVE field is
// `align(16)` and would re-force 16-byte alignment); it lives in `UContext`.
#[repr(C)]
#[derive(Clone)]
pub struct MContext {
    r8: usize,
    r9: usize,
    r10: usize,
    r11: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    rdi: usize,
    rsi: usize,
    rbp: usize,
    rbx: usize,
    rdx: usize,
    rax: usize,
    rcx: usize,
    rsp: usize,
    rip: usize,
    eflags: usize,
    cs: u16,
    gs: u16,
    fs: u16,
    _pad: u16,
    err: usize,
    trapno: usize,
    oldmask: usize,
    cr2: usize,
    // musl's `mcontext_t` fpregs pointer. Kept NULL (musl tolerates a null
    // `fpstate`); the interrupted thread's FP/SSE state is round-tripped through
    // `UContext::ext_state` (kernel-internal, outside the musl-visible mcontext)
    // instead — see that field.
    fpstate: usize,
    _reserved1: [usize; 8],
}

impl MContext {
    pub fn new(uctx: &UserContext) -> Self {
        Self {
            r8: uctx.r8 as _,
            r9: uctx.r9 as _,
            r10: uctx.r10 as _,
            r11: uctx.r11 as _,
            r12: uctx.r12 as _,
            r13: uctx.r13 as _,
            r14: uctx.r14 as _,
            r15: uctx.r15 as _,
            rdi: uctx.rdi as _,
            rsi: uctx.rsi as _,
            rbp: uctx.rbp as _,
            rbx: uctx.rbx as _,
            rdx: uctx.rdx as _,
            rax: uctx.rax as _,
            rcx: uctx.rcx as _,
            rsp: uctx.rsp as _,
            rip: uctx.rip as _,
            eflags: uctx.rflags as _,
            cs: uctx.cs as _,
            gs: 0,
            fs: 0,
            _pad: 0,
            err: uctx.error_code as _,
            trapno: uctx.vector as _,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            _reserved1: [0; 8],
        }
    }

    pub fn restore(&self, uctx: &mut UserContext) {
        uctx.r8 = self.r8 as _;
        uctx.r9 = self.r9 as _;
        uctx.r10 = self.r10 as _;
        uctx.r11 = self.r11 as _;
        uctx.r12 = self.r12 as _;
        uctx.r13 = self.r13 as _;
        uctx.r14 = self.r14 as _;
        uctx.r15 = self.r15 as _;
        uctx.rdi = self.rdi as _;
        uctx.rsi = self.rsi as _;
        uctx.rbp = self.rbp as _;
        uctx.rbx = self.rbx as _;
        uctx.rdx = self.rdx as _;
        uctx.rax = self.rax as _;
        uctx.rcx = self.rcx as _;
        uctx.rsp = self.rsp as _;
        uctx.rip = self.rip as _;
        uctx.rflags = self.eflags as _;
        uctx.cs = self.cs as _;
        uctx.error_code = self.err as _;
        uctx.vector = self.trapno as _;
    }
}

// `align(16)` keeps the whole signal frame 16-byte aligned on the user stack
// (the x86-64 signal ABI requires the handler to observe `RSP % 16 == 8` after
// its return address is pushed). `mcontext` keeps its natural 8-byte alignment
// and therefore sits at offset 40 (Linux ABI); `ext_state` is the kernel-only FP
// save area, placed AFTER the musl-visible `uc_sigmask` (where musl's
// `__fpregs_mem` would be — unused, since `fpstate` is NULL), so it never
// perturbs the musl-visible `ucontext_t` ABI.
#[repr(C, align(16))]
#[derive(Clone)]
pub struct UContext {
    pub flags: usize,
    pub link: usize,
    pub stack: SignalStack,
    pub mcontext: MContext,
    pub sigmask: SignalSet,
    // Kernel-saved x87/SSE/MMX/MXCSR state of the interrupted thread. On x86-64,
    // signal delivery runs the user handler IN-LINE with NO context switch, so
    // the per-task `TaskContext.ext_state` (saved only on context switch) does
    // NOT capture the interrupted thread's live XMM/x87. The handler clobbers
    // XMM/MXCSR (SSE2 is the x86-64 baseline ABI: memcpy/string ops use XMM), and
    // sigreturn would otherwise restore only the GP regs. For V8 pointer
    // compression a clobbered XMM-resident pointer decompresses to ~0 → NULL
    // deref (node/V8 SIGSEGV at VA:0x0, #242). We FXSAVE the live FP at delivery
    // and FXRSTOR it on sigreturn — the x86 analog of the loongarch LSX fix.
    ext_state: ExtendedState,
}

impl UContext {
    pub fn new(uctx: &UserContext, sigmask: SignalSet) -> Self {
        // Capture the interrupted thread's live FP/SSE state before the handler
        // runs (trap entry saves only GPRs and signal delivery does not
        // context-switch, so XMM/x87/MXCSR still hold the interrupted state).
        let mut ext_state = ExtendedState::default();
        ext_state.save();
        Self {
            flags: 0,
            link: 0,
            stack: SignalStack::default(),
            mcontext: MContext::new(uctx),
            sigmask,
            ext_state,
        }
    }

    /// Restores the interrupted thread's GP registers and FP/SSE state. Called by
    /// `sigreturn` (via `Signal::restore`).
    pub fn restore(&self, uctx: &mut UserContext) {
        self.mcontext.restore(uctx);
        // Restore the FP/SSE state the handler may have clobbered, before
        // resuming the interrupted user code.
        self.ext_state.restore();
    }
}

const _: () = {
    // Lock the Linux/musl x86-64 `ucontext_t` ABI offsets (regression guard for
    // the alignment trap documented on `MContext`): `uc_mcontext`@40,
    // `uc_sigmask`@296. Appending `ext_state` after `sigmask` must not move them.
    assert!(core::mem::offset_of!(UContext, mcontext) == 40);
    assert!(core::mem::offset_of!(UContext, sigmask) == 296);
};
