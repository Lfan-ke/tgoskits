# win-abi

Runs a PE32+ image on StarryOS through the Windows personality package.

The image is a few dozen bytes of machine code that issues NT system calls
directly - `NtWriteFile` then `NtTerminateProcess` - with no Win32 layer
between it and the trap. `make-pe.py` emits it; nothing is checked in.

What the case shows is that the kernel runs a format it does not parse and an
ABI it does not implement, because a package claims both: `exec` routes the
image by its magic bytes to the personality that recognizes it, that package
maps it, and the trap path afterwards goes to the same package because the
process now carries its ABI. Enabling `starry-kernel/abi-win` is the whole
difference; no kernel code is conditional on it.

What it does not show is a real Windows program. `python.exe` and its kind call
kernel32 and the UCRT rather than the NT layer, and arrive as a tree of DLLs
with imports to resolve; the NT calling convention (`rcx` moved to `r10`, then
`rdx`, `r8`, `r9`) and the full call prototypes are not mapped either. Those
are the next steps for the package, not for the kernel.

    cargo xtask starry app qemu -t win-abi --arch x86_64
