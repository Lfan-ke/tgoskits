# mac-abi

Runs a Mach-O image on StarryOS through the Darwin personality package.

The image is a few dozen bytes of machine code that issues Darwin system calls
directly - `write` then `exit`, with the UNIX class in the top byte of the call
number - and reaches them with no dyld and no libSystem in between.
`make-macho.py` emits it; nothing is checked in.

It is the same shape as the `win-abi` case, and shows the same thing from the
other side: the kernel runs a format it does not parse and an ABI it does not
implement, because a package claims both. Enabling `starry-kernel/abi-mac` is
the whole difference.

What it does not show is a real macOS program. Those are dynamically linked
against libSystem and arrive through dyld, with chained fixups to apply and
Mach traps - `mach_task_self`, `mach_vm_allocate`, `mach_msg` - used from very
early on. Those are the next steps for the package, not for the kernel.

    cargo xtask starry app qemu -t mac-abi --arch x86_64
