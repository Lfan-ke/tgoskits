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

A second image, `hello-dyld.macho`, is shaped the way a real macOS program is:
it names `/usr/lib/libSystem.B.dylib`, calls `write` through a pointer a bind
fills in, and returns from `main` instead of exiting itself. Nothing of
libSystem is on disk - the package synthesizes it - so this one covers the
whole loader path: placing the set, running the rebase and bind streams, and
the code that runs the initializers, calls `main` and hands its result to
`exit`.

What neither shows is the real macOS CPython. That one arrives with a
framework dylib beside it and needs libSystem's own C library - `malloc`,
`fprintf`, the pthread family - behind the stubs. Those are the next steps for
the package, not for the kernel.

    cargo xtask starry app qemu -t mac-abi --arch x86_64
