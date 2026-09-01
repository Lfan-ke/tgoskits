# win-k32

Runs a PE32+ image on StarryOS that reaches the system through kernel32, the
way a compiler-built Windows program does.

The image imports `GetStdHandle`, `WriteFile` and `ExitProcess` from
`KERNEL32.dll` and calls them through its import address table; it never traps
on its own. `make-pe.py` emits it; nothing is checked in.

What the case shows, on top of `win-abi`: the personality binds an import
table to entry points it synthesizes (there is no kernel32 file), starts the
process the way ntdll would - thread and process blocks in place, the module
list published, the parameters block filled - and serves the calls with Win32
conventions: a handle back from `GetStdHandle`, a `BOOL` and a byte count from
`WriteFile`, and an `ExitProcess` that does not return.

    cargo xtask starry app qemu -t win-k32 --arch x86_64
