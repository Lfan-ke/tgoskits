# win-py

Runs Microsoft's real CPython on StarryOS through the Windows personality.

Nothing is checked in: `prebuild.sh` installs `python.exe`, `python313.dll` and
the C runtime from `STARRY_WIN_DLL_DIR` into the image. The shell runs
`python.exe -c "print('WIN-PY-OK')"`.

This is the target the personality is built toward, and it is expected to fail
until enough of the Win32 surface `python313.dll` uses is implemented. Each run
names, in the kernel log's `abi:` lines, the next function the interpreter
reached that is still a stub - which is the list to work down.

    STARRY_WIN_DLL_DIR=/path/with/python.exe cargo xtask starry app qemu -t win-py --arch x86_64
