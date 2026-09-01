# win-crt

Runs a PE32+ image on StarryOS that calls the real C runtime.

The program imports `puts` and `exit` from `ucrtbase.dll`, Microsoft's
Universal CRT, and nothing else. The runtime is not checked in: `prebuild.sh`
installs it from `STARRY_WIN_DLL_DIR` (a directory holding `ucrtbase.dll`)
into the image's `/windows/system32`.

What the case shows, on top of `win-k32`: a real library found by the loader's
search, mapped and relocated, its own hundred-odd kernel32 imports bound, its
entry point run with `DLL_PROCESS_ATTACH` so the runtime initializes itself -
heap, locks, thread locals, locale, standard streams - and then `puts`
reaching standard output through the Win32 layer.

    STARRY_WIN_DLL_DIR=/path/with/ucrtbase.dll cargo xtask starry app qemu -t win-crt --arch x86_64
