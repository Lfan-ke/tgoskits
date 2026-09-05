#!/usr/bin/env bash
# Install Microsoft's real CPython, the libraries it needs, and its standard
# library as a directory tree beside the executable. Nothing is checked in;
# point STARRY_WIN_DLL_DIR at a directory holding python.exe, python314.dll,
# python314.zip, ucrtbase.dll and vcruntime140*.dll.
set -euo pipefail

overlay_dir="${STARRY_OVERLAY_DIR:-}"
dll_dir="${STARRY_WIN_DLL_DIR:-$HOME/rcore/wt-personality/tmp/win}"

if [[ -z "$overlay_dir" ]]; then
    echo "ERROR: STARRY_OVERLAY_DIR is required" >&2
    exit 1
fi
if [[ "$STARRY_ARCH" != "x86_64" ]]; then
    echo "ERROR: this case covers x86-64 only" >&2
    exit 1
fi
for f in python.exe python314.dll python314.zip ucrtbase.dll vcruntime140.dll; do
    if [[ ! -f "$dll_dir/$f" ]]; then
        echo "ERROR: $dll_dir/$f not found; set STARRY_WIN_DLL_DIR" >&2
        exit 1
    fi
done

install -d "$overlay_dir/python" "$overlay_dir/windows/system32"
install -m 0755 "$dll_dir/python.exe" "$overlay_dir/python/python.exe"
install -m 0644 "$dll_dir/python314.dll" "$overlay_dir/python/python314.dll"
for f in ucrtbase.dll vcruntime140.dll vcruntime140_1.dll python3.dll \
         libcrypto-3.dll libssl-3.dll sqlite3.dll libffi-8.dll libtommath.dll; do
    [[ -f "$dll_dir/$f" ]] || continue
    install -m 0644 "$dll_dir/$f" "$overlay_dir/windows/system32/$f"
    install -m 0644 "$dll_dir/$f" "$overlay_dir/python/$f"
done

# The standard library as a directory tree the file finder walks, rather than
# a zip: encodings and the rest are read as plain files. The archive built on
# the host is expanded into Lib.
install -d "$overlay_dir/python/Lib"
unzip -qo "$dll_dir/python314.zip" -d "$overlay_dir/python/Lib"

# The embeddable distribution leaves venv out of its archive, so the module
# comes from the official source release of the same version - the pure-Python
# package as CPython ships it, no third party in it.
venv_src="${STARRY_PY_SOURCE:-$dll_dir/Python-3.14.7.tgz}"
if [[ ! -f "$venv_src" ]]; then
    curl -fsSL -o "$venv_src" \
        "https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tgz"
fi
tar -xzf "$venv_src" -C "$overlay_dir/python/Lib" \
    --strip-components=2 "Python-3.14.7/Lib/venv"

# venv copies a launcher into every environment it makes. An installed
# Windows Python ships those built; the source release ships their C sources
# and the embeddable distribution has none, so the interpreter itself stands
# in - which is what venv copied before the launchers existed, and what the
# environment's pyvenv.cfg points back at either way.
install -d "$overlay_dir/python/Lib/venv/scripts/nt"
for f in venvlauncher.exe venvwlauncher.exe; do
    install -m 0755 "$dll_dir/python.exe" "$overlay_dir/python/Lib/venv/scripts/nt/$f"
done

# No python._pth: one beside the executable pins sys.path to what it lists and,
# as a side effect, turns on safe_path - so neither the working directory nor
# PYTHONPATH reaches sys.path, and `python -m <module beside me>` cannot find
# its module. It was here because the prefix landmark search once failed on
# this host; it no longer does, and the search finds Lib, the zip and
# site-packages by itself.

# Stage the extended python-lang suite (shared with the Linux personality)
# so the Windows python.exe runs the same t01..t22 modules.
suite_src="$HOME/rcore/wt-personality/apps/starry/python-lang/python"
install -d "$overlay_dir/suite"
for f in "$suite_src"/*.py; do
    install -m 0644 "$f" "$overlay_dir/suite/$(basename "$f")"
done

# A small import smoke: exercises the C-runtime heap and directory
# enumeration by importing real stdlib modules, then prints IMPORT-OK.
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe.py" "$overlay_dir/python/probe.py"

# The C extension modules shipped beside the interpreter (unicodedata,
# _socket, _decimal, ...): LoadLibraryExW brings each in on first import.
for f in "$dll_dir"/*.pyd; do
    [[ -f "$f" ]] || continue
    install -m 0644 "$f" "$overlay_dir/python/$(basename "$f")"
done

# In-process runner for the extended suite: the suite's own run_all.py spawns
# a child interpreter per module, which needs CreateProcessW; this runs them
# in one interpreter instead.
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/suite_inproc.py" "$overlay_dir/python/suite_inproc.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_thread.py" "$overlay_dir/python/probe_thread.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/child_capture.py" "$overlay_dir/python/child_capture.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_gaps.py" "$overlay_dir/python/probe_gaps.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_wait.py" "$overlay_dir/python/probe_wait.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_failing.py" "$overlay_dir/python/probe_failing.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_cli.py" "$overlay_dir/python/probe_cli.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_crt.py" "$overlay_dir/python/probe_crt.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_shm.py" "$overlay_dir/python/probe_shm.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_mp.py" "$overlay_dir/python/probe_mp.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_sem.py" "$overlay_dir/python/probe_sem.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_exit.py" "$overlay_dir/python/probe_exit.py"
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe_queue.py" "$overlay_dir/python/probe_queue.py"
