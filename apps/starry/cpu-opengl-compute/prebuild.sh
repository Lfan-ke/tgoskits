#!/usr/bin/env bash
# prebuild.sh - provision the software desktop-OpenGL compute runtime (Mesa llvmpipe over the gallium
# DRI path + libGL + libEGL) and the compiled OpenGL compute carpet binaries into the per-arch Alpine
# rootfs.
#
# Portable model: extract the base Alpine rootfs to a staging tree, `apk add` mesa-gl / mesa-egl /
# mesa-gles / mesa-dri-gallium (the llvmpipe CPU software GL/GLES stack) and the build toolchain INTO
# it via qemu-user-static (apk resolves every package for the TARGET arch on an x86 build host - no
# drifting URLs, no cache-miss-exit), cross-compile the OpenGL compute carpet sources against the
# provisioned musl headers/libraries with a HOST cross toolchain (${triple}-gcc/g++ or zig; the target
# gcc under qemu-user cannot spawn cc1/collect2), then copy the shared-library
# closure, the EGL/GL vendor metadata and the carpet binaries + runner into the overlay. The
# arch-independent GL/glcorearb.h + EGL + KHR headers are vendored under programs/headers (Alpine's
# mesa-dev is the only package carrying the desktop GL/glcorearb.h and it pulls a large clang closure,
# so the pared-down headers are shipped with the app instead). Inputs are the base rootfs and the
# Alpine edge apk repos only.
#
# All backends are CPU software: Mesa's llvmpipe runs the GL 4.3 compute pipeline (glDispatchCompute)
# on the LLVM CPU JIT, so no host GPU is required. Alpine edge builds mesa-gl / mesa-egl /
# mesa-dri-gallium for all four target arches (x86_64 / aarch64 / riscv64 / loongarch64), so the
# surfaceless-EGL desktop-GL carpet (opengl_c_egl) runs on-target on every arch.
#
# Alpine ships no mesa-osmesa package on any arch, so the C/C++/Python desktop-GL compute cells reach
# the GL 4.3 compute surface (compile/link/SSBO/dispatch/barrier/readback) through EGL-surfaceless
# instead of OSMesa: opengl_c_egl, opengl_c and opengl_cpp create a surfaceless EGL desktop-GL 4.5 core
# context and resolve the compute entry points via eglGetProcAddress; opengl_py uses PyOpenGL's
# OpenGL.EGL over the same context. All of these run on-target on every arch (mesa-gl + mesa-egl built
# 4-arch). Only the native moderngl cell (opengl_moderngl) stays best-effort - Alpine builds no
# py3-moderngl for any arch, so it is wired only where it happens to resolve and the manifest omits it
# otherwise.
#
# Env from the app runner: STARRY_ARCH, STARRY_ROOTFS (base alpine working copy),
# STARRY_STAGING_ROOT (scratch extraction tree), STARRY_OVERLAY_DIR, STARRY_APP_DIR.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
arch="${STARRY_ARCH:?prebuild: STARRY_ARCH required}"
base_rootfs="${STARRY_ROOTFS:?prebuild: STARRY_ROOTFS required}"
staging_root="${STARRY_STAGING_ROOT:?prebuild: STARRY_STAGING_ROOT required}"
overlay_dir="${STARRY_OVERLAY_DIR:?prebuild: STARRY_OVERLAY_DIR required}"
CAR="$app_dir/programs/carpets"

# qemu_runner: apk still resolves the TARGET rootfs under qemu-user (only gcc/cc1 was broken there).
# triple:      the musl target triple for the HOST cross C/C++ compiler that builds the cells.
# rust_target: the Rust cross target (cargo cross-compiles natively - the link step uses a host cross cc).
case "$arch" in
    aarch64)     qemu_runner="qemu-aarch64-static";     apk_arch="aarch64";     triple="aarch64-linux-musl";     rust_target="aarch64-unknown-linux-musl" ;;
    riscv64)     qemu_runner="qemu-riscv64-static";     apk_arch="riscv64";     triple="riscv64-linux-musl";     rust_target="riscv64gc-unknown-linux-musl" ;;
    x86_64)      qemu_runner="qemu-x86_64-static";      apk_arch="x86_64";      triple="x86_64-linux-musl";      rust_target="x86_64-unknown-linux-musl" ;;
    loongarch64) qemu_runner="qemu-loongarch64-static"; apk_arch="loongarch64"; triple="loongarch64-linux-musl"; rust_target="loongarch64-unknown-linux-musl" ;;
    *) echo "prebuild: unsupported arch: $arch" >&2; exit 1 ;;
esac

ensure_host_tools() {
    local missing=()
    command -v debugfs >/dev/null 2>&1 || missing+=(e2fsprogs)
    command -v "$qemu_runner" >/dev/null 2>&1 || missing+=(qemu-user-static)
    if [[ ${#missing[@]} -gt 0 ]]; then
        command -v apt-get >/dev/null 2>&1 && apt-get update && apt-get install -y --no-install-recommends "${missing[@]}" \
            || { echo "prebuild: missing host tools: ${missing[*]}" >&2; exit 1; }
    fi
    # The C/C++ cells link Alpine mesa libEGL/libGL (which carry a .relr.dyn section); the link runs
    # HOST-side against the staged sysroot with a HOST cross toolchain (${triple}-gcc/g++ or zig). Target
    # gcc under qemu-user cannot spawn cc1/cc1plus/collect2 (posix_spawn fails under qemu-user).
    command -v "${triple}-g++" >/dev/null 2>&1 || [[ -x "/opt/${triple}-cross/bin/${triple}-g++" ]] \
        || [[ -x "/opt/cross/${triple}-cross/bin/${triple}-g++" ]] || command -v zig >/dev/null 2>&1 \
        || { echo "prebuild: no host C++ cross toolchain (need ${triple}-g++ or zig) for $arch" >&2; exit 1; }
}

extract_base_rootfs() {
    rm -rf "$staging_root"; mkdir -p "$staging_root"
    debugfs -R "rdump / $staging_root" "$base_rootfs" >/dev/null 2>&1
    [[ -x "$staging_root/sbin/apk" ]] || { echo "prebuild: base rootfs has no apk" >&2; exit 2; }
}

# The harness injects $STARRY_OVERLAY_DIR into $base_rootfs via debugfs WITHOUT resizing, so the
# per-app image must be grown here first. The overlay carries the full mesa/llvmpipe closure plus its
# LLVM runtime (~200 MiB); the stock ~2 GiB image overflows and debugfs silently truncates the
# backend libraries ("Could not allocate block"), which surfaces at runtime as "symbol not found".
# 4 GiB leaves ample headroom. Idempotent: truncate only grows, e2fsck/resize2fs are safe to re-run.
# The image stays sparse on the host.
ROOTFS_SIZE=4G
grow_rootfs() {
    [[ -f "$base_rootfs" ]] || { echo "prebuild: rootfs image missing: $base_rootfs" >&2; exit 2; }
    command -v resize2fs >/dev/null 2>&1 || { echo "prebuild: resize2fs required (e2fsprogs)" >&2; exit 1; }
    local before after
    before=$(stat -c %s "$base_rootfs")
    truncate -s "$ROOTFS_SIZE" "$base_rootfs"
    e2fsck -f -y "$base_rootfs" >/dev/null 2>&1 || true
    resize2fs "$base_rootfs" >/dev/null 2>&1
    after=$(stat -c %s "$base_rootfs")
    echo "prebuild: rootfs grown $((before/1024/1024)) -> $((after/1024/1024)) MiB (fs resized) for mesa/llvmpipe closure"
}

normalize_symlinks() {
    local link tgt rel
    while IFS= read -r link; do
        tgt="$(readlink "$link")"; [[ "$tgt" == /* ]] || continue
        rel="$(realpath -m --relative-to="$(dirname "$link")" "$staging_root$tgt")"
        ln -sf "$rel" "$link"
    done < <(find "$staging_root/lib" "$staging_root/usr/lib" -type l 2>/dev/null)
}

# mesa software desktop-GL + GLES + EGL + the gallium DRI drivers (llvmpipe) + LLVM + build toolchain,
# all musl for the target arch. mesa-dev is intentionally NOT installed (it pulls the ~200MB clang-libs
# closure the runtime does not need; the GL/EGL/KHR headers are vendored under programs/headers).
# Alpine builds mesa-gl / mesa-egl / mesa-gles / mesa-dri-gallium for every arch.
GPU_PKGS=(musl mesa-gl mesa-egl mesa-gles mesa-dri-gallium
          build-base pkgconf
          gmp mpfr4 mpc1 isl26 zlib
          python3 py3-numpy)
# PyOpenGL (opengl_py cell) - pure-python desktop-GL binding over the surfaceless-EGL llvmpipe context,
# from apk (py3-opengl, present in Alpine community on every arch). moderngl (opengl_moderngl cell) is a
# native extension; Alpine builds no py3-moderngl for any arch, so it is best-effort and the manifest
# omits it where it does not resolve - opengl_py (PyOpenGL) is the on-target python cell.
PY_BINDING_PKGS=(py3-opengl py3-moderngl)

apk_provision() {
    normalize_symlinks
    [[ -f /etc/resolv.conf ]] && cp -f /etc/resolv.conf "$staging_root/etc/resolv.conf" || true
    local edge="https://dl-cdn.alpinelinux.org/alpine"
    printf '%s/edge/main\n%s/edge/community\n' "$edge" "$edge" > "$staging_root/etc/apk/repositories"
    local apk_common=(--root "$staging_root" --repositories-file "$staging_root/etc/apk/repositories"
                      --keys-dir "$staging_root/etc/apk/keys" --no-progress --no-scripts)
    echo "prebuild: apk add desktop-GL stack (${GPU_PKGS[*]}) via $qemu_runner..."
    QEMU_LD_PREFIX="$staging_root" LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" "$staging_root/sbin/apk" "${apk_common[@]}" --update-cache add "${GPU_PKGS[@]}"
    [[ -f "$staging_root/usr/lib/libGL.so.1" || -n "$(ls "$staging_root/usr/lib/libGL.so"* 2>/dev/null)" ]] \
        || { echo "prebuild: mesa-gl (libGL) not provisioned" >&2; exit 3; }
    [[ -n "$(ls "$staging_root/usr/lib/libEGL.so"* 2>/dev/null)" ]] \
        || { echo "prebuild: mesa-egl (libEGL) not provisioned" >&2; exit 3; }
    # PyOpenGL (opengl_py) is required on-target; py3-opengl resolves on every arch (Alpine community).
    # moderngl (opengl_moderngl) is best-effort in the same transaction - if the native py3-moderngl does
    # not resolve, add py3-opengl alone so opengl_py is still provisioned; opengl_moderngl is then omitted
    # from the manifest.
    if QEMU_LD_PREFIX="$staging_root" LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" "$staging_root/sbin/apk" "${apk_common[@]}" add "${PY_BINDING_PKGS[@]}"; then
        echo "prebuild: PyOpenGL + moderngl provisioned for $arch"
    elif QEMU_LD_PREFIX="$staging_root" LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" "$staging_root/sbin/apk" "${apk_common[@]}" add py3-opengl; then
        echo "prebuild: PyOpenGL (opengl_py) provisioned for $arch; moderngl unavailable (opengl_moderngl not wired)"
    else
        echo "prebuild: py3-opengl unavailable for $arch (apk could not resolve; opengl_py not wired this arch)"
    fi
}

libpath() { ls "$staging_root/usr/lib/$1".so* 2>/dev/null | head -1 || true; }

# The HOST cross toolchains for $triple, resolved once each. The C/C++ cells link Alpine's mesa
# libEGL/libGL, which carry a `.relr.dyn` (SHT_RELR 0x13) section older musl-cross binutils ld rejects
# ("unknown type [0x13] section .relr.dyn"); a RELR-aware linker reads it. So both the C and C++ paths
# probe the GNU cross first, then retry that native GNU compiler with `-fuse-ld=lld` (LLD is a cross-linker
# and reads RELR on every arch) when a standalone ld.lld is reachable, and only then fall back to
# `zig cc`/`zig c++` (zig bundles its own LLD). The Debian x86_64-linux-musl-gcc ignores --sysroot for
# headers, so an explicit -I$staging_root/usr/include is added for the vendored/staged headers.
cc_mode=""; cc_gcc=""; cc_lldflags=()
cxx_mode=""; cxx_gpp=""; cxx_incflags=(); cxx_lldflags=()

# resolve_lld: locate a standalone ld.lld (PATH, then versioned Debian/Ubuntu names) and symlink it into a
# private -B dir so `${triple}-g?? -fuse-ld=lld` finds it as plain `ld.lld`. Echoes the flags on success.
resolve_lld() {
    local lld="" c
    if command -v ld.lld >/dev/null 2>&1; then lld="$(command -v ld.lld)"; fi
    if [[ -z "$lld" ]]; then
        for c in /usr/bin/ld.lld /usr/lib/llvm-*/bin/ld.lld; do [[ -x "$c" ]] && { lld="$c"; break; }; done
    fi
    [[ -n "$lld" ]] || return 1
    local d; d="$(mktemp -d)"; ln -sf "$lld" "$d/ld.lld"; printf -- '-fuse-ld=lld\n-B%s\n' "$d"
}

# resolve_cc: the C toolchain for opengl_c_egl / opengl_c (link libEGL+libGL positionally).
resolve_cc() {
    local gcc probelib EGL GL
    if command -v "${triple}-gcc" >/dev/null 2>&1; then gcc="${triple}-gcc"
    elif [[ -x "/opt/${triple}-cross/bin/${triple}-gcc" ]]; then gcc="/opt/${triple}-cross/bin/${triple}-gcc"
    elif [[ -x "/opt/cross/${triple}-cross/bin/${triple}-gcc" ]]; then gcc="/opt/cross/${triple}-cross/bin/${triple}-gcc"
    else gcc=""; fi

    # Prefer the GNU cross only if its ld can actually link an Alpine .relr.dyn mesa .so - probe libEGL.
    probelib="$(libpath libEGL)"
    if [[ -n "$gcc" && -n "$probelib" ]]; then
        local probe; probe="$(mktemp)"
        printf 'int main(){return 0;}\n' > "$probe.c"
        if "$gcc" --sysroot="$staging_root" -O0 "$probe.c" -o "$probe" \
                -Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib" \
                "$probelib" >/dev/null 2>&1; then
            cc_mode="gcc"; cc_gcc="$gcc"; rm -f "$probe" "$probe.c"
            echo "prebuild: C toolchain = $gcc (--sysroot, native GNU ABI, ld reads .relr.dyn)"; return 0
        fi
        # GNU ld choked on RELR; retry the same native gcc with LLD before falling to zig.
        local lldf; if lldf="$(resolve_lld)"; then
            mapfile -t cc_lldflags <<< "$lldf"
            if "$gcc" "${cc_lldflags[@]}" --sysroot="$staging_root" -O0 "$probe.c" -o "$probe" \
                    -Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib" \
                    "$probelib" >/dev/null 2>&1; then
                cc_mode="gcc"; cc_gcc="$gcc"; rm -f "$probe" "$probe.c"
                echo "prebuild: C toolchain = $gcc -fuse-ld=lld (--sysroot, native GNU ABI, LLD reads .relr.dyn)"; return 0
            fi
            cc_lldflags=()
        fi
        rm -f "$probe" "$probe.c"
    fi
    if command -v zig >/dev/null 2>&1; then
        cc_mode="zig"
        echo "prebuild: C toolchain = zig cc -target $triple (LLD reads .relr.dyn)"; return 0
    fi
    echo "prebuild: no host C cross toolchain for $triple (tried ${triple}-gcc, /opt, gcc -fuse-ld=lld, zig cc)" >&2; exit 4
}

# resolve_cxx: the C++ toolchain for opengl_cpp. zig c++ needs the STAGED libstdc++ headers/lib for the
# correct std::__cxx11 (GNU ABI) mangling that matches Alpine's libstdc++.so.6 (bare zig libc++ mismatches).
resolve_cxx() {
    local gxxver cxxinc cxxinc_tri gpp probelib
    gxxver="$(ls -d "$staging_root"/usr/include/c++/* 2>/dev/null | head -1)"
    cxxinc="$gxxver"
    cxxinc_tri="$(ls -d "$gxxver"/*-alpine-linux-musl 2>/dev/null | head -1)"

    if command -v "${triple}-g++" >/dev/null 2>&1; then gpp="${triple}-g++"
    elif [[ -x "/opt/${triple}-cross/bin/${triple}-g++" ]]; then gpp="/opt/${triple}-cross/bin/${triple}-g++"
    elif [[ -x "/opt/cross/${triple}-cross/bin/${triple}-g++" ]]; then gpp="/opt/cross/${triple}-cross/bin/${triple}-g++"
    else gpp=""; fi

    probelib="$(libpath libEGL)"
    if [[ -n "$gpp" && -n "$probelib" ]]; then
        local probe; probe="$(mktemp)"
        printf 'int main(){return 0;}\n' > "$probe.cpp"
        if "$gpp" --sysroot="$staging_root" -O0 "$probe.cpp" -o "$probe" \
                -Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib" \
                "$probelib" >/dev/null 2>&1; then
            cxx_mode="gpp"; cxx_gpp="$gpp"; rm -f "$probe" "$probe.cpp"
            echo "prebuild: C++ toolchain = $gpp (--sysroot, native GNU ABI, ld reads .relr.dyn)"; return 0
        fi
        # GNU ld choked on RELR; retry the same native g++ with LLD (keeps native libstdc++ ABI) before zig.
        local lldf; if lldf="$(resolve_lld)"; then
            mapfile -t cxx_lldflags <<< "$lldf"
            if "$gpp" "${cxx_lldflags[@]}" --sysroot="$staging_root" -O0 "$probe.cpp" -o "$probe" \
                    -Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib" \
                    "$probelib" >/dev/null 2>&1; then
                cxx_mode="gpp"; cxx_gpp="$gpp"; rm -f "$probe" "$probe.cpp"
                echo "prebuild: C++ toolchain = $gpp -fuse-ld=lld (--sysroot, native GNU ABI, LLD reads .relr.dyn)"; return 0
            fi
            cxx_lldflags=()
        fi
        rm -f "$probe" "$probe.cpp"
    fi
    if command -v zig >/dev/null 2>&1; then
        [[ -d "$cxxinc" ]] || { echo "prebuild: no staged libstdc++ headers for zig c++ path" >&2; exit 4; }
        cxx_mode="zig"; cxx_incflags=(-nostdinc++ -isystem "$cxxinc")
        [[ -n "$cxxinc_tri" ]] && cxx_incflags+=(-isystem "$cxxinc_tri")
        cxx_incflags+=(-idirafter "$staging_root/usr/include")
        echo "prebuild: C++ toolchain = zig c++ -target $triple (staged libstdc++ headers, LLD reads .relr.dyn)"
        return 0
    fi
    echo "prebuild: no host C++ cross toolchain for $triple (tried ${triple}-g++, /opt, zig c++)" >&2; exit 4
}

# cc_build: compile+link one C cell against the staged mesa .so. -no-pie avoids riscv64 static-PIE
# read-only-reloc failures; here the cells are dynamic (link mesa .so) so it is harmless elsewhere.
# The Debian musl-cross gcc ignores --sysroot for headers -> add explicit -I$staging_root/usr/include.
cc_build() {
    local src="$1" out="$2"; shift 2
    local rpl=(-Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib")
    case "$cc_mode" in
        gcc) "$cc_gcc" "${cc_lldflags[@]}" --sysroot="$staging_root" -O2 -std=c11 -I"$staging_root/usr/include" "$src" -o "$out" "${rpl[@]}" "$@" ;;
        zig) zig cc -target "$triple" -O2 -std=c11 -I"$staging_root/usr/include" "$src" -o "$out" "${rpl[@]}" "$@" ;;
    esac
}

# Compile one C++ cell to a .o first, then link - zig reuses a stale object on the combined step, so split.
cxx_object() {
    local src="$1" obj="$2"; shift 2
    case "$cxx_mode" in
        gpp) "$cxx_gpp" --sysroot="$staging_root" -O2 -std=c++17 -I"$staging_root/usr/include" "$@" -c "$src" -o "$obj" ;;
        zig) zig c++ -target "$triple" "${cxx_incflags[@]}" -O2 -std=c++17 "$@" -c "$src" -o "$obj" ;;
    esac
}

# Link one C++ object into a target ELF against the staged mesa .so. zig gets the staged libstdc++.so.6
# positionally (GNU-ABI symbols); g++ pulls its own libstdc++ implicitly. Callers pass the mesa .so paths.
cxx_link() {
    local obj="$1" out="$2"; shift 2
    local rpl=(-Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib")
    case "$cxx_mode" in
        gpp) "$cxx_gpp" "${cxx_lldflags[@]}" --sysroot="$staging_root" "$obj" -o "$out" "${rpl[@]}" "$@" ;;
        zig) zig c++ -target "$triple" "$obj" -o "$out" "${rpl[@]}" "$@" "$staging_root/usr/lib/libstdc++.so.6" ;;
    esac
}

# write_rust_linker: cargo cross-compiles the glow/khronos-egl Rust cell natively, but its link step needs
# a musl cross linker. The target Alpine gcc under qemu-user cannot spawn collect2/ld, so the cargo linker
# points at the HOST cross gcc (${triple}-gcc on PATH -> /opt -> zig cc -> x86_64 musl-gcc). This cell
# dlopens libEGL at runtime, so the link does not need the mesa .so - only a musl C linker.
write_rust_linker() {
    local ccwrap="$1" hostcc=""
    if command -v "${triple}-gcc" >/dev/null 2>&1; then hostcc="${triple}-gcc"
    elif [[ -x "/opt/${triple}-cross/bin/${triple}-gcc" ]]; then hostcc="/opt/${triple}-cross/bin/${triple}-gcc"
    elif [[ -x "/opt/cross/${triple}-cross/bin/${triple}-gcc" ]]; then hostcc="/opt/cross/${triple}-cross/bin/${triple}-gcc"
    elif [[ "$arch" == "x86_64" ]] && command -v musl-gcc >/dev/null 2>&1; then hostcc="musl-gcc"; fi
    if [[ -n "$hostcc" ]]; then
        printf '#!/bin/sh\nexec %s "$@"\n' "$hostcc" > "$ccwrap"
    elif command -v zig >/dev/null 2>&1; then
        printf '#!/bin/sh\nexec zig cc -target %s "$@"\n' "$triple" > "$ccwrap"
    else
        echo "prebuild: no host cross C linker for $triple (Rust cell)" >&2; return 1
    fi
    chmod +x "$ccwrap"
}

# Cross-compile the glow (Rust) desktop-GL cell to a dynamic musl binary. glow resolves GL 4.3 entry
# points via a loader closure and khronos-egl's "dynamic" feature dlopen()s libEGL at runtime, so
# nothing is C-linked at build time - but the binary MUST be dynamic musl (a static musl binary stubs
# dlopen -> vacuous no-context green). Built on every arch (mesa-gl/egl present 4-arch); the libEGL/
# libGL it dlopens ride the same /usr/lib closure as opengl_c_egl.
compile_rust() {
    local bin="$1"
    command -v cargo >/dev/null 2>&1 || { echo "prebuild: cargo required for the glow (Rust) cell" >&2; exit 5; }
    rustup target list --installed 2>/dev/null | grep -qx "$rust_target" || rustup target add "$rust_target" >/dev/null 2>&1 || true
    local ccwrap="$staging_root/opt/rust-cc"; mkdir -p "$staging_root/opt"
    write_rust_linker "$ccwrap" || exit 5
    echo "prebuild: cross-compile glow (Rust) cell for $arch -> $rust_target (dynamic musl; khronos-egl dlopens libEGL, GL via eglGetProcAddress)"
    local linkervar; linkervar="CARGO_TARGET_$(printf '%s' "$rust_target" | tr 'a-z.-' 'A-Z__')_LINKER"
    local cargohome; cargohome="$(mktemp -d)"
    ( cd "$CAR/opengl_rust" && env "$linkervar"="$ccwrap" CARGO_HOME="$cargohome" \
        CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
        RUSTFLAGS="-C target-feature=-crt-static" \
        cargo build --release --locked --target "$rust_target" 2>&1 | tail -5 ) || \
    ( cd "$CAR/opengl_rust" && env "$linkervar"="$ccwrap" CARGO_HOME="$cargohome" \
        CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse RUSTFLAGS="-C target-feature=-crt-static" \
        cargo build --release --target "$rust_target" 2>&1 | tail -5 )
    rm -rf "$cargohome"
    local rustbin="$CAR/opengl_rust/target/$rust_target/release/opengl_rust_full_api"
    [[ -x "$rustbin" ]] || { echo "prebuild: glow (Rust) cell failed to cross-compile for $arch" >&2; exit 5; }
    cp "$rustbin" "$bin/opengl_rust"
    echo "prebuild: glow (Rust) cell -> /opt/cpu-opengl-compute/opengl_rust ($(stat -c %s "$rustbin") bytes, dynamic musl)"
}

# moderngl (opengl_moderngl) cell: stage the source + a wrapper. python3 + numpy + the moderngl native
# extension come from apk, carried into the overlay by populate_overlay's cp -a of /usr/lib/. Wired
# only where moderngl provisioned; it drives a standalone (headless EGL) GL 4.3 core context.
provision_python() {
    local bin="$staging_root/opt/cpu-opengl-compute"
    [[ -x "$staging_root/usr/bin/python3" ]] || { echo "prebuild: python3 not provisioned - python cells not wired" >&2; return 0; }

    # opengl_py: PyOpenGL desktop-GL compute over surfaceless EGL. Wired where py3-opengl resolved
    # (Alpine community, every arch). The wrapper exports the surfaceless-EGL/llvmpipe env just like the
    # C EGL cell and the render/gles python cells; the .py selects PYOPENGL_PLATFORM=egl before import.
    if ls -d "$staging_root"/usr/lib/python3*/site-packages/OpenGL >/dev/null 2>&1; then
        cp "$CAR/opengl_py/opengl_py_full_api.py" "$bin/opengl_py.py"
        cat > "$bin/opengl_py" <<'PYW'
#!/bin/sh
export PYOPENGL_PLATFORM=egl
export EGL_PLATFORM=surfaceless
export GALLIUM_DRIVER=llvmpipe
export LIBGL_ALWAYS_SOFTWARE=1
export LP_NUM_THREADS=1
exec python3 -X faulthandler /opt/cpu-opengl-compute/opengl_py.py "$@"
PYW
        chmod +x "$bin/opengl_py"
        echo "prebuild: opengl_py -> /opt/cpu-opengl-compute/opengl_py (python3 + numpy + PyOpenGL, surfaceless EGL)"
    else
        echo "prebuild: PyOpenGL absent for $arch - opengl_py not wired"
    fi

    # opengl_moderngl: native moderngl extension over a standalone (headless EGL) GL 4.3 core context.
    # Alpine builds no py3-moderngl for any arch, so this is normally absent; wired only where present.
    if ls -d "$staging_root"/usr/lib/python3*/site-packages/moderngl >/dev/null 2>&1; then
        cp "$CAR/opengl_moderngl/opengl_moderngl_full_api.py" "$bin/opengl_moderngl.py"
        cat > "$bin/opengl_moderngl" <<'PYW'
#!/bin/sh
export EGL_PLATFORM=surfaceless
export GALLIUM_DRIVER=llvmpipe
export MESA_LOADER_DRIVER_OVERRIDE=llvmpipe
export LP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
exec python3 -X faulthandler /opt/cpu-opengl-compute/opengl_moderngl.py "$@"
PYW
        chmod +x "$bin/opengl_moderngl"
        echo "prebuild: moderngl (opengl_moderngl) carpet -> /opt/cpu-opengl-compute/opengl_moderngl (python3 + numpy + moderngl)"
    else
        echo "prebuild: moderngl absent for $arch - opengl_moderngl cell not wired"
    fi
}

compile_carpets() {
    local bin="$staging_root/opt/cpu-opengl-compute"; mkdir -p "$bin"
    local hdr="$app_dir/programs/headers"
    local EGL; EGL="$(libpath libEGL)"
    local GL;  GL="$(libpath libGL)"
    [[ -n "$EGL" && -n "$GL" ]] || { echo "prebuild: libEGL/libGL not provisioned" >&2; exit 4; }

    echo "prebuild: host cross-compile OpenGL compute carpets for $arch (llvmpipe desktop-GL 4.3)"
    resolve_cc
    resolve_cxx
    local cxxobj
    # desktop GL via EGL-surfaceless: 1.x symbols from libGL, GL 4.3 compute entry points resolved at
    # runtime via eglGetProcAddress. This is the on-target gate carpet (buildable+runnable on every
    # arch that has mesa-gl + mesa-egl, which Alpine builds for all four). Built HOST-side (cross toolchain
    # + staged sysroot); the mesa .so carry .relr.dyn so resolve_cc auto-picks the RELR-capable linker.
    cc_build "$CAR/opengl_c_egl/opengl_c_egl_full_api.c" "$bin/opengl_c_egl" -I"$hdr" "$EGL" "$GL" -lm
    [[ -x "$bin/opengl_c_egl" ]] || { echo "prebuild: opengl_c_egl failed to compile" >&2; exit 4; }
    # opengl_cpp: reworked from OSMesa to surfaceless-EGL (GL 1.x from libGL, GL 4.3 via eglGetProcAddress),
    # so it builds+runs on-target on every arch alongside opengl_c_egl - the matrix's C++ desktop-GL
    # compute binding. A compile failure here is a genuine breakage (no swallow).
    cxxobj="$bin/opengl_cpp.o"
    cxx_object "$CAR/opengl_cpp/opengl_cpp_full_api.cpp" "$cxxobj" -I"$hdr"
    cxx_link "$cxxobj" "$bin/opengl_cpp" "$EGL" "$GL" -lm
    rm -f "$cxxobj"
    [[ -x "$bin/opengl_cpp" ]] || { echo "prebuild: opengl_cpp failed to compile" >&2; exit 4; }

    # opengl_c: reworked from OSMesa to surfaceless-EGL (GL 1.x from libGL, GL 4.3 compute entry points
    # via eglGetProcAddress), so it builds+runs on-target on every arch alongside opengl_c_egl - the
    # matrix's second C desktop-GL compute cell, carrying the shared-memory reduction / 2D-grid dispatch
    # / indirect-dispatch / injected GL_INVALID_* / program-resource-reflection coverage that
    # opengl_c_egl does not. A compile failure here is a genuine breakage (no swallow).
    cc_build "$CAR/opengl_c/opengl_c_full_api.c" "$bin/opengl_c" -I"$hdr" "$EGL" "$GL" -lm
    [[ -x "$bin/opengl_c" ]] || { echo "prebuild: opengl_c failed to compile" >&2; exit 4; }

    # glow (Rust) desktop-GL cell: dynamic musl, dlopens libEGL - buildable on every arch alongside
    # opengl_c_egl (both ride mesa-gl/egl, present 4-arch).
    compile_rust "$bin"
    provision_python

    cp "$app_dir/programs/run_all.sh" "$bin/run_all.sh"; chmod +x "$bin/run_all.sh"
    echo "prebuild: compiled $(find "$bin" -maxdepth 1 -type f -perm -u+x ! -name '*.sh' | wc -l) OpenGL carpet binary(ies) + run_all.sh"
}

populate_overlay() {
    local bin="$staging_root/opt/cpu-opengl-compute"
    # Capability manifest: list exactly the cells provisioned on this arch. Every cell build hard-fails
    # (compile_carpets / compile_rust exit on error), so a present binary genuinely built - the manifest
    # cannot silently under-count. run_all.sh gates on this exact set (fail==0 && total==EXPECTED==pass,
    # EXPECTED>=1 floor). opengl_c_egl / opengl_c / opengl_cpp (surfaceless-EGL C/C++) and opengl_rust
    # (glow, dynamic musl) build unconditionally on every arch; opengl_py (PyOpenGL) is present where
    # py3-opengl resolved (community, every arch); opengl_moderngl only where the native ext resolved.
    : > "$bin/expected_cells"
    for c in opengl_c_egl opengl_cpp opengl_rust opengl_moderngl opengl_c opengl_py; do [[ -x "$bin/$c" ]] && echo "$c" >> "$bin/expected_cells"; done
    echo "prebuild: expected_cells for $arch = $(tr '\n' ' ' < "$bin/expected_cells")"
    mkdir -p "$overlay_dir/usr/lib" "$overlay_dir/usr/share" "$overlay_dir/opt" "$overlay_dir/usr/bin"
    # the whole provisioned /usr/lib closure (mesa llvmpipe + LLVM + libGL/libEGL + gallium DRI)
    cp -a "$staging_root/usr/lib/." "$overlay_dir/usr/lib/"
    cp -a "$staging_root/usr/share/glvnd" "$overlay_dir/usr/share/" 2>/dev/null || true
    # python3 interpreter for the opengl_moderngl cell (site-packages + moderngl ext ride /usr/lib/. above)
    cp -a "$staging_root"/usr/bin/python3* "$overlay_dir/usr/bin/" 2>/dev/null || true
    cp -a "$staging_root/opt/cpu-opengl-compute" "$overlay_dir/opt/"
    ln -sf /opt/cpu-opengl-compute/run_all.sh "$overlay_dir/usr/bin/run_all.sh"
    echo "prebuild: overlay populated for $arch ($(du -sh "$overlay_dir/usr/lib" | cut -f1) libs)"
}

ensure_host_tools
grow_rootfs
extract_base_rootfs
apk_provision
compile_carpets
populate_overlay
