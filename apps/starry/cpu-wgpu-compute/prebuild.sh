#!/usr/bin/env bash
# prebuild.sh - provision the software GPU compute runtime (Mesa lavapipe / llvmpipe, the CPU software
# Vulkan driver) and build the wgpu (WebGPU) Rust compute carpet into the per-arch Alpine rootfs.
#
# On-target model (identical driver stack to the merged gpu-vulkan app): extract the base Alpine
# rootfs to a staging tree, `apk add` mesa-vulkan-swrast (lavapipe) + the Vulkan loader via
# qemu-user-static (apk resolves every package for the TARGET arch on an x86 build host - no drifting
# URLs, no cache-miss-exit), then cross-compile the wgpu Rust carpet to <arch>-unknown-linux-musl. The
# wgpu crate carries its own wgpu-core/naga and reaches the GPU through the ash Vulkan backend, which
# dlopens libvulkan.so.1 at runtime; that loader plus lavapipe are the exact software Vulkan stack the
# gpu-vulkan app already runs on-target on all four arches. Finally copy the /usr/lib closure, the
# lavapipe ICD metadata and the carpet binary + runner into the overlay. Inputs are the base rootfs and
# the Alpine edge apk repos only.
#
# lavapipe runs the Vulkan compute queue on llvmpipe (LLVM CPU JIT), so no host GPU is required. Alpine
# edge builds mesa-vulkan-swrast for all four target arches, so the wgpu Rust carpet runs on-target on
# every arch. The C / C++ / Python wgpu bindings drive the wgpu-native C API. gfx-rs ships that cdylib
# only as linux-x86_64 / linux-aarch64 glibc (no musl / riscv64 / loongarch64), and wgpu-py's wheels are
# glibc x86_64 / aarch64 only - so neither prebuilt artifact is usable on-target. Instead this recipe
# builds libwgpu_native.so from source against musl for every arch (build_native_cells) and installs
# wgpu-py from its pure-python sdist pointed at that musl lib (provision_wgpu_py). All four cells
# (wgpu_rust / wgpu_c / wgpu_cpp / wgpu_py) therefore run on-target on the same Vulkan loader + lavapipe
# stack; each is listed in expected_cells only when its binary was actually produced.
#
# Env from the app runner: STARRY_ARCH, STARRY_ROOTFS (base alpine working copy),
# STARRY_STAGING_ROOT (scratch extraction tree), STARRY_OVERLAY_DIR, STARRY_APP_DIR.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
arch="${STARRY_ARCH:?prebuild: STARRY_ARCH required}"
base_rootfs="${STARRY_ROOTFS:?prebuild: STARRY_ROOTFS required}"
staging_root="${STARRY_STAGING_ROOT:?prebuild: STARRY_STAGING_ROOT required}"
overlay_dir="${STARRY_OVERLAY_DIR:?prebuild: STARRY_OVERLAY_DIR required}"
RSDIR="$app_dir/rssrc/wgpu-carpet"

case "$arch" in
    aarch64)     qemu_runner="qemu-aarch64-static";     rust_target="aarch64-unknown-linux-musl";     triple="aarch64-linux-musl" ;;
    riscv64)     qemu_runner="qemu-riscv64-static";     rust_target="riscv64gc-unknown-linux-musl";   triple="riscv64-linux-musl" ;;
    x86_64)      qemu_runner="qemu-x86_64-static";      rust_target="x86_64-unknown-linux-musl";      triple="x86_64-linux-musl" ;;
    loongarch64) qemu_runner="qemu-loongarch64-static"; rust_target="loongarch64-unknown-linux-musl"; triple="loongarch64-linux-musl" ;;
    *) echo "prebuild: unsupported arch: $arch" >&2; exit 1 ;;
esac

# Resolve the HOST musl-cross C / C++ compiler for the target arch. The target gcc/g++ cannot run
# under qemu-user (cc1/cc1plus posix_spawn fails), so the C/C++ cells are cross-compiled on the host:
# standard ${triple}-gcc on PATH, then the conventional /opt/${triple}-cross install prefix (musl.cc
# layout), then `zig cc/c++ -target ${triple}` as a portable single-toolchain fallback. `musl_cc` /
# `musl_cxx` are command arrays so the zig fallback carries its -target argument.
ZIG_BIN="$(command -v zig 2>/dev/null || ls /usr/local/zig-*/zig 2>/dev/null | head -1 || true)"
resolve_cc() {
    if command -v "${triple}-gcc" >/dev/null 2>&1; then printf '%s' "${triple}-gcc"
    elif [[ -x "/opt/${triple}-cross/bin/${triple}-gcc" ]]; then printf '%s' "/opt/${triple}-cross/bin/${triple}-gcc"
    elif [[ -x "/usr/local/${triple}-cross/bin/${triple}-gcc" ]]; then printf '%s' "/usr/local/${triple}-cross/bin/${triple}-gcc"
    elif [[ "$arch" == "x86_64" ]] && command -v musl-gcc >/dev/null 2>&1; then printf '%s' "musl-gcc"
    else return 1; fi
}
resolve_cxx() {
    if command -v "${triple}-g++" >/dev/null 2>&1; then printf '%s' "${triple}-g++"
    elif [[ -x "/opt/${triple}-cross/bin/${triple}-g++" ]]; then printf '%s' "/opt/${triple}-cross/bin/${triple}-g++"
    elif [[ -x "/usr/local/${triple}-cross/bin/${triple}-g++" ]]; then printf '%s' "/usr/local/${triple}-cross/bin/${triple}-g++"
    else return 1; fi
}
if cc_bin="$(resolve_cc)"; then musl_cc=("$cc_bin"); elif [[ -n "$ZIG_BIN" ]]; then musl_cc=("$ZIG_BIN" cc -target "$triple"); else musl_cc=(); fi
if cxx_bin="$(resolve_cxx)"; then musl_cxx=("$cxx_bin"); elif [[ -n "$ZIG_BIN" ]]; then musl_cxx=("$ZIG_BIN" c++ -target "$triple"); else musl_cxx=(); fi
# cargo cross-links the dynamic-musl Rust cells (Rust carpet + libwgpu_native.so) through a single-word
# gcc linker; a resolved bare ${triple}-gcc is required for that (zig-as-cargo-linker is out of scope).
rust_cc="$(resolve_cc || true)"

ensure_host_tools() {
    local missing=()
    command -v debugfs >/dev/null 2>&1 || missing+=(e2fsprogs)
    command -v "$qemu_runner" >/dev/null 2>&1 || missing+=(qemu-user-static)
    if [[ ${#missing[@]} -gt 0 ]]; then
        command -v apt-get >/dev/null 2>&1 && apt-get update && apt-get install -y --no-install-recommends "${missing[@]}" \
            || { echo "prebuild: missing host tools: ${missing[*]}" >&2; exit 1; }
    fi
}

extract_base_rootfs() {
    rm -rf "$staging_root"; mkdir -p "$staging_root"
    debugfs -R "rdump / $staging_root" "$base_rootfs" >/dev/null 2>&1
    [[ -x "$staging_root/sbin/apk" ]] || { echo "prebuild: base rootfs has no apk" >&2; exit 2; }
}

# The harness injects $STARRY_OVERLAY_DIR into $base_rootfs via debugfs WITHOUT resizing, so the
# per-app image must be grown here first. The overlay carries the full mesa/lavapipe closure plus its
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
    echo "prebuild: rootfs grown $((before/1024/1024)) -> $((after/1024/1024)) MiB (fs resized) for mesa/lavapipe closure"
}

normalize_symlinks() {
    local link tgt rel
    while IFS= read -r link; do
        tgt="$(readlink "$link")"; [[ "$tgt" == /* ]] || continue
        rel="$(realpath -m --relative-to="$(dirname "$link")" "$staging_root$tgt")"
        ln -sf "$rel" "$link"
    done < <(find "$staging_root/lib" "$staging_root/usr/lib" -type l 2>/dev/null)
}

# mesa software Vulkan (lavapipe) + LLVM + the Vulkan loader, all musl for the target arch. mesa-dev is
# intentionally NOT installed (it pulls the ~200MB clang-libs closure the runtime does not need).
# Alpine builds mesa-vulkan-swrast for every arch.
GPU_PKGS=(musl mesa-vulkan-swrast vulkan-loader vulkan-headers zlib
          python3 py3-numpy py3-cffi py3-sniffio)

apk_provision() {
    normalize_symlinks
    [[ -f /etc/resolv.conf ]] && cp -f /etc/resolv.conf "$staging_root/etc/resolv.conf" || true
    local edge="https://dl-cdn.alpinelinux.org/alpine"
    printf '%s/edge/main\n%s/edge/community\n' "$edge" "$edge" > "$staging_root/etc/apk/repositories"
    local apk_common=(--root "$staging_root" --repositories-file "$staging_root/etc/apk/repositories"
                      --keys-dir "$staging_root/etc/apk/keys" --no-progress --no-scripts)
    echo "prebuild: apk add Vulkan stack (${GPU_PKGS[*]}) via $qemu_runner..."
    QEMU_LD_PREFIX="$staging_root" LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" "$staging_root/sbin/apk" "${apk_common[@]}" --update-cache add "${GPU_PKGS[@]}"
    [[ -f "$staging_root/usr/lib/libvulkan_lvp.so" ]] || { echo "prebuild: mesa-vulkan-swrast (lavapipe) not provisioned" >&2; exit 3; }
}

# Cross-compile the wgpu Rust carpet to <arch>-unknown-linux-musl. Notes:
#  - dynamic musl (`-C target-feature=-crt-static`) is REQUIRED. The musl default is a fully static
#    binary whose dlopen is a NULL stub, so ash's runtime dlopen("libvulkan.so.1") returns nothing and
#    wgpu reports "no adapter". A dynamic-musl PIE links the real musl loader, so dlopen resolves the
#    staged Vulkan loader -> lavapipe.
#  - the toolchain is pinned to the workspace nightly (rust-toolchain.toml selects a no_std kernel
#    channel; the musl std for the host tools lives in that same nightly, selected explicitly here).
#  - cargo inherits every ancestor .cargo/config.toml, so a build host whose global config
#    source-replaces crates.io with an unreachable mirror would fail. Build from a scratch copy under a
#    fresh CARGO_HOME so cargo uses only the default crates.io sparse index (immune to the host mirror,
#    reproducible on a clean host). --locked pins the committed Cargo.lock.
RUST_CHANNEL="${GPU_WGPU_RUST_CHANNEL:-nightly-2026-05-28-x86_64-unknown-linux-gnu}"
build_rust_carpet() {
    command -v cargo >/dev/null 2>&1 || { echo "prebuild: cargo required to build the wgpu Rust carpet" >&2; exit 5; }
    [[ -n "$rust_cc" ]] || { echo "prebuild: ${triple}-gcc required on PATH or /opt/${triple}-cross to cross-link the musl carpet for $arch" >&2; exit 5; }
    local bin="$staging_root/opt/cpu-wgpu-compute"; mkdir -p "$bin"
    local rsbuild rsout rshome
    rsbuild="$(mktemp -d)"; rsout="$(mktemp -d)"; rshome="$(mktemp -d)"
    cp -a "$RSDIR/." "$rsbuild/"
    local link_var="CARGO_TARGET_$(echo "$rust_target" | tr 'a-z-' 'A-Z_')_LINKER"
    local cc_var="CC_$(echo "$rust_target" | tr '-' '_')"
    echo "prebuild: cross-build wgpu Rust carpet -> $rust_target (dynamic musl, lavapipe at runtime)"
    if ( cd "$rsbuild" && env \
            CARGO_HOME="$rshome" CARGO_TARGET_DIR="$rsout" \
            CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
            "$cc_var=$rust_cc" "$link_var=$rust_cc" \
            RUSTFLAGS="-C target-feature=-crt-static" \
            cargo "+$RUST_CHANNEL" build --release --locked --target "$rust_target" ) \
       && [[ -f "$rsout/$rust_target/release/wgpu-carpet" ]]; then
        install -Dm0755 "$rsout/$rust_target/release/wgpu-carpet" "$bin/wgpu_rust"
        echo "prebuild: staged wgpu_rust for $rust_target (dynamic musl PIE, dlopens libvulkan.so.1 -> lavapipe)"
    else
        echo "prebuild: wgpu Rust carpet failed to build for $rust_target" >&2
        rm -rf "$rsbuild" "$rsout" "$rshome"
        exit 5
    fi
    rm -rf "$rsbuild" "$rsout" "$rshome"
    cp "$app_dir/programs/run_all.sh" "$bin/run_all.sh"; chmod +x "$bin/run_all.sh"
}

# wgpu-native (the wgpu C API cdylib gfx-rs ships glibc-only) is built from source for musl so the
# wgpu_c / wgpu_cpp cells run on-target. Fetched at build time from the official repo at a pinned tag
# (reproducible), submodules included (ffi/webgpu-headers, else ffi/wgpu.h cannot find webgpu.h and
# build.rs bindgen fails), built with the SAME proven dynamic-musl recipe as the Rust carpet (musl_cc
# linker, -crt-static off, fresh CARGO_HOME + official crates.io sparse index). The tag is v27.0.4.0:
# the wgpu_c / wgpu_cpp carpets are written against that webgpu.h ABI (WGPUStringView labels, the
# WGPUFuture *CallbackInfo async model, wgpuQueueGetTimestampPeriod), which the older v22.x headers do
# not expose. Its wgpu-core rides the same lavapipe path as the Rust cell (whose own wgpu = "22" crate
# is a separate crates.io dependency, unaffected by this cdylib tag).
# v27.0.4.0 adds wgpuQueueGetTimestampPeriod (used by the C/C++ cells) over v27.0.2.0. wgpu-py 0.26.0 binds
# v27.0.2.0, whose cffi cdef is a forward-compatible subset of this .so's v27.0.4.0 ABI (the delta is the
# additive timestamp accessor the Python cell does not call), so the pure-python cell resolves cleanly
# against this lib. The commit SHA is verified after clone.
WGPU_NATIVE_TAG="${GPU_WGPU_NATIVE_TAG:-v27.0.4.0}"
WGPU_NATIVE_SHA="${GPU_WGPU_NATIVE_SHA:-768f15f6ace8e4ec8e8720d5732b29e0b34250a8}"
build_native_cells() {
    local bin="$staging_root/opt/cpu-wgpu-compute"; mkdir -p "$bin"
    command -v git >/dev/null 2>&1 || { echo "prebuild: git required to fetch wgpu-native" >&2; exit 5; }
    [[ ${#musl_cc[@]} -gt 0 ]]  || { echo "prebuild: no host musl-cross C compiler for $triple (tried ${triple}-gcc, /opt/${triple}-cross, zig cc)" >&2; exit 5; }
    [[ ${#musl_cxx[@]} -gt 0 ]] || { echo "prebuild: no host musl-cross C++ compiler for $triple (tried ${triple}-g++, /opt/${triple}-cross, zig c++)" >&2; exit 5; }
    [[ -n "$rust_cc" ]]         || { echo "prebuild: ${triple}-gcc required to cross-link libwgpu_native.so for $arch" >&2; exit 5; }
    local wn wnout wnhome; wn="$(mktemp -d)"; wnout="$(mktemp -d)"; wnhome="$(mktemp -d)"
    echo "prebuild: fetch wgpu-native $WGPU_NATIVE_TAG (official gfx-rs) + submodules for $arch"
    git clone --depth 1 --branch "$WGPU_NATIVE_TAG" https://github.com/gfx-rs/wgpu-native "$wn" >/dev/null 2>&1 \
        || { echo "prebuild: wgpu-native clone failed ($WGPU_NATIVE_TAG)" >&2; rm -rf "$wn" "$wnout" "$wnhome"; exit 5; }
    local got_sha; got_sha="$(git -C "$wn" rev-parse HEAD 2>/dev/null)"
    [[ "$got_sha" == "$WGPU_NATIVE_SHA" ]] \
        || { echo "prebuild: wgpu-native $WGPU_NATIVE_TAG SHA mismatch (got $got_sha want $WGPU_NATIVE_SHA)" >&2; rm -rf "$wn" "$wnout" "$wnhome"; exit 6; }
    ( cd "$wn" && git submodule update --init --recursive >/dev/null 2>&1 ) \
        || { echo "prebuild: wgpu-native submodule init failed (ffi/webgpu-headers)" >&2; rm -rf "$wn" "$wnout" "$wnhome"; exit 5; }
    local link_var="CARGO_TARGET_$(echo "$rust_target" | tr 'a-z-' 'A-Z_')_LINKER"
    local cc_var="CC_$(echo "$rust_target" | tr '-' '_')"
    echo "prebuild: cross-build libwgpu_native.so (cdylib) -> $rust_target (dynamic musl)"
    # wgpuGetVersion() reads option_env!("WGPU_NATIVE_VERSION") at compile time
    # (src/logging.rs); gfx-rs' release CD sets it to the git tag. A plain source
    # build leaves it unset -> the function returns 0, so pass the pinned tag here
    # to make the packed version report major 27 (matching the wgpu_c version
    # assert and the v27.0.4.0 pin).
    if ! ( cd "$wn" && env CARGO_HOME="$wnhome" CARGO_TARGET_DIR="$wnout" \
            CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse WGPU_NATIVE_VERSION="$WGPU_NATIVE_TAG" \
            "$cc_var=$rust_cc" "$link_var=$rust_cc" RUSTFLAGS="-C target-feature=-crt-static" \
            cargo "+$RUST_CHANNEL" build --release --locked --target "$rust_target" ) \
       || [[ ! -f "$wnout/$rust_target/release/libwgpu_native.so" ]]; then
        echo "prebuild: libwgpu_native.so failed to build for $rust_target" >&2; rm -rf "$wn" "$wnout" "$wnhome"; exit 5
    fi
    install -Dm0755 "$wnout/$rust_target/release/libwgpu_native.so" "$staging_root/usr/lib/libwgpu_native.so"
    echo "prebuild: staged libwgpu_native.so ($(stat -c %s "$staging_root/usr/lib/libwgpu_native.so") bytes) for $arch"
    # wgpu_c / wgpu_cpp: dynamic-musl executables linking the built cdylib; headers from the fetched ffi
    # tree (the carpets #include "webgpu.h"/"wgpu.h"). A failure here is a genuine breakage (no swallow).
    local inc=(-I"$wn/ffi" -I"$wn/ffi/webgpu-headers")
    # Link the staged Rust cdylib; -rpath-link lets the host linker resolve its transitive musl deps
    # that live under the staging root (not the host's own /usr/lib).
    local link_flags=(-L"$staging_root/usr/lib" -Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib" -lwgpu_native -lm)
    "${musl_cc[@]}" -O2 -std=c11 "${inc[@]}" "$app_dir/csrc/gpu_wgpu_carpet.c" -o "$bin/wgpu_c" \
        "${link_flags[@]}" \
        || { echo "prebuild: wgpu_c failed to compile/link for $arch" >&2; rm -rf "$wn" "$wnout" "$wnhome"; exit 5; }
    "${musl_cxx[@]}" -O2 -std=c++17 "${inc[@]}" "$app_dir/cppsrc/gpu_wgpu_carpet.cpp" -o "$bin/wgpu_cpp" \
        "${link_flags[@]}" \
        || { echo "prebuild: wgpu_cpp failed to compile/link for $arch" >&2; rm -rf "$wn" "$wnout" "$wnhome"; exit 5; }
    echo "prebuild: wgpu_c + wgpu_cpp linked against libwgpu_native.so for $arch"
    rm -rf "$wn" "$wnout" "$wnhome"
}

# wgpu_py cell: wgpu-py is pure-python (its sdist excludes the .so) and dlopens the wgpu-native lib via
# cffi, honoring WGPU_LIB_PATH (verified in wgpu/backends/wgpu_native/_ffi.py). So install the
# pure-python package from the pinned official sdist and point WGPU_LIB_PATH at the musl libwgpu_native
# this recipe already built. python3 + numpy + cffi + sniffio come from apk (GPU_PKGS). Wired only where
# python3 + libwgpu_native are present (manifest-honest); a SHA mismatch is a hard error.
# wgpu-py 0.26.0 is the release whose bundled wgpu-native pin is exactly v27.0.2.0 (its __version__/
# __commit_sha__), so its cffi cdef matches this .so's ABI; wgpu-py 0.22.2 binds wgpu-native v24 whose
# symbol set this v27 .so does not match.
WGPU_PY_VER="${GPU_WGPU_PY_VER:-0.26.0}"
WGPU_PY_SHA256="${GPU_WGPU_PY_SHA256:-c90c1fee6fe0fcd573fc9d490e2a25979be693ede3696a9ea3bbbf83bef1ca63}"
provision_wgpu_py() {
    local bin="$staging_root/opt/cpu-wgpu-compute"
    [[ -x "$staging_root/usr/bin/python3" ]] || { echo "prebuild: python3 not provisioned - wgpu_py cell not wired" >&2; return 0; }
    [[ -f "$staging_root/usr/lib/libwgpu_native.so" ]] || { echo "prebuild: libwgpu_native.so absent - wgpu_py cell not wired"; return 0; }
    local sp; sp="$(ls -d "$staging_root"/usr/lib/python3.*/site-packages 2>/dev/null | head -1)"
    [[ -n "$sp" ]] || { echo "prebuild: site-packages not found - wgpu_py cell not wired"; return 0; }
    local wt; wt="$(mktemp -d)"
    echo "prebuild: fetch + verify wgpu-py sdist $WGPU_PY_VER (pure-python, official PyPI)"
    if ! curl -fsSL -o "$wt/wgpu.tar.gz" "https://files.pythonhosted.org/packages/source/w/wgpu/wgpu-${WGPU_PY_VER}.tar.gz"; then
        echo "prebuild: wgpu-py sdist download failed - required wgpu_py cell cannot be provisioned" >&2; rm -rf "$wt"; exit 5
    fi
    echo "$WGPU_PY_SHA256  $wt/wgpu.tar.gz" | sha256sum -c - >/dev/null 2>&1 \
        || { echo "prebuild: wgpu-py sdist SHA-256 mismatch" >&2; rm -rf "$wt"; exit 6; }
    ( cd "$wt" && tar xzf wgpu.tar.gz )
    [[ -d "$wt/wgpu-$WGPU_PY_VER/wgpu" ]] || { echo "prebuild: wgpu-py sdist layout unexpected" >&2; rm -rf "$wt"; exit 6; }
    cp -a "$wt/wgpu-$WGPU_PY_VER/wgpu" "$sp/"
    rm -rf "$wt"
    cp "$app_dir/python/GpuWgpuCarpet.py" "$bin/wgpu_py.py"
    cat > "$bin/wgpu_py" <<'PYW'
#!/bin/sh
export WGPU_LIB_PATH=/usr/lib/libwgpu_native.so
mkdir -p /tmp/vkrt; export XDG_RUNTIME_DIR=/tmp/vkrt
export LP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
exec python3 -X faulthandler /opt/cpu-wgpu-compute/wgpu_py.py "$@"
PYW
    chmod +x "$bin/wgpu_py"
    echo "prebuild: wgpu-py carpet -> /opt/cpu-wgpu-compute/wgpu_py (pure-python wgpu $WGPU_PY_VER + WGPU_LIB_PATH -> musl libwgpu_native)"
}

populate_overlay() {
    mkdir -p "$overlay_dir/usr/lib" "$overlay_dir/usr/share" "$overlay_dir/opt" "$overlay_dir/usr/bin"
    # python3 interpreter for the wgpu_py cell (its site-packages wgpu/ + cffi + sniffio ride /usr/lib/. below)
    cp -a "$staging_root"/usr/bin/python3* "$overlay_dir/usr/bin/" 2>/dev/null || true
    # Capability manifest: list the cells provisioned on this arch (each build hard-fails, so a present
    # binary genuinely built). run_all.sh gates on this exact set (fail==0 && total==EXPECTED==pass,
    # EXPECTED>=1 floor). wgpu_py (wgpu-py + WGPU_LIB_PATH) appends here once its provisioning lands.
    local mbin="$staging_root/opt/cpu-wgpu-compute"
    : > "$mbin/expected_cells"
    # All 4 cells are required on every arch; a missing binary means an upstream build/provision step
    # failed silently, so hard-fail rather than shrinking the manifest (which would let the gate pass
    # on a partial run).
    for c in wgpu_rust wgpu_c wgpu_cpp wgpu_py; do
        [[ -x "$mbin/$c" ]] || { echo "prebuild: required cell $c absent at overlay time for $arch (upstream build/provision failed)" >&2; exit 5; }
        echo "$c" >> "$mbin/expected_cells"
    done
    echo "prebuild: expected_cells for $arch = $(tr '\n' ' ' < "$mbin/expected_cells")"
    # the whole provisioned /usr/lib closure (mesa lavapipe + LLVM + Vulkan loader) and ICD metadata
    cp -a "$staging_root/usr/lib/." "$overlay_dir/usr/lib/"
    cp -a "$staging_root/usr/share/vulkan" "$overlay_dir/usr/share/" 2>/dev/null || true
    cp -a "$staging_root/opt/cpu-wgpu-compute" "$overlay_dir/opt/"
    ln -sf /opt/cpu-wgpu-compute/run_all.sh "$overlay_dir/usr/bin/run_all.sh"
    echo "prebuild: overlay populated for $arch ($(du -sh "$overlay_dir/usr/lib" | cut -f1) libs)"
}

ensure_host_tools
grow_rootfs
extract_base_rootfs
apk_provision
build_rust_carpet
build_native_cells
provision_wgpu_py
populate_overlay
