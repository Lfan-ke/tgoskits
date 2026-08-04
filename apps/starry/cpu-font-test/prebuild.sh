#!/usr/bin/env bash
# prebuild.sh - provision the cpu-font-test carpet ("pyte for fonts") into the per-arch Alpine rootfs.
#
# The carpet drives libfreetype (glyph rasterization + metrics) and libharfbuzz (text shaping) and asserts
# the output BYTE-EXACT (per-pixel SHA / exact-integer 26.6 metrics / exact glyph-index+position shaping)
# against goldens captured host-side with the SAME FreeType/HarfBuzz the image ships. Runtime dependency is
# just libfreetype + libharfbuzz (Alpine musl `freetype` + `harfbuzz`); the SHA-256, the comparison logic
# and the golden constants are self-written in the cells. No rasterizer or shaper is re-implemented - the
# whole point is to TEST freetype/harfbuzz.
#
# Model: extract the base Alpine rootfs, `apk add` freetype/freetype-dev + harfbuzz/harfbuzz-dev for the
# TARGET arch via qemu-user (apk runs fine under qemu-user - it is not gcc), then cross-compile each cell on
# the HOST with a musl cross-gcc, --sysroot at the staging root so the target headers and .so link. The
# earlier staging-gcc-under-qemu path could not compile: gcc spawns cc1 via posix_spawn, which qemu-user
# cannot exec (cc1: posix_spawn), so no cell built and no overlay was produced. Then stage the TTF fonts (+
# the WOFF/WOFF2 wrappers converted host-side) and LICENSE files under /opt/cpu-font-test/fonts, and write a
# capability manifest that run_all.sh gates on (fail==0 && total==EXPECTED==pass, EXPECTED>=1 floor).
#
# All five cells build and gate on the staged fonts (always present). font_realassets asserts every staged
# font; since prebuild exit-5s if it stages zero TTFs, an absent $ASSET_DIR on-target fails the gate.
#
# Env from the app runner: STARRY_ARCH, STARRY_ROOTFS, STARRY_STAGING_ROOT, STARRY_OVERLAY_DIR,
# STARRY_APP_DIR. Optional: FONT_ASSET_SRC (host path to the render-assets/fonts tree to stage; defaults
# to <repo>/render-assets/fonts if present).
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
arch="${STARRY_ARCH:?prebuild: STARRY_ARCH required}"
base_rootfs="${STARRY_ROOTFS:?prebuild: STARRY_ROOTFS required}"
staging_root="${STARRY_STAGING_ROOT:?prebuild: STARRY_STAGING_ROOT required}"
overlay_dir="${STARRY_OVERLAY_DIR:?prebuild: STARRY_OVERLAY_DIR required}"
CAR="$app_dir/programs/carpets"

case "$arch" in
    aarch64)     qemu_runner="qemu-aarch64-static" ;;
    riscv64)     qemu_runner="qemu-riscv64-static" ;;
    x86_64)      qemu_runner="qemu-x86_64-static" ;;
    loongarch64) qemu_runner="qemu-loongarch64-static" ;;
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
}

ROOTFS_SIZE=4G
grow_rootfs() {
    [[ -f "$base_rootfs" ]] || { echo "prebuild: rootfs image missing: $base_rootfs" >&2; exit 2; }
    command -v resize2fs >/dev/null 2>&1 || { echo "prebuild: resize2fs required (e2fsprogs)" >&2; exit 1; }
    local before after; before=$(stat -c %s "$base_rootfs")
    truncate -s "$ROOTFS_SIZE" "$base_rootfs"
    e2fsck -f -y "$base_rootfs" >/dev/null 2>&1 || true
    resize2fs "$base_rootfs" >/dev/null 2>&1
    after=$(stat -c %s "$base_rootfs")
    echo "prebuild: rootfs grown $((before/1024/1024)) -> $((after/1024/1024)) MiB for freetype/harfbuzz closure + fonts"
}

extract_base_rootfs() {
    rm -rf "$staging_root"; mkdir -p "$staging_root"
    debugfs -R "rdump / $staging_root" "$base_rootfs" >/dev/null 2>&1
    [[ -x "$staging_root/sbin/apk" ]] || { echo "prebuild: base rootfs has no apk" >&2; exit 2; }
}

normalize_symlinks() {
    local link tgt rel
    while IFS= read -r link; do
        tgt="$(readlink "$link")"; [[ "$tgt" == /* ]] || continue
        rel="$(realpath -m --relative-to="$(dirname "$link")" "$staging_root$tgt")"
        ln -sf "$rel" "$link"
    done < <(find "$staging_root/lib" "$staging_root/usr/lib" -type l 2>/dev/null)
}

# FreeType + HarfBuzz shared libs, headers and pkg-config .pc files (musl) for the target arch. The .so are
# the runtime closure; the -dev packages carry the headers + freetype2.pc/harfbuzz.pc the host pkgconf reads
# to resolve the transitive link closure (-lz -lbz2 -lpng16 -lbrotlidec ...). No target gcc is staged - cells
# are cross-compiled on the host (see resolve_cc); the staging-gcc path spawned cc1 via posix_spawn, which
# qemu-user cannot exec, so no cell ever compiled.
PKGS=(musl freetype freetype-dev harfbuzz harfbuzz-dev)

apk_provision() {
    normalize_symlinks
    [[ -f /etc/resolv.conf ]] && cp -f /etc/resolv.conf "$staging_root/etc/resolv.conf" || true
    local edge="https://dl-cdn.alpinelinux.org/alpine"
    printf '%s/edge/main\n%s/edge/community\n' "$edge" "$edge" > "$staging_root/etc/apk/repositories"
    local apk_common=(--root "$staging_root" --repositories-file "$staging_root/etc/apk/repositories"
                      --keys-dir "$staging_root/etc/apk/keys" --no-progress --no-scripts)
    echo "prebuild: apk add font carpet stack (${PKGS[*]}) via $qemu_runner..."
    QEMU_LD_PREFIX="$staging_root" LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" "$staging_root/sbin/apk" "${apk_common[@]}" --update-cache add "${PKGS[@]}"
    [[ -e "$staging_root/usr/lib/libfreetype.so" || -e "$staging_root/usr/lib/libfreetype.so.6" ]] \
        || { echo "prebuild: libfreetype not provisioned for $arch" >&2; exit 3; }
    [[ -e "$staging_root/usr/lib/libharfbuzz.so" || -e "$staging_root/usr/lib/libharfbuzz.so.0" ]] \
        || { echo "prebuild: libharfbuzz not provisioned for $arch" >&2; exit 3; }
}

# Host cross-compiler for the target musl triple. The cross-toolchain musl and Alpine musl are ABI-compatible
# for C, so linking the target .so from the staging root with the host cross-gcc works. Resolution order
# mirrors the sibling cpu-concurrency carpet: standard cross-gcc on PATH, then the /opt/<triple>-cross prefix,
# then `zig cc -target <triple>`, then musl-gcc for a native x86_64 build. CC is a global set here.
#
# Alpine edge ships freetype/harfbuzz with DT_RELR (SHT_RELR `.relr.dyn`) relocations, which GNU ld 2.37 in
# the musl-cross toolchains cannot parse ("unknown type [0x13] section `.relr.dyn'"), so a plain cross-gcc
# link fails. LINK_FLAGS therefore selects a RELR-aware linker: `-fuse-ld=lld` when a standalone ld.lld is
# reachable (LLD is a cross-linker and reads RELR on every arch), staged into LLD_BINDIR so gcc's -B can find
# it. `zig cc` carries its own LLD, so that path needs no extra linker flag. GNU ld is kept only as a final
# fallback for images without DT_RELR.
CC=""
LINK_FLAGS=()
LLD_BINDIR=""
# Resolve a standalone ld.lld: on PATH, then common Debian/Ubuntu versioned names. Symlink it into a private
# dir so `${triple}-gcc -B$LLD_BINDIR -fuse-ld=lld` finds it under the plain `ld.lld` name.
resolve_lld() {
    local lld=""
    if command -v ld.lld >/dev/null 2>&1; then lld="$(command -v ld.lld)"; fi
    if [[ -z "$lld" ]]; then
        local c
        for c in /usr/bin/ld.lld /usr/lib/llvm-*/bin/ld.lld; do
            [[ -x "$c" ]] && { lld="$c"; break; }
        done
    fi
    [[ -n "$lld" ]] || return 1
    LLD_BINDIR="$(mktemp -d)"; trap 'rm -rf "$LLD_BINDIR"' EXIT
    ln -sf "$lld" "$LLD_BINDIR/ld.lld"
    return 0
}
resolve_cc() {
    case "$arch" in
        x86_64)      triple="x86_64-linux-musl" ;;
        aarch64)     triple="aarch64-linux-musl" ;;
        riscv64)     triple="riscv64-linux-musl" ;;
        loongarch64) triple="loongarch64-linux-musl" ;;
        *) echo "prebuild: unsupported arch: $arch" >&2; exit 1 ;;
    esac
    if command -v "${triple}-gcc" >/dev/null 2>&1; then
        CC=("${triple}-gcc")
    elif [[ -x "/opt/${triple}-cross/bin/${triple}-gcc" ]]; then
        CC=("/opt/${triple}-cross/bin/${triple}-gcc")
    elif command -v zig >/dev/null 2>&1; then
        CC=(zig cc -target "$triple")
    elif [[ "$arch" == "x86_64" ]] && command -v musl-gcc >/dev/null 2>&1; then
        CC=(musl-gcc)
    else
        echo "prebuild: no musl cross toolchain for $triple (tried ${triple}-gcc, /opt/${triple}-cross, zig cc, musl-gcc)" >&2
        exit 1
    fi
    # A gcc-family compiler needs an explicit RELR-aware linker; zig cc already links with its own LLD.
    if [[ "${CC[0]}" != "zig" ]]; then
        if resolve_lld; then
            LINK_FLAGS=(-fuse-ld=lld -B"$LLD_BINDIR")
        elif command -v zig >/dev/null 2>&1; then
            echo "prebuild: no ld.lld found; switching to 'zig cc -target $triple' for RELR-aware linking" >&2
            CC=(zig cc -target "$triple")
        else
            echo "prebuild: warning: no RELR-aware linker (ld.lld or zig); GNU ld cannot link Alpine's DT_RELR .so" >&2
        fi
    fi
    echo "prebuild: host cross-compiler for $arch = ${CC[*]} ${LINK_FLAGS[*]} (sysroot=$staging_root)"
}

# Resolve the freetype/harfbuzz include + transitive link flags against the staging root with the HOST pkgconf
# (reading the target .pc files under the staging pkgconfig dir). PKG_CONFIG_SYSROOT_DIR rewrites the -I/-L
# prefixes to the staging root. Fall back to explicit flags if pkgconf or the .pc files are unavailable.
host_pkgconf() {
    PKG_CONFIG_SYSROOT_DIR="$staging_root" PKG_CONFIG_LIBDIR="$staging_root/usr/lib/pkgconfig" \
        pkgconf "$@"
}

# Each cell is a standalone C program including font_common.h, linking libfreetype + libharfbuzz. A compile
# failure is a genuine breakage. Cells build on the host with the cross-gcc, --sysroot at the staging root so
# the target headers and .so are found; the transitive closure (-lz -lbz2 -lpng16 -lbrotlidec ...) comes from
# the host pkgconf run against the staged .pc files.
compile_cells() {
    local bin="$1"
    local cflags libs cell
    cflags="$(host_pkgconf --cflags freetype2 harfbuzz 2>/dev/null || echo "-I$staging_root/usr/include/freetype2 -I$staging_root/usr/include/harfbuzz -I$staging_root/usr/include")"
    libs="$(host_pkgconf --libs freetype2 harfbuzz 2>/dev/null || echo "-L$staging_root/usr/lib -lfreetype -lharfbuzz")"
    # -rpath-link lets ld resolve the target .so DT_NEEDED chain (libc.musl-<arch>.so.1, libz, ...) against the
    # staging root at link time. Without it ld only warns and still links, but resolving it keeps the build clean.
    local rpath_link=(-Wl,-rpath-link,"$staging_root/usr/lib:$staging_root/lib")
    # gcc-family resolves the target headers/.so via --sysroot; zig cc treats the pkgconf-emitted absolute
    # -I/-L (already staging-root prefixed) directly, and would double-prefix them under --sysroot.
    local sysroot_flags=()
    [[ "${CC[0]}" != "zig" ]] && sysroot_flags=(--sysroot="$staging_root")
    for cell in font_raster font_metrics font_shape font_formats font_realassets; do
        echo "prebuild: cross-compile $cell for $arch (links libfreetype + libharfbuzz; self-written SHA-256 + goldens)"
        # shellcheck disable=SC2086
        "${CC[@]}" "${sysroot_flags[@]}" "${LINK_FLAGS[@]}" -O2 -std=c11 -I"$CAR" $cflags "$CAR/$cell.c" -o "$bin/$cell" "${rpath_link[@]}" $libs -lm
        [[ -x "$bin/$cell" ]] || { echo "prebuild: $cell failed to compile" >&2; exit 4; }
    done
}

# Locate the render-assets/fonts tree (host). Walk up from the app dir if FONT_ASSET_SRC is unset.
find_font_src() {
    local src="${FONT_ASSET_SRC:-}"
    # Preferred source: the per-app `assets` git submodule (same fonts/ layout as render-assets).
    # On a fresh CI checkout the gitlink dir exists but is empty until inited, and the TTFs arrive as
    # LFS pointers - init + sparse-pull the fonts/ subdir so the marker materializes with real bytes.
    if [[ -z "$src" && -d "$app_dir/assets" ]]; then
        if [[ ! -e "$app_dir/assets/fonts/root__JetBrainsMono-Regular.ttf" ]] && command -v git >/dev/null 2>&1; then
            git -C "$app_dir" submodule update --init assets >/dev/null 2>&1 || true
        fi
        if command -v git >/dev/null 2>&1 && git -C "$app_dir/assets" lfs env >/dev/null 2>&1; then
            git -C "$app_dir/assets" lfs pull --include="fonts/*" >/dev/null 2>&1 || true
        fi
        [[ -f "$app_dir/assets/fonts/root__JetBrainsMono-Regular.ttf" ]] && src="$app_dir/assets/fonts"
    fi
    if [[ -z "$src" ]]; then
        local d="$app_dir"
        for _ in 1 2 3 4 5 6; do
            d="$(dirname "$d")"
            if [[ -f "$d/render-assets/fonts/root__JetBrainsMono-Regular.ttf" ]]; then src="$d/render-assets/fonts"; break; fi
        done
    fi
    echo "$src"
}

# Stage the TTF fonts + LICENSE files under /opt/cpu-font-test/fonts so the golden cells assert against
# them on-target. Also convert JetBrains Mono Regular -> WOFF/WOFF2 host-side (fontTools; WOFF2 needs
# brotli) for font_formats' wrapper matrix. A font source is required for the golden cells, and the
# WOFF/WOFF2 wrappers are mandatory: wrapper generation failure aborts provisioning so font_formats'
# format-identity matrix is guaranteed to run on-target instead of degrading to the TTF baseline.
stage_fonts() {
    local bin="$1" src
    src="$(find_font_src)"
    [[ -n "$src" && -d "$src" ]] || { echo "prebuild: render-assets/fonts not found (set FONT_ASSET_SRC)" >&2; exit 5; }
    echo "prebuild: staging fonts from $src -> /opt/cpu-font-test/fonts"
    mkdir -p "$bin/fonts"
    cp -a "$src"/*.ttf "$bin/fonts/" 2>/dev/null || true
    # keep the LICENSE files (Apache/OFL for JetBrains Mono, HarmonyOS Sans licenses)
    cp -a "$src"/LICENSE*.txt "$bin/fonts/" 2>/dev/null || true
    local n; n=$(ls "$bin/fonts"/*.ttf 2>/dev/null | wc -l)
    echo "prebuild: staged $n TTF fonts + $(ls "$bin/fonts"/LICENSE*.txt 2>/dev/null | wc -l) license files"
    [[ "$n" -ge 1 ]] || { echo "prebuild: no TTF fonts staged" >&2; exit 5; }

    # WOFF/WOFF2 wrappers for the format matrix (host-side conversion; on-target FreeType decodes them).
    # font_formats treats both wrappers as mandatory, so wrapper generation must succeed or the whole
    # provisioning fails here - a missing wrapper is a build-host tooling gap to fix, not something to
    # silently degrade the format-identity coverage over.
    local ttf="$bin/fonts/root__JetBrainsMono-Regular.ttf"
    command -v python3 >/dev/null 2>&1 || { echo "prebuild: python3 required for WOFF/WOFF2 wrappers" >&2; exit 6; }
    [[ -f "$ttf" ]] || { echo "prebuild: JetBrains Mono TTF missing, cannot build wrappers: $ttf" >&2; exit 6; }
    python3 - "$ttf" "$bin/fonts" <<'PY' || { echo "prebuild: WOFF/WOFF2 wrapper generation failed - install fontTools + brotli" >&2; exit 6; }
import sys
ttf, outdir = sys.argv[1], sys.argv[2]
from fontTools.ttLib import TTFont
f = TTFont(ttf); f.flavor = "woff"; f.save(outdir + "/jbm-format.woff")
f = TTFont(ttf); f.flavor = "woff2"; f.save(outdir + "/jbm-format.woff2")
print("prebuild: staged font wrappers: woff woff2")
PY
    [[ -f "$bin/fonts/jbm-format.woff" && -f "$bin/fonts/jbm-format.woff2" ]] \
        || { echo "prebuild: WOFF/WOFF2 wrapper not staged after conversion" >&2; exit 6; }
}

compile_carpets() {
    local bin="$staging_root/opt/cpu-font-test"; mkdir -p "$bin"
    resolve_cc
    compile_cells "$bin"
    stage_fonts "$bin"
    cp "$app_dir/programs/run_all.sh" "$bin/run_all.sh"; chmod +x "$bin/run_all.sh"
}

populate_overlay() {
    local bin="$staging_root/opt/cpu-font-test"
    : > "$bin/expected_cells"
    for c in font_raster font_metrics font_shape font_formats font_realassets; do
        [[ -x "$bin/$c" ]] && echo "$c" >> "$bin/expected_cells"; done
    echo "prebuild: expected_cells for $arch = $(tr '\n' ' ' < "$bin/expected_cells")"
    mkdir -p "$overlay_dir/usr/lib" "$overlay_dir/opt"
    cp -a "$staging_root/usr/lib/." "$overlay_dir/usr/lib/"
    cp -a "$staging_root/opt/cpu-font-test" "$overlay_dir/opt/"
    mkdir -p "$overlay_dir/usr/bin"
    ln -sf /opt/cpu-font-test/run_all.sh "$overlay_dir/usr/bin/run_all.sh"
    echo "prebuild: overlay populated for $arch ($(du -sh "$overlay_dir/usr/lib" | cut -f1) libs, $(du -sh "$overlay_dir/opt/cpu-font-test/fonts" | cut -f1) fonts)"
}

ensure_host_tools
grow_rootfs
extract_base_rootfs
apk_provision
compile_carpets
populate_overlay
echo "prebuild: cpu-font-test overlay ready for $arch"
