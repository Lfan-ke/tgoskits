#!/usr/bin/env bash
# prebuild.sh - provision the software Vulkan runtime (Mesa lavapipe) and cross-compile the egui/eframe
# GUI test carpet cells into the per-arch Alpine rootfs. Each cell drives the official egui_kittest test
# harness, which renders an egui UI headlessly through egui_wgpu on the wgpu crate; wgpu selects the CPU
# adapter (= lavapipe), the same software Vulkan path cpu-wgpu-render proved on musl. No host GPU, one
# vCPU. The cells:
#   - egui_render:  builds a UI of known widgets (colored painter rect, label, button, checkbox), renders
#                   to an RGBA8 image and hard-asserts per-pixel against a closed-form reference (rect
#                   interior == its color, background == the Dark-theme panel fill), determinism, and
#                   font-AA-tolerant ink bounding boxes.
#   - egui_layout:  drives vertical / horizontal / grid layouts of fixed-size widgets and asserts each
#                   widget's Response.rect == the closed-form position (margin + item_spacing), plus
#                   resize re-layout.
#   - egui_interact: real egui_kittest event simulation - get_by_label(...).click(), type_text(...),
#                    arrow keys on a slider - asserting resulting state AND re-rendered pixels, with a
#                    disabled-widget negative control.
#   - egui_snapshot: renders a fixed composite UI and asserts a robust 8x8 pooled-luminance signature vs
#                    a committed golden (calibrated to the pinned egui version) + SHA fingerprint.
# Each cell is cross-compiled to <arch>-unknown-linux-musl (dynamic musl, -C target-feature=-crt-static,
# --release --locked), staged as its own binary; egui/egui_kittest are pinned to 0.32.3 and Cargo.lock is
# committed. A capability manifest lists the cells provisioned on this arch; run_all.sh gates on that set
# (fail==0 && total==cells==pass, >=1 cell floor).
#
# Env from the app runner: STARRY_ARCH, STARRY_ROOTFS, STARRY_STAGING_ROOT, STARRY_OVERLAY_DIR,
# STARRY_APP_DIR.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
arch="${STARRY_ARCH:?prebuild: STARRY_ARCH required}"
base_rootfs="${STARRY_ROOTFS:?prebuild: STARRY_ROOTFS required}"
staging_root="${STARRY_STAGING_ROOT:?prebuild: STARRY_STAGING_ROOT required}"
overlay_dir="${STARRY_OVERLAY_DIR:?prebuild: STARRY_OVERLAY_DIR required}"
CAR="$app_dir/programs/carpets"

case "$arch" in
    aarch64)     qemu_runner="qemu-aarch64-static";     rust_target="aarch64-unknown-linux-musl";     musl_cc="aarch64-linux-musl-gcc" ;;
    riscv64)     qemu_runner="qemu-riscv64-static";     rust_target="riscv64gc-unknown-linux-musl";   musl_cc="riscv64-linux-musl-gcc" ;;
    x86_64)      qemu_runner="qemu-x86_64-static";      rust_target="x86_64-unknown-linux-musl";      musl_cc="x86_64-linux-musl-gcc" ;;
    loongarch64) qemu_runner="qemu-loongarch64-static"; rust_target="loongarch64-unknown-linux-musl"; musl_cc="loongarch64-linux-musl-gcc" ;;
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

extract_base_rootfs() {
    rm -rf "$staging_root"; mkdir -p "$staging_root"
    debugfs -R "rdump / $staging_root" "$base_rootfs" >/dev/null 2>&1
    [[ -x "$staging_root/sbin/apk" ]] || { echo "prebuild: base rootfs has no apk" >&2; exit 2; }
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
    echo "prebuild: rootfs grown $((before/1024/1024)) -> $((after/1024/1024)) MiB for the mesa/lavapipe closure"
}

normalize_symlinks() {
    local link tgt rel
    while IFS= read -r link; do
        tgt="$(readlink "$link")"; [[ "$tgt" == /* ]] || continue
        rel="$(realpath -m --relative-to="$(dirname "$link")" "$staging_root$tgt")"
        ln -sf "$rel" "$link"
    done < <(find "$staging_root/lib" "$staging_root/usr/lib" -type l 2>/dev/null)
}

# mesa software Vulkan (lavapipe) + the Vulkan loader for the wgpu backend, musl for the target arch.
GPU_PKGS=(musl mesa-vulkan-swrast vulkan-loader vulkan-headers zlib)

apk_provision() {
    normalize_symlinks
    [[ -f /etc/resolv.conf ]] && cp -f /etc/resolv.conf "$staging_root/etc/resolv.conf" || true
    local edge="https://dl-cdn.alpinelinux.org/alpine"
    printf '%s/edge/main\n%s/edge/community\n' "$edge" "$edge" > "$staging_root/etc/apk/repositories"
    local apk_common=(--root "$staging_root" --repositories-file "$staging_root/etc/apk/repositories"
                      --keys-dir "$staging_root/etc/apk/keys" --no-progress --no-scripts)
    echo "prebuild: apk add Vulkan software stack (${GPU_PKGS[*]}) via $qemu_runner..."
    QEMU_LD_PREFIX="$staging_root" LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" "$staging_root/sbin/apk" "${apk_common[@]}" --update-cache add "${GPU_PKGS[@]}"
    [[ -f "$staging_root/usr/lib/libvulkan_lvp.so" ]] || { echo "prebuild: mesa-vulkan-swrast (lavapipe) not provisioned" >&2; exit 3; }
}

# The four egui_kittest carpet cells, each its own cargo crate. Cross-compiled to
# <arch>-unknown-linux-musl (dynamic musl; wgpu/egui carry their own wgpu-core/naga and dlopen
# libvulkan.so.1 at runtime), staged as its own binary.
CELLS=(egui_render egui_layout egui_interact egui_snapshot)
RUST_CHANNEL="${GUI_EGUI_RUST_CHANNEL:-nightly-2026-05-28-x86_64-unknown-linux-gnu}"
build_cells() {
    command -v cargo >/dev/null 2>&1 || { echo "prebuild: cargo required to build the egui carpet cells" >&2; exit 5; }
    command -v "$musl_cc" >/dev/null 2>&1 || { echo "prebuild: $musl_cc required on PATH to cross-link the musl carpets for $arch" >&2; exit 5; }
    local bin="$staging_root/opt/cpu-gui-egui-test"; mkdir -p "$bin"
    local link_var="CARGO_TARGET_$(echo "$rust_target" | tr 'a-z-' 'A-Z_')_LINKER"
    local cc_var="CC_$(echo "$rust_target" | tr '-' '_')"
    local cell
    for cell in "${CELLS[@]}"; do
        local srcdir="$CAR/$cell"
        [[ -f "$srcdir/Cargo.toml" ]] || { echo "prebuild: cell $cell source missing at $srcdir" >&2; exit 5; }
        local sbuild sout shome; sbuild="$(mktemp -d)"; sout="$(mktemp -d)"; shome="$(mktemp -d)"
        cp -a "$srcdir/." "$sbuild/"
        echo "prebuild: cross-build egui carpet $cell -> $rust_target (dynamic musl, lavapipe at runtime)"
        if ( cd "$sbuild" && env \
                CARGO_HOME="$shome" CARGO_TARGET_DIR="$sout" \
                CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
                "$cc_var=$musl_cc" "$link_var=$musl_cc" \
                RUSTFLAGS="-C target-feature=-crt-static" \
                cargo "+$RUST_CHANNEL" build --release --locked --target "$rust_target" ) \
           && [[ -f "$sout/$rust_target/release/$cell" ]]; then
            install -Dm0755 "$sout/$rust_target/release/$cell" "$bin/$cell"
            echo "prebuild: staged $cell for $rust_target (dynamic musl PIE)"
        else
            echo "prebuild: egui carpet $cell failed to build for $rust_target" >&2
            rm -rf "$sbuild" "$sout" "$shome"; exit 5
        fi
        rm -rf "$sbuild" "$sout" "$shome"
    done
    cp "$app_dir/programs/run_all.sh" "$bin/run_all.sh"; chmod +x "$bin/run_all.sh"
}

populate_overlay() {
    mkdir -p "$overlay_dir/usr/lib" "$overlay_dir/usr/share" "$overlay_dir/opt" "$overlay_dir/usr/bin"
    local mbin="$staging_root/opt/cpu-gui-egui-test"
    : > "$mbin/expected_cells"
    for c in "${CELLS[@]}"; do
        [[ -x "$mbin/$c" ]] && echo "$c" >> "$mbin/expected_cells"
    done
    echo "prebuild: expected_cells for $arch = $(tr '\n' ' ' < "$mbin/expected_cells")"
    cp -a "$staging_root/usr/lib/." "$overlay_dir/usr/lib/"
    cp -a "$staging_root/usr/share/vulkan" "$overlay_dir/usr/share/" 2>/dev/null || true
    cp -a "$staging_root/opt/cpu-gui-egui-test" "$overlay_dir/opt/"
    ln -sf /opt/cpu-gui-egui-test/run_all.sh "$overlay_dir/usr/bin/run_all.sh"
    echo "prebuild: overlay populated for $arch ($(du -sh "$overlay_dir/usr/lib" | cut -f1) libs)"
}

ensure_host_tools
grow_rootfs
extract_base_rootfs
apk_provision
build_cells
populate_overlay
echo "prebuild: cpu-gui-egui-test overlay ready for $arch"
