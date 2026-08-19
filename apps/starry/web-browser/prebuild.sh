#!/usr/bin/env bash
set -euo pipefail

# Assembles an Alpine rootfs overlay that runs the NetSurf web browser under a
# Weston (DRM backend + pixman software renderer) compositor on StarryOS. Reuses
# the exact Alpine-apk-over-qemu-user staging model proven by the qt-calc app;
# only the installed package set (NetSurf + GTK3 stack instead of Qt6) and the
# launched application differ.

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
arch="${STARRY_ARCH:-x86_64}"
base_rootfs="${STARRY_ROOTFS:-${STARRY_BASE_ROOTFS:-}}"
staging_root="${STARRY_STAGING_ROOT:-}"
overlay_dir="${STARRY_OVERLAY_DIR:-}"
# Reuse the qt-calc apk cache: weston/fonts/input libs are shared, so only the
# NetSurf + GTK3 packages are newly downloaded. Alpine's aliyun mirror is the
# one empirically proven to work here (qt-calc installs 200+ pkgs through it);
# dl-cdn over the local proxy is unreliable for a 600 MB+ pull.
apk_cache="${STARRY_WORKSPACE:-$(cd "$app_dir/../../.." && pwd)}/target/qalc-apk-cache"

require_env() {
    local name="$1"
    local value="$2"
    if [[ -z "$value" ]]; then
        echo "error: $name is required" >&2
        exit 1
    fi
}

ensure_host_packages() {
    local missing=()
    command -v debugfs >/dev/null 2>&1 || missing+=(e2fsprogs)
    command -v install >/dev/null 2>&1 || missing+=(coreutils)
    command -v readelf >/dev/null 2>&1 || missing+=(binutils)

    case "$arch" in
        aarch64)     command -v qemu-aarch64-static >/dev/null 2>&1 || missing+=(qemu-user-static) ;;
        riscv64)     command -v qemu-riscv64-static >/dev/null 2>&1 || missing+=(qemu-user-static) ;;
        x86_64)      command -v qemu-x86_64-static >/dev/null 2>&1 || missing+=(qemu-user-static) ;;
        loongarch64) command -v qemu-loongarch64-static >/dev/null 2>&1 || missing+=(qemu-user-static) ;;
    esac

    if [[ ${#missing[@]} -eq 0 ]]; then
        return
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "error: missing required host packages and apt-get is unavailable: ${missing[*]}" >&2
        exit 1
    fi

    echo "installing missing host packages: ${missing[*]}"
    apt-get update
    apt-get install -y --no-install-recommends "${missing[@]}"
}

extract_base_rootfs() {
    debugfs -R "rdump / $staging_root" "$base_rootfs" >/dev/null
}

resize_rootfs() {
    local img="$1"
    local target_mib="$2"
    local current_mib
    current_mib=$(stat --format=%s "$img" 2>/dev/null | awk '{print int($1/1048576)}')
    if [ "$current_mib" -ge "$target_mib" ]; then
        return
    fi
    local extra=$((target_mib - current_mib))
    echo "[browser prebuild] enlarging rootfs from ${current_mib}M to ${target_mib}M (+${extra}M)..."
    dd if=/dev/zero bs=1M count="$extra" >> "$img" 2>/dev/null
    e2fsck -f "$img" >/dev/null 2>&1 || true
    resize2fs "$img" >/dev/null
}

install_packages() {
    local qemu_runner
    case "$arch" in
        aarch64)     qemu_runner="qemu-aarch64-static" ;;
        riscv64)     qemu_runner="qemu-riscv64-static" ;;
        x86_64)      qemu_runner="qemu-x86_64-static" ;;
        loongarch64) qemu_runner="qemu-loongarch64-static" ;;
        *)           echo "error: unsupported arch: $arch" >&2; exit 1 ;;
    esac

    if ! command -v "$qemu_runner" >/dev/null 2>&1; then
        echo "error: $qemu_runner not found" >&2
        exit 1
    fi

    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf "$staging_root/etc/resolv.conf"
    fi

    mkdir -p "$apk_cache"

    cat > "$staging_root/etc/apk/repositories" <<'REPO'
https://mirrors.aliyun.com/alpine/v3.23/main
https://mirrors.aliyun.com/alpine/v3.23/community
REPO

    # apk itself needs libz, which the base Alpine rootfs does not ship; fetch
    # the musl-linked libz apk directly and unpack it before running apk.
    local zlib_url="https://mirrors.aliyun.com/alpine/v3.23/main/${arch}/zlib-1.3.2-r0.apk"
    local zlib_apk="$apk_cache/zlib-1.3.2-r0.apk"
    if [[ ! -f "$zlib_apk" ]]; then
        echo "[browser prebuild] downloading zlib apk..."
        wget -q --timeout=30 -O "$zlib_apk" "$zlib_url" || curl -fsSL --connect-timeout 15 --max-time 30 -o "$zlib_apk" "$zlib_url" || true
    fi
    if [[ -f "$zlib_apk" ]] && [[ -s "$zlib_apk" ]]; then
        tar xzf "$zlib_apk" -C "$staging_root" --no-same-owner 2>/dev/null || true
        echo "[browser prebuild] extracted zlib from zlib-1.3.2-r0.apk"
    fi

    echo "[browser prebuild] installing NetSurf + Weston via qemu-user apk..."
    QEMU_LD_PREFIX="$staging_root" \
    LD_LIBRARY_PATH="$staging_root/lib:$staging_root/usr/lib" \
        "$qemu_runner" -L "$staging_root" \
            "$staging_root/sbin/apk" \
            --root "$staging_root" \
            --repositories-file "$staging_root/etc/apk/repositories" \
            --keys-dir "$staging_root/etc/apk/keys" \
            --cache-dir "$apk_cache" \
            --update-cache \
            --no-progress \
            --no-scripts \
            add weston weston-backend-drm weston-shell-desktop \
                netsurf ca-certificates \
                font-dejavu fontconfig \
                gsettings-desktop-schemas shared-mime-info \
                libinput libxkbcommon pixman xkeyboard-config \
                fbgrab
}

populate_overlay() {
    echo "[browser prebuild] copying usr/ tree from staging to overlay..."
    (cd "$staging_root" && find usr \( -type f -o -type l \) | while read -r rel; do
        local src="$staging_root/$rel"
        local target="$overlay_dir/$rel"
        mkdir -p "$(dirname "$target")"
        rm -f "$target" 2>/dev/null || true
        cp -d "$src" "$target" 2>/dev/null || true
    done)

    if [[ -d "$staging_root/lib" ]]; then
        echo "[browser prebuild] copying lib/ tree from staging to overlay..."
        (cd "$staging_root" && find lib \( -type f -o -type l \) | while read -r rel; do
            local src="$staging_root/$rel"
            local target="$overlay_dir/$rel"
            mkdir -p "$(dirname "$target")"
            rm -f "$target" 2>/dev/null || true
            cp -d "$src" "$target" 2>/dev/null || true
        done)
    fi

    # GTK + fontconfig runtime config. NetSurf is a GTK3 app and aborts
    # ("Cannot load default config file") without a fontconfig config. Under
    # apk --no-scripts the Alpine fontconfig config is not staged, and our usr/
    # + lib/ copy skips /etc, so carry the GTK config trees and synthesize a
    # minimal /etc/fonts/fonts.conf pointing at the bundled dejavu fonts.
    for sub in etc/gtk-3.0 etc/xdg etc/fonts; do
        if [[ -d "$staging_root/$sub" ]]; then
            (cd "$staging_root" && find "$sub" \( -type f -o -type l \) | while read -r rel; do
                mkdir -p "$overlay_dir/$(dirname "$rel")"
                cp -d "$staging_root/$rel" "$overlay_dir/$rel" 2>/dev/null || true
            done)
        fi
    done
    mkdir -p "$overlay_dir/etc/fonts" "$overlay_dir/var/cache/fontconfig"
    if [[ ! -f "$overlay_dir/etc/fonts/fonts.conf" ]]; then
        cat > "$overlay_dir/etc/fonts/fonts.conf" <<'FC'
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <dir>/usr/share/fonts</dir>
  <cachedir>/var/cache/fontconfig</cachedir>
  <cachedir>/tmp/fontconfig</cachedir>
</fontconfig>
FC
    fi

    # A self-contained local page so the first render does not depend on the
    # network; the test also attempts a real http fetch afterwards.
    install -Dm0644 "$app_dir/test.html" "$overlay_dir/usr/share/web-browser/test.html"

    # Test script
    install -Dm0755 "$app_dir/test_browser.sh" "$overlay_dir/usr/bin/test-browser.sh"
}

require_env STARRY_ROOTFS "$base_rootfs"
require_env STARRY_STAGING_ROOT "$staging_root"
require_env STARRY_OVERLAY_DIR "$overlay_dir"

ensure_host_packages
resize_rootfs "$base_rootfs" 2560
extract_base_rootfs
install_packages
populate_overlay
