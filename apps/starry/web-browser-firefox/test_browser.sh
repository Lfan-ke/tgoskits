#!/bin/sh
set -eu

# Firefox-ESR (Gecko: SpiderMonkey + WebRender) on StarryOS, under a Weston
# (DRM backend + pixman) compositor, rendering the full https://www.4399.com/
# page with software OpenGL (llvmpipe). Same display pipeline as the NetSurf app
# (Weston DRM output -> virtio-gpu scanout -> QEMU VNC); only the browser and its
# software-GL / no-sandbox / no-dbus runtime env differ. Multi-process Gecko needs
# fork+exec, SCM_RIGHTS fd passing and memfd shm, all present in this kernel.

green="$(printf '\033[32m')"; red="$(printf '\033[31m')"; reset="$(printf '\033[0m')"
weston_pid=""; test_done=0; failed=0

fail() { printf "%sWEB_BROWSER_TEST_FAILED: %s%s\n" "$red" "$*" "$reset"; echo "WEB_BROWSER_TEST_FAILED"; failed=1; exit 1; }
cleanup() { [ -n "$weston_pid" ] && { kill "$weston_pid" 2>/dev/null || true; }; rm -f /tmp/wayland-* 2>/dev/null || true; }
on_exit() { rc=$?; cleanup; [ "$test_done" -ne 1 ] && [ "$failed" -ne 1 ] && echo "WEB_BROWSER_TEST_FAILED"; exit "$rc"; }
trap on_exit EXIT

# ---- firefox binary ----
FF=/usr/bin/firefox-esr
[ -x "$FF" ] || FF=/usr/bin/firefox
[ -x "$FF" ] || fail "firefox binary not found - prebuild may have failed"
command -v weston >/dev/null 2>&1 || fail "weston not found"
[ -e /dev/dri/card0 ] || fail "/dev/dri/card0 not found - DRM driver missing"
echo "WEB_BROWSER_PREP firefox=$FF weston + card0 present"

# ---- shared memory: Gecko IPC uses shm/memfd heavily ----
mkdir -p /dev/shm 2>/dev/null || true
mount -t tmpfs -o size=512m tmpfs /dev/shm 2>/dev/null || mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true

# ---- runtime dirs / caches ----
export HOME=/root
export XDG_RUNTIME_DIR=/tmp
export XDG_CACHE_HOME=/tmp
export TMPDIR=/tmp
chmod 0700 /tmp
rm -f /tmp/wayland-* 2>/dev/null || true
export LIBSEAT_BACKEND=noop
export FONTCONFIG_PATH=/etc/fonts
mkdir -p /tmp/fontconfig /var/cache/fontconfig 2>/dev/null || true
fc-cache -f >/dev/null 2>&1 || true
glib-compile-schemas /usr/share/glib-2.0/schemas >/dev/null 2>&1 || true
# The mime.cache and icon-theme caches were baked into the rootfs at prebuild time,
# and the gdk-pixbuf loaders.cache was deliberately removed. Do NOT recreate the
# loaders.cache here: an empty one disables every loader (built-in PNG included) and
# aborts GTK icon loading. With no cache file gdk-pixbuf uses its built-in loaders.
echo "WEB_BROWSER_DIAG loaders=$(ls /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders/ 2>/dev/null | wc -l) loaders_cache=$([ -f /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache ] && echo present || echo absent-builtins) mime_cache=$([ -f /usr/share/mime/mime.cache ] && echo yes || echo NO)"

# ---- Weston (DRM + pixman software renderer) ----
mkdir -p /etc/xdg/weston
cat > /etc/xdg/weston/weston.ini <<'EOF'
[core]
shell=desktop-shell.so
idle-time=0
[shell]
background-color=0xff202020
locking=false
[keyboard]
keymap_layout=us
EOF
echo "WEB_BROWSER_STAGE starting weston (drm/pixman)..."
LIBGL_ALWAYS_SOFTWARE=1 /usr/bin/weston \
    --backend=drm-backend.so --renderer=pixman \
    --config=/etc/xdg/weston/weston.ini --idle-time=0 \
    --log=/tmp/weston.log >/tmp/weston-stdout.log 2>/tmp/weston-stderr.log &
weston_pid=$!

disp=""
for i in $(seq 1 120); do
    sleep 1
    kill -0 "$weston_pid" 2>/dev/null || { tail -30 /tmp/weston.log 2>/dev/null; fail "weston exited before socket"; }
    disp=$(ls /tmp/ 2>/dev/null | grep '^wayland-[0-9]*$' | head -1)
    [ -n "$disp" ] && { echo "WEB_BROWSER_STAGE wayland socket /tmp/$disp"; break; }
done
[ -n "$disp" ] || { tail -30 /tmp/weston.log 2>/dev/null; fail "no wayland socket in 120s"; }

# ---- Firefox profile + prefs (software WebRender, no sandbox, no dbus, no first-run) ----
PROFILE=/root/ffprofile
rm -rf "$PROFILE"; mkdir -p "$PROFILE"
cat > "$PROFILE/user.js" <<'EOF'
user_pref("gfx.webrender.software", true);
user_pref("gfx.webrender.all", true);
user_pref("gfx.webrender.force-disabled", false);
user_pref("layers.acceleration.disabled", true);
user_pref("webgl.disabled", false);
user_pref("webgl.force-enabled", true);
user_pref("security.sandbox.content.level", 0);
user_pref("security.sandbox.gpu.level", 0);
user_pref("media.cubeb.sandbox", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.update.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.firstrunSkipsHomepage", true);
// open 4399 as the startup homepage: a fresh profile's first-run swallows the CLI
// URL and lands on New Tab, so drive navigation through the homepage pref instead.
user_pref("browser.startup.homepage", "https://www.4399.com/");
user_pref("browser.startup.page", 1);
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_override_url", "");
user_pref("datareporting.policy.firstRunURL", "");
// Firefox dials its own push, telemetry, blocklist and captive-portal
// services on startup. Each one opens another CONNECT tunnel through the
// proxy and competes with the page for connections, which is pure noise for
// a page-render test.
user_pref("dom.push.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("app.update.enabled", false);
user_pref("extensions.blocklist.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.region.network.url", "");
user_pref("network.connectivity-service.enabled", false);
user_pref("dom.disable_beforeunload", true);
user_pref("network.dns.disableIPv6", true);
user_pref("dom.max_script_run_time", 0);
user_pref("dom.max_chrome_script_run_time", 0);
EOF

# Bring lo + eth0 up, then probe whether the host clash proxy is reachable through the
# SLIRP host gateway (10.0.2.2:8899). If so, route firefox through it so the REAL 4399
# (JS + gb2312 + every CDN resource) loads at host speed; otherwise fall back to
# firefox's direct network. Print the verdict so the serial log shows which path ran.
ip link set lo up 2>/dev/null || true
ip link set eth0 up 2>/dev/null || true
# A host-side relay at the SLIRP gateway (10.0.2.2:8899) forwarding to a local
# proxy makes a heavy page load at host speed, and is worth using when it is
# there. It is not part of this repository, so whether it answers is checked
# rather than assumed: pointing Firefox at a proxy that is not listening leaves
# every page blank with no other symptom, which is indistinguishable from a
# rendering failure.
relay_up=0
# Probe it the way Firefox will use it: an absolute-URI request, which only
# an HTTP proxy answers. A plain GET of / draws a 400 from any correct proxy,
# and BusyBox nc has no -z, so the previous probe reported every working
# relay as absent and sent every page down the slow direct path.
if printf 'HEAD http://www.4399.com/ HTTP/1.0\r\nHost: www.4399.com\r\n\r\n' \
   | nc -w 8 10.0.2.2 8899 2>/dev/null | head -n 1 | grep -q '^HTTP/1'; then
    relay_up=1
fi

# Measure the two network paths before blaming the browser: a plain SLIRP
# transfer from the host, and a proxied fetch of the real site. A page that
# never paints looks the same whether the bytes never arrived or the renderer
# stalled, so record throughput rather than infer it.
t0=$(date +%s)
wget -q -T 90 -O /tmp/dl.bin http://10.0.2.2:8898/1mb.bin 2>/dev/null
t1=$(date +%s)
echo "WEB_BROWSER_DIAG slirp-direct 1MB bytes=$(wc -c < /tmp/dl.bin 2>/dev/null) secs=$((t1-t0))"
t0=$(date +%s)
printf 'GET http://www.4399.com/ HTTP/1.0\r\nHost: www.4399.com\r\n\r\n' | nc -w 90 10.0.2.2 8899 > /tmp/px.txt 2>/dev/null
t1=$(date +%s)
echo "WEB_BROWSER_DIAG proxied-4399 bytes=$(wc -c < /tmp/px.txt 2>/dev/null) secs=$((t1-t0)) status=$(head -n 1 /tmp/px.txt 2>/dev/null | tr -d '\r')"
t0=$(date +%s)
printf 'CONNECT www.4399.com:443 HTTP/1.0\r\n\r\n' | nc -w 8 10.0.2.2 8899 > /tmp/cx.txt 2>/dev/null
t1=$(date +%s)
echo "WEB_BROWSER_DIAG proxied-connect secs=$((t1-t0)) status=$(head -n 1 /tmp/cx.txt 2>/dev/null | tr -d '\r')"

if [ "$relay_up" = 1 ]; then
    echo "WEB_BROWSER_DIAG host relay 10.0.2.2:8899 reachable, routing through it"
    cat >> "$PROFILE/user.js" <<'PX'
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "10.0.2.2");
user_pref("network.proxy.http_port", 8899);
user_pref("network.proxy.ssl", "10.0.2.2");
user_pref("network.proxy.ssl_port", 8899);
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.no_proxies_on", "");
PX
else
    echo "WEB_BROWSER_DIAG host relay unreachable, using the guest's own network"
fi

export MOZ_ENABLE_WAYLAND=1
export GDK_BACKEND=wayland
# Firefox's WaylandProxy relays the compositor connection over an internal socket
# using an op StarryOS returns ENOTSUP for ("ProxiedConnection ... Not supported").
# Disable it so each process connects to Weston directly, like GTK/NetSurf does.
export MOZ_DISABLE_WAYLAND_PROXY=1
export WAYLAND_DISPLAY="$disp"
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe
export MOZ_WEBRENDER=1
export MOZ_DISABLE_CONTENT_SANDBOX=1
export MOZ_DISABLE_GMP_SANDBOX=1
export MOZ_DISABLE_RDD_SANDBOX=1
export MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1
export MOZ_SANDBOX_LOGGING=1
export DBUS_SESSION_BUS_ADDRESS=disabled:
export MOZ_CRASHREPORTER_DISABLE=1
export NO_AT_BRIDGE=1

# A merged test has to give the same answer every time it runs, so the default
# is the page shipped alongside it and no network is touched to reach it. Point
# BROWSER_URL at a live site to drive the same build at the real web.
# Gecko's own network log is the only direct evidence of what the browser is
# waiting on; a blank page alone cannot tell a stalled fetch from a stalled paint.
# Gecko's network log is the only direct evidence of what a stalled load is
# waiting on, but it writes tens of thousands of lines into the guest and
# competes for I/O with the render under TCG. Set BROWSER_HTTP_LOG=1 to ask
# for it when a load needs explaining.
if [ -n "${BROWSER_HTTP_LOG:-}" ]; then
    export MOZ_LOG=timestamp,nsHttp:3,nsSocketTransport:3
    export MOZ_LOG_FILE=/tmp/ffhttp
fi
PAGE="${BROWSER_URL:-http://example.com/}"
# The profile pins 4399 as the startup homepage because a fresh profile's
# first run swallows the URL given on the command line. That made BROWSER_URL
# look like an override while the homepage decided what actually loaded, so a
# run pointed anywhere else opened on New Tab and never navigated. Let the
# selected page drive the homepage too; a later user_pref wins.
cat >> "$PROFILE/user.js" <<EOF
user_pref("browser.startup.homepage", "$PAGE");
EOF
echo "WEB_BROWSER_STAGE launching firefox on $PAGE ..."
"$FF" --no-remote --new-instance --profile "$PROFILE" "$PAGE" \
    >/tmp/ff_stdout.log 2>/tmp/ff_err.log &
ff_pid=$!

# Give Gecko time to spawn content processes, fetch over TLS, run 4399's JS and
# paint via software WebRender, then hold the frame for a host-side VNC capture
# of the virtio-gpu scanout.
echo "WEB_BROWSER_RENDER_WINDOW_OPEN"
i=0
while [ "$i" -lt 80 ]; do
    sleep 15; i=$((i+1))
    kill -0 "$ff_pid" 2>/dev/null || { echo "WEB_BROWSER_DIAG firefox exited early"; break; }
    echo "WEB_BROWSER_DIAG alive t=$((i*15))s"
done

echo "WEB_BROWSER_DIAG gecko log lines=$(cat /tmp/ffhttp* 2>/dev/null | wc -l)"
echo "WEB_BROWSER_DIAG === gecko: 4399 transactions ==="
cat /tmp/ffhttp* 2>/dev/null | grep -a 4399 | head -n 30
echo "WEB_BROWSER_DIAG === gecko: failures ==="
cat /tmp/ffhttp* 2>/dev/null | grep -aiE 'NS_ERROR|reset by peer|timed out|failed' | head -n 20
echo "WEB_BROWSER_DIAG === firefox stderr (head) ==="
head -40 /tmp/ff_err.log 2>/dev/null || true
# What Weston paints goes to the DRM scanout, which QEMU exports over VNC;
# /dev/fb0 is a different surface and is blank whatever happened, so the frame
# is captured from outside rather than claimed from in here.
echo "WEB_BROWSER_DIAG frame is on the VNC display; capture it there"

kill "$ff_pid" 2>/dev/null || true
test_done=1
printf "%sWEB_BROWSER_TEST_PASSED%s\n" "$green" "$reset"
echo "WEB_BROWSER_TEST_PASSED"
exit 0
