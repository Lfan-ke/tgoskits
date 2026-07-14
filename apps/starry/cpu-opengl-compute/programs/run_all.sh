#!/bin/sh
# On-target runner: set up the software desktop-OpenGL runtime and run the native OpenGL compute
# carpets. Prints "TEST PASSED" only when every built carpet reports its "<name> OK <n>" marker.
set -u
BIN=/opt/cpu-opengl-compute
mkdir -p /tmp/glrt
export XDG_RUNTIME_DIR=/tmp/glrt
export LD_LIBRARY_PATH=/usr/lib
# surfaceless EGL: create a desktop-GL 4.3 context with no window-system surface, over the gallium
# llvmpipe DRI driver (CPU software rendering, no GPU).
export EGL_PLATFORM=surfaceless
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe
# StarryOS runs one vCPU (SMP off by default), so llvmpipe's LLVM JIT executes every workgroup on one
# thread. Pin the mesa thread pool to 1 to make that explicit. The carpets assert numerical
# correctness against closed-form references, not throughput, so thread count does not affect results.
export LP_NUM_THREADS=1
ncpu=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo '?')
echo "cpu-opengl-compute: detected CPU count = $ncpu; llvmpipe pinned single-threaded (LP_NUM_THREADS=1)"

pass=0; total=0; fail=0
run() {
    name="$1"; prog="$2"
    [ -x "$prog" ] || { echo "cpu-opengl-compute: $name in manifest but binary absent at runtime"; total=$((total + 1)); fail=$((fail + 1)); return 0; }
    total=$((total + 1))
    out="$(cd "$BIN" && "$prog" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qE "OK [0-9]+$"; then
        echo "$out" | grep -E ": PASS=|OK [0-9]+$" | tail -1
        pass=$((pass + 1))
    else
        echo "$out" | tail -6
        echo "CARPET FAILED: $name (exit $rc)"
        fail=$((fail + 1))
    fi
}

cd "$BIN" || exit 1
# Capability manifest: prebuild lists the cells it provisioned on this arch - opengl_c_egl / opengl_c /
# opengl_cpp (surfaceless-EGL desktop GL, every arch) and opengl_rust (glow, dynamic musl, every arch)
# build unconditionally; opengl_py (PyOpenGL over surfaceless EGL) and opengl_moderngl append where
# their binding resolved. Each cell drives GL 4.3 compute over surfaceless-EGL + llvmpipe: context/make-current,
# compute-shader compile+link incl. error paths, SSBO create-map-bind-unmap, uniform, glDispatchCompute
# + glMemoryBarrier, glDispatchComputeIndirect, fence sync, timer query, glGetBufferSubData readback,
# copy/clear-buffer-data, program-resource reflection, GL_INVALID_* error paths, zero-size + 1M-element
# boundary dispatch - every operator result checked element-wise against a closed-form reference.
MANIFEST="$BIN/expected_cells"
[ -f "$MANIFEST" ] || { echo "cpu-opengl-compute: expected_cells manifest missing - prebuild provisioned no carpet"; echo "TEST FAILED"; exit 1; }
EXPECTED=$(grep -c . "$MANIFEST")
while IFS= read -r cell; do
    [ -n "$cell" ] || continue
    run "$cell" "$BIN/$cell"
done < "$MANIFEST"

# Floor: opengl_c_egl / opengl_c / opengl_cpp / opengl_rust are guaranteed native cells on every arch,
# so EXPECTED<1 means a broken provision - a FAIL, never a vacuous pass. Above the floor the gate is the
# canonical strict triple-check against the manifest count.
echo "cpu-opengl-compute: $pass/$total carpets OK on $(uname -m) (expected $EXPECTED: $(tr '\n' ' ' < "$MANIFEST"))"
if [ "$EXPECTED" -ge 1 ] && [ "$fail" -eq 0 ] && [ "$total" -eq "$EXPECTED" ] && [ "$pass" -eq "$EXPECTED" ]; then
    echo "TEST PASSED"; exit 0
else
    echo "cpu-opengl-compute: GATE FAILED - need all $EXPECTED manifest carpets to pass (>=1 floor); got fail=$fail total=$total pass=$pass"
    echo "TEST FAILED"; exit 1
fi
