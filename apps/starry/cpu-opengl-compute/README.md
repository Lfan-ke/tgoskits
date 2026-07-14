# cpu-opengl-compute

Per-binding desktop-OpenGL compute carpet on StarryOS. OpenGL runs as a CPU software implementation:
Mesa llvmpipe provides a real GL 4.5 core context whose GL 4.3 compute pipeline (`glDispatchCompute`)
executes on the LLVM CPU JIT, so no host GPU is required. The on-target StarryOS gate builds and runs
every cell over the same surfaceless-EGL desktop-GL path: the two C carpets (`opengl_c_egl`, `opengl_c`,
both reworked from OSMesa to surfaceless-EGL), the C++ carpet (`opengl_cpp`), the glow (Rust) cell
(`opengl_rust`, dynamic musl) and the PyOpenGL cell (`opengl_py`); the moderngl (Python) cell
(`opengl_moderngl`) is provisioned best-effort and gated where the native extension resolves. There is no
separate host-only layer - `programs/run_all.sh` is the single runner, and it gates exactly the cells the
prebuild wired into the per-arch manifest. Each cell enumerates the compute-relevant GL
API surface against the real `GL/gl.h` / `GL/glcorearb.h` headers (or the binding's documented API),
dispatches GLSL 430 compute shaders and checks every result element against a numpy or closed-form
reference, and drives the error paths against real `GL_INVALID_*` enums. A cell prints `<name> OK <n>`
only when its failure count is zero and the assertion total equals a pinned `EXPECTED` constant.

## Cells and assertions

| Cell | Binding | Context | Runs |
|:--|:--|:--|:--|
| `opengl_c_egl` | GL C API + `eglGetProcAddress` loader | EGL surfaceless | on-target (all arches) |
| `opengl_c` | GL C API + `eglGetProcAddress` loader | EGL surfaceless | on-target (all arches) |
| `opengl_cpp` | GL C++ + DSA (`glMapNamedBufferRange`, program-uniform) | EGL surfaceless | on-target (all arches) |
| `opengl_py` | PyOpenGL + numpy | EGL surfaceless | on-target (all arches; `py3-opengl`) |
| `opengl_moderngl` | moderngl + numpy | standalone (llvmpipe) | on-target where moderngl resolves (x64/aa apk; rv/la sdist follow-up) |
| `opengl_rust` | glow + khronos-egl (dynamic musl) | EGL surfaceless | on-target (all arches) |

Every wired cell reports its own assertion count at runtime as `<name> OK <n>`, and `run_all.sh` gates on
all of them (`fail==0 && total==EXPECTED==pass`, `EXPECTED>=1` floor). The exact `<n>` per cell is the
authoritative count printed on-target; the assertion coverage of each cell is described below.

Each cell covers the compute API end to end: surfaceless EGL context creation
 - make-current - GL version/renderer introspection - compute work-group limit queries -
GLSL 430 compute-shader compile (plus a compile-error path asserting `GL_COMPILE_STATUS == GL_FALSE`
with a non-empty info log) - program link (plus a link-error path) - SSBO create / `glBufferData` /
`glBufferStorage` / `glBindBufferBase` / `glBindBufferRange` - uniform set + read-back -
`glDispatchCompute` + `glMemoryBarrier` - `glDispatchComputeIndirect` - fence sync
(`glFenceSync` / `glClientWaitSync` / `glGetSynciv`) - timer query (`GL_TIME_ELAPSED` /
`glQueryCounter`) - map read / map write + explicit flush - `glGetBufferSubData` readback -
`glCopyBufferSubData` / `glClearBufferData` - program-resource reflection
(`glGetProgramResourceIndex` / `glGetProgramInterfaceiv` / `glGetProgramResourceiv` /
`glGetProgramResourceName`). The operators (vector-add, saxpy including `alpha=0`, element-multiply and
a shared-memory tree reduction) are dispatched as real GLSL compute shaders and every output element is
compared to the closed-form / numpy reference with a relative tolerance. Boundary cases (zero-size
dispatch left as a no-op, a non-divisible tail guard, oversubscription with an `i>=n` guard, and a
`1<<20`-element grid verified element-wise) and error paths are asserted directly against the real GL
enum (`GL_INVALID_VALUE` / `GL_INVALID_OPERATION` / `GL_INVALID_ENUM`), and each operator carries a
negative control proving the checker rejects a wrong reference.

## Backend and runtime

Provisioned from Alpine edge (main + community) as musl packages: `mesa-gl` (libGL), `mesa-egl`
(libEGL), `mesa-gles` and `mesa-dri-gallium` (the llvmpipe gallium DRI driver), plus the `llvm-libs`
closure llvmpipe links against. Alpine edge builds these for all four target architectures (x86_64,
aarch64, riscv64, loongarch64), so the surfaceless-EGL desktop-GL carpet runs on-target on every arch.
`prebuild.sh` cross-compiles the C/C++ cells **on the host** against the provisioned musl
headers/libraries (`apk` itself still runs under qemu-user - only `gcc`/`cc1` cannot, since gcc spawns
`cc1` via `posix_spawn` which qemu-user cannot exec). The GL/glcorearb.h, EGL and KHR headers are
vendored under `programs/headers` (Alpine's `mesa-dev` is the only package carrying `glcorearb.h` and it
pulls a large clang closure the runtime does not need). Alpine edge's mesa `libEGL`/`libGL` carry
`DT_RELR` (`.relr.dyn`, section type `0x13`) relocations that GNU ld 2.37 in the musl-cross toolchains
rejects; the link uses a RELR-aware linker - `${triple}-gcc/g++ -fuse-ld=lld` when a standalone `ld.lld`
is reachable, else `zig cc`/`zig c++` (which bundle their own LLD). The prebuild therefore needs, on the
build host: `qemu-user-static` + `e2fsprogs` (rootfs provisioning), a musl cross toolchain
(`${triple}-gcc`/`g++`, e.g. from `/opt/<triple>-linux-musl-cross`), a RELR-aware linker (any LLVM
`ld.lld`, i.e. the `lld` package, or a `zig` on PATH), and a Rust nightly with the target added
(`rustup target add`) plus crates.io access for the glow cell. It then stages the binaries plus the mesa
closure into the per-arch rootfs. `programs/run_all.sh` runs the native carpets and prints `TEST PASSED`
when every wired cell reports `OK` and none
fails.

Runtime environment on target:

- `EGL_PLATFORM=surfaceless` creates a desktop-GL 4.3 context with no window-system surface.
- `LIBGL_ALWAYS_SOFTWARE=1` + `GALLIUM_DRIVER=llvmpipe` pin the gallium DRI driver to the llvmpipe CPU
  software rasterizer.
- `XDG_RUNTIME_DIR` points at a writable directory.
- `LP_NUM_THREADS=1` pins the mesa thread pool to one thread, matching StarryOS's single vCPU.

## Per-binding coverage (all on-target)

Every cell drives the same surfaceless-EGL desktop-GL path on-target; there is no host-only cell.

- `opengl_c_egl` / `opengl_c` (C, `eglGetProcAddress` loader): both were reworked from OSMesa to
  surfaceless-EGL (GL 1.x symbols from libGL, GL 4.3 compute entry points via `eglGetProcAddress`), so
  both build and run on-target on every arch. `opengl_c` carries the shared-memory reduction / 2D-grid
  dispatch / indirect-dispatch / injected `GL_INVALID_*` / program-resource-reflection coverage that
  `opengl_c_egl` does not.
- `opengl_cpp` (C++, DSA + program-uniform): reworked from OSMesa to the same surfaceless-EGL path, built
  and run on-target on every arch - the matrix's C++ desktop-GL compute binding.
- `opengl_rust` (glow + khronos-egl): cross-compiled to a **dynamic** musl binary
  (`-C target-feature=-crt-static`); khronos-egl's `dynamic` feature `dlopen()`s the provisioned `libEGL`
  at runtime, requests a GL 4.5 core context over EGL-surfaceless and drives the compute lifecycle through
  glow's safe wrappers - the same surfaceless-EGL path as `opengl_c_egl`. Built and run on-target on
  every arch.
- `opengl_py` (PyOpenGL + numpy): binds the GL 4.3 compute API over the same surfaceless-EGL context;
  provisioned from `py3-opengl` (Alpine community, every arch) and wired on-target - the matrix's Python
  desktop-GL compute binding.
- `opengl_moderngl` (moderngl standalone headless-EGL context): provisioned best-effort
  (`apk add py3-moderngl` + python3 + numpy) and appended to the manifest on every arch where the native
  extension resolves - Alpine builds it for x86_64/aarch64; rv/la may need an sdist build (a follow-up),
  in which case it is honestly omitted from that arch's manifest and `run_all.sh` does not gate on it.

## Single-core execution

StarryOS runs on one vCPU (SMP is off by default), so llvmpipe's LLVM JIT executes every workgroup on a
single thread. `run_all.sh` pins the mesa thread pool with `LP_NUM_THREADS=1` and prints the detected
CPU count, so the single-core reality is explicit in the output. The carpets assert numerical
correctness and API ordering semantics, not throughput; the results are independent of thread count.

## Run

```
cargo xtask starry app qemu -t cpu-opengl-compute --arch x86_64
cargo xtask starry app qemu -t cpu-opengl-compute --arch aarch64
cargo xtask starry app qemu -t cpu-opengl-compute --arch riscv64
cargo xtask starry app qemu -t cpu-opengl-compute --arch loongarch64
```
