# gpu-opengl (G-side, virtio-gpu vGPU)

Placeholder reserving the GPU-side counterpart of the CPU-side software carpet
`cpu-opengl` (#1609). It exercises the same OpenGL API surface and the same full
language-binding cartesian (C / C++ / Rust / Python / JS / TS / Kotlin) as the
CPU side, but against the qemu virtio-gpu virtual GPU device (virtio-gpu OpenGL (virgl over the 3D render node)) under
-smp 1, instead of the llvmpipe CPU software rasterizer.

Blocked on the virtio-gpu 3D/compute driver bring-up (virtio-drivers 3D transport
plus the StarryOS render-node path). Tracked in
campaign-records/taskbook-G-virtio-gpu-bringup.md. Closed until the driver
foundation lands; it will be completed and reopened.
