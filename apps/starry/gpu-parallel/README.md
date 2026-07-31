# gpu-parallel (G-side, virtio-gpu vGPU)

Placeholder reserving the GPU-side counterpart of the CPU-side software carpet
`cpu-parallel` (#1648). It exercises the same parallel compute API surface and the same full
language-binding cartesian (C / C++ / Rust / Python / JS / TS / Kotlin) as the
CPU side, but against the qemu virtio-gpu virtual GPU device (concurrent dispatch on the virtio-gpu vGPU) under
-smp 1, instead of the lavapipe/pocl concurrent CPU software.

Blocked on the virtio-gpu 3D/compute driver bring-up (virtio-drivers 3D transport
plus the StarryOS render-node path). Tracked in
campaign-records/taskbook-G-virtio-gpu-bringup.md. Closed until the driver
foundation lands; it will be completed and reopened.
