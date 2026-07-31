# gpu-webgpu (G-side, virtio-gpu vGPU)

Placeholder reserving the GPU-side counterpart of the CPU-side software carpet
`cpu-webgpu` (#1578). It exercises the same WebGPU API surface and the same full
language-binding cartesian (C / C++ / Rust / Python / JS / TS / Kotlin) as the
CPU side, but against the qemu virtio-gpu virtual GPU device (Node/Deno dawn on the virtio-gpu backend) under
-smp 1, instead of the Node/wgpu-native CPU software.

Blocked on the virtio-gpu 3D/compute driver bring-up (virtio-drivers 3D transport
plus the StarryOS render-node path). Tracked in
campaign-records/taskbook-G-virtio-gpu-bringup.md. Closed until the driver
foundation lands; it will be completed and reopened.
