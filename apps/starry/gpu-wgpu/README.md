# gpu-wgpu (G-side, virtio-gpu vGPU)

Placeholder reserving the GPU-side counterpart of the CPU-side software carpet
`cpu-wgpu` (#1576). It exercises the same wgpu API surface and the same full
language-binding cartesian (C / C++ / Rust / Python / JS / TS / Kotlin) as the
CPU side, but against the qemu virtio-gpu virtual GPU device (wgpu-native on the virtio-gpu Vulkan/GL backend) under
-smp 1, instead of the wgpu-native on lavapipe/llvmpipe.

Blocked on the virtio-gpu 3D/compute driver bring-up (virtio-drivers 3D transport
plus the StarryOS render-node path). Tracked in
campaign-records/taskbook-G-virtio-gpu-bringup.md. Closed until the driver
foundation lands; it will be completed and reopened.
