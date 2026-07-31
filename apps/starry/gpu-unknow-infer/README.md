# gpu-unknow-infer (GPU virtio-gpu vGPU (-smp1), unified inference capstone)

Placeholder reserving the unified inference capstone of the entire parallel-compute matrix on the GPU virtio-gpu vGPU side. llama.cpp runs qw (Qwen) and ds (DeepSeek) greedy token-by-token, asserted == the CPU reference, across the inference-capable backends (Vulkan + OpenCL). The "unknow" slot marks that this spans ALL parallel-compute stacks rather than a single backend - the final end-to-end validation after the compute and rendering tracks. Later extended with vLLM / TVM.

Industrial-grade: deterministic greedy decode parity per model x backend, four-arch on-target. Closed until implemented; it will be completed and reopened.
