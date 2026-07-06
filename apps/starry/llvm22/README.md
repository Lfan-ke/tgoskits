# llvm22 - LLVM 22 工具链地毯式测试

工业级、精确断言（exact-assertion）的 LLVM 22 工具链正确性测试：由 **musl 原生 LLVM 22.1.x**
（Alpine `apk add llvm22 clang22 lld22 g++ ...`）在 StarryOS 四个架构（x86_64 / aarch64 / riscv64 /
loongarch64）上运行真实的工具，针对一组 LLVM IR / C / C++ 测例，覆盖工业级测试的七个维度（文档逐项、
`--help`/`--version`、逐选项单测、功能输出、边界输入、异常处理、集成流水线），每项一条精确断言。
**不使用交叉编译产物替代**: `lli`、`llc`、`opt`、`clang`、`clang++`、`lld`、`llvm-ar` 等本体都在
StarryOS 上运行。

枚举式、矩阵式：后端的每个已注册目标、优化级、前端语言、输出形式、IR pass、IR/目标工具都逐格一条精确断言。

| 维度 | 覆盖 | 断言数 |
|:--|:--|:--:|
| `llvm-config` | `--version` 主版本号 = 22；`--targets-built` 枚举含 X86 / AArch64 / RISCV / LoongArch / ARM / Mips / PowerPC / SystemZ / WebAssembly / BPF / Sparc / AVR / MSP430 / Hexagon / NVPTX / AMDGPU / SPIRV / VE / Lanai / XCore | 21 |
| `--version` 汇总 | 21 个工具（`llvm-as`/`-dis`/`-link`/`-nm`/`-objdump`/`-ar`/`-extract`/`-bcanalyzer`/`-cat`/`-mc`/`-readelf`/`-size`/`-strings`/`-objcopy`/`-strip`/`-cxxfilt`/`-dwarfdump`/`-diff`/`opt`/`llc`/`lli`）各报告 `LLVM version 22.x`；`opt --print-passes` 列出 mem2reg+instcombine；`FileCheck --help` 退出 0 | 23 |
| **后端矩阵：汇编** | `llc --version` 全部 **47** 个已注册目标 × `-O0/-O1/-O2/-O3`，每格 `-filetype=asm` 产出含函数符号 | 188 |
| **后端矩阵：目标码** | **44** 个可产出目标码的目标 × `-O0/-O1/-O2/-O3`，每格 `-filetype=obj` 校验精确签名（ELF 魔数 + 逐目标 `e_machine`；SPIR-V 魔数；wasm 魔数）。`nvptx`/`nvptx64`/`xcore` 无目标码发射器，仅汇编 | 176 |
| `llc` 本机 + 目标工具 | 本机汇编（`.globl main`）与 ELF 目标；`llvm-nm`（`T main`）/`llvm-objdump`/`llvm-readelf`/`llvm-size`/`llvm-strings`/`llvm-objcopy`/`llvm-strip`/`llvm-cxxfilt`（demangle）/`llvm-mc`（汇编→目标）/`llvm-dwarfdump`（`-g` 编译单元） | 12 |
| `llvm-as` / `llvm-dis` | IR→bitcode（`BC C0 DE` 魔数）；bitcode→IR（含 `@main`）；往返可重汇编；空模块（边界）合法 bitcode；`verify-uselistorder` use-list 往返 | 5 |
| `lli`（JIT） | hello 精确 stdout；算术退出码；1..100 循环求和 = 5050；递归 `fib(10)` = 55；1000 条 add 链大 IR（边界）退出码 = 232 | 5 |
| `opt` 精确变换 | `mem2reg`/`sroa` 消 alloca；`instcombine` 折 `(x*1)+0`→`x`；`inline` 消调用点；`gvn` 消冗余 load；`dce`/`adce` 删死指令；`simplifycfg` 折分支链；`sccp` 解常量分支；`constmerge` 合并常量；`globaldce` 删无用全局；`deadargelim` 删无用参数；`early-cse` 消公共子表达式；`dse` 删被覆盖 store；`tailcallelim` 消尾递归；`loop-unroll` 全展开定长循环 | 17 |
| `opt` 优化级 | `-O0` 保留 alloca、`-O1`/`-O2`/`-O3`/`default<O2>` 提升 SSA；`llvm-as \| opt \| llvm-dis` bitcode 流水线 | 6 |
| `opt` pass 枚举 | 更广的 pass 集逐个 run-clean（`loop-rotate`/`loop-simplify`/`lcssa`/`indvars`/`loop-deletion`/`jump-threading`/`correlated-propagation`/`aggressive-instcombine`/`mldst-motion`/`sink`/`memcpyopt`/`newgvn`/`function-attrs`/`argpromotion`/`ipsccp`/`called-value-propagation`/`globalopt`/`reassociate`/`licm`/`slp-vectorizer`/`loop-vectorize`），各产出 verifier 合法 IR | 21 |
| IR 模块工具 | `llvm-link` 合并模块；`llvm-extract` 抽单个函数；`llvm-bcanalyzer` 报 bitcode 结构；`llvm-cat` 拼接 bitcode；`llvm-diff` 同模块无差异 | 5 |
| `llvm-ar` | `rcs` 建库（`!<arch>` 魔数）；`t` 列成员；`llvm-nm` 读符号索引；`x` 抽取成员 | 4 |
| `FileCheck` | 正例匹配 + 反例（缺失模式必须失败，证明其判别） | 2 |
| `clang`（C 前端矩阵） | `--version` = 22.x；C→IR（`@main`+`@printf`）/→汇编/→目标（ELF）/→可执行运行；`-std=c99/c11/c17/c23/gnu11/gnu17/gnu23` 各产出目标；`-O0/-O1/-O2/-O3` 各链接运行；`-O2 -lm`（`sqrt(2)`） | 17 |
| `clang++`（C++ 前端矩阵） | `--version` = 22.x；C++→IR（Itanium mangling `_ZN7Counter…`）/→汇编/→目标/→可执行（模板 + STL `std::vector`/`std::string`）；`-std=c++17/c++20/c++23` 各产出目标 | 8 |
| `clang`（Objective-C 前端） | `-x objective-c`→IR（含 `OBJC_CLASS`+`OBJC_METACLASS` 元数据）/→本机目标；不做运行时链接 | 2 |
| `lld` | `ld.lld --version` = 22.x；`clang -fuse-ld=lld` 链接并运行 | 2 |
| 异常处理 | 畸形 IR 被 `llvm-as`/`llc` 拒绝；未知 pass 名被 `opt` 拒绝；缺失输入被 `lli` 拒绝 | 4 |
| 集成流水线 | `clang -emit-llvm \| opt -O2 \| llc \| clang -fuse-ld=lld` 端到端；`opt -O2` 优化后 IR 回灌 `lli` 仍算 SUM=5050 | 2 |

**Fortran / flang**: Alpine edge 无 `flang22` 包，LLVM Fortran 前端未随工具链提供，据实记录、未测（非 StarryOS 问题）。

断言全部针对**与补丁版本无关的稳定不变量**（精确整数、闭式代数、bitcode 魔数、逐目标 ELF `e_machine`、
Itanium 符号名、固定 stdout 字符串），因此宿主参照工具与目标端 Alpine 工具（22.1.8）给出逐字相同的结果。
`programs/run-llvm22.sh` 依次执行全部 520 项检查，仅当全部通过时才打印 `LLVM22_OK=520/520` 与
`TEST PASSED`（尾部锚点仅在脚本内出现，success_regex 不会自匹配启动命令）；任一失败则打印 `TEST FAILED`。
**不允许跳过**。

## 运行

```
cargo xtask starry app qemu -t llvm22 --arch x86_64
cargo xtask starry app qemu -t llvm22 --arch aarch64
cargo xtask starry app qemu -t llvm22 --arch riscv64
cargo xtask starry app qemu -t llvm22 --arch loongarch64
```

`prebuild.sh` 通过 qemu-user-static 把 base Alpine rootfs 解到 staging 树后，将其 apk 仓库指向
Alpine **edge**（`llvm22` 22.1.x 只在 edge/main 分支，且四个架构齐全），`apk add`
`llvm22 llvm22-dev llvm22-test-utils clang22 lld22 gcc g++ musl-dev binutils`, 由 apk 为目标架构解析
**当前版本**及其完整的 musl 原生 `.so` 闭包（无写死会漂移的 apk URL，无缓存缺失即退出）。随后脚本从
apk 的 installed 数据库里精确取出**本次事务新装/升级的那批包**所拥有的文件（LLVM/Clang 工具本体 +
`libLLVM.so.22.1` 等），复制进 per-app overlay。base 镜像（Alpine 3.23.4）本身已带
`gcc`/`binutils`/`musl-dev`（crt + 链接器），供 `clang` 的 C→可执行链接路径使用；apk 行仍显式列出这些，
以便某个缺失它们的 base 会把它们拉入被复制的事务增量。`g++` 提供 C++ 标准头文件与 `libstdc++`，
供 `clang++` 的 STL 路径使用。

LLVM 闭包体积很大（安装后约 760 MiB），prebuild 在 harness 注入 overlay 之前先把 per-app rootfs 镜像
扩容（truncate + e2fsck + resize2fs），以免 debugfs 注入时静默截断大型 `.so` 文件。

Alpine 的 `llvm22` 包把未加版本后缀的工具（`lli`/`llc`/`opt`/`llvm-config`/`FileCheck`/`llvm-*`）装到
`/usr/lib/llvm22/bin`，只有 `clang`/`clang-22`/`ld.lld` 落在 `/usr/bin`；`run-llvm22.sh` 因此把
`/usr/lib/llvm22/bin` 加入 `PATH`。测例源码位于 `src/`，注入到 `/root/llvm22/src`。

## 架构说明

- x86_64：`-cpu Haswell` 向用户态暴露 XSAVE/AVX2，`lli`/`llc` 的 host-CPU 代码生成路径据此选择向量特性；
  内核侧 CR4.OSXSAVE 与 XCR0 的开启在 dev 分支中。`-m 4096M` 给 `libLLVM`（映射约 190 MiB）与 `clang`
  留出工作集余量。
- aarch64：`-cpu max`（完整 AArch64 特性集，含 LSE 原子与 ARMv8.2+ 扩展）。
- riscv64：`-cpu rv64`。
- loongarch64：`-machine virt -cpu la464`，动态平台（`build-loongarch64*.toml` 带
  `ax-driver/serial`，`uefi=false` / `to_bin=true` 为动态平台的裸二进制引导路径；不再使用已退休的静态
  LoongArch 写法）。

TCG 模拟下运行 LLVM 工具较慢，qemu toml 的 `timeout` 相应放宽。
