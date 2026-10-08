# 系统调用参考实现：拆包与三种 ABI

状态：Linux 与 Windows 在本分支（`feat-personality-win`），Darwin 在 `feat-personality-mac`。设计讨论见 [#2202](https://github.com/rcore-os/tgoskits/issues/2202)。

## 为什么拆

同一台机器、同一套指令集上，Linux、Windows、macOS 提供的是同一批能力：读写文件、映射内存、建线程、计时。差别只在系统调用这一层怎么编号、怎么传参、怎么报错。所以把这一层从内核里拆出来：内核只实现一遍能力端口，每种 ABI 是一个包，链接进来就自己注册；摘掉一个包，内核不用改。

## 包

| 包 | 做什么 |
|:--:|:--:|
| `ax-dispatch` | 收集链接进来的实现，把陷入的调用号交给认领它的实现 |
| `ax-binfmt` | 按文件头认格式，交给认领的包加载 |
| `ax-abi-port` | 内核实现一遍的能力端口：文件、路径、内存、任务、信号、时钟、随机数 |
| `ax-abi` | 分发包：按 feature 选哪几套进链接，给出默认分发策略 |
| `ax-abi-linux` | Linux 系统调用与 ELF 加载 |
| `ax-abi-windows` | NT 调用、Win32 入口与 PE 加载 |
| `ax-abi-darwin` | BSD 调用、合成的 libSystem 与 Mach-O 加载 |
| `ax-abi-embedded`、`ax-abi-custom` | 中断向量表；用户扩展的调用号段 |
| `ax-abi-path`、`ax-abi-driver` | Windows 路径与设备控制码的转换 |

内核默认只链接 Linux 那一套，另外两套由 `starry-kernel` 的 `abi-win`、`abi-mac` 打开。

## 一次陷入

```mermaid
flowchart LR
    A[用户态 syscall] --> B[handle_syscall] --> C[TrapDispatch] --> D["dispatch_at(abi_slot)"] --> E[参考实现] --> F[能力端口]
%% syscall -> handle_syscall -> TrapDispatch -> dispatch_at(abi_slot) -> 参考实现 -> 能力端口
```

不同 ABI 的调用号会相撞（NT 的 `WriteFile` 与 Linux 的 `write` 在 x86-64 上都是 1），所以进程控制块记下它属于哪套：`ProcessData::abi_slot` 在 exec 时由加载器写入，fork 时照抄，陷入时按它直接取实现，不搜索。返回值由实现自己写回：Linux 是负 errno，Windows 是 NTSTATUS，Darwin 是 errno 加进位标志。

## 加载

格式实现 `ImageFormat`（`recognizes`、`load`），用 `register_binfmt!` 注册；内核一侧只有 `dispatch_image()`，相当于 Linux 的 `search_binary_handler`。格式向内核要的能力是 `LoadEnv`：`map_image`、`map_region`、`read_image`、`write`、`interpret`、`reset`、`trace`。

| | ELF | PE | Mach-O |
|:--:|:--:|:--:|:--:|
| 重定位 | 重定位表 | `.reloc` | rebase 操作码流 |
| 导入 | `DT_NEEDED` 加符号表 | 导入表：库名加函数名 | bind 操作码流：库序号加符号名 |
| 原生由谁动态链接 | `PT_INTERP` 点名的 ld.so | ntdll 里的加载器 | dyld |
| 这里由谁做 | 仍是 ld.so，内核只映射 | `ax-abi-windows` | `ax-abi-darwin` |

## 三种系统调用风格

| | Linux | Windows | macOS |
|:--:|:--:|:--:|:--:|
| 稳定的边界 | 调用号 | DLL 导出的函数名 | libSystem 导出的符号名 |
| 调用号 | 固定 | 随版本变，只有同版本的 ntdll 知道 | 不承诺稳定，只有同版本的 libSystem 知道 |
| 原生的接口层 | 内核 | 用户态：kernel32 到 ntdll | 用户态：libSystem |

后两家的接口层原本在用户态、靠名字找到，这里把它移进随内核运行的包：

- **Windows**：系统库不是文件。加载器走导入表，KERNEL32、WS2_32、ADVAPI32 等 14 个库的 421 个入口各绑到一段合成指令：把 `rcx`、`rdx`、`r8`、`r9` 与栈上参数搬到 `rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9`，以 `0x1000 + 下标` 陷入。随程序发布的 DLL（`python314.dll`、`vcruntime140.dll`、`ucrtbase.dll`、`.pyd`）从程序目录与 `/windows/system32` 找到后照常按 PE 映射。合成库带导出目录，`GetModuleHandleW` 加 `GetProcAddress` 照样能答。进程起来前建好 TEB 与 PEB，`gs` 指向 TEB。
- **Darwin**：libSystem 同样在进程里合成，382 个入口加 8 个变量，按 python.org 的 CPython 3.14 及其扩展模块的绑定列出。C 调用约定与陷入约定只差 `rcx`，入口只需挪开 `rcx`，以 `0x0F000000 + 下标` 陷入，再按进位标志写 `errno`；浮点入口另有把 `xmm` 搬进整数寄存器的桩。rebase 与 bind 两条操作码流在启动前全部执行，缺一个符号就拒绝加载。扩展模块经 `dlopen` 在运行时加载，已加载镜像表放在进程自己的内存里。

## 现状

| ABI | 验证用的程序 | 结果 |
|:--:|:--:|:--:|
| Linux | Alpine 的 CPython 3.14.7 | 套件 23 个模块全过 |
| Windows | python.org 的 Windows 版 CPython 3.14.7 | 套件 19/23；`platform.platform()` 得 `Windows-10-10.0.19041-SP0` |
| Darwin | python.org 的 macOS 版 CPython 3.14.7 | 交互解释器可用，`platform.platform()` 得 `Darwin-20.6.0-x86_64-64bit`；套件未跑 |

Darwin 还没有 `fork`、`pipe`、`kqueue`、线程创建与信号投递；调到没实现的入口时，内核日志有一行 `abi: X is not implemented`。两条分支各自往前走了一段，`feat-personality-mac` 还没有 Windows 这边后加的端口，需要专门合一次。

## 怎么跑

```bash
cargo xtask starry app qemu -t python-lang --arch x86_64   # Linux
cargo xtask starry app qemu -t win-py --arch x86_64        # Windows，DLL 放在 STARRY_WIN_DLL_DIR
cargo xtask starry app qemu -t mac-py --arch x86_64        # Darwin，在 feat-personality-mac 上；框架放在 STARRY_MAC_PY_DIR
```

最小用例：`win-abi`、`win-k32`、`win-crt`（Windows），`mac-abi`（Darwin）。各包都在 `scripts/test/std_crates.csv` 里，`cargo xtask test` 在宿主上跑它们的单元测试。
