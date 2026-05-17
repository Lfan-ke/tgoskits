# bug-openat-resolve-at-relative-sigsegv

## 现象
在 starry kernel x86_64 上，以下 syscall 序列触发 SIGSEGV (host/Linux/wsl2 全部正常):

```c
int dfd = open("/tmp/x/sub", O_RDONLY | O_DIRECTORY);  // OK
int fd  = openat(dfd, "inner", O_RDONLY);              // ← starry 此处 crash
```

| 平台 | 行为 |
|------|------|
| Linux host / wsl2 | `fd >= 0`，可正常 read |
| starry x86_64     | **SIGSEGV (status=139)** |
| starry 其他 arch  | 未确认（matrix fail-fast 取消） |

## 触发条件
1. 在 starry kernel 上应用 PR `Lfan-ke/tgoskits#2 fix-open-openat-bugs`（即 "15 类局部修复" 系列 patch）。
2. 用 host musl-gcc 静态编译此最小 C 程序。
3. 放到 starry rootfs 的 `/usr/bin/`。
4. 在 starry shell 内执行 `/usr/bin/bug-openat-resolve-at-relative-sigsegv`。
5. starry **直接 panic / SIGSEGV** 而不是返回 fd。

## 推测原因（待 starry 维护方排查）
- `resolve_at` 路径在「dirfd 为已打开的 O_DIRECTORY fd」+ 「相对路径」组合时，
  PR #2 的修复改动了 resolve 顺序 / 释放时机，可能导致 use-after-free 或
  null deref。

## 出处
- 发现: PR `Lfan-ke/tgoskits#2 fix-open-openat-bugs` 头 `5692f37e0` 的 CI run `25955202119`
  - 最后 PASS: `openat_dirfd.c:53 | openat AT_FDCWD: both opens ok`
  - 紧接着 `relative_with_dirfd` 内 `open(M_SUB, O_RDONLY|O_DIRECTORY) + openat(dfd, "inner", O_RDONLY)` 崩
- 处理: 由于该 bug 不在 open/openat 测试任务职责范围内（属于 starry kernel resolve_at 内部 bug），
  按 user 2026-05-16 指示，**抽离到此独立分支 `bug-starry-openat-resolve-at-relative-sigsegv`** 最小复现。
  PR #2 `fix-open-openat-bugs` 已 reset 回上次 CI 全绿头 `a21248ff7`。

## 复现指引（建议 starry kernel 团队）
```sh
# 1. 拉本分支
git fetch fork bug-starry-openat-resolve-at-relative-sigsegv
git checkout bug-starry-openat-resolve-at-relative-sigsegv

# 2. apply PR #2 kernel patch on top of dev (可选 — 用于精确复现原观察环境)
git remote add lfan https://github.com/Lfan-ke/tgoskits.git
git fetch lfan fix-open-openat-bugs
git cherry-pick lfan/fix-open-openat-bugs  # 仅 kernel 修，可能 conflict 需手解

# 3. 运行 starry CI 流程或 xtask 本地：
cargo run --bin xtask -- --target=x86_64 starry-qemu  # 跑 bugfix/qemu-x86_64.toml 中本测项

# 4. 观察输出: "SETUP-FAIL" 或 "FAIL: openat" 是测例自身错；
#    "TEST PASSED" 是 bug 已修；
#    starry kernel panic / runner status=139 是 bug 现身。
```

## 相关
- [PR Lfan-ke/tgoskits#2 fix-open-openat-bugs](https://github.com/Lfan-ke/tgoskits/pull/2)
- starry kernel `os/StarryOS/kernel/src/file/resolve.rs` 与 `syscall/fs/io.rs::sys_openat`
