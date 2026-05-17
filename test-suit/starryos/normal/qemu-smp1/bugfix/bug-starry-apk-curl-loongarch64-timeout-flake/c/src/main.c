/*
 * bug-starry-apk-curl-loongarch64-timeout-flake
 *
 * 现象 (CI 历史观察, 非纯 C-level bug):
 *   starry loongarch64 qemu CI 上 `apk-curl` test case (执行 `apk add curl`
 *   + `curl https://baidu.com`) 经常在 600s 内超时 (qemu run 超过 timeout),
 *   阻塞整个 CI 让 PR 显示 fail. 在 starry x86_64 / aarch64 / riscv64 以及
 *   Linux 全 arch 上正常 (apk add + curl 在 <30s 完成).
 *
 *   该 timeout 频率统计 (2026-05-15 ~ 2026-05-17 fork CI):
 *     - PR #9-14 (open/setuid bug-*): 7/7 各 1 次 loongarch64 apk-curl fail
 *     - PR #17 (procfs-loongarch64): 1/1 fail
 *     - PR #18 (procfs-groups-sync): 0/1 (一次幸运 pass)
 *     - PR #4 (test-uid-gid-getters) 历史: 多次同样 fail
 *     综合: starry loongarch64 apk-curl ~90% timeout 率
 *
 * Linux 行为: alpine apk + curl 网络下载和 TLS 握手在所有 arch <30s 完成.
 * starry 其他 arch: 同 Linux, <30s 完成 (PR #15 fix-uid-gid-bugs 各 arch
 *                   apk-curl 历史观察均 PASS, 仅 loongarch64 偶发 timeout).
 *
 * 推测范围 (优先级排序):
 *   1. starry loongarch64 网络 stack (TCP / DNS / TLS) 异常慢
 *      — 排查 ax-net / smoltcp 在 loongarch64 上的调度延迟
 *   2. starry loongarch64 fork/execve 性能问题 (apk 包管理 fork 多 subprocess)
 *      — 排查进程创建 / page table setup 时延
 *   3. CI Docker runner 共享 noisy neighbor — 但其他 arch 同 runner 不受影响,
 *      所以 unlikely 单 starry loongarch64 noisy
 *   4. starry loongarch64 timer interrupt 频率异常 — apk 内部依赖 timer
 *
 * 影响:
 *   - 任何 starry loongarch64 上需要包管理 + 网络的应用偶发不可用
 *   - CI 上所有依赖 apk-curl 配置的 PR 受 noise (本任务 8 bug-* PR 即 7/8 误报)
 *   - 阻塞迭代速度 (CI 重跑成本高, ~10 min/次)
 *
 * 本 C 程序的复现策略 (有限):
 *   apk-curl 本质涉及 alpine 包管理 + TLS — 无法用单 C 程序在 starry 沙箱
 *   完整复现. 此程序仅做 starry 网络 + fork+wait 基础链路最小 timing:
 *
 *   1. fork() + execve("/bin/true") 100 次 — 测 process creation 时延
 *   2. socket() + close() 100 次 — 测 net stack init 时延
 *   3. 输出累计时延 ms, 与 Linux 基线对比
 *
 *   若 starry loongarch64 上 fork/socket 时延异常高 (>10x Linux), 即定位
 *   apk-curl timeout 的主因之一.
 *
 * 期望修复方向:
 *   - starry-team 排查上述 4 项推测, 优先 1 + 2
 *   - 短期 mitigation: 把 apk-curl test timeout 600s → 1800s, 但治标不治本
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define ITER 100

static long ms_diff(struct timeval *a, struct timeval *b)
{
    return (a->tv_sec - b->tv_sec) * 1000L + (a->tv_usec - b->tv_usec) / 1000L;
}

static long bench_fork_exec(void)
{
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    for (int i = 0; i < ITER; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            char *argv[] = {"/bin/true", NULL};
            execve("/bin/true", argv, NULL);
            _exit(99);  /* execve failed */
        }
        if (pid < 0) return -1;
        int status;
        waitpid(pid, &status, 0);
    }
    gettimeofday(&t1, NULL);
    return ms_diff(&t1, &t0);
}

static long bench_socket(void)
{
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    for (int i = 0; i < ITER; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        close(fd);
    }
    gettimeofday(&t1, NULL);
    return ms_diff(&t1, &t0);
}

int main(void)
{
    printf("=== bug-starry-apk-curl-loongarch64-timeout-flake ===\n");
    printf("CI 现象: apk-curl 600s timeout 在 starry loongarch64 上 ~90%% 触发\n");
    printf("Linux 全 arch + starry 其他 arch: 同测试 <30s 完成\n\n");

    long t_fork = bench_fork_exec();
    long t_sock = bench_socket();

    printf("  fork+execve x %d: %ld ms\n", ITER, t_fork);
    printf("  socket+close x %d: %ld ms\n", ITER, t_sock);

    /* Linux 基线 (typical): fork+exec ~50ms, socket ~5ms.
     * 若 starry loongarch64 上 fork+exec > 5000ms, socket > 500ms,
     * 即可定位为性能问题. 阈值留宽以减少 noise. */
    int fork_anomaly = (t_fork < 0) || (t_fork > 5000);
    int sock_anomaly = (t_sock < 0) || (t_sock > 500);

    if (!fork_anomaly && !sock_anomaly) {
        printf("\nTEST PASSED (Linux 基线行为或 starry 已修)\n");
        return 0;
    }
    printf("\nTEST FAILED — fork/socket 性能异常 (starry loongarch64 平台 bug)\n");
    return 1;
}
