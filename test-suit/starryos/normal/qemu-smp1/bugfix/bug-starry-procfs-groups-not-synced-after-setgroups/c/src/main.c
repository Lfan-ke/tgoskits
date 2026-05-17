/*
 * bug-starry-procfs-groups-not-synced-after-setgroups
 *
 * 现象: starry kernel 在 setgroups(N, list) 写入 cred.groups 后,
 *       /proc/self/status "Groups:" 行不反映新的 supplementary group set
 *       (间歇性, race-sensitive — 同 sha 2 次 CI run 可能一 PASS 一 FAIL).
 *
 * Linux 行为: setgroups 后 /proc/self/status Groups 行立即同步反映, getgroups
 *             syscall 与 procfs 始终一致.
 *
 * starry 行为: setgroups 调 sys_setgroups → cred.groups 更新; 但 procfs Groups
 *              行生成路径未绑定到当前 cred.groups (或绑定但有 cache stale),
 *              偶发输出仍是旧值 (root 启动时 empty 或上次 setgroups 值).
 *
 * 来源: PR #8 Group E (test-uid-gid-groups) procfs_visibility (a-e) 5 case
 *       在 starry x86_64 CI 上间歇 FAIL:
 *         FAIL | procfs_visibility.c:84  | procfs (a) setgroups(0, NULL) → Groups 空
 *         FAIL | procfs_visibility.c:115 | procfs (b) setgroups(3, {100,200,300}) → Groups 含三值
 *         FAIL | procfs_visibility.c:137 | procfs (c) setgroups(1, {500}) → Groups 仅 500
 *         FAIL | procfs_visibility.c:167 | procfs (d) setgroups(16, {1000-1015}) → Groups 含全 16
 *         FAIL | procfs_visibility.c:202 | procfs (e) Groups 行 与 getgroups syscall 一致 (set)
 *
 * Linux man 5 proc §/proc/[pid]/status:
 *   "Groups: Supplementary group list."
 *   该值必须实时反映当前进程的 cred.groups.
 *
 * 推测 starry 缺陷范围:
 *   - procfs Groups 行生成器 (filesystem virt) 未绑定 cred.groups 字段
 *   - 或绑定但 set_cred process-wide 更新与 procfs read 路径未做 memory barrier
 *     (SeqCst / Acquire-Release 协调)
 *
 * 期望修复方向:
 *   1. 排查 starry procfs /proc/<pid>/status Groups 行 implementer, 确认
 *      读取的是 thread.cred() 而非缓存
 *   2. 检查 set_cred (task/mod.rs:280) 与 procfs read 之间是否有合适的同步原语
 *   3. 验证 cred 是 Arc<Cred>, 每次读应通过 .lock() / SpinNoIrq 保证最新
 *
 * 影响:
 *   - 任何依赖 /proc/<pid>/status Groups 行的用户态程序 (e.g. id, getent,
 *     security agent) 在 starry 上读到 stale 的 supp groups 集 → 权限决策错配
 */

#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int parse_proc_groups(unsigned *out, int max_n)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[8192];
    int count = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "Groups:", 7) == 0) {
            count = 0;
            char *p = line + 7;
            while (*p) {
                while (*p == ' ' || *p == '\t') p++;
                if (*p == '\0' || *p == '\n') break;
                char *end;
                unsigned val = (unsigned)strtoul(p, &end, 10);
                if (end == p) break;
                if (count >= max_n) break;
                out[count++] = val;
                p = end;
            }
            break;
        }
    }
    fclose(f);
    return count;
}

static int run_setgroups_then_check_procfs(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        gid_t g[3] = {100, 200, 300};
        if (setgroups(3, g) != 0) {
            printf("  setgroups failed: errno=%d\n", errno);
            _exit(99);
        }
        unsigned proc_g[16];
        int n = parse_proc_groups(proc_g, 16);
        if (n < 0) {
            printf("  parse_proc_groups failed (no Groups line)\n");
            _exit(98);
        }
        printf("  Groups line after setgroups(3, {100,200,300}): n=%d {", n);
        for (int i = 0; i < n; i++) printf("%u%s", proc_g[i], i + 1 < n ? "," : "");
        printf("}\n");
        printf("  expected: n=3, {100,200,300}\n");
        if (n == 3 && proc_g[0] == 100 && proc_g[1] == 200 && proc_g[2] == 300) {
            _exit(0);
        }
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void)
{
    printf("=== bug-starry-procfs-groups-not-synced-after-setgroups ===\n");
    printf("Linux: setgroups 后 /proc/self/status Groups 行立即反映\n");
    printf("starry: 间歇性 Groups 行不同步 (race-sensitive)\n\n");

    if (getuid() != 0) {
        printf("SKIP: needs root for setgroups\n");
        return 0;
    }
    int rc = run_setgroups_then_check_procfs();
    if (rc == 0) {
        printf("\nTEST PASSED (Linux 行为或 starry 已修)\n");
        return 0;
    }
    printf("\nTEST FAILED — procfs Groups 行不同步 setgroups (starry race bug)\n");
    return 1;
}
