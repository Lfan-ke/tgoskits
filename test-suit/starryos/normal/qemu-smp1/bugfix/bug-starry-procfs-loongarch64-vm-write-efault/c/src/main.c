/*
 * bug-starry-procfs-loongarch64-vm-write-efault
 *
 * 现象: starry kernel 在 loongarch64 上, 用户态 fopen("/proc/self/status", "r")
 *       + fgets() 读 "Groups:" 行(长行包含数十个 supplementary group id) 时,
 *       内核 vm_write 路径返回 errno=14 (EFAULT, Bad address).
 *
 *       其他 arch (x86_64 / aarch64 / riscv64) 与 Linux 全 arch 都正常返回
 *       Groups 行内容. 仅 loongarch64 失败.
 *
 * 来源: PR #4 Group A test-uid-gid-getters procfs_visibility (d) case 在
 *       CI loongarch64 上 FAIL:
 *         FAIL | procfs_visibility.c:133 | procfs (d) parse Groups line failed
 *                                          | errno=14 (Bad address)
 *
 * Linux man 5 proc §/proc/[pid]/status:
 *   "Groups: Supplementary group list."
 *   该行长度随 supp groups 数量增长 (root 通常较短, alpine root 常为 10 个).
 *
 * 推测 starry 缺陷范围:
 *   - 与 fgets 内部 read() 系列调用 + 用户态 buffer (栈上 char line[8192])
 *     在 loongarch64 page table / vm_write 校验路径耦合
 *   - 可能是 starry-vm vm_write_slice 在 loongarch64 上对跨 page 边界的
 *     buffer 误判 invalid user address
 *
 * 期望修复方向:
 *   - 排查 starry_vm::vm_write_slice 在 loongarch64 上的 vm 权限位 / page
 *     boundary 处理是否与其他 arch 不一致
 *   - 检查 procfs Groups 行生成路径是否调 vm_write 写入 buffer 的偏移计算
 *
 * 影响:
 *   - 任何 userspace 程序在 loongarch64 starry 上读 /proc/self/status 的
 *     长行 (e.g. Groups, NSpid 在 namespace 内) 都可能失败
 *   - id(1), groups(1), ps(1) 等基础 utility 在 loongarch64 上行为异常
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_groups_line(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        printf("  fopen /proc/self/status failed: errno=%d (%s)\n",
               errno, strerror(errno));
        return 1;
    }
    char line[8192];
    int found_groups = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "Groups:", 7) == 0) {
            found_groups = 1;
            printf("  Groups line (%zu bytes): %s",
                   strlen(line), line);
            break;
        }
    }
    int err = errno;
    if (!found_groups) {
        printf("  fgets did not return Groups line; last errno=%d (%s)\n",
               err, strerror(err));
    }
    fclose(f);
    return found_groups ? 0 : 1;
}

int main(void)
{
    printf("=== bug-starry-procfs-loongarch64-vm-write-efault ===\n");
    printf("Linux 全 arch: fopen+fgets /proc/self/status 'Groups:' 行可读\n");
    printf("starry loongarch64: 同 syscall 链 vm_write 返 EFAULT (errno=14)\n");
    printf("starry x86_64/aarch64/riscv64: 与 Linux 一致, 通过\n\n");

    int rc = read_groups_line();
    if (rc == 0) {
        printf("\nTEST PASSED (Linux 行为或 starry 已修)\n");
        return 0;
    }
    printf("\nTEST FAILED — Groups 行读取失败 (starry loongarch64 vm_write bug)\n");
    return 1;
}
