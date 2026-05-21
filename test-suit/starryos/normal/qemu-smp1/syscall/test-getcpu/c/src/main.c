#define _GNU_SOURCE
#include "test_framework.h"
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>

/*
 * getcpu(2) 对比测试: Linux/WSL 行为 vs StarryOS 行为
 *
 * 触发背景 (为什么写这个测例):
 *   在 starry 上运行 OpenJDK 17 (musl/Alpine) 时, HotSpot 启动后
 *   立刻 SIGSEGV。根因: glibc/musl 的 sched_getcpu() 经 getcpu(2)
 *   读取当前 CPU; starry 当时**未实现 getcpu**, 该 syscall 走到
 *   未知分支返回错误/不写出参, 上层把未初始化的 cpu 号当数组下标 ->
 *   越界 -> JVM 崩溃。补上 sys_getcpu 后 JVM 正常启动。
 *
 * man 2 getcpu:
 *   int getcpu(unsigned int *cpu, unsigned int *node);
 *   - 把调用线程当前所在的 CPU 号写入 *cpu, NUMA node 号写入 *node。
 *   - cpu 与 node 任一或两者都可为 NULL (此时不写对应出参)。
 *   - 原始 syscall 有第三参数 tcache, 自 Linux 2.6.24 起已废弃, 必须忽略。
 *   - 成功返回 0; 指针指向非法地址时返回 -1 / EFAULT。
 *
 * StarryOS 实现 (kernel/src/syscall/task/thread.rs sys_getcpu):
 *   - *cpu  <- this_cpu_id()
 *   - *node <- 0  (starry 单 NUMA node)
 *   - tcache 忽略; cpu/node 均按 NULL 可选处理。
 *
 * 注: 本测例位于 qemu-smp1 (单核), 故 starry 上 cpu 恒为 0;
 *     在 host(多核) 上 cpu 可为 [0, nproc) 任意值。两边都用
 *     "cpu < nproc 且 node == 0" 这一不依赖核数的不变式断言。
 */

static long raw_getcpu(unsigned int *cpu, unsigned int *node)
{
    /* 直接走原始 syscall, 不依赖 libc 是否导出 getcpu() 包装。
     * 第三参数 tcache 传 NULL —— 内核应忽略。 */
    return syscall(SYS_getcpu, cpu, node, (void *)0);
}

int main(void)
{
    TEST_START("getcpu");

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1)
        nproc = 1;
    printf("  INFO | _SC_NPROCESSORS_ONLN = %ld\n", nproc);

    /* ================================================================
     * 1. getcpu(&cpu, &node) — 常规路径, 两出参都写
     * ================================================================ */
    {
        unsigned int cpu = 0xDEADBEEF, node = 0xDEADBEEF;
        CHECK_RET(raw_getcpu(&cpu, &node), 0,
                  "getcpu(&cpu,&node) 应返回 0");
        CHECK(cpu < (unsigned int)nproc,
              "cpu 号应落在 [0, nproc) 内");
        CHECK(node == 0,
              "node 应为 0 (starry 单 NUMA node)");
    }

    /* ================================================================
     * 2. getcpu(&cpu, NULL) — node 可为 NULL, 只写 cpu
     * ================================================================ */
    {
        unsigned int cpu = 0xDEADBEEF;
        CHECK_RET(raw_getcpu(&cpu, NULL), 0,
                  "getcpu(&cpu,NULL) 应返回 0");
        CHECK(cpu < (unsigned int)nproc,
              "node=NULL 时 cpu 仍应被正确写出");
    }

    /* ================================================================
     * 3. getcpu(NULL, &node) — cpu 可为 NULL, 只写 node
     * ================================================================ */
    {
        unsigned int node = 0xDEADBEEF;
        CHECK_RET(raw_getcpu(NULL, &node), 0,
                  "getcpu(NULL,&node) 应返回 0");
        CHECK(node == 0,
              "cpu=NULL 时 node 仍应为 0");
    }

    /* ================================================================
     * 4. getcpu(NULL, NULL) — 两者都 NULL, 只返回成功不写内存
     * ================================================================ */
    {
        CHECK_RET(raw_getcpu(NULL, NULL), 0,
                  "getcpu(NULL,NULL) 应返回 0 (合法, 不写任何出参)");
    }

    /* ================================================================
     * 5. tcache (第三参数) 必须被忽略 —— 传一个非法指针也不应影响结果
     *    man: 自 2.6.24 起该参数废弃, 内核不得解引用。
     * ================================================================ */
    {
        unsigned int cpu = 0xDEADBEEF;
        errno = 0;
        long r = syscall(SYS_getcpu, &cpu, (void *)0, (void *)0x1);
        CHECK(r == 0,
              "tcache=非法指针 0x1 应被忽略, getcpu 仍返回 0");
        CHECK(cpu < (unsigned int)nproc,
              "tcache 被忽略时 cpu 仍应被正确写出");
    }

    /* ================================================================
     * 6. glibc/musl sched_getcpu() 包装 —— Java/musl 实际走的路径
     *    返回当前 CPU 号 (>= 0), 失败返回 -1。
     * ================================================================ */
    {
        errno = 0;
        int c = sched_getcpu();
        CHECK(c >= 0,
              "sched_getcpu() 应返回非负 CPU 号 (musl/Java 实际路径)");
        CHECK(c < (int)nproc,
              "sched_getcpu() 返回值应落在 [0, nproc) 内");
    }

    /* ================================================================
     * 7. 出参非法地址 —— Linux 返回 EFAULT。
     *    starry sys_getcpu 用 vm_write 写出参, 写非法地址应失败映射为
     *    EFAULT (而非静默成功 / panic)。
     * ================================================================ */
    {
        /* (void*)-1 是一定不可写的内核/越界地址。 */
        CHECK_ERR(raw_getcpu((unsigned int *)(intptr_t)-1, NULL), EFAULT,
                  "getcpu(非法 cpu 指针) 应返回 EFAULT");
    }

    TEST_DONE();
}
