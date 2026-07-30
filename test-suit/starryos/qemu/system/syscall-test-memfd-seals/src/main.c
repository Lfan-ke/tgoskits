/*
 * !test-memfd-seals — memfd_create(2) + fcntl file sealing 穷尽测试
 *
 * ground truth: man 2 memfd_create / man 2 fcntl "File Sealing"
 * + Linux v7.2 mm/memfd.c + mm/shmem.c。逐条覆盖创建/flags/errno、
 * F_ADD_SEALS/F_GET_SEALS 全 seal、以及 seal 执行(SHRINK/GROW/WRITE/FUTURE_WRITE)。
 *
 * =====================================================================
 * 语义 (man 2 memfd_create, man 2 fcntl)
 * =====================================================================
 *   memfd_create(name, flags): 建匿名 O_RDWR 内存 fd, 初始大小 0。
 *   flags: MFD_CLOEXEC / MFD_ALLOW_SEALING。无 ALLOW_SEALING 时初始封印
 *   F_SEAL_SEAL(不可再加封印 -> F_ADD_SEALS 得 EPERM)。
 *   F_ADD_SEALS: 加封印(幂等 OR); F_GET_SEALS: 读封印位掩码。
 *   封印执行: F_SEAL_SHRINK 禁缩(ftruncate 缩 -> EPERM); F_SEAL_GROW 禁增;
 *   F_SEAL_WRITE 禁写(且有活跃可写映射时加封 -> EBUSY);
 *   F_SEAL_FUTURE_WRITE 禁"将来"写(已有映射仍可写, 新写/新可写映射 -> EPERM)。
 *
 * =====================================================================
 * Linux v7.2 源码对齐 (mm/memfd.c, mm/shmem.c)
 * =====================================================================
 *   - memfd_create SYSCALL_DEFINE2 :505; sanitize_flags :409 未知位 -> EINVAL;
 *     名字 > MFD_NAME_MAX_LEN(249) -> EINVAL :446。
 *   - memfd_add_seals :230: 非 ALLOW_SEALING(初始 F_SEAL_SEAL) -> EPERM :268;
 *     ~F_ALL_SEALS 位 -> EINVAL; *file_seals |= seals :304(幂等)。
 *   - 写封印执行 shmem.c:3227-3237 (WRITE/FUTURE_WRITE -> EPERM); SHRINK/GROW
 *     truncate 执行 shmem.c:1340-1342。
 *
 *   浏览器关联: Chromium/Firefox 用 memfd + F_SEAL_WRITE/F_SEAL_FUTURE_WRITE 建
 *   只读共享内存快照, 传给沙箱子进程防篡改。
 * =====================================================================
 */

#include "test_framework.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

static void alarm_handler(int s)
{
    (void)s;
    const char *m = "\n  FAIL | TIMEOUT | 测试挂死(疑内核gap)\n"
                    "==== test-memfd-seals 汇总: FAIL ====\n";
    ssize_t r = write(2, m, strlen(m));
    (void)r;
    _exit(1);
}

/* ===== A. 创建 + flags ===== */
static int test_create(void)
{
    TEST_START("A. memfd_create 创建 + flags");
    int fd = memfd_create("t", 0);
    CHECK(fd >= 0, "memfd_create(\"t\",0) 成功");
    if (fd >= 0) {
        int fl = fcntl(fd, F_GETFL);
        CHECK(fl != -1 && (fl & O_ACCMODE) == O_RDWR, "memfd 是 O_RDWR");
        struct stat st;
        CHECK(fstat(fd, &st) == 0 && st.st_size == 0, "初始大小 0");
        int fdfl = fcntl(fd, F_GETFD);
        CHECK(fdfl != -1 && !(fdfl & FD_CLOEXEC), "无 MFD_CLOEXEC -> 无 FD_CLOEXEC");
        CHECK(ftruncate(fd, 4096) == 0 && fstat(fd, &st) == 0 && st.st_size == 4096,
              "ftruncate 设大小 4096");
        close(fd);
    }
    int cf = memfd_create("c", MFD_CLOEXEC);
    CHECK(cf >= 0, "memfd_create(MFD_CLOEXEC) 成功");
    if (cf >= 0) {
        int fdfl = fcntl(cf, F_GETFD);
        CHECK(fdfl != -1 && (fdfl & FD_CLOEXEC), "MFD_CLOEXEC -> FD_CLOEXEC");
        close(cf);
    }
    TEST_DONE();
}

/* ===== B. 创建 errno ===== */
static int test_create_errno(void)
{
    TEST_START("B. memfd_create errno");
    errno = 0;
    CHECK(memfd_create("x", 0x8000U) == -1 && errno == EINVAL, "未知 flags 位 -> EINVAL");

    char longname[300];
    memset(longname, 'a', sizeof(longname));
    longname[299] = '\0'; /* 299 字节 > 249 */
    errno = 0;
    CHECK(memfd_create(longname, 0) == -1 && errno == EINVAL, "名字过长(>249) -> EINVAL");

    char n249[250];
    memset(n249, 'b', 249);
    n249[249] = '\0';
    int f249 = memfd_create(n249, 0);
    CHECK(f249 >= 0, "名字恰 249 字节 -> 成功(边界)");
    if (f249 >= 0) close(f249);
    TEST_DONE();
}

/* ===== C. F_ADD_SEALS / F_GET_SEALS ===== */
static int test_add_seals(void)
{
    TEST_START("C. F_ADD_SEALS / F_GET_SEALS");
    /* 无 ALLOW_SEALING: 初始 F_SEAL_SEAL, 加封印 -> EPERM */
    int nf = memfd_create("noseal", 0);
    if (nf >= 0) {
        int s = fcntl(nf, F_GET_SEALS);
        CHECK(s == F_SEAL_SEAL, "无 ALLOW_SEALING 初始封印 = F_SEAL_SEAL");
        errno = 0;
        CHECK(fcntl(nf, F_ADD_SEALS, F_SEAL_SHRINK) == -1 && errno == EPERM,
              "F_SEAL_SEAL 已封 -> F_ADD_SEALS EPERM");
        close(nf);
    }

    /* ALLOW_SEALING: 初始 0, 可加封印 */
    int sf = memfd_create("seal", MFD_ALLOW_SEALING);
    if (sf >= 0) {
        CHECK(fcntl(sf, F_GET_SEALS) == 0, "ALLOW_SEALING 初始封印 = 0");
        CHECK_RET(fcntl(sf, F_ADD_SEALS, F_SEAL_SHRINK), 0, "加 F_SEAL_SHRINK");
        CHECK((fcntl(sf, F_GET_SEALS) & F_SEAL_SHRINK) != 0, "回读含 SHRINK");
        CHECK_RET(fcntl(sf, F_ADD_SEALS, F_SEAL_GROW), 0, "加 F_SEAL_GROW(累加)");
        int all = fcntl(sf, F_GET_SEALS);
        CHECK((all & F_SEAL_SHRINK) && (all & F_SEAL_GROW), "回读含 SHRINK|GROW");
        CHECK_RET(fcntl(sf, F_ADD_SEALS, F_SEAL_SHRINK), 0, "重复加 SHRINK 幂等 no-op");
        close(sf);
    }
    TEST_DONE();
}

/* ===== D. seal 执行: SHRINK / GROW ===== */
static int test_enforce_size(void)
{
    TEST_START("D. SHRINK/GROW 封印执行");
    int fd = memfd_create("sz", MFD_ALLOW_SEALING);
    if (fd < 0) { CHECK(0, "前置"); TEST_DONE(); }
    CHECK(ftruncate(fd, 8192) == 0, "初始 ftruncate 8192");

    CHECK_RET(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK), 0, "加 F_SEAL_SHRINK");
    errno = 0;
    CHECK(ftruncate(fd, 4096) == -1 && errno == EPERM, "SHRINK 封印后缩小 -> EPERM");
    CHECK(ftruncate(fd, 16384) == 0, "SHRINK 封印后仍可增大");

    CHECK_RET(fcntl(fd, F_ADD_SEALS, F_SEAL_GROW), 0, "加 F_SEAL_GROW");
    errno = 0;
    CHECK(ftruncate(fd, 32768) == -1 && errno == EPERM, "GROW 封印后增大 -> EPERM");
    close(fd);
    TEST_DONE();
}

/* ===== E. seal 执行: WRITE / FUTURE_WRITE ===== */
static int test_enforce_write(void)
{
    TEST_START("E. WRITE/FUTURE_WRITE 封印执行");
    /* F_SEAL_WRITE: 封后写 -> EPERM */
    int wf = memfd_create("w", MFD_ALLOW_SEALING);
    if (wf >= 0) {
        CHECK(ftruncate(wf, 4096) == 0, "ftruncate 4096");
        CHECK(write(wf, "x", 1) == 1, "封印前可写");
        CHECK_RET(fcntl(wf, F_ADD_SEALS, F_SEAL_WRITE), 0, "加 F_SEAL_WRITE");
        errno = 0;
        CHECK(pwrite(wf, "y", 1, 0) == -1 && errno == EPERM, "F_SEAL_WRITE 后写 -> EPERM");
        close(wf);
    }

    /* F_SEAL_FUTURE_WRITE: 封后新写 -> EPERM(浏览器关键封印) */
    int ff = memfd_create("fw", MFD_ALLOW_SEALING);
    if (ff >= 0) {
        CHECK(ftruncate(ff, 4096) == 0, "ftruncate 4096");
        CHECK(write(ff, "AB", 2) == 2, "FUTURE_WRITE 封印前可写");
        CHECK_RET(fcntl(ff, F_ADD_SEALS, F_SEAL_FUTURE_WRITE), 0, "加 F_SEAL_FUTURE_WRITE");
        CHECK((fcntl(ff, F_GET_SEALS) & F_SEAL_FUTURE_WRITE) != 0, "回读含 FUTURE_WRITE");
        errno = 0;
        CHECK(pwrite(ff, "z", 1, 0) == -1 && errno == EPERM,
              "F_SEAL_FUTURE_WRITE 后写 -> EPERM");
        close(ff);
    }
    TEST_DONE();
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, alarm_handler);
    alarm(60);
    int fail = 0;
    fail |= test_create();
    fail |= test_create_errno();
    fail |= test_add_seals();
    fail |= test_enforce_size();
    fail |= test_enforce_write();
    printf("\n==== test-memfd-seals 汇总: %s ====\n", fail ? "FAIL" : "PASS");
    return fail;
}
