/*
 * test_vmsplice_tee.c — vmsplice(2) 与 tee(2) 的参数校验及功能验证。
 *
 * 参照 Linux v7.2 fs/splice.c:
 *   SYSCALL_DEFINE4(vmsplice, fd, uiov, nr_segs, flags)  (1578)
 *   SYSCALL_DEFINE4(tee, fdin, fdout, len, flags)        (1977)
 *   do_tee()                                             (1938)
 *
 * 覆盖：
 *   - ENOSYS 探针（缺失实现时整套失败，test-first 基线）
 *   - vmsplice 用户内存 -> pipe（gather 多 iovec，读回逐字节校验）
 *   - vmsplice pipe -> 用户内存（scatter 多 iovec，非消耗性对比）
 *   - vmsplice 全部 flags（MOVE/NONBLOCK/MORE/GIFT）被接受
 *   - vmsplice 未知 flag -> EINVAL；坏 fd -> EBADF；非 pipe -> EBADF
 *   - vmsplice nr_segs 越界(>1024) -> EINVAL；nr_segs=0 -> 0
 *   - vmsplice 空 iovec 合计 0 长度 -> 0；坏 iov_base -> EFAULT
 *   - vmsplice NONBLOCK 满 pipe -> EAGAIN
 *   - tee pipe->pipe 复制且源不被消耗（读回两端）
 *   - tee 部分 len；tee len=0 -> 0（即使坏 fd 也不触发，flags 优先）
 *   - tee 未知 flag -> EINVAL；坏 fd -> EBADF
 *   - tee 非 pipe 端 -> EINVAL；方向错(读端作输出/写端作输入) -> EBADF
 *   - tee 同一 pipe 两端 -> EINVAL
 *   - tee EOF -> 0；tee NONBLOCK 空源 -> EAGAIN
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "test_framework.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* SPLICE_F_* (fcntl.h)。为避免头文件差异，本文件自定义。 */
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE     0x01
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 0x02
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE     0x04
#endif
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT     0x08
#endif

/*
 * 直接走裸 syscall：musl 的 vmsplice/tee 包装器存在（fcntl.h 声明），但直调
 * SYS_* 可让 ENOSYS 探针含义明确，且不依赖包装器被链接，风格与 splice 测试一致。
 */
static ssize_t my_vmsplice(int fd, const struct iovec *iov,
                           unsigned long nr_segs, unsigned int flags)
{
    return syscall(SYS_vmsplice, fd, iov, nr_segs, flags);
}

static ssize_t my_tee(int fd_in, int fd_out, size_t len, unsigned int flags)
{
    return syscall(SYS_tee, fd_in, fd_out, len, flags);
}

int main(void)
{
    TEST_START("vmsplice + tee");

    /*
     * 0. ENOSYS 探针：缺少实现的内核对每个 syscall 返回 ENOSYS。
     *    这里断言"不是 ENOSYS"，因此在裸内核上整套必红（test-first 基线）。
     */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "probe: create pipe");
        char b = 'x';
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };

        errno = 0;
        long r = my_vmsplice(pipefd[1], &iov, 1, 0);
        CHECK(!(r == -1 && errno == ENOSYS), "vmsplice is implemented (not ENOSYS)");

        errno = 0;
        r = my_tee(pipefd[0], pipefd[1], 0, 0);
        CHECK(!(r == -1 && errno == ENOSYS), "tee is implemented (not ENOSYS)");

        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* ============================ vmsplice ============================ */

    /* 1. gather：多个用户 iovec -> pipe，读回逐字节校验、返回值=总字节 */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice gather: create pipe");

        char a[] = "hello";     /* 5 */
        char c[] = "world!!";   /* 7 */
        struct iovec iov[2] = {
            { .iov_base = a, .iov_len = 5 },
            { .iov_base = c, .iov_len = 7 },
        };

        ssize_t n = my_vmsplice(pipefd[1], iov, 2, 0);
        CHECK(n == 12, "vmsplice gather returns total 12 bytes");

        char buf[16] = {0};
        CHECK_RET(read(pipefd[0], buf, 12), 12, "read 12 bytes back from pipe");
        CHECK(memcmp(buf, "helloworld!!", 12) == 0, "gathered content is contiguous helloworld!!");

        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 2. 全部合法 flags 被接受（MOVE|NONBLOCK|MORE|GIFT） */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice flags: create pipe");
        char d[] = "flagbytes"; /* 9 */
        struct iovec iov = { .iov_base = d, .iov_len = 9 };

        ssize_t n = my_vmsplice(pipefd[1], &iov, 1,
                                SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT);
        CHECK(n == 9, "vmsplice accepts all valid flags and writes 9 bytes");

        char buf[16] = {0};
        CHECK_RET(read(pipefd[0], buf, 9), 9, "read 9 bytes after flagged vmsplice");
        CHECK(memcmp(buf, "flagbytes", 9) == 0, "flagged content preserved");

        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 3. scatter：pipe -> 多个用户 iovec，且不消耗多余数据 */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice scatter: create pipe");
        CHECK_RET(write(pipefd[1], "ABCDEFGH", 8), 8, "seed pipe with 8 bytes");

        char p1[3] = {0};
        char p2[3] = {0};
        struct iovec iov[2] = {
            { .iov_base = p1, .iov_len = 3 },
            { .iov_base = p2, .iov_len = 3 },
        };
        /* 请求 6 字节，管道有 8 字节，应正好取 6 到用户缓冲 */
        ssize_t n = my_vmsplice(pipefd[0], iov, 2, 0);
        CHECK(n == 6, "vmsplice pipe->user consumes 6 bytes into two iovecs");
        CHECK(memcmp(p1, "ABC", 3) == 0, "first iovec = ABC");
        CHECK(memcmp(p2, "DEF", 3) == 0, "second iovec = DEF");

        /* 剩余 2 字节仍在管道中 */
        char rest[4] = {0};
        CHECK_RET(read(pipefd[0], rest, 4), 2, "remaining 2 bytes readable");
        CHECK(memcmp(rest, "GH", 2) == 0, "remaining bytes are GH");

        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 4. 未知 flag -> EINVAL（先于 fd 检查） */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice badflag: create pipe");
        char b = 'z';
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        CHECK_ERR(my_vmsplice(pipefd[1], &iov, 1, 0x80000000u), EINVAL,
                  "vmsplice unknown flag -> EINVAL");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 5. 坏 fd -> EBADF */
    {
        char b = 'z';
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        CHECK_ERR(my_vmsplice(-1, &iov, 1, 0), EBADF, "vmsplice bad fd -> EBADF");
    }

    /* 6. 非 pipe fd -> EBADF（普通文件既非源亦非目标 pipe） */
    {
        int fd = open("/tmp/starry_vmsplice_reg", O_RDWR | O_CREAT | O_TRUNC, 0644);
        CHECK(fd >= 0, "open regular file");
        char b = 'z';
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        /* 写端普通文件 -> ITER_SOURCE，但 get_pipe_info 失败 -> EBADF */
        CHECK_ERR(my_vmsplice(fd, &iov, 1, 0), EBADF, "vmsplice on non-pipe -> EBADF");
        if (fd >= 0) close(fd);
        unlink("/tmp/starry_vmsplice_reg");
    }

    /* 7. nr_segs 越界 (> UIO_MAXIOV=1024) -> EINVAL */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice nrsegs: create pipe");
        char b = 'z';
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        CHECK_ERR(my_vmsplice(pipefd[1], &iov, 1025, 0), EINVAL,
                  "vmsplice nr_segs>1024 -> EINVAL");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 8. nr_segs=0 -> 0（无数据可搬，成功返回 0） */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice nrsegs0: create pipe");
        CHECK_RET(my_vmsplice(pipefd[1], NULL, 0, 0), 0, "vmsplice nr_segs=0 -> 0");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 9. 全零长度 iovec -> 合计 0 -> 0 */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice zerolen: create pipe");
        struct iovec iov[2] = {
            { .iov_base = NULL, .iov_len = 0 },
            { .iov_base = NULL, .iov_len = 0 },
        };
        CHECK_RET(my_vmsplice(pipefd[1], iov, 2, 0), 0,
                  "vmsplice all-zero-length iovecs -> 0");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 10. 坏 iov_base（非零长度指向未映射地址） -> EFAULT */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice efault: create pipe");
        struct iovec iov = { .iov_base = (void *)0x1, .iov_len = 16 };
        CHECK_ERR(my_vmsplice(pipefd[1], &iov, 1, 0), EFAULT,
                  "vmsplice bad iov_base -> EFAULT");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 11. NONBLOCK 且 pipe 已满 -> EAGAIN */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice nonblock-full: create pipe");
        /* 用 F_SETPIPE_SZ 缩小到一页，便于填满 */
        int cap = fcntl(pipefd[1], F_SETPIPE_SZ, 4096);
        CHECK(cap >= 4096, "shrink pipe to one page");

        /* 填满：非阻塞写至 EAGAIN。用"填充循环以 EAGAIN 收尾"证明管道真满,
           而非依赖 cap 的精确记账(Starry 与 Linux 的管道容量口径可能不同)。 */
        CHECK(fcntl(pipefd[1], F_SETFL, O_NONBLOCK) == 0, "set write end nonblocking");
        static char big[8192];
        memset(big, 'F', sizeof(big));
        ssize_t total = 0;
        int hit_eagain = 0;
        for (;;) {
            errno = 0;
            ssize_t w = write(pipefd[1], big, sizeof(big));
            if (w <= 0) {
                hit_eagain = (w == -1 && errno == EAGAIN);
                break;
            }
            total += w;
        }
        CHECK(total > 0, "filled pipe with some bytes");
        CHECK(hit_eagain, "pipe is genuinely full (fill loop ended on EAGAIN)");

        struct iovec iov = { .iov_base = big, .iov_len = 64 };
        CHECK_ERR(my_vmsplice(pipefd[1], &iov, 1, SPLICE_F_NONBLOCK), EAGAIN,
                  "vmsplice NONBLOCK into full pipe -> EAGAIN");

        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* ============================== tee ============================== */

    /* 12. pipe -> pipe，源不被消耗，目标获得副本 */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee dup: create input pipe");
        CHECK(pipe(op) == 0, "tee dup: create output pipe");
        CHECK_RET(write(ip[1], "TEEDATA", 7), 7, "seed input pipe with 7 bytes");

        ssize_t n = my_tee(ip[0], op[1], 7, 0);
        CHECK(n == 7, "tee duplicates 7 bytes");

        /* 源仍可读原始 7 字节（未消耗） */
        char src[8] = {0};
        CHECK_RET(read(ip[0], src, 7), 7, "source pipe still has 7 bytes (not consumed)");
        CHECK(memcmp(src, "TEEDATA", 7) == 0, "source content intact");

        /* 目标获得副本 */
        char dst[8] = {0};
        CHECK_RET(read(op[0], dst, 7), 7, "dest pipe received duplicate 7 bytes");
        CHECK(memcmp(dst, "TEEDATA", 7) == 0, "dest content equals source");

        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 13. 部分 len：请求少于可用，只复制 len 字节 */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee partial: create input pipe");
        CHECK(pipe(op) == 0, "tee partial: create output pipe");
        CHECK_RET(write(ip[1], "0123456789", 10), 10, "seed input with 10 bytes");

        ssize_t n = my_tee(ip[0], op[1], 4, 0);
        CHECK(n == 4, "tee with len=4 duplicates 4 bytes");

        char dst[8] = {0};
        CHECK_RET(read(op[0], dst, 8), 4, "dest received exactly 4 bytes");
        CHECK(memcmp(dst, "0123", 4) == 0, "dest holds first 4 bytes");

        /* 源仍完整 */
        char src[16] = {0};
        CHECK_RET(read(ip[0], src, 16), 10, "source still full 10 bytes");
        CHECK(memcmp(src, "0123456789", 10) == 0, "source unchanged by partial tee");

        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 14. len=0 -> 0（即使一端是坏 fd，flags==0 且 len==0 先短路返回 0） */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee len0: create input pipe");
        CHECK(pipe(op) == 0, "tee len0: create output pipe");
        CHECK_RET(my_tee(ip[0], op[1], 0, 0), 0, "tee len=0 -> 0");
        /* len==0 优先于 fd 检查 */
        CHECK_RET(my_tee(-1, op[1], 0, 0), 0, "tee len=0 short-circuits before EBADF");
        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 15. 未知 flag -> EINVAL（先于 len==0 与 fd 检查） */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee badflag: create input pipe");
        CHECK(pipe(op) == 0, "tee badflag: create output pipe");
        CHECK_ERR(my_tee(ip[0], op[1], 4, 0x80000000u), EINVAL,
                  "tee unknown flag -> EINVAL");
        /* 未知 flag 即便 len==0 也应 EINVAL（flags 检查在前） */
        CHECK_ERR(my_tee(ip[0], op[1], 0, 0x80000000u), EINVAL,
                  "tee unknown flag with len=0 still EINVAL");
        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 16. 坏输入 fd -> EBADF；坏输出 fd -> EBADF */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee badfd: create input pipe");
        CHECK(pipe(op) == 0, "tee badfd: create output pipe");
        CHECK_ERR(my_tee(-1, op[1], 4, 0), EBADF, "tee bad input fd -> EBADF");
        CHECK_ERR(my_tee(ip[0], -1, 4, 0), EBADF, "tee bad output fd -> EBADF");
        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 17. 非 pipe 端 -> EINVAL（fd 合法但不是 pipe，且方向合法） */
    {
        int ip[2];
        CHECK(pipe(ip) == 0, "tee nonpipe: create input pipe");
        CHECK_RET(write(ip[1], "abc", 3), 3, "seed input pipe");

        /* 输出是普通只写文件（方向 FMODE_WRITE 合法），但非 pipe -> EINVAL */
        int reg = open("/tmp/starry_tee_reg", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CHECK(reg >= 0, "open regular write file as tee output");
        CHECK_ERR(my_tee(ip[0], reg, 3, 0), EINVAL, "tee to non-pipe output -> EINVAL");
        if (reg >= 0) close(reg);

        /* 输入是普通只读文件（方向 FMODE_READ 合法），但非 pipe -> EINVAL */
        int rfd = open("/tmp/starry_tee_reg2", O_RDWR | O_CREAT | O_TRUNC, 0644);
        CHECK(rfd >= 0, "create regular readable file");
        if (rfd >= 0) {
            CHECK_RET(write(rfd, "xyz", 3), 3, "write regular file content");
            lseek(rfd, 0, SEEK_SET);
        }
        int op2[2];
        CHECK(pipe(op2) == 0, "create output pipe for non-pipe-input test");
        CHECK_ERR(my_tee(rfd, op2[1], 3, 0), EINVAL, "tee from non-pipe input -> EINVAL");

        if (rfd >= 0) close(rfd);
        close(op2[0]); close(op2[1]);
        close(ip[0]); close(ip[1]);
        unlink("/tmp/starry_tee_reg");
        unlink("/tmp/starry_tee_reg2");
    }

    /* 18. 方向错误：pipe 写端作输入 / pipe 读端作输出 -> EBADF */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee dir: create input pipe");
        CHECK(pipe(op) == 0, "tee dir: create output pipe");

        /* 输入用写端（无 FMODE_READ） -> EBADF */
        CHECK_ERR(my_tee(ip[1], op[1], 4, 0), EBADF,
                  "tee input from pipe write end -> EBADF");
        /* 输出用读端（无 FMODE_WRITE） -> EBADF */
        CHECK_ERR(my_tee(ip[0], op[0], 4, 0), EBADF,
                  "tee output to pipe read end -> EBADF");

        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 19. 同一 pipe 两端 -> EINVAL（ipipe == opipe） */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "tee samepipe: create pipe");
        CHECK_RET(write(pipefd[1], "abc", 3), 3, "seed same-pipe test");
        CHECK_ERR(my_tee(pipefd[0], pipefd[1], 3, 0), EINVAL,
                  "tee same pipe in and out -> EINVAL");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    /* 20. EOF：源空且写端已关 -> 0 */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee eof: create input pipe");
        CHECK(pipe(op) == 0, "tee eof: create output pipe");
        close(ip[1]); /* 关闭写端 -> 输入 pipe 到达 EOF */
        CHECK_RET(my_tee(ip[0], op[1], 4, 0), 0, "tee at EOF -> 0");
        close(ip[0]);
        close(op[0]); close(op[1]);
    }

    /* 21. NONBLOCK 且源空(写端仍在) -> EAGAIN */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee nonblock: create input pipe");
        CHECK(pipe(op) == 0, "tee nonblock: create output pipe");
        /* 输入 pipe 空且写端仍开：非阻塞应 EAGAIN */
        CHECK_ERR(my_tee(ip[0], op[1], 4, SPLICE_F_NONBLOCK), EAGAIN,
                  "tee NONBLOCK on empty source -> EAGAIN");
        close(ip[0]); close(ip[1]);
        close(op[0]); close(op[1]);
    }

    /* 22. vmsplice 写入无读者的 pipe -> EPIPE(opipe_prep 发 SIGPIPE 返 -EPIPE) */
    {
        signal(SIGPIPE, SIG_IGN); /* 否则 SIGPIPE 直接杀进程 */
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice epipe: create pipe");
        close(pipefd[0]); /* 无读者 */
        char b = 'x';
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        CHECK_ERR(my_vmsplice(pipefd[1], &iov, 1, 0), EPIPE,
                  "vmsplice into pipe with closed reader -> EPIPE");
        close(pipefd[1]);
    }

    /* 23. tee 写入无读者的 pipe -> EPIPE(link_pipe/opipe_prep) */
    {
        signal(SIGPIPE, SIG_IGN);
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee epipe: input pipe");
        CHECK(pipe(op) == 0, "tee epipe: output pipe");
        CHECK_RET(write(ip[1], "DATA", 4), 4, "seed input");
        close(op[0]); /* 输出无读者 */
        CHECK_ERR(my_tee(ip[0], op[1], 4, 0), EPIPE,
                  "tee into pipe with closed reader -> EPIPE");
        close(ip[0]); close(ip[1]); close(op[1]);
    }

    /* 24. vmsplice pipe->用户内存,目标缓冲无效 -> EFAULT(pipe_to_user 短拷贝) */
    {
        int pipefd[2];
        CHECK(pipe(pipefd) == 0, "vmsplice dest-efault: create pipe");
        CHECK_RET(write(pipefd[1], "ABCDEFGH", 8), 8, "seed 8 bytes");
        struct iovec iov = { .iov_base = (void *)0x1, .iov_len = 16 };
        CHECK_ERR(my_vmsplice(pipefd[0], &iov, 1, 0), EFAULT,
                  "vmsplice pipe->bad user buffer -> EFAULT");
        close(pipefd[0]); close(pipefd[1]);
    }

    /* 25. tee len 大于可用且写端已关 -> 仅复制现有字节(link_pipe 循环收敛) */
    {
        int ip[2], op[2];
        CHECK(pipe(ip) == 0, "tee biglen: input pipe");
        CHECK(pipe(op) == 0, "tee biglen: output pipe");
        CHECK_RET(write(ip[1], "SEVENB", 6), 6, "seed 6 bytes");
        close(ip[1]); /* 写端关闭:循环确定性终止 */
        CHECK_RET(my_tee(ip[0], op[1], 1000, 0), 6, "tee len>available -> exactly 6 bytes");
        char dst[8] = {0};
        CHECK_RET(read(op[0], dst, 8), 6, "dest received 6 bytes");
        CHECK(memcmp(dst, "SEVENB", 6) == 0, "dest content == source");
        close(ip[0]); close(op[0]); close(op[1]);
    }

    /* 26. tee 输出到 O_RDONLY 普通文件 -> EBADF(FMODE 门先于 pipe 检查) */
    {
        int ip[2];
        CHECK(pipe(ip) == 0, "tee rdonly-out: input pipe");
        CHECK_RET(write(ip[1], "abc", 3), 3, "seed input");
        int rofd = open("/tmp/starry_tee_ro", O_RDONLY | O_CREAT, 0644);
        CHECK(rofd >= 0, "open O_RDONLY regular file");
        CHECK_ERR(my_tee(ip[0], rofd, 3, 0), EBADF,
                  "tee output to O_RDONLY file (no FMODE_WRITE) -> EBADF");
        if (rofd >= 0) close(rofd);
        close(ip[0]); close(ip[1]);
        unlink("/tmp/starry_tee_ro");
    }

    /* 27. tee INPUT from O_WRONLY 普通文件 -> EBADF(FMODE_READ 缺失, 先于非pipe判定) */
    {
        int op[2];
        CHECK(pipe(op) == 0, "tee wronly-in: output pipe");
        int wofd = open("/tmp/starry_tee_wo", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CHECK(wofd >= 0, "open O_WRONLY regular file");
        CHECK_ERR(my_tee(wofd, op[1], 3, 0), EBADF,
                  "tee input from O_WRONLY file (no FMODE_READ) -> EBADF");
        if (wofd >= 0) close(wofd);
        close(op[0]); close(op[1]);
        unlink("/tmp/starry_tee_wo");
    }

    TEST_DONE();
}
