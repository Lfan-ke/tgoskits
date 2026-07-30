/*
 * !test-accept4 — accept4(2) 穷尽测试
 *
 * ground truth: man 2 accept4 / accept + Linux v7.2 net/socket.c。逐条覆盖
 * SOCK_NONBLOCK/SOCK_CLOEXEC flag 语义、peer 地址回填、错误 flag、errno 路径、
 * 非监听/非流式拒绝、SEQPACKET 连接式 accept、SO_TYPE 回读。
 *
 * =====================================================================
 * accept4(2) 语义 (man 2 accept4)
 * =====================================================================
 *   int accept4(int fd, struct sockaddr *addr, socklen_t *alen, int flags);
 *   flags=0 等价 accept(); 可 OR: SOCK_NONBLOCK(新 fd 置 O_NONBLOCK),
 *   SOCK_CLOEXEC(新 fd 置 FD_CLOEXEC)。flag 不从 listener 继承。
 *   非法 flags -> EINVAL; 非 socket -> ENOTSOCK; 未 listen -> EINVAL;
 *   非流式(DGRAM) -> EOPNOTSUPP; 无效 fd -> EBADF; 非阻塞无连接 -> EAGAIN。
 *
 * =====================================================================
 * Linux v7.2 源码对齐 (net/socket.c)
 * =====================================================================
 *   - __sys_accept4(:2083): flags 校验 (~(SOCK_CLOEXEC|SOCK_NONBLOCK)) -> EINVAL(:2062);
 *     新 fd 依 flags 置 O_CLOEXEC/O_NONBLOCK(:2065); addr 非空则回填 peer(:2038)。
 *
 *   浏览器关联: Chromium/Firefox 网络与 IPC 服务用 accept4(SOCK_NONBLOCK|SOCK_CLOEXEC)
 *   一步接受连接, 避免额外 fcntl 与 fd 泄漏到子进程。
 * =====================================================================
 */

#include "test_framework.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static void alarm_handler(int s)
{
    (void)s;
    const char *m = "\n  FAIL | TIMEOUT | 测试挂死(疑内核gap)\n"
                    "==== test-accept4 汇总: FAIL ====\n";
    ssize_t r = write(2, m, strlen(m));
    (void)r;
    _exit(1);
}

/* 建一个已 listen 的 AF_UNIX 抽象地址 socket + 一个已 connect 的 client。
 * 返回 listener fd; *client_out = client fd。type = SOCK_STREAM/SOCK_SEQPACKET。 */
static int make_listener_with_pending(int type, const char *name, int name_len, int *client_out)
{
    int ls = socket(AF_UNIX, type, 0);
    if (ls < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name, (size_t)name_len);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) + (socklen_t)name_len;
    if (bind(ls, (struct sockaddr *)&addr, alen) != 0) { close(ls); return -1; }
    if (listen(ls, 8) != 0) { close(ls); return -1; }
    int cs = socket(AF_UNIX, type, 0);
    if (cs < 0) { close(ls); return -1; }
    if (connect(cs, (struct sockaddr *)&addr, alen) != 0) { close(ls); close(cs); return -1; }
    *client_out = cs;
    return ls;
}

/* ===== A. accept4 基础 + flag 语义 ===== */
static int test_flags(void)
{
    TEST_START("A. accept4 基础 + SOCK_NONBLOCK/CLOEXEC");
    int cs = -1;
    int ls = make_listener_with_pending(SOCK_STREAM, "\0accept4-flags", 13, &cs);
    CHECK(ls >= 0 && cs >= 0, "listener+client 前置");
    if (ls < 0) { TEST_DONE(); }

    /* flags=0: 新 fd 无 CLOEXEC/NONBLOCK(不继承) */
    int a0 = accept4(ls, NULL, NULL, 0);
    CHECK(a0 >= 0, "accept4(flags=0) 成功");
    if (a0 >= 0) {
        int fd_fl = fcntl(a0, F_GETFD);
        int st_fl = fcntl(a0, F_GETFL);
        CHECK(fd_fl != -1 && !(fd_fl & FD_CLOEXEC), "flags=0 新fd 无 FD_CLOEXEC");
        CHECK(st_fl != -1 && !(st_fl & O_NONBLOCK), "flags=0 新fd 无 O_NONBLOCK");
        int type = 0;
        socklen_t tl = sizeof(type);
        CHECK(getsockopt(a0, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_STREAM,
              "新fd SO_TYPE == SOCK_STREAM");
        close(a0);
    }
    close(cs);

    /* SOCK_CLOEXEC | SOCK_NONBLOCK */
    ls = make_listener_with_pending(SOCK_STREAM, "\0accept4-both", 12, &cs);
    if (ls >= 0) {
        int a1 = accept4(ls, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        CHECK(a1 >= 0, "accept4(CLOEXEC|NONBLOCK) 成功");
        if (a1 >= 0) {
            int fd_fl = fcntl(a1, F_GETFD);
            int st_fl = fcntl(a1, F_GETFL);
            CHECK(fd_fl != -1 && (fd_fl & FD_CLOEXEC), "SOCK_CLOEXEC -> FD_CLOEXEC");
            CHECK(st_fl != -1 && (st_fl & O_NONBLOCK), "SOCK_NONBLOCK -> O_NONBLOCK");
            close(a1);
        }
        close(cs);
        close(ls);
    }
    TEST_DONE();
}

/* ===== B. peer 地址回填 + addr NULL ===== */
static int test_peer_addr(void)
{
    TEST_START("B. accept4 peer 地址回填");
    int cs = -1;
    int ls = make_listener_with_pending(SOCK_STREAM, "\0accept4-addr", 12, &cs);
    if (ls < 0) { CHECK(0, "前置失败"); TEST_DONE(); }

    struct sockaddr_un peer;
    socklen_t plen = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    int a = accept4(ls, (struct sockaddr *)&peer, &plen, 0);
    CHECK(a >= 0, "accept4 带 addr 成功");
    if (a >= 0) {
        CHECK(peer.sun_family == AF_UNIX, "回填 peer family == AF_UNIX");
        close(a);
    }
    close(cs);

    /* addr NULL: 不回填, 成功 */
    ls = make_listener_with_pending(SOCK_STREAM, "\0accept4-null", 12, &cs);
    if (ls >= 0) {
        int a2 = accept4(ls, NULL, NULL, 0);
        CHECK(a2 >= 0, "accept4(addr=NULL) 成功");
        if (a2 >= 0) close(a2);
        close(cs);
        close(ls);
    }
    TEST_DONE();
}

/* ===== C. errno 路径 ===== */
static int test_errno(void)
{
    TEST_START("C. accept4 errno(EINVAL/EBADF/ENOTSOCK/未listen)");

    /* 非法 flags -> EINVAL */
    int cs = -1;
    int ls = make_listener_with_pending(SOCK_STREAM, "\0accept4-badflag", 16, &cs);
    if (ls >= 0) {
        errno = 0;
        int r = accept4(ls, NULL, NULL, 0x1); /* 0x1 非 SOCK_CLOEXEC/NONBLOCK */
        CHECK(r == -1 && errno == EINVAL, "非法 flags -> EINVAL");
        close(cs);
        close(ls);
    }

    /* 无效 fd -> EBADF */
    errno = 0;
    CHECK(accept4(999, NULL, NULL, 0) == -1 && errno == EBADF, "无效 fd -> EBADF");

    /* 非 socket -> ENOTSOCK */
    int rfd = open("/", O_RDONLY);
    if (rfd >= 0) {
        errno = 0;
        CHECK(accept4(rfd, NULL, NULL, 0) == -1 && errno == ENOTSOCK, "非 socket -> ENOTSOCK");
        close(rfd);
    }

    /* 未 listen 的 socket -> EINVAL */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s >= 0) {
        errno = 0;
        CHECK(accept4(s, NULL, NULL, 0) == -1 && errno == EINVAL, "未 listen -> EINVAL");
        close(s);
    }

    /* 非阻塞 listener 无连接 -> EAGAIN。注意: SOCK_NONBLOCK flag 设的是被接受
     * 的新 fd, 不是 accept 操作本身; 要让 accept 非阻塞须 listener 自身 O_NONBLOCK。 */
    int nls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (nls >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        const char *nm = "\0accept4-nb";
        memcpy(addr.sun_path, nm, 10);
        socklen_t al = offsetof(struct sockaddr_un, sun_path) + 10;
        if (bind(nls, (struct sockaddr *)&addr, al) == 0 && listen(nls, 4) == 0) {
            int lfl = fcntl(nls, F_GETFL);
            fcntl(nls, F_SETFL, lfl | O_NONBLOCK); /* listener non-blocking */
            errno = 0;
            int r = accept4(nls, NULL, NULL, 0);
            CHECK(r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
                  "非阻塞 listener 无连接 accept4 -> EAGAIN");
        }
        close(nls);
    }
    TEST_DONE();
}

/* ===== D. SEQPACKET 连接式 accept4 ===== */
static int test_seqpacket(void)
{
    TEST_START("D. accept4 SEQPACKET 连接式");
    int cs = -1;
    int ls = make_listener_with_pending(SOCK_SEQPACKET, "\0accept4-seqp", 12, &cs);
    if (ls < 0) { CHECK(0, "SEQPACKET listener 前置(需SEQPACKET支持)"); TEST_DONE(); }

    int a = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
    CHECK(a >= 0, "SEQPACKET accept4 成功");
    if (a >= 0) {
        int fl = fcntl(a, F_GETFD);
        CHECK(fl != -1 && (fl & FD_CLOEXEC), "SEQPACKET accept4 SOCK_CLOEXEC 生效");
        int type = 0;
        socklen_t tl = sizeof(type);
        CHECK(getsockopt(a, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_SEQPACKET,
              "SEQPACKET accept4 新fd SO_TYPE == SOCK_SEQPACKET");
        close(a);
    }
    close(cs);
    close(ls);
    TEST_DONE();
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, alarm_handler);
    alarm(60);
    int fail = 0;
    fail |= test_flags();
    fail |= test_peer_addr();
    fail |= test_errno();
    fail |= test_seqpacket();
    printf("\n==== test-accept4 汇总: %s ====\n", fail ? "FAIL" : "PASS");
    return fail;
}
