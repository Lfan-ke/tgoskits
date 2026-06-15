/*
 * bug-openat-resolve-at-relative-sigsegv
 *
 * 现象: starry kernel 在以下序列下触发 SIGSEGV (host: 全部正常):
 *
 *   1. mkdir + 子目录 + 子目录内文件
 *   2. open(子目录, O_RDONLY|O_DIRECTORY) 得 dirfd
 *   3. openat(dirfd, "child", O_RDONLY) ← starry x86_64 此处崩
 *
 * 触发条件: 在已应用 fix-open-openat-bugs PR (15 类局部修) 的 kernel 上。
 *           dev 上是否复现待 maintainer 验证。
 *
 * Linux/host 行为: openat(dfd, "inner", O_RDONLY) 返回 fd >= 0，可正常 read。
 * starry x86_64: SIGSEGV (status=139)
 *
 * 影响范围: starry kernel resolve_at + relative dirfd 解析路径。
 *
 * 出处: PR Lfan-ke/tgoskits#2 (fix-open-openat-bugs) CI run 25955202119
 *       崩在 openat_dirfd.c:53 (PASS "openat AT_FDCWD: both opens ok") 之后
 *       的下一个 case `relative_with_dirfd`。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TOPDIR   "/tmp/bug_openat_rel"
#define SUBDIR   TOPDIR "/sub"
#define INNER    SUBDIR "/inner"

static int write_file(const char *path, const char *content)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return n == (ssize_t)strlen(content) ? 0 : -1;
}

int main(void)
{
    printf("=== bug-openat-resolve-at-relative-sigsegv ===\n");
    printf("expect: openat(dirfd, \"inner\", O_RDONLY) returns fd >= 0\n");
    printf("starry: SIGSEGV (status=139) on x86_64\n\n");

    /* setup */
    mkdir(TOPDIR, 0755);
    mkdir(SUBDIR, 0755);
    if (write_file(INNER, "hello") != 0) {
        printf("SETUP-FAIL: cannot write %s (errno=%d)\n", INNER, errno);
        return 2;
    }

    /* 1. 打开子目录 */
    int dfd = open(SUBDIR, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        printf("FAIL: open(%s, O_RDONLY|O_DIRECTORY) errno=%d\n", SUBDIR, errno);
        return 2;
    }
    printf("OK: open(%s, O_RDONLY|O_DIRECTORY) -> dfd=%d\n", SUBDIR, dfd);

    /* 2. 相对路径 openat ←— starry 此处崩 */
    int fd = openat(dfd, "inner", O_RDONLY);
    if (fd < 0) {
        printf("FAIL: openat(dfd, \"inner\", O_RDONLY) errno=%d\n", errno);
        close(dfd);
        return 1;
    }

    /* 3. 验证内容 */
    char buf[16] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n == 5 && memcmp(buf, "hello", 5) == 0) {
        printf("PASS: read returned %zd bytes, content matches\n", n);
        close(fd);
        close(dfd);
        printf("TEST PASSED (bug NOT reproduced)\n");
        return 0;
    }
    printf("FAIL: read n=%zd content=\"%s\"\n", n, buf);
    close(fd);
    close(dfd);
    return 1;
}
