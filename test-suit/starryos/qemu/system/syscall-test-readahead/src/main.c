/*
 * readahead(2) conformance.
 *
 * Ground truth: readahead(2) man page and Linux mm/readahead.c ksys_readahead
 * (v7.2, line 724). readahead validates the fd, then issues an advisory
 * POSIX_FADV_WILLNEED hint and returns 0. It is a hint, so a validated no-op
 * returning 0 is correct, but the fd validation must match Linux exactly:
 *   - closed / never-opened fd            -> EBADF   (fd_empty)
 *   - fd not opened for reading (O_WRONLY)-> EBADF   (!(f_mode & FMODE_READ))
 *   - fd whose type cannot readahead
 *     (pipe, socket, directory, char dev) -> EINVAL  (!S_ISREG && !S_ISBLK)
 * A regular readable file returns 0 for any offset/count including zero-count,
 * negative offset (offset is loff_t but not range-checked by the syscall), and
 * huge counts (count is only a hint bound).
 *
 * All four target arches provide __NR_readahead (x86_64=187, aarch64=213,
 * riscv64=213, loongarch64=213) and the ABI is three scalar registers with no
 * exposed struct, so no per-arch struct handling is needed. On a kernel that
 * does not implement the syscall every call returns ENOSYS, so this whole
 * suite fails there (test-first baseline).
 */

#include "test_framework.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Call the syscall directly rather than the libc wrapper so the errno branches
 * are exercised deterministically regardless of any libc-side count splitting.
 */
static long ra(int fd, off_t offset, size_t count)
{
    return syscall(SYS_readahead, fd, (long long)offset, count);
}

/* Populate a scratch regular file with known content and return its fd. */
static int make_regular(const char *path, int flags)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    char buf[8192];
    memset(buf, 'A', sizeof(buf));
    for (int i = 0; i < 4; i++)
        if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf))
        {
            close(fd);
            return -1;
        }
    close(fd);
    return open(path, flags);
}

static void test_regular_success(void)
{
    const char *path = "/tmp/ra_reg.bin";
    int fd = make_regular(path, O_RDONLY);
    CHECK(fd >= 0, "open regular file O_RDONLY");

    /* Baseline: a readable regular file returns 0. */
    CHECK_RET(ra(fd, 0, 4096), 0, "readahead(reg, 0, 4096) -> 0");

    /* Whole-file span. */
    CHECK_RET(ra(fd, 0, 32768), 0, "readahead full-file span -> 0");

    /* Offset in the middle of the file. */
    CHECK_RET(ra(fd, 16384, 4096), 0, "readahead mid-file offset -> 0");

    /* Zero count is a valid no-op hint. */
    CHECK_RET(ra(fd, 0, 0), 0, "readahead zero count -> 0");

    /* Offset beyond EOF: still a valid hint, returns 0. */
    CHECK_RET(ra(fd, 1 << 20, 4096), 0, "readahead offset past EOF -> 0");

    /* Huge count is only an upper bound on the hint; returns 0. */
    CHECK_RET(ra(fd, 0, (size_t)1 << 30), 0, "readahead huge count -> 0");

    /* Negative offset: loff_t is signed and not range-checked by the syscall. */
    CHECK_RET(ra(fd, -1, 4096), 0, "readahead negative offset -> 0 (not range-checked)");

    close(fd);
    unlink(path);
}

static void test_rdwr_and_wronly(void)
{
    const char *path = "/tmp/ra_mode.bin";

    /* O_RDWR is readable -> success. */
    int rw = make_regular(path, O_RDWR);
    CHECK(rw >= 0, "open regular file O_RDWR");
    CHECK_RET(ra(rw, 0, 4096), 0, "readahead on O_RDWR fd -> 0");
    close(rw);

    /* O_WRONLY is not readable -> EBADF (FMODE_READ missing). */
    int wo = open(path, O_WRONLY);
    CHECK(wo >= 0, "open regular file O_WRONLY");
    CHECK_ERR(ra(wo, 0, 4096), EBADF, "readahead on O_WRONLY fd -> EBADF");
    close(wo);

    unlink(path);
}

static void test_ebadf(void)
{
    /* Never-opened descriptor. */
    CHECK_ERR(ra(999, 0, 4096), EBADF, "readahead on unopened fd -> EBADF");

    /* Explicitly closed descriptor. */
    const char *path = "/tmp/ra_closed.bin";
    int fd = make_regular(path, O_RDONLY);
    CHECK(fd >= 0, "open then close fixture");
    close(fd);
    CHECK_ERR(ra(fd, 0, 4096), EBADF, "readahead on closed fd -> EBADF");

    /* Negative fd. */
    CHECK_ERR(ra(-1, 0, 4096), EBADF, "readahead on fd=-1 -> EBADF");

    unlink(path);
}

static void test_einval_types(void)
{
    /* Pipe read end: readable but not a regular/block file -> EINVAL. */
    int pfd[2];
    CHECK(pipe(pfd) == 0, "pipe fixture");
    CHECK_ERR(ra(pfd[0], 0, 4096), EINVAL, "readahead on pipe read end -> EINVAL");
    close(pfd[0]);
    close(pfd[1]);

    /* Socket: readable but cannot readahead -> EINVAL. */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(s >= 0, "socket fixture");
    CHECK_ERR(ra(s, 0, 4096), EINVAL, "readahead on socket -> EINVAL");
    close(s);

    /* Directory fd: S_ISDIR is neither S_ISREG nor S_ISBLK -> EINVAL. */
    int d = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(d >= 0, "open directory fixture");
    CHECK_ERR(ra(d, 0, 4096), EINVAL, "readahead on directory fd -> EINVAL");
    close(d);

    /* Character device (/dev/null): S_ISCHR -> EINVAL. */
    int c = open("/dev/null", O_RDONLY);
    if (c >= 0)
    {
        CHECK_ERR(ra(c, 0, 4096), EINVAL, "readahead on char device -> EINVAL");
        close(c);
    }
    else
    {
        printf("  SKIP | /dev/null unavailable; char-device EINVAL not checked\n");
    }
}

static void test_ordering_ebadf_before_einval(void)
{
    /*
     * Negative control on precedence: an O_WRONLY *pipe*-like case cannot be
     * constructed, but we assert the two distinct branches never collapse:
     * a closed fd is EBADF, a live pipe is EINVAL. If a kernel returned the
     * same errno for both, one of these checks fails.
     */
    int pfd[2];
    CHECK(pipe(pfd) == 0, "precedence pipe fixture");
    int saved = pfd[0];
    CHECK_ERR(ra(saved, 0, 4096), EINVAL, "live pipe -> EINVAL");
    close(pfd[0]);
    close(pfd[1]);
    CHECK_ERR(ra(saved, 0, 4096), EBADF, "same fd after close -> EBADF (not EINVAL)");
}

int main(void)
{
    TEST_START("readahead(2)");

    test_regular_success();
    test_rdwr_and_wronly();
    test_ebadf();
    test_einval_types();
    test_ordering_ebadf_before_einval();

    TEST_DONE();
}
