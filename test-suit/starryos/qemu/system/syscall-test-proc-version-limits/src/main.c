/*
 * procfs completeness: /proc/version, /proc/thread-self, /proc/[pid]/limits.
 *
 * Ground truth: proc(5) man page and Linux fs/proc/version.c
 * (version_proc_show -> linux_proc_banner "%s version %s ..."),
 * fs/proc/thread_self.c (proc_thread_self_get_link -> "<tgid>/task/<tid>"
 * symlink), fs/proc/base.c (proc_pid_limits -> "Limit / Soft Limit /
 * Hard Limit / Units" table, one row per RLIMIT_* in lnames[] order, with
 * fixed column widths "%-25s %-20s %-20s %-10s" and "unlimited" for
 * RLIM_INFINITY).
 *
 * The suite verifies existence, exact content/format, symlink target and
 * resolution, readback consistency against getrlimit(2), and negative
 * controls. On a kernel that does not expose these entries every open()
 * fails with ENOENT so the whole suite fails there (test-first baseline).
 */

#include "test_framework.h"

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Read a whole small pseudo-file into buf (NUL-terminated). Returns bytes read
 * or -1 (errno set). Uses openat/read so a missing file yields ENOENT. */
static ssize_t slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    size_t total = 0;
    for (;;)
    {
        if (total + 1 >= cap)
        {
            errno = ENOMEM;
            close(fd);
            return -1;
        }
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n < 0)
        {
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);
    return (ssize_t)total;
}

/* Locate the row for a named limit in the /proc/self/limits body and confirm
 * it begins with the exact 25-wide left-justified name column. Returns a
 * pointer just past that column (to the Soft-Limit field) or NULL. */
static const char *limit_row(const char *body, const char *name)
{
    const char *p = body;
    size_t nlen = strlen(name);
    while (p && *p)
    {
        if (strncmp(p, name, nlen) == 0)
        {
            /* Linux pads the name field to width 25 with a trailing space:
             * "%-25s ". The name column is exactly 25 chars then a space. */
            size_t pad = 25 > nlen ? 25 - nlen : 0;
            const char *q = p + nlen;
            for (size_t i = 0; i < pad; i++)
            {
                if (q[i] != ' ')
                    return NULL;
            }
            /* one separator space after the 25-wide column */
            const char *field = p + (nlen < 25 ? 25 : nlen);
            if (*field == ' ')
                field++;
            return field;
        }
        p = strchr(p, '\n');
        if (p)
            p++;
    }
    return NULL;
}

static void test_version(void)
{
    char buf[4096];
    ssize_t n = slurp("/proc/version", buf, sizeof(buf));
    CHECK(n > 0, "/proc/version is readable");
    if (n <= 0)
        return;

    /* linux_proc_banner: "%s version %s ...\n" with sysname="Linux". */
    CHECK(strncmp(buf, "Linux version ", 14) == 0,
          "/proc/version starts with \"Linux version \"");
    /* A release token must follow "Linux version " and be non-empty. */
    const char *rel = buf + 14;
    CHECK(rel[0] != '\0' && rel[0] != ' ' && rel[0] != '\n',
          "/proc/version has a non-empty release token");
    /* Banner is a single line terminated by newline. */
    CHECK(buf[n - 1] == '\n', "/proc/version ends with newline");
    CHECK(strchr(buf, '\n') == buf + n - 1,
          "/proc/version is exactly one line");
}

static void test_thread_self(void)
{
    struct stat st;
    /* lstat must see a symlink, not a regular file or dir. */
    CHECK_RET(lstat("/proc/thread-self", &st), 0, "lstat /proc/thread-self");
    CHECK(S_ISLNK(st.st_mode), "/proc/thread-self is a symlink");

    /* Single-threaded process: tgid == tid == getpid(). Target must be
     * exactly "<tgid>/task/<tid>". */
    char want[64];
    snprintf(want, sizeof(want), "%d/task/%d", (int)getpid(), (int)getpid());

    char link[128];
    ssize_t n = readlink("/proc/thread-self", link, sizeof(link) - 1);
    CHECK(n > 0, "readlink /proc/thread-self succeeds");
    if (n > 0)
    {
        link[n] = '\0';
        CHECK(strcmp(link, want) == 0,
              "/proc/thread-self -> \"<tgid>/task/<tid>\"");
    }

    /* readlink must NOT NUL-terminate; verify the returned length matches. */
    CHECK((size_t)n == strlen(want),
          "readlink returns unterminated exact length");

    /* Resolving the link must reach the current thread's status: Pid == tid. */
    char status[8192];
    ssize_t sn = slurp("/proc/thread-self/status", status, sizeof(status));
    CHECK(sn > 0, "/proc/thread-self/status resolves and reads");
    if (sn > 0)
    {
        char pidline[64];
        snprintf(pidline, sizeof(pidline), "Pid:\t%d\n", (int)getpid());
        CHECK(strstr(status, pidline) != NULL,
              "/proc/thread-self/status shows this thread's Pid");
    }
}

/* Names must appear in the exact fs/proc/base.c lnames[] order (index order
 * matches RLIMIT_* values, identical across x86/aarch64/riscv64/loongarch64). */
static const char *const kLimitNames[] = {
    "Max cpu time",       "Max file size",       "Max data size",
    "Max stack size",     "Max core file size",  "Max resident set",
    "Max processes",      "Max open files",      "Max locked memory",
    "Max address space",  "Max file locks",      "Max pending signals",
    "Max msgqueue size",  "Max nice priority",   "Max realtime priority",
    "Max realtime timeout",
};

static const char *const kLimitUnits[] = {
    "seconds", "bytes",   "bytes",  "bytes",    "bytes", "bytes",
    "processes", "files", "bytes",  "bytes",    "locks", "signals",
    "bytes",   NULL,      NULL,     "us",
};

static void test_limits(void)
{
    char buf[8192];
    ssize_t n = slurp("/proc/self/limits", buf, sizeof(buf));
    CHECK(n > 0, "/proc/self/limits is readable");
    if (n <= 0)
        return;

    /* Exact header line from fs/proc/base.c seq_puts. */
    const char *hdr = "Limit                     "
                      "Soft Limit           "
                      "Hard Limit           "
                      "Units     \n";
    CHECK(strncmp(buf, hdr, strlen(hdr)) == 0,
          "/proc/self/limits header matches Linux exactly");

    /* Every RLIMIT_* row present, in order, with the exact name column. */
    const size_t nlim = sizeof(kLimitNames) / sizeof(kLimitNames[0]);
    const char *scan = buf;
    for (size_t i = 0; i < nlim; i++)
    {
        const char *field = limit_row(scan, kLimitNames[i]);
        char msg[96];
        snprintf(msg, sizeof(msg), "limits row \"%s\" present in order",
                 kLimitNames[i]);
        CHECK(field != NULL, msg);
        if (field)
            scan = field; /* enforce ordering by advancing past this row */
    }

    /* Units column: rows with a unit end in that unit; RLIMIT_NICE and
     * RLIMIT_RTPRIO have no unit (lnames[].unit == NULL -> bare newline). */
    for (size_t i = 0; i < nlim; i++)
    {
        const char *field = limit_row(buf, kLimitNames[i]);
        if (!field)
            continue;
        const char *eol = strchr(field, '\n');
        if (!eol)
            continue;
        char msg[96];
        if (kLimitUnits[i])
        {
            /* Unit token must appear on the row before the newline. */
            size_t ulen = strlen(kLimitUnits[i]);
            int found = 0;
            for (const char *q = field; q + ulen <= eol; q++)
            {
                if (strncmp(q, kLimitUnits[i], ulen) == 0)
                {
                    found = 1;
                    break;
                }
            }
            snprintf(msg, sizeof(msg), "\"%s\" row carries unit \"%s\"",
                     kLimitNames[i], kLimitUnits[i]);
            CHECK(found, msg);
        }
        else
        {
            /* No-unit rows: trailing field is blank up to newline. */
            const char *q = field;
            while (q < eol && *q == ' ')
                q++;
            /* skip the numeric soft/hard columns */
            while (q < eol && (*q == ' ' || (*q >= '0' && *q <= '9') ||
                               (*q >= 'a' && *q <= 'z')))
                q++;
            snprintf(msg, sizeof(msg), "\"%s\" row has no unit column",
                     kLimitNames[i]);
            CHECK(q == eol, msg);
        }
    }

    /* RLIM_INFINITY (u64::MAX) must render as "unlimited". RLIMIT_DATA is
     * seeded to infinity by both Linux INIT_RLIMITS and Starry Rlimits::default,
     * so its soft AND hard columns are "unlimited" regardless of the
     * default-seeding gap on the other limits. This isolates the "unlimited"
     * rendering path in proc_pid_limits. */
    {
        const char *field = limit_row(buf, "Max data size");
        CHECK(field && strncmp(field, "unlimited", 9) == 0,
              "RLIM_INFINITY renders as \"unlimited\" (Max data size soft)");
        if (field)
        {
            const char *hard = field + 9;
            while (*hard == ' ')
                hard++;
            CHECK(strncmp(hard, "unlimited", 9) == 0,
                  "RLIM_INFINITY renders as \"unlimited\" (Max data size hard)");
        }
    }

    /* Readback consistency: getrlimit(RLIMIT_NOFILE) soft/hard must match the
     * numbers printed in the "Max open files" row (default 1024/1024 here). */
    {
        struct rlimit rl;
        CHECK_RET(getrlimit(RLIMIT_NOFILE, &rl), 0, "getrlimit(RLIMIT_NOFILE)");
        const char *field = limit_row(buf, "Max open files");
        CHECK(field != NULL, "Max open files row found for readback");
        if (field && rl.rlim_cur != RLIM_INFINITY)
        {
            char want[32];
            snprintf(want, sizeof(want), "%lu", (unsigned long)rl.rlim_cur);
            CHECK(strstr(field, want) != NULL,
                  "limits soft NOFILE matches getrlimit");
        }
        if (field && rl.rlim_max != RLIM_INFINITY)
        {
            char want[32];
            snprintf(want, sizeof(want), "%lu", (unsigned long)rl.rlim_max);
            CHECK(strstr(field, want) != NULL,
                  "limits hard NOFILE matches getrlimit");
        }
    }

    /* Mutate a limit then confirm the file reflects it (live read, not a
     * cached snapshot). Lower the NOFILE soft limit and re-read. */
    {
        struct rlimit save, rl;
        CHECK_RET(getrlimit(RLIMIT_NOFILE, &save), 0, "save NOFILE");
        rl = save;
        rl.rlim_cur = 512;
        CHECK_RET(setrlimit(RLIMIT_NOFILE, &rl), 0, "setrlimit NOFILE soft=512");

        char buf2[8192];
        ssize_t n2 = slurp("/proc/self/limits", buf2, sizeof(buf2));
        CHECK(n2 > 0, "re-read /proc/self/limits after setrlimit");
        if (n2 > 0)
        {
            const char *field = limit_row(buf2, "Max open files");
            CHECK(field && strstr(field, "512") != NULL,
                  "limits reflects lowered NOFILE soft (live)");
        }
        /* restore */
        setrlimit(RLIMIT_NOFILE, &save);
    }

    /* Cross-check via explicit pid path: /proc/<pid>/limits == /proc/self. */
    {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/limits", (int)getpid());
        char buf3[8192];
        ssize_t n3 = slurp(path, buf3, sizeof(buf3));
        CHECK(n3 > 0, "/proc/<pid>/limits readable by numeric pid");
        if (n3 > 0)
            CHECK(strncmp(buf3, hdr, strlen(hdr)) == 0,
                  "/proc/<pid>/limits has same header");
    }
}

static void test_negative_controls(void)
{
    /* Nonexistent siblings must still be ENOENT (guards against a wildcard
     * that would answer any name). */
    CHECK_ERR(open("/proc/version-nope", O_RDONLY), ENOENT,
              "/proc/version-nope -> ENOENT");
    CHECK_ERR(open("/proc/thread-self-nope", O_RDONLY), ENOENT,
              "/proc/thread-self-nope -> ENOENT");

    /* thread-self is a symlink: O_RDONLY|O_NOFOLLOW must refuse to open it. */
    errno = 0;
    int fd = open("/proc/thread-self", O_RDONLY | O_NOFOLLOW);
    CHECK(fd < 0 && (errno == ELOOP || errno == EMLINK),
          "open(/proc/thread-self, O_NOFOLLOW) refuses the symlink");
    if (fd >= 0)
        close(fd);

    /* A bogus numeric pid dir has no limits file. */
    CHECK_ERR(open("/proc/999999/limits", O_RDONLY), ENOENT,
              "/proc/<bad-pid>/limits -> ENOENT");
}

int main(void)
{
    TEST_START("proc-version-thread-self-limits");
    test_version();
    test_thread_self();
    test_limits();
    test_negative_controls();
    TEST_DONE();
}
