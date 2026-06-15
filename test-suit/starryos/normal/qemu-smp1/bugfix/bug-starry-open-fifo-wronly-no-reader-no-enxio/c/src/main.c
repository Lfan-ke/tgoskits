/*
 * bug-open-fifo-wronly-no-reader-no-enxio: open(FIFO, O_WRONLY|O_NONBLOCK)
 * with no reader must ENXIO.
 *
 * man 2 open §"ENXIO" (1st variant):
 *   "O_NONBLOCK | O_WRONLY is set, the named file is a FIFO, and no process
 *    has the FIFO open for reading."
 *
 * Linux behavior: -1 ENXIO.
 * StarryOS bug: returns valid fd (FIFO handling doesn't check reader presence).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    const char *fifo = "/tmp/bug_fifo_no_reader";
    unlink(fifo);
    if (mkfifo(fifo, 0644) != 0) { perror("mkfifo"); return 1; }

    errno = 0;
    int fd = open(fifo, O_WRONLY | O_NONBLOCK);
    int ok = (fd == -1 && errno == ENXIO);
    if (ok) {
        printf("PASS: open(FIFO, O_WRONLY|O_NONBLOCK) no reader -> -1 ENXIO\n");
    } else {
        printf("FAIL: expected -1 ENXIO, got fd=%d errno=%d (%s)\n",
               fd, errno, strerror(errno));
    }
    if (fd >= 0) close(fd);
    unlink(fifo);
    return ok ? 0 : 1;
}
