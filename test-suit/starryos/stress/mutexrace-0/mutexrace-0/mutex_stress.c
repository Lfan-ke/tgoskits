// mutex_stress.c — deterministic SMP stress for axsync::RawMutex page-cache path.
//
// N threads concurrently pread() the SAME (cached) file in a tight loop. Every
// read goes through axfs-ng with_pages() -> page_cache.lock() (file.rs:584),
// a single per-file axsync::Mutex hammered from multiple CPUs. On the
// pre-existing SMP RawMutex handoff/owner race this triggers the kernel panic:
//   "Thread(N) tried to acquire mutex it already owns" (mutex.rs:167)
//
// Each thread keeps its own fd open and re-reads the first few pages (warm in
// the page cache after the first pass) so the only meaningful work per
// iteration is lock()/copy/unlock() on the shared mutex — maximizing the
// lock-handoff rate and the chance of hitting the owner-handoff race.
//
// Prints MUTEX_STRESS_OK only if all threads finish without the kernel
// panicking (a panic aborts the whole VM, so success == survival).

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef NTHREADS
#define NTHREADS 8
#endif
#ifndef NITERS
#define NITERS 200000
#endif
#ifndef NPAGES
#define NPAGES 8 /* pages touched per iteration (kept warm in page cache) */
#endif

static const char *PATH = "/tmp/mutex_stress_data.bin";
static volatile int go = 0;

static void *worker(void *arg) {
    long id = (long)arg;
    int fd = open(PATH, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open fail t%ld\n", id); return (void *)1; }
    char buf[256];
    while (!go) { /* start gun */ }
    for (int i = 0; i < NITERS; i++) {
        // Read a couple of pages that stay warm in the page cache; the hot path
        // is purely page_cache.lock() / copy / unlock() across CPUs.
        for (int p = 0; p < NPAGES; p++) {
            if (pread(fd, buf, sizeof(buf), (off_t)p * 4096) < 0) {
                close(fd); return (void *)1;
            }
        }
    }
    close(fd);
    return (void *)0;
}

int main(void) {
    int fd = open(PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("create"); return 2; }
    char page[4096];
    memset(page, 'x', sizeof(page));
    for (int i = 0; i < 16; i++) {
        if (write(fd, page, sizeof(page)) != (ssize_t)sizeof(page)) {
            perror("write"); close(fd); return 2;
        }
    }
    close(fd);

    pthread_t th[NTHREADS];
    for (long t = 0; t < NTHREADS; t++) {
        if (pthread_create(&th[t], NULL, worker, (void *)t) != 0) {
            fprintf(stderr, "pthread_create fail\n"); return 3;
        }
    }
    printf("MUTEX_STRESS_START threads=%d iters=%d pages=%d\n",
           NTHREADS, NITERS, NPAGES);
    fflush(stdout);
    go = 1;
    int rc = 0;
    for (int t = 0; t < NTHREADS; t++) {
        void *r;
        pthread_join(th[t], &r);
        if (r) rc = 4;
    }
    if (rc == 0) printf("MUTEX_STRESS_OK\n");
    else printf("MUTEX_STRESS_FAIL rc=%d\n", rc);
    fflush(stdout);
    return rc;
}
