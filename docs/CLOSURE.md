# Closure — futex-overlay road (2026-09-12)

> Status: **closed, structural NO**. This file records the verdict so nobody re-runs it blind.
> Reopen condition (exact): a walk inside `[block, wake+unqueue]` with a named retainer,
> plus logs showing `AFTER→walk` order on the same stack S. Absent that, this road stays closed.

## What was proven on this device (V2117, 4.14.186-gdfd, read-only throughout)
- Race window real: `race_oracle` 8/8 waiter `EDEADLK` (live gates 2026-09-10, see `docs/ACHIEVEMENTS.md`).
- Op-11 waiter is a waiter-thread-owned on-stack `rt_mutex_waiter` (`do_futex` `0x260` frame,
  `sp+0x140`); op-11 dispatch proven in Ghidra (`case 0xb` = inline PI-wait, no
  `futex_wait_requeue_pi` symbol on this build); post-wake proxy walk reports the waiter's `35`.
- Overlay influence caps at 16 bytes (`tree_entry` head) via `recvmsg` msghdr fill; the `lock`
  field has no writer in any surveyed path (`recvmsg`/`sendmsg`/poll/select mapped to the field).
  Strongest fill found (`select` bitmaps) still lands post-consumer.
- Ordering (measured, 7 QEMU+gdb sessions on a true 4.14.186-virt lab): the consuming walk runs
  during the window while the waiter sleeps; any same-thread planting lands ~3s later.
- Retention: no verified pointer outlives the waiter frame (all five candidates NULL/unlink/clear
  on the wake path). Geometry ✅, value ✅, order ❌, retention ❌ — the two failures are
  kernel-lifetime facts, so no syscall rearrangement inside this design space moves them.

## What this repo remains
Gates, offsets (`targets/target_y75.h`), fork spec (`fork_v2117/FORK_PLAN.md`), methods, and this
verdict. `boot/` + `vmlinux/` stay off-GitHub (see `.gitignore`); no `selinux`/`cred`/boot write was
ever performed — every gate is forked + RAM-only, worst case a 10s power-hold reboot.

## Reopen price
A one-page design (retained pointer, re-walk trigger, 16-byte value shape, thread sequence,
lab-falsifiable observables) reviewed before anything boots — per the bar that closed this road.
