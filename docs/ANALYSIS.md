# Technical analysis — futex overlay on V2117 4.14.186 (all read-only, closed)

Device: V2117 MT6781, `PD2150F_EX_A_38.21.2`, `4.14.186-gdfd963175-dirty`.
Dump: `38.17.2 g6de895749` (`vmlinux_new.elf`, 106k kallsyms — both kept off GitHub).
Method: static analysis (capstone + pyelftools + Ghidra) of the dump, live read-only gates on the
phone, and a from-source `4.14.186-virt` QEMU lab with gdb. No `selinux`/`cred`/boot write was ever made.

## 1. Waiter geometry (per image — offsets never transfer)
Phone (MTK gcc, fp-based), `do_futex` frame `0x260` (`stp [sp,#-96]!` + `sub #0x200`, `x29 = entry-0x60`):
op-11 waiter (`rt_mutex_waiter`) at `x29-0xc0` = frame `sp+0x140` = thread-top `T-0x2F0`
(assumes `pt_regs 0x110`, same-thread top). `futex_q` at `T-0x388` (out of every msg frame below).
Main-side `futex_requeue` waiter (`x29-0x68` = `sp+0x78`) lives on the wrong thread for this purpose.
`rt_mutex_waiter` layout (`rtmutex_common.h`: `tree_entry` 0x0, `pi_tree_entry` 0x18, `task` 0x30,
`lock` 0x38, `prio` 0x40, 80B).

## 2. Op-11 path (Ghidra-proven on the dump)
`do_futex`: `cmp w27,#0xb` + wait-mask `{0,9,11}` + jump table → inner `case 0xb`
(PI group `6/7/8/b/c`, `cmpxchg`-gated) → `futex_q_init` / `rt_mutex_init_waiter` /
`get_futex_key` / `futex_wait_setup` / `futex_wait_queue_me` (sleep) → key-match →
`fixup_pi_state_owner` loop → `rt_mutex_wait_proxy_lock(&waiter)` post-wake → owner
adjudication → `unqueue_me_pi` → return select: proxy result (incl. `-EDEADLK`) /
`-EAGAIN` / `-EINTR` / `-ETIMEDOUT` (`0xffffff92`, present). No `futex_wait_requeue_pi`
symbol exists on this build (nm + Ghidra agree) — the logic above is its inline equivalent.

## 3. Walk attribution (deterministic both sides)
Phone: `futex_requeue` contains no `adjust` walk (full 60-call histogram) → CMP succeeds →
waiter requeued → post-wake proxy walk hits the cycle → waiter reports `35`, 8/8.
Mainline lab: CMP walks unconditionally (`adjust` via `futex_requeue`) → CMP fails `35` →
waiter never requeues → waiter times out `110`. Same code shape, opposite interleaving.

## 4. Overlay verdicts per route (field granularity, phone coordinates)
- `recvmsg` (`___sys_recvmsg` `0x180` over `sys_recvmsg` `0x90`): waiter body `+0x30` inside the
  kernel-msghdr fill `[sp+0x8, sp+0x40]`; `lock` (`+0x68`) has no writer (all 6 reg-offset
  sites resolve off-frame; no copy/memset/import in path). Body influence, no lock control.
- `sendmsg` (`0x190`): waiter at fill top edge; on-stack `ctl[36]` = `[sp+0x10, sp+0x34]`
  (length clamped ≤ 36); lock (`+0x78`) has no writer. Weaker.
- `select` (`core_sys_select`, `stack_fds` 256B at `sp+0x50`, stack path iff `nfds ≤ ~336`):
  `in/out/ex` bitmaps fully user-controlled covering the whole 80B object incl. `lock`
  — strongest fill found. Does not change the verdict below.
- Lab builds miss outright (`recvmsg` −48B, `sendmsg` −16B — different compiler layout).

## 5. Why the road is closed (ordering + retention, both proven)
Sessions show the consuming walk running during the window while the waiter sleeps; any
same-thread planting lands ~3s post-wake. No verified pointer retains the slot past frame
death (`q.rt_waiter` NULLed by requeue, `pi_blocked_on` cleared pre-resume, hb node unlinked,
`pi_state` holds no slot pointer). Score: geometry ✅, value ✅, order ❌, retention ❌ —
the two failures are kernel-lifetime facts. Full close-out: `docs/CLOSURE.md`.

## 6. Reproduce (needs the off-GitHub dump + kallsyms)
`python3 tools_out/waiter_map.py` → `sp+0x78` main-side geometry ·
`python3 tools_out/recvmsg_frame.py` → msg-frame survey ·
`python3 tools_out/feas_y75_v2.py` → feasibility pass ·
`lab/lab_init.c` + `lab/mkinitramfs.py` → QEMU `virt` bench harness (fix included:
newc padding is relative to archive offset).
