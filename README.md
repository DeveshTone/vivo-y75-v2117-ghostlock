# vivo Y75 V2117 — GhostLock on 4.14.186 → Pipe Reclaim Path

[![Device](https://img.shields.io/badge/device-V2117%20MT6781-blue)](https://github.com/DeveshTone/vivo-y75-v2117-ghostlock)
[![Kernel](https://img.shields.io/badge/kernel-4.14.186--gdfd963175--dirty-green)](https://github.com/DeveshTone/vivo-y75-v2117-ghostlock)
[![Build](https://img.shields.io/badge/build-PD2150F__EX__A__38.21.2-orange)](https://github.com/DeveshTone/vivo-y75-v2117-ghostlock)
[![Status](https://img.shields.io/badge/gates-6%2F6%20pipe%20%7C%206%2F6%20heap-brightgreen)](docs/ACHIEVEMENTS.md)
[![Safety](https://img.shields.io/badge/safety-RAM--only%20%7C%20freeze--or--reboot-lightgrey)](docs/ACHIEVEMENTS.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Authorized-device research only.** Every kernel touch stays **forked + RAM-only**. Worst case is a freeze — hold **Power 10s** and stock returns. No `boot` / `system` / `persist` / `rpmb` write.

`V2117 MT6781` `PD2150F_EX_A_38.21.2` `4.14.186-gdfd963175-dirty` · Dump `38.17.2 g6de895749` · Live gates `2026-09-10` `paranoid -1` `KASLR 0x858c000000`

Stock `ghostlock-app` (YuKongA, `6.1 .. 6.12`, `pselect 320`) is **not** one-tap on this `4.14`. This repo proves **why**, and proves the `4.14` heap reclaim that is.

> **Verdict (2026-09-12): the futex-overlay road is closed — structural NO.** Geometry ✅, value shape ✅,
> order ❌, retention ❌ (kernel-lifetime facts, proven). Gates below stand as read-only record.
> Full technical analysis: [docs/ANALYSIS.md](docs/ANALYSIS.md) · close-out: [docs/CLOSURE.md](docs/CLOSURE.md).

---

## Table of Contents

- [TL;DR — Live Gates](#tldr--live-gates)
- [Verdict — Road Closed](#verdict--road-closed)
- [Why pselect Fails, Why Pipe Succeeds](#why-pselect-fails-why-pipe-succeeds)
- [Quick Start — Every Boot (Read-Only)](#quick-start--every-boot-read-only)
- [Repository Layout](#repository-layout)
- [Canonical Offsets](#canonical-offsets)
- [Reproducing the Analysis](#reproducing-the-analysis)
- [Forking ghostlock-app for V2117](#forking-ghostlock-app-for-v2117)
- [Safety & Reversibility](#safety--reversibility)
- [Contributing](#contributing)
- [Credits & License](#credits--license)

---

## TL;DR — Live Gates

| Gate | Build | Live `38.21.2` | Verdict |
| :--- | :--- | :--- | :--- |
| `perf_leak` | `_text 0xffffff8008080000` | `0x858c000000 · 512 addrs` | KASLR re-leaks clean every boot |
| `race_oracle 8/8` | `futex_requeue sp+0x78` | `requeue 35 waiter 110 · HIT EDEADLK 8/8` | UAF window reachable |
| `pipe_probe_final 6/6` | `pipe 12/12 held 3.5s` | `6/6 HIT` `requeue 35 waiter 110` | Reclaim holds |
| `leak_probe 6/6` | `LEAK-ROUND` tags | `6/6` `LEAK-ROUND-N` readable | Heap alias plumbing intact |
| `heap_alias_verify 4/4` | `ALIAS-N-POST-0` | `4/4 HEAP-ALIAS RECLAIM` `read-first` | `38.17.2` map still live on `38.21.2` |

All five are **read-only** — no `selinux_state` or `cred` written. See [docs/ACHIEVEMENTS.md](docs/ACHIEVEMENTS.md).

## Verdict — Road Closed

| Leg | Result | Proof |
| :--- | :--- | :--- |
| Geometry (slot reachable) | ✅ closed | waiter `T-0x2F0`, inside all msg frames (`ANALYSIS §1`) |
| Value shape (bytes incl. lock) | ✅ closed | `select` bitmaps cover the full object (`ANALYSIS §4`) |
| Order (plant before consume) | ❌ fails, proven | consumer runs in-window, planting lands ~3s post-wake |
| Retention (slot outlives frame) | ❌ fails, proven | all five pointer candidates die on the wake path |

Reopen condition (exact): a walk inside `[block, wake+unqueue]` with a named retainer, plus logs
showing `AFTER→walk` order on the same stack. Details: [docs/CLOSURE.md](docs/CLOSURE.md),
[docs/ANALYSIS.md](docs/ANALYSIS.md).

## Why pselect Fails, Why Pipe Succeeds

| Signal | `6.12` stock | `4.14.186 V2117` measured |
| :--- | :--- | :--- |
| `futex_wait_requeue_pi` | symbol exists, `0x70 rt_waiter_node` | `0/106k` hits — opcode `11` lives in `futex_requeue frame 0x140 x29=sp+0xe0 waiter x29-0x68 = sp+0x78 lock sp+0xb0` (`tools_out/waiter_map.py`) |
| `sys_pselect6` frame | `0x190` with `256B stack_fds 0..14` | `0xa0` (160 B) — too small (`logs/waiter_verdict_4.14.txt` → `pselect NOT feasible`) |
| `System V msg_msg` | `kmalloc-4K` heap | `msgget: Function not implemented` on stock V2117 |
| **Working heap** | `msg_msg` | **`pipe_buffer 4K`** — `pipe 12/12` `F_SETPIPE_SZ 16*4K` `write 4K` held alive across `CMP_REQUEUE +3.5s` stays `6/6` |

`pipe_buffer 4K` covers waiter `0x50` through `lock 0x38` with `lock = &f_pi_target` valid, so the PI chain `lock` check `plVar20[7] != param_4` passes. `Stack[-0xd8]` (`__stack_chk_guard` canary) is the `pselect` gamble this repo removes.

## Quick Start — Every Boot (Read-Only)

> KASLR changes each boot. Re-leak and re-gate before any write.

```bat
:: 1) Re-leak KASLR
adb shell "/data/local/tmp/perf_leak_y75 2>&1 | tee /data/local/tmp/perf_leak_out.txt"
:: 2) Re-gate reclaim (6/6 expected)
adb shell "/data/local/tmp/y75_pipe_probe_final"
adb shell "/data/local/tmp/y75_leak_probe"
:: Or one click (Windows):
y75_clean/tools_out/run_step2.bat
```

Binaries stay at `/data/local/tmp/` — see `src/` for builds with `aarch64-linux-gnu-gcc -O2 -static -pthread`.

## Repository Layout

```
y75_clean/
├── README.md
├── docs/
│   ├── ACHIEVEMENTS.md       # full 5-gate table + provenance
│   ├── ANALYSIS.md           # consolidated technical analysis (geometry, walks, verdicts)
│   └── CLOSURE.md            # road-closed verdict + reopen condition
├── archive/                  # old y75_v2..v4 pselect attempts (never copied exp[9])
├── lab/                      # QEMU virt bench harness sources (lab_init.c, mkinitramfs.py)
├── fork_v2117/
│   ├── FORK_PLAN.md            # V2117-only pipe fork for ghostlock-app
│   └── src/kernels/4.14.186-gdfd963175-dirty/offsets.h
├── targets/target_y75.h        # canonical header (only one)
├── tools_out/
│   ├── offsets_gdfd963175.json # 1360 B for exact uname -r, at /data/local/tmp/offsets.json
│   ├── waiter_map.py           # capstone sp+0x78 extractor
│   ├── feas_y75_v2.py          # feasibility pass over dump + kallsyms
│   ├── publish_helper.py       # repo doc generator
│   ├── run_step2.bat           # one-click KASLR + 6/6
│   └── recvmsg_frame.py        # alternative stack-spray survey (0x180 vs 0xa0)
├── logs/
│   ├── waiter_verdict_4.14.txt # pselect NOT feasible verdict
│   └── extract_target.log      # 38.17.2 DIFF vs 6.x
├── src/                        # reclaim-only probes (no selinux/cred write)
│   ├── perf_leak.c
│   ├── race_oracle.c
│   ├── race_oracle_v2.c        # counts EDEADLK on either side
│   ├── y75_pipe_probe.c        # pipe reclaim v2 (robust)
│   ├── y75_pipe_probe_final.c
│   ├── y75_leak_probe.c
│   ├── y75_msg_probe.c         # msg_msg attempt (filtered: ENOSYS on stock ROM)
│   └── y75_heap_alias_verify.c
├── boot/                       # 39 MB boot.img — kept off GitHub (see .gitignore)
└── vmlinux/                    # 44 MB vmlinux_new.elf — kept off GitHub
```

`logs/kallsyms_output.txt` (106k) stays local — never committed.

## Canonical Offsets

`targets/target_y75.h` is the **only** header. Fixed from `g6de` dump against `106k kallsyms`:

| Symbol | Image-relative | Live example `KASLR 0x858c000000` | Fix |
| :--- | :--- | :--- | :--- |
| `selinux_state` | `0x01914b08` | `0x858d914b08` | was `0x01994b08` |
| `init_thread_union` | `0x02390000` | `0x858e390000` | was `0x02410000` |
| `commit_creds` | `0x000e6170` | `0x858c0e6170` | — |
| `rb_erase_cached` | `0x01263580` | — | — |
| `anon_pipe_buf_ops` | `0x01235d00` | — | — |

`KIMAGE 0xffffff8008080000` `_stext 0xffffff8008080800` `VA_BITS 39` `PAGE 4096`. `BTF not found` is expected on `4.14`.

Live import for exact `uname -r 4.14.186-gdfd963175-dirty`: `tools_out/offsets_gdfd963175.json` → push to `/data/local/tmp/offsets.json` (`GHOSTLOCK_HOME` default) and use **Import offsets.json** in ghostlock-app.

## Reproducing the Analysis

No boot flash. All from a `38.17.2` dump, verified live on `38.21.2`:

```bash
# waiter geometry (capstone 5.0.7 + pyelftools)
python3 tools_out/waiter_map.py
# → sub x8,x29,#0x68 → sp+0x78 lock sp+0xb0 frame 0x140

# offset extraction vs live
python3 ghostlock-oneplus/tools/extract_target.py --kallsyms logs/kallsyms_output.txt
# BTF
python3 ghostlock-oneplus/tools/extract_btf.py vmlinux/vmlinux_new.elf
# → BTF not found (expected on 4.14)

# alternative spray survey
python3 tools_out/recvmsg_frame.py
# → __sys_recvmsg 0x180 fp 288  (bigger than sys_pselect6 0xa0, still on-stack)

# feasibility pass over dump + kallsyms (needs logs/kallsyms_output.txt, kept local)
python3 tools_out/feas_y75_v2.py

# QEMU virt bench harness sources (needs a 4.14 arm64 Image + initramfs rebuild)
# lab/lab_init.c (PID 1: mounts, dumps kallsyms, runs race oracle) + lab/mkinitramfs.py
```

See `logs/extract_target.log` for the `DIFF` vs `6.x` defaults.

## Forking ghostlock-app for V2117

Stock [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) ships `37` kernels `6.1..6.12` and gate-checks `4.14.186-gdfd963175-dirty` as `Unsupported` before `Run`. `Import offsets.json` flips `Unsupported → Supported` and exposes its read-only preflight (`exit 6` = `patched, no write`). Stock will still not be one-tap after just the import — its internal route still assumes `6.x pselect 320`.

**Reliable fork for this `V2117` only:**

1. Clone `YuKongA/ghostlock-app`, new branch.
2. Add `src/kernels/4.14.186-gdfd963175-dirty/offsets.h` from `targets/target_y75.h`.
3. Keep its UI, its forking with `alarm`, and its staging to `/data/adb/ksu` + manager `APK` to `/data/app` exactly as stock.
4. Switch its heap route from `pselect 320` to the `pipe 12/12` held alive across `CMP_REQUEUE +3.5s` you proved `6/6`.
5. Build as `APK` with `gradlew` on `main`, gate every kernel touch in a forked child, preflight `remove_waiter()` stays first.

Staged entry is at `fork_v2117/src/kernels/4.14.186-gdfd963175-dirty/offsets.h`. No other kernel is touched.

Full plan: [fork_v2117/FORK_PLAN.md](fork_v2117/FORK_PLAN.md)

## Safety & Reversibility

- **Every kernel touch stays forked + RAM-only.** Parent stays `shell`. Worst case is freeze.
- **Read-first, then narrow write.** `selinux_state` is `enforcing 1` byte + `initialized 1` byte + `policycap` packed beside it. `cred +0x640` vs `real_cred +0x638` is `8` bytes apart. An `8-byte` store there one word off hits the wrong pointer. The safe pattern keeps the `8-byte` store in a `pipe_buffer` you own, then `read`s that heap alias — only after that `read` shows `0x01` at `enforcing` does a narrow `1-byte 0` go there from a child.
- **Persistent writes only to `/data/adb/ksu` + manager `APK` to `/data/app`** — both wiped by factory reset. `boot 39 MB` is never flashed.

Keep `boot.img` backup, battery `>50%`, `paranoid -1` still, re-leak `KASLR` and re-run the two pipes to `6/6` before any tap.

## Contributing

PRs to this `V2117` record are welcome — keep them read-only and `4.14`-specific. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits & License

- GhostLock original: [NebuSec/CyberMeowfia](https://github.com/CyberMeowfia/IonStack) · [ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) · App: [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
- `vmlinux-to-elf`, `capstone`, `pyelftools`, `extract_target` / `check_feasibility`

Licensed under [Apache-2.0](LICENSE) — same as upstream.

> This repo documents **how to reach `KernelSU management`** (`ksud` + manager), not just one `uid 0` shell that dies with its process.
