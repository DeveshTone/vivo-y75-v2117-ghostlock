# vivo Y75 V2117 — Kernel Research Record (authorized device)

[![Device](https://img.shields.io/badge/device-V2117%20MT6781-blue)](https://github.com/DeveshTone/vivo-y75-v2117-ghostlock)
[![Kernel](https://img.shields.io/badge/kernel-4.14.186--gdfd963175--dirty-green)](https://github.com/DeveshTone/vivo-y75-v2117-ghostlock)
[![Build](https://img.shields.io/badge/build-PD2150F__EX__A__38.21.2-orange)](https://github.com/DeveshTone/vivo-y75-v2117-ghostlock)
[![Futex road](https://img.shields.io/badge/futex--road-closed-lightgrey)](docs/CLOSURE.md)
[![Mali lead](https://img.shields.io/badge/mali-r32p1--lead-yellow)](docs/MALI_TRACK.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> **Authorized-device research only.** Everything here is read-only or RAM-only.
> No `boot` / `system` / `persist` flash, no `selinux` / `cred` write was ever made.
> Worst case observed: a frozen test process or a reboot that clears everything.

Goal: root management (KernelSU) on our own Vivo Y75. Two roads were worked, one is closed
with proof, one holds the only live lead. This README is the map; details live in `docs/`.

## Table of Contents

- [Device](#device)
- [Road 1 — Futex overlay (closed)](#road-1--futex-overlay-closed)
- [Road 2 — Mali GPU driver (live lead)](#road-2--mali-gpu-driver-live-lead)
- [Live gates (read-only)](#live-gates-read-only)
- [Canonical offsets](#canonical-offsets)
- [Repository layout](#repository-layout)
- [Safety](#safety)
- [Credits & License](#credits--license)

## Device

Fingerprinted live over adb (authorized USB debugging):

| Item | Value |
| :--- | :--- |
| Model / SoC | V2117 / mt6781 |
| Build | `PD2150F_EX_A_38.21.2`, patch `2024-11-01` |
| Kernel | `4.14.186-gdfd963175-dirty`, clang 11.0.1, Nov 2024 |
| Dump analyzed | `38.17.2 g6de895749` (`vmlinux` + 106k kallsyms, kept off GitHub) |
| KASLR | re-leaks clean every boot (`perf`, 512 addrs, `paranoid -1`) |
| GPU | Mali-G57 MC2, driver `r32p1` both sides, `/dev/mali0` world-RW |
| Extras | full MTK node tree, `vivo_io`, ION (heap 0 works), no dma-heap |

## Road 1 — Futex overlay (closed)

GhostLock-style stack reuse of the PI-futex waiter (`CVE-2026-43499` family).
Proven real: race window `8/8` waiter `EDEADLK`, op-11 path mapped instruction-by-instruction
(Ghidra + a true `4.14.186-virt` QEMU lab with gdb — 7 sessions).

| Leg | Result |
| :--- | :--- |
| Geometry (slot reachable) | ✅ waiter `T-0x2F0`, inside all msg frames |
| Value shape (bytes incl. lock) | ✅ `select` bitmaps cover the full 80B object |
| Order (plant before consume) | ❌ consumer runs in-window; planting lands ~3s post-wake |
| Retention (slot outlives frame) | ❌ all 7 pointer candidates die on the wake path |

Structural NO — further runs re-prove the same FAIL. Reopen price (exact): a walk inside
`[block, wake+unqueue]` with a named retainer + logs showing `AFTER→walk` on one stack.
Full record: [docs/ANALYSIS.md](docs/ANALYSIS.md) · [docs/CLOSURE.md](docs/CLOSURE.md) ·
branch-2 proposal review (accepted as negative result).

## Road 2 — Mali GPU driver (live lead)

`CVE-2022-22706` shape on Valhall `r32p1` (affected: `r19–r35`; `r34–r40` UAF does **not** apply).

| Check | Result |
| :--- | :--- |
| Vulnerable instruction | ✅ `GPU_WR`-only bit into page pinning, no CPU-side check, all 320 bytes |
| Backport | ✅ absent — vulnerable shape as-shipped |
| Trigger chain | ✅ `mali0` → submit → external resources → vulnerable pin, all with addresses |
| Channel (live shell) | ✅ open/handshake/setup/version queries all succeed |
| Alloc + map + read-back | ✅ own GPU memory round-trips (`MATCH`) |
| Import (5 input shapes) | ❌ identical `ENOMEM` — gate reads nothing attacker-controlled |

One gate stands between here and the vulnerable function: `MEM_IMPORT` acceptance.
Binder-class bugs are closed by the `2024-11-01` patch level, not pursued.
Details: [docs/MALI_TRACK.md](docs/MALI_TRACK.md) (device probes kept local, never published).

## Live gates (read-only)

| Gate | Live `38.21.2` | Verdict |
| :--- | :--- | :--- |
| `perf_leak` | `0x858c000000 · 512 addrs` | KASLR re-leaks clean every boot |
| `race_oracle 8/8` | `waiter errno 35 ×8 HIT` (phone; lab mirror reports requeue-side) | PI window reachable |
| `pipe_probe_final 6/6` | `6/6 HIT` | spray/race coexistence holds |
| `leak_probe` + `heap_alias_verify` | tags round-trip | plumbing intact, own bytes only |

Re-gate every boot: `adb shell /data/local/tmp/perf_leak_y75` then the two pipe probes
(one click: `tools_out/run_step2.bat`). Binaries stay at `/data/local/tmp/`, built with
`aarch64-linux-gnu-gcc -O2 -static -pthread` from `src/`.

## Canonical offsets

From the `g6de` dump against 106k kallsyms (prediction until a live read confirms the rebuild slide):

| Symbol | Image-relative | Fix |
| :--- | :--- | :--- |
| `selinux_state` | `0x01914b08` | was `0x01994b08` |
| `init_thread_union` | `0x02390000` | was `0x02410000` |
| `commit_creds` | `0x000e6170` | — |

`KIMAGE 0xffffff8008080000` · `VA_BITS 39` · `PAGE 4096`. Import file for ghostlock-app:
`tools_out/offsets_gdfd963175.json` → `/data/local/tmp/offsets.json`.

## Repository layout

```
y75_clean/
├── README.md
├── docs/
│   ├── ACHIEVEMENTS.md       # full 5-gate table + provenance
│   ├── ANALYSIS.md           # futex technical analysis (geometry, walks, verdicts)
│   ├── MALI_TRACK.md         # Mali lead record (versions, static findings, probe table)
│   └── CLOSURE.md            # futex road-closed verdict + reopen condition
├── archive/                  # old y75_v2..v4 pselect attempts
├── lab/                      # QEMU virt bench harness sources (lab_init.c, mkinitramfs.py)
├── fork_v2117/               # V2117 ghostlock-app fork spec (superseded, kept as record)
├── targets/target_y75.h      # canonical header (only one)
├── tools_out/                # waiter_map.py, feas scripts, offsets json, run_step2.bat
├── logs/                     # waiter_verdict_4.14.txt, extract_target.log
├── src/                      # reclaim-only probes (no selinux/cred write)
├── boot/                     # boot.img backup — kept off GitHub
└── vmlinux/                  # vmlinux_new.elf + kallsyms — kept off GitHub
```

`logs/kallsyms_output.txt` (106k) stays local — never committed.

## Safety

- Phone: every touch forked + RAM-only (futex) or read/query/own-memory-only (Mali).
  Worst cases seen: frozen test process, clean `ENOMEM`, reboot-clears-all. Mali note: its
  failure mode touches *shared* caches, so targets stay restricted to our own bytes by rule.
- Never flashed: `boot`/`system`/`persist`. Never written: `selinux`/`cred`.
- Keep `boot.img` backup, battery `>50%`, re-gate after every reboot.

## Credits & License

- GhostLock original: [NebuSec/CyberMeowfia](https://github.com/CyberMeowfia/IonStack) · [ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) · App: [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
- Mali: ARM bulletins + NVD + Project Zero RCA (defensive mapping only)
- `vmlinux-to-elf`, `capstone`, `pyelftools`, QEMU+gdb lab

Licensed under [Apache-2.0](LICENSE) — same as upstream.
