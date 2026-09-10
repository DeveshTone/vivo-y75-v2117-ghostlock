# vivo Y75 V2117 MT6781 — 4.14.186 GhostLock → KernelSU (Authorized Device)

**Authorized-device research only. Every kernel touch stays forked + RAM-only. Worst case is freeze — hold power 10 s. No boot/system/persist rewrite.**

- **Device:** `V2117 MT6781` `PD2150F_EX_A_38.21.2` `4.14.186-gdfd963175-dirty` `paranoid -1` `Enforcing`
- **Dump:** `PD2150F_EX_A_38.17.2` `4.14.186-g6de895749-dirty` `vmlinux_new.elf 44 MB 106k kallsyms` (`_text 0xffffff8008080000`)
- **Live gates (2026-09-10):** `paranoid -1` `KASLR 0x858c000000 512 addrs` `race 8/8 EDEADLK` `pipe 6/6 + heap 6/6 + alias 4/4`

Full results: [docs/ACHIEVEMENTS.md](docs/ACHIEVEMENTS.md) · Fork plan: [fork_v2117/FORK_PLAN.md](fork_v2117/FORK_PLAN.md)

## Quick start (read-only gates on your device)

```bat
REM every boot (KASLR changes each boot):
y75_clean/tools_out/run_step2.bat
adb shell "/data/local/tmp/y75_pipe_probe_final"
adb shell "/data/local/tmp/y75_leak_probe"
```

## What this proves

- No `futex_wait_requeue_pi` on `4.14` (`0/106k` hits) — opcode `11` lives in `futex_requeue frame 0x140 x29=sp+0xe0 waiter x29-0x68 = sp+0x78 lock sp+0xb0` (`tools_out/waiter_map.py`)
- Stock `pselect 320 256B` does not exist on `4.14` — `sys_pselect6 0xa0` vs `pselect NOT feasible` (`logs/waiter_verdict_4.14.txt`)
- `System V msg_msg` filtered on stock V2117 — `pipe_buffer 4K` with `pipe 12/12` held alive is the `4.14` heap that stays `6/6`

## Offsets

- Canonical header: `targets/target_y75.h` — `SELINUX 0x01914b08` fixed from `0x01994b08`, `INIT 0x02390000`
- Live import for exact `uname -r 4.14.186-gdfd963175-dirty`: `tools_out/offsets_gdfd963175.json` `1360` bytes at `/data/local/tmp/offsets.json`

## Safety

- No `boot 39 MB` flash. `selinux_state` and `cred` are RAM — reboot clears them.
- Every future `Step 7/8` would be `read-first` in a forked child — `1-byte 0` to `enforcing` only.
