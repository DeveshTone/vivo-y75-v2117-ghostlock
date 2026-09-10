# vivo Y75 V2117 MT6781 4.14.186 — GhostLock Path to KernelSU (Authorized Device)

> Authorized-device research only. Every kernel touch stays forked + RAM-only.  
  
**Device:** `V2117 MT6781` `PD2150F_EX_A_38.21.2` `4.14.186-gdfd963175-dirty` `paranoid -1`
  
**Dump:** `PD2150F_EX_A_38.17.2` `4.14.186-g6de895749-dirty` `vmlinux_new.elf 44MB 106k kallsyms`  
  
**Live gates re-proved 2026-09-10:** `paranoid -1` `KASLR 0x858c000000 512 addrs` `race 8/8 EDEADLK` `pipe 6/6 + heap 6/6 + alias 4/4` (worst case `freeze hold power 10s`)
  
## What this repo proves
- Same `4.14.186` family `g6de` vs `gdfd` after `g` is Vivo rebuild hash — `futex` waiter family did not move, so dump analysis holds live
- No `futex_wait_requeue_pi` on `4.14` (`0/106k` hits) — opcode `11` lives in `futex_requeue frame 0x140 x29=sp+0xe0 waiter x29-0x68 = sp+0x78 lock sp+0xb0` (see `tools_out/waiter_map.py`)
- Stock `pselect 320 256B stack_fds` does not exist on `4.14` — `sys_pselect6 0xa0` vs `pselect NOT feasible` per `logs/waiter_verdict_4.14.txt`
- `System V msg_msg` filtered on stock V2117 (`msgget: Function not implemented`), so `pipe_buffer 4K` with `pipe 12/12` held alive across `CMP_REQUEUE +3.5s` is the `4.14` heap that stays `6/6`
- Every future `Step 7 selinux_state 0x01914b08` / `Step 8 cred 0x640` would be `read-first` in a forked child with `alarm 9` — `1-byte 0` to `enforcing` only, neighbors never overwritten

## Results table
| Gate | Build | Live `38.21.2` | Verdict |
|---|---|---|---|
| `perf_leak` | `vmlinux 0x8080000` | `0x858c000000 512 addrs` | `KASLR` re-leaks clean every boot |
| `race_oracle 8/8` | `futex_requeue sp+0x78` | `requeue 35 waiter 110 HIT EDEADLK 8/8` | `UAF` window reachable |
| `pipe_probe_final 6/6` | `pipe 12/12` | `6/6 HIT` `requeue 35 waiter 110` | Reclaim holds |
| `leak_probe 6/6` | `LEAK-ROUND` tags | `6/6` `LEAK-ROUND-N` readable | Heap alias plumbing intact |
| `heap_alias_verify 4/4` | `ALIAS-N-POST-0` | `4/4 HEAP-ALIAS RECLAIM` `read-first` | `38.17.2` waiter map still live on `38.21.2` |

## How to use this repo
- `targets/target_y75.h` is the only header (`SELINUX 0x01914b08` fixed from `0x01994b08`, `INIT 0x02390000`)
- `tools_out/run_step2.bat` re-leaks `KASLR` and re-runs the two pipe probes to `6/6` before any write
- `tools_out/offsets_gdfd963175.json` `1360` bytes for exact `uname -r 4.14.186-gdfd963175-dirty` is already at `C:\Users\LOQ\Downloads\` and on the phone at `/data/local/tmp/offsets.json`

## Provenance
`vmlinux_new.elf` via `vmlinux-to-elf` `256k relocs`, `kallsyms_output.txt 106k`, `capstone 5.0.7 + pyelftools`, `tools_out/waiter_map.py` `sub x8,x29,#0x68 -> sp+0x78`

Reversible: `boot 39MB` on PC never flashed. `selinux_state` and `cred` live in RAM. `pipe_buffer` is heap you own and can `close`. Hold `power 10s` is worst case.
