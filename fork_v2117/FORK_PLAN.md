# Fork plan V2117 — ghostlock-app pipe fork for MT6781 4.14.186-gdfd963175-dirty

## Why stock ghostlock is not one-tap here
- Ships `37` kernels `6.1..6.12`, checks exact `uname -r` — your `4.14.186-gdfd963175-dirty` shows `Unsupported`
- Internal route assumes `6.x` `futex_wait_requeue_pi` symbol with `pselect 320 256B` — your `4.14` has `0/106k` hits for that symbol, opcode `11` lives in `futex_requeue frame 0x140 x29=sp+0xe0 waiter x29-0x68 = sp+0x78 lock sp+0xb0`
- `sys_pselect6` is only `0xa0` on `4.14` — `pselect NOT feasible` per `logs/waiter_verdict_4.14.txt`

## What the fork does for this one phone
- Clone `YuKongA/ghostlock-app`, add `src/kernels/4.14.186-gdfd963175-dirty/offsets.h` from `targets/target_y75.h` (`SELINUX 0x01914b08`, `INIT 0x02390000`)
- Keep UI, forking with `alarm`, and staging to `/data/adb/ksu` + manager `APK` to `/data/app` exactly as stock
- Switch its internal heap route from `pselect 320` to the `pipe 12/12` held alive across `CMP_REQUEUE +3.5s` you proved `6/6` in `y75_pipe_probe_final.c` — `msgget filtered` chose `pipe_buffer 4K` over `msg_msg` on stock V2117
- Build as `APK` with `gradlew` on `main`, gate every kernel touch in a forked child, preflight disassembles `remove_waiter()` first — `exit 6` is `patched, no write`

## Import before the fork build
- [tools_out/offsets_gdfd963175.json](../tools_out/offsets_gdfd963175.json) `1360` bytes for exact `uname -r` is already at `C:\Users\LOQ\Downloads\` and on the phone at `/data/local/tmp/offsets.json`
- `Import offsets.json` in the app flips `Unsupported -> Supported` and lets you see its read-only preflight without tapping `Run`

## Why freeze-only stays worst case
- `RB_ERASE_CACHED 0x9263580` `8-byte` store only lands in a `pipe_buffer` you own in the fork, then `read` there
- Only after that alias `read` shows `0x01` at `0x01914b08 + KASLR 0x858c000000` does a narrow `1-byte 0` to `enforcing` happen from a child
- Same alias dump contains `task_struct` — `cred 0x640` `real_cred 0x638` parsed from that view, `uid +0x04` confirmed `2000` before any write
- `boot 39MB` never flashed; `selinux_state` and `cred` clear on reboot, `KASLR` changes so you re-leak
