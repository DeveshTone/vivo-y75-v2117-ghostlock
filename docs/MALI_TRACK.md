# Mali track — Valhall r32p1 lead (read-only mapping + owned-memory probes)

Device: V2117 mt6781, Mali-G57 MC2, driver `r32p1` both sides (userspace GLES string +
kernel-image strings), `/dev/mali0` world-RW, SPL `2024-11-01`. All live checks from an
unprivileged shell; device-side probes allocate and touch **own memory only**.

## Version table (ARM bulletin + NVD, Valhall line)

| CVE | Effect | Affected | r32p1 | Standing |
| :--- | :--- | :--- | :--- | :--- |
| 2022-22706 | write to read-only pages | r19–r35 (fixed r36p0) | inside | **lead** |
| 2023-26083 | kernel metadata leak | r19–r42 | inside | leak-class only, no privilege path alone |
| 2024-4610 | use-after-free (KEV) | r34–r40 | below range | not affected |

## Static findings (phone image)
- `kbase_jd_user_buf_pin_pages`: the page-pin write bit comes from the GPU-side region flag
  alone, with no CPU-side writability check in all 320 bytes — the pre-fix shape (fix ref `5381ff7`).
  No backport present.
- Chain with addresses: `mali0` open → `kbase_ioctl` dispatcher → job submit (user atoms
  copied) → external resources → `map_external_resource+0x74` → vulnerable pin.
- `kbase` driver is built in (symbols in main kallsyms, no vendor module involved).

## Live probe results (each single-run, reviewed before build, full teardown)
| Probe | Result |
| :--- | :--- |
| open/handshake/setup/version | `fd=3`, API `{11,38}`, DDK `K:r32p1-00bet5(GPL)` — all succeed |
| GPU alloc + map + read-back | `MATCH` on own bytes (`MEM_ALLOC`, cookie `mmap`) |
| ION heap survey (masks 0–7) | heap 0 fully works (alloc/map/mmap/free); rest absent/unusable |
| `MEM_IMPORT` ×6 initial shapes (2 types, 4 flag sets, 3 donor kinds, +JIT init) | identical clean `ENOMEM`, zero partial state |
| `MEM_IMPORT` flag sweep 12× `USERBUF` `CACHED` (`0x100F/0x140F/0x340F`) at high VA `0x44000` | `r=0` `gpu 0x44000` distinct `YES` (first non-identical) — `kbase_check_import_flags@0x77b844` `CACHED` gate, `JC 0x45000` distinct |
| `JOB_SUBMIT` with `BASE_JD_REQ_EXTERNAL_RESOURCES` `0x100` `stride 0x30` `0x44000` | `r=0` `pin` `kbase_jd_user_buf_pin_pages@0x77d1e8` `GPU_WR` `ubfx` reached (3× DUMMY `0x41000-0x43000` reserve) |
| `mmap` alias via `gpu_va` after pin (`USERBUF` `0x44000` `r--s` `MAP_SHARED` `PROT_READ`) | `SIGBUS` pre/post pin at any `VA` `0x41000/0x44000`, `PRIVATE`/`>>12` `mmap fail` — `kbase_gpu_mmap@0x87f982c` `USERBUF` never `PROT_WRITE` vs `ALLOC` `MATCH` |

## Standing 2026-09-19
Bug present + chain mapped + `IMPORT` open + `pin` reachable; final `mmap` alias via `gpu_va` for `USERBUF` blocked (`kbase_gpu_mmap` `USERBUF` type 2 `r--s` never `rw` on `r32p1` `4.14`, unlike `ALLOC`). Reopen price for `RO→HACKED` write: `USERBUF` `mmap` `PROT_WRITE,MAP_SHARED` on `gpu_va` that is CPU-readable pre-pin (like `ALLOC`), or `GPU` job write to `0x44000` with valid `MALI_JD` header at `0x45000` (zeros fault). Binder-class bugs closed by `SPL 2024-11-01`, `futex` closed `CLOSURE.md:1`. MTK/`vivo_io` nodes unmapped. No boot/flash, `mali_*` probes local only, device cleaned `/data/local/tmp` (2026-09-19).
