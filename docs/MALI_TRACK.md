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
| `MEM_IMPORT` ×6 shapes (2 types, 4 flag sets, 3 donor kinds, +JIT init) | identical clean `ENOMEM`, zero partial state |

## Standing
Bug present + chain mapped + channel proven; the single doorway (`IMPORT`) refuses all tested
shapes identically, so its gate reads nothing attacker-controlled. Reopen price: any input shape
(or context state) returning anything but identical `ENOMEM`, or the refusing branch with a
flippable input. Binder-class bugs closed by patch level, not pursued. MTK/`vivo_io` nodes
unmapped. No device writes performed at any point; probe sources kept local.
