# Contributing — vivo Y75 V2117

Keep this repo read-only. Every kernel touch stays **forked + RAM-only**.

- Scope: V2117 MT6781 4.14.186-gdfd963175-dirty only
- Header: targets/target_y75.h only
- Probes: reclaim-only — read on pipe_buffer you own, then HEAP WRITE VERIFIED before 1-byte 0 to enforcing
- Do not commit boot/ vmlinux/ dumps. BTF not found expected on 4.14
- Test gate every boot: paranoid -1, re-leak KASLR, re-run y75_pipe_probe_final + y75_leak_probe to 6/6
- Fork: one entry src/kernels/4.14.186-gdfd963175-dirty/offsets.h from targets/target_y75.h, swap pselect 320 to pipe 12/12
