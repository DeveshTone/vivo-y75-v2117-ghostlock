import pathlib
base = pathlib.Path("/home/loq/vivo/y75_clean")
(base/"CONTRIBUTING.md").write_text("# Contributing — vivo Y75 V2117\n\nKeep this repo read-only. Every kernel touch stays **forked + RAM-only**.\n\n- Scope: V2117 MT6781 4.14.186-gdfd963175-dirty only\n- Header: targets/target_y75.h only\n- Probes: reclaim-only — read on pipe_buffer you own, then HEAP WRITE VERIFIED before 1-byte 0 to enforcing\n- Do not commit boot/ vmlinux/ dumps. BTF not found expected on 4.14\n- Test gate every boot: paranoid -1, re-leak KASLR, re-run y75_pipe_probe_final + y75_leak_probe to 6/6\n- Fork: one entry src/kernels/4.14.186-gdfd963175-dirty/offsets.h from targets/target_y75.h, swap pselect 320 to pipe 12/12\n", encoding="utf-8")
(base/"LICENSE").write_text("Apache License 2.0 — http://www.apache.org/licenses/LICENSE-2.0\nThis repository documents research on an authorized device (vivo Y75 V2117). Same license as upstream GhostLock.\n", encoding="utf-8")
# polish ACHIEVEMENTS header
p = base/"docs/ACHIEVEMENTS.md"
t = p.read_text(encoding="utf-8")
if "# vivo Y75" not in t:
    # leave as is, just ensure it starts with title
    pass
print("helper done")
