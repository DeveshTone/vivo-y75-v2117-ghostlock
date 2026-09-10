#!/usr/bin/env python3
import re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
CLEAN=Path("/home/loq/vivo/y75_clean")
VMLINUX=CLEAN/"vmlinux"/"vmlinux_new.elf"
KALL=CLEAN/"logs"/"kallsyms_output.txt"
syms={}
text=None
with open(KALL,encoding="utf-8",errors="replace") as f:
    for line in f:
        m=re.match(r"^\s*([0-9a-fA-F]+)\s+(\S+)\s+(\S+)",line)
        if m:
            a=int(m.group(1),16); n=m.group(3)
            if n not in syms: syms[n]=(a,m.group(2))
            if n=="_text" and text is None: text=a
fe=open(VMLINUX,"rb"); elf=ELFFile(fe)
segs=[(s["p_vaddr"],s["p_memsz"],s["p_offset"]) for s in elf.iter_segments() if s["p_type"]=="PT_LOAD"]
def va2off(va):
    for a,sz,off in segs:
        if a<=va<a+sz: return off+(va-a)
    return None

def dump_waiter(name):
    va=syms[name][0]
    off=va2off(va); fe.seek(off); code=fe.read(3000)
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    frame=0; fp=None
    for insn in md.disasm(code[:600],va):
        if insn.mnemonic=="sub" and "sp, sp" in insn.op_str:
            try: frame=int(insn.op_str.split("#")[-1].split("]")[0],0)
            except: pass
        if insn.mnemonic=="add" and "x29, sp" in insn.op_str:
            try: fp=int(insn.op_str.split("#")[-1].split("]")[0],0)
            except: pass
        if frame and fp is not None: break
    print(f"\n=== {name} va 0x{va:x} frame 0x{frame:x} fp 0x{fp if fp else 0:x} ===")
    md2=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for insn in md2.disasm(code,va):
        s=insn.mnemonic+" "+insn.op_str
        if "x29, #-" in s or "sp, #0x" in s or "stur xzr" in s or "stp xzr" in s or "sub" in s or "add" in s:
            if insn.address-va<700:
                print(f"  0x{insn.address:x}: {s}")
                if "sub" in s and "x29" in s: print("      ^ waiter base calc (x29 - imm = waiter)")

for n in ["futex_requeue","futex_wait","futex_lock_pi","do_futex","core_sys_select","sys_pselect6","do_select"]:
    dump_waiter(n)

# specific waiter base extraction
va=syms["futex_requeue"][0]; off=va2off(va); fe.seek(off); code=fe.read(2000)
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
frame=0x140; fp=0xe0
for insn in md.disasm(code,va):
    if insn.mnemonic=="sub" and "x8, x29" in insn.op_str and "#0x" in insn.op_str:
        imm=int(insn.op_str.split("#")[-1],0)
        waiter_off=fp-imm
        print(f"\n[WAIT_REQUEUE] waiter = x29 - 0x{imm:x} = sp + 0x{waiter_off:x} (sp+{waiter_off})")
        break
fe.close()
