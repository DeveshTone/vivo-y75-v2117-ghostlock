#!/usr/bin/env python3
"""Feasibility check for vivo Y75 4.14.186 via vmlinux_new.elf + kallsyms_output.txt
Uses pyelftools + capstone directly, bypassing the 6.x-only check_feasibility.py kallsyms finder.
"""
import re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    HAS_CS=True
except: HAS_CS=False

CLEAN = Path("/home/loq/vivo/y75_clean")
VMLINUX = CLEAN / "vmlinux" / "vmlinux_new.elf"
KALL = CLEAN / "logs" / "kallsyms_output.txt"

def parse_kallsyms(p):
    syms={}
    text_base=None
    with open(p, encoding='utf-8', errors='replace') as f:
        for line in f:
            m=re.match(r'^\s*([0-9a-fA-F]+)\s+(\S+)\s+(\S+)', line)
            if not m: continue
            addr=int(m.group(1),16); typ=m.group(2); name=m.group(3)
            # keep first occurrence for name
            if name not in syms:
                syms[name]=(addr,typ)
            if name=="_text" and text_base is None:
                text_base=addr
    return syms, text_base

def load_elf():
    f=open(VMLINUX,'rb')
    elf=ELFFile(f)
    # build vaddr -> file offset map from PT_LOAD segments
    segs=[]
    for seg in elf.iter_segments():
        if seg['p_type']=='PT_LOAD':
            segs.append((seg['p_vaddr'], seg['p_memsz'], seg['p_offset']))
    # find .text
    text_sec=elf.get_section_by_name('.text')
    return f, elf, segs, text_sec

def vaddr_to_offset(vaddr, segs):
    for va, msz, off in segs:
        if va <= vaddr < va+msz:
            return off + (vaddr - va)
    return None

def disasm_at(vaddr, nbytes, segs, f):
    off=vaddr_to_offset(vaddr, segs)
    if off is None: return None, None
    f.seek(off)
    code=f.read(nbytes)
    return code, off

def frame_size_from_prologue(code):
    if not HAS_CS: return None
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=False
    sz=0
    stp_extra=0
    for insn in md.disasm(code, 0):
        op=insn.op_str
        if insn.mnemonic=='sub' and 'sp' in op and '#' in op:
            try: sz+=int(op.split('#')[-1].strip().rstrip(']'),0)
            except: pass
        if insn.mnemonic=='stp' and 'sp' in op and '-' in op and '!' in op:
            try: stp_extra+=int(op.split('#-')[-1].strip().rstrip(']!'),0)
            except: pass
        if sz>0 and insn.mnemonic not in ('sub','stp','mov','add','str','stur','stp'):
            break
    return sz+stp_extra

def find_zero_stores_and_adds(code):
    if not HAS_CS: return [], []
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    zeros=[]; adds=[]
    for insn in md.disasm(code, 0):
        op=insn.op_str
        if insn.mnemonic in ('str','stur') and 'xzr' in op and 'sp' in op and '#' in op:
            try:
                # op like "xzr, [sp, #0x40]" or "[x29, #0x...]" handle sp only
                if '[sp' in op:
                    zeros.append(int(op.split('#')[-1].strip().rstrip(']'),0))
            except: pass
        if insn.mnemonic=='stp' and 'xzr, xzr' in op and 'sp' in op and '#' in op:
            try:
                v=int(op.split('#')[-1].strip().rstrip(']'),0)
                zeros.append(v); zeros.append(v+8)
            except: pass
        if insn.mnemonic=='add' and 'sp' in op and '#' in op:
            try:
                # add xN, sp, #imm  where dest is x register
                dst=op.split(',')[0].strip()
                if dst.startswith('x'):
                    adds.append(int(op.split('#')[-1].strip().rstrip(']'),0))
            except: pass
    return sorted(set(zeros)), sorted(set(adds))

print("=== Y75 feasibility — ELF + kallsyms ===")
syms, text_base = parse_kallsyms(KALL)
print(f"_text = 0x{text_base:016x}  total syms {len(syms)}")
# show kernel version string from vmlinux raw
with open(VMLINUX,'rb') as tmp:
    data=tmp.read(2<<20)
    m=re.search(b'Linux version 4\\.14[^\\x00]{0,200}', data)
    if m: print(m.group(0).decode(errors='replace')[:180])

candidates = ['futex_wait_requeue_pi','futex_wait_requeue_pi','core_sys_select','sys_pselect6','__sys_pselect6','do_select','core_sys_select','sys_select','rb_erase_cached','rt_mutex_adjust_prio_chain','futex_lock_pi','futex_requeue','do_futex']
print("\n--- key symbols from kallsyms_output.txt ---")
for name in ['futex_wait_requeue_pi','core_sys_select','sys_pselect6','__sys_pselect6','do_select','sys_select','rb_erase_cached','rb_erase','rt_mutex_adjust_prio_chain','futex_lock_pi','do_futex','remove_waiter']:
    v=syms.get(name)
    print(f"{name:35s} {'0x%x'%v[0] if v else 'NOT FOUND'}  {v[1] if v else ''}")

# search for any select-related symbol
print("\n--- all *select* symbols ---")
for n,(a,t) in sorted(syms.items()):
    if 'select' in n.lower(): print(f"  0x{a:016x} {t} {n}")
    if len([1 for k in syms if 'select' in k.lower()])>100: break

print("\n--- all *rb_erase* / *rt_mutex* / *waiter* symbols ---")
for n,(a,t) in sorted(syms.items()):
    if any(k in n for k in ('rb_erase','rt_mutex','waiter')): print(f"  0x{a:016x} {t} {n}")

# ELF analysis
f, elf, segs, text_sec = load_elf()
print(f"\nELF .text: addr 0x{text_sec['sh_addr']:x} size 0x{text_sec['sh_size']:x}  fileoff 0x{text_sec['sh_offset']:x}")
print(f"PT_LOAD segments: {len(segs)}")
for va,msz,off in segs[:4]: print(f"  va 0x{va:016x}  msz 0x{msz:x}  off 0x{off:x}")

def analyze_func(name):
    v=syms.get(name)
    if not v: 
        print(f"\n[{name}] not in kallsyms — skip")
        return
    va=v[0]
    code, off = disasm_at(va, 900, segs, f)
    if code is None:
        print(f"\n[{name}] va 0x{va:016x} -> no file offset (maybe init?)")
        return
    print(f"\n[{name}] va 0x{va:016x} fileoff 0x{off:x} size {len(code)}")
    # hexdump first 64 bytes
    print("  hex:", code[:64].hex()[:96]+"...")
    if HAS_CS:
        fs=frame_size_from_prologue(code[:300])
        zeros, adds = find_zero_stores_and_adds(code[:1200])
        print(f"  estimated frame ~ 0x{fs:x} ({fs})" if fs else "  frame parse failed")
        print(f"  zero stores @sp+ : {zeros[:20]}")
        print(f"  add sp,off       : {adds[:20]}")
        # full disasm first 40 insns
        md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        print("  disasm prologue:")
        for i,insn in enumerate(md.disasm(code[:400], va)):
            if i>=30: break
            print(f"    0x{insn.address:016x}: {insn.mnemonic:10s} {insn.op_str}")
            if i>8 and insn.mnemonic=='bl': break

for func in ['futex_wait_requeue_pi','do_futex','futex_lock_pi','core_sys_select','__sys_pselect6','sys_pselect6','do_select','rb_erase_cached','rt_mutex_adjust_prio_chain']:
    analyze_func(func)

f.close()
print("\n=== done ===")
