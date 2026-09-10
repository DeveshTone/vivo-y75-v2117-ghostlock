#!/usr/bin/env python3
import re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
CLEAN=Path("/home/loq/vivo/y75_clean")
VMLINUX=CLEAN/"vmlinux"/"vmlinux_new.elf"
KALL=CLEAN/"logs"/"kallsyms_output.txt"

def parse_kallsyms(p):
    syms={}; text=None
    with open(p,encoding="utf-8",errors="replace") as f:
        for line in f:
            m=re.match(r"^\s*([0-9a-fA-F]+)\s+(\S+)\s+(\S+)",line)
            if not m: continue
            addr=int(m.group(1),16); name=m.group(3)
            if name not in syms: syms[name]=(addr,m.group(2))
            if name=="_text" and text is None: text=addr
    return syms,text

syms,text_base=parse_kallsyms(KALL)
print(f"_text 0x{text_base:016x} total {len(syms)}")

f=open(VMLINUX,"rb"); elf=ELFFile(f)
segs=[(s["p_vaddr"],s["p_memsz"],s["p_offset"]) for s in elf.iter_segments() if s["p_type"]=="PT_LOAD"]
def va2off(va):
    for a,sz,off in segs:
        if a<=va<a+sz: return off+(va-a)
    return None

# check symtab for extra symbols
symtab=elf.get_section_by_name(".symtab")
elf_syms={}
if symtab:
    for s in symtab.iter_symbols():
        if s.name and s["st_value"]>0:
            elf_syms[s.name]=s["st_value"]
    print(f"ELF .symtab has futex_wait_requeue_pi={ 'futex_wait_requeue_pi' in elf_syms}")

# list key syms
for n in ["core_sys_select","sys_pselect6","do_select","sys_select","futex_lock_pi","futex_wait","futex_requeue","futex_wait_queue_me","do_futex","rt_mutex_init_waiter","rb_erase_cached","rt_mutex_adjust_prio_chain","task_blocks_on_rt_mutex","futex_wait_requeue_pi"]:
    v=syms.get(n)
    ev=elf_syms.get(n)
    print(f"{n:32s} kall {('0x%x'%v[0] if v else '----'):18s} elf {('0x%x'%ev if ev else '----')}")

def analyze(name):
    va=syms.get(name)
    if not va: va=(elf_syms.get(name), "t") if elf_syms.get(name) else None
    if not va: print(f"\n[{name}] NOT FOUND"); return None
    if isinstance(va,tuple): va=va[0]
    print(f"\n========== {name} va 0x{va:016x} ==========")
    off=va2off(va)
    if off is None: print(" no mapping"); return None
    f.seek(off); code=f.read(2500)
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    # find frame and fp
    frame=0; stp_extra=0; fp_off=None
    for insn in md.disasm(code[:400], va):
        op=insn.op_str
        if insn.mnemonic=="sub" and "sp, sp" in op and "#" in op:
            try: frame+=int(op.split("#")[-1].strip().rstrip("]"),0)
            except: pass
        if insn.mnemonic=="stp" and "sp, #-" in op and "!" in op:
            try: stp_extra+=int(op.split("#-")[-1].strip().rstrip("]!"),0)
            except: pass
        if insn.mnemonic=="add" and "x29, sp" in op and "#" in op and fp_off is None:
            try:
                imm=int(op.split("#")[-1].strip().rstrip("]"),0)
                if imm>0x10: fp_off=imm
            except: pass
        if frame>0 and insn.address-va>60 and insn.mnemonic not in ("sub","stp","mov","add","str","stur","stp","strb","ldr","adrp"):
            break
    total=frame+stp_extra
    print(f" frame sub 0x{frame:x} stp_extra 0x{stp_extra:x} total 0x{total:x} fp_off {('0x%x'%fp_off if fp_off else 'none')}")
    # collect stores
    md2=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    sp_map=[]  # list of (sp_offset, src, full)
    # x29-relative stores need fp_off
    if fp_off is None: fp_off=total if total else 0
    for insn in md2.disasm(code, va):
        op=insn.op_str
        mn=insn.mnemonic
        # direct sp stores
        if mn in ("str","stur","stp","strb","strh") and "[sp" in op and "#" in op and "#-" not in op:
            try:
                # extract imm: [sp, #0x..] or [sp, #imm]
                imm_str=op.split("#")[-1].split("]")[0].strip()
                imm=int(imm_str,0)
                sp_map.append((imm, f"sp+0x{imm:x}", f"{mn} {op}  @0x{insn.address:x}"))
            except: pass
            if mn=="stp" and "xzr" in op:
                try:
                    imm=int(op.split("#")[-1].split("]")[0].strip(),0)
                    sp_map.append((imm+8, f"sp+0x{imm+8:x}", f"{mn} {op}+8 @0x{insn.address:x}"))
                except: pass
        # x29-relative
        if "[x29" in op and "#" in op:
            try:
                if "#-" in op:
                    imm=int(op.split("#-")[-1].split("]")[0].strip(),0)
                    sp_off=fp_off - imm
                    # filter valid range
                    if 0<=sp_off<total+0x40:
                        # extract value reg
                        src=op.split(",")[0].strip() if "," in op else op
                        sp_map.append((sp_off, f"x29-0x{imm:x}->sp+0x{sp_off:x}", f"{mn} {op} @0x{insn.address:x}"))
                elif "#0x" in op or "#" in op:
                    imm=int(op.split("#")[-1].split("]")[0].strip(),0)
                    sp_off=fp_off + imm
                    sp_map.append((sp_off, f"x29+0x{imm:x}->sp+0x{sp_off:x}", f"{mn} {op} @0x{insn.address:x}"))
            except: pass
        if insn.address-va>1200:
            break
    sp_map_sorted=sorted(sp_map)
    # print xzr zero stores specifically
    zero_sp=[x for x in sp_map if "xzr" in x[2]]
    print(f" zero/xzr stores ({len(zero_sp)}):")
    for off2,desc,full in sorted(zero_sp)[:40]:
        print(f"   sp+0x{off2:03x} {full}")
    # general map summary
    print(f" all stores (first 40):")
    for off2,desc,full in sp_map_sorted[:40]:
        print(f"   sp+0x{off2:03x} {full}")
    # adds
    adds=[]
    md3=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for insn in md3.disasm(code, va):
        if insn.mnemonic=="add" and "sp" in insn.op_str and "#0x" in insn.op_str and "x29" not in insn.op_str:
            try:
                imm=int(insn.op_str.split("#")[-1].split("]")[0].strip(),0)
                if 0<imm<0x500:
                    adds.append(imm)
            except: pass
        if insn.address-va>800: break
    print(f" add xN, sp, #imm : {sorted(set(adds))}")
    # disasm head
    print(" prologue:")
    md4=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for i,insn in enumerate(md4.disasm(code[:600], va)):
        if i>=30: break
        print(f"  {i:2d} 0x{insn.address:016x}: {insn.mnemonic:8s} {insn.op_str}")
    return {"frame":total,"fp":fp_off,"zero_sp":zero_sp,"adds":adds,"sp_map":sp_map}

res={}
for n in ["futex_lock_pi","futex_wait","futex_requeue","futex_wait_queue_me","do_futex","core_sys_select","sys_pselect6","do_select","rt_mutex_init_waiter","task_blocks_on_rt_mutex"]:
    r=analyze(n)
    if r: res[n]=r

print("\n"+"="*80)
print(" SUMMARY")
print("="*80)
for k,v in res.items():
    print(f"{k:30s} frame 0x{v['frame']:03x} fp 0x{v['fp']:03x} zero_cnt {len(v['zero_sp'])} adds {sorted(set(v['adds']))[:6]}")
# try to estimate feasibility for 4.14: waiter in futex_lock_pi vs fds in core_sys_select
# In 4.14 waiter allocation is in futex_lock_pi? But FUTEX_WAIT_REQUEUE_PI path uses futex_wait_requeue_pi which doesnt exist - maybe uses futex_requeue's waiter?
# Check do_futex dispatch - search for futex ops
print("\n--- checking do_futex for requeue_pi opcodes ---")
va=syms["do_futex"][0]
off=va2off(va)
f.seek(off); code=f.read(6000)
import re as re2
# look for immediate constants often used as futex ops: 3, 9, 11, 12 etc
# dump hex around do_futex
# quick search for strings
f.seek(off)
# read until far
# disasm search for cmp with futex op values
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ops_found=set()
for insn in md.disasm(code, va):
    # and w?, w?, #0x.. ; cmp w? etc - capture mov w8, #0x... patterns that might be op checks
    if insn.mnemonic in ("mov","movz","movk","cmp","ands","tst","and","orr"):
        # extract hex immediates
        for tok in re2.findall(r"#0x[0-9a-fA-F]+|#\d+", insn.op_str):
            try:
                v=int(tok[1:],0)
                if 0<=v<=30: ops_found.add(v)
            except: pass
    if insn.address-va>5000: break
print(f" immediates 0..30 seen in do_futex: {sorted(ops_found)}")

f.close()
print("\n=== deep_feas done ===")
