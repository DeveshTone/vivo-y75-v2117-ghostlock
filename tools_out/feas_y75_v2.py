#!/usr/bin/env python3
import re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
CLEAN = Path("/home/loq/vivo/y75_clean")
VMLINUX = CLEAN/"vmlinux"/"vmlinux_new.elf"
KALL = CLEAN/"logs"/"kallsyms_output.txt"
RAW = CLEAN/"boot"/"kernel.decompressed"

def parse_kallsyms(p):
    syms={}; text_base=None
    with open(p, encoding='utf-8', errors='replace') as f:
        for line in f:
            m=re.match(r'^\s*([0-9a-fA-F]+)\s+(\S+)\s+(\S+)', line)
            if not m: continue
            addr=int(m.group(1),16); name=m.group(3)
            if name not in syms: syms[name]=(addr,m.group(2))
            if name=="_text" and text_base is None: text_base=addr
    return syms, text_base

def load_elf_segs():
    f=open(VMLINUX,'rb'); elf=ELFFile(f)
    segs=[]
    for seg in elf.iter_segments():
        if seg['p_type']=='PT_LOAD': segs.append((seg['p_vaddr'], seg['p_memsz'], seg['p_offset']))
    # sections debug
    secs=[s.name for s in elf.iter_sections()]
    print(f"ELF sections: {secs[:20]}")
    f2=open(VMLINUX,'rb')
    return f2, elf, segs

def vaddr_to_off(vaddr, segs):
    for va,msz,off in segs:
        if va <= vaddr < va+msz: return off+(vaddr-va)
    return None

syms, text_base = parse_kallsyms(KALL)
print(f"_text 0x{text_base:016x}  total {len(syms)} syms")

# also pull via ELF symtab
f_elf, elf, segs = load_elf_segs()
symtab = elf.get_section_by_name('.symtab')
elf_syms={}
if symtab:
    for sym in symtab.iter_symbols():
        if sym.name and sym['st_value']>0:
            elf_syms[sym.name]=sym['st_value']
    print(f"ELF .symtab {len(elf_syms)} symbols, has futex_wait_requeue_pi={ 'futex_wait_requeue_pi' in elf_syms}")

# search for any requeue / futex symbols in ELF symtab
for k in sorted(elf_syms):
    if 'requeue' in k.lower() or ('futex' in k.lower() and 'wait' in k.lower()):
        print(f"  ELF sym {k:40s} 0x{elf_syms[k]:016x}")

print("\n--- kallsyms key ---")
for n in ['core_sys_select','sys_pselect6','__sys_pselect6','do_select','sys_select','rb_erase_cached','rt_mutex_adjust_prio_chain','futex_lock_pi','do_futex','remove_waiter','task_blocks_on_rt_mutex','rt_mutex_init_waiter']:
    v=syms.get(n)
    print(f"{n:35s} {f'0x{v[0]:016x} {v[1]}' if v else 'NOT FOUND'}")

# also search substring requeue in kallsyms
print("\n--- kallsyms *requeue* ---")
found=False
for n,(a,t) in syms.items():
    if 'requeue' in n.lower():
        print(f"  0x{a:016x} {t} {n}"); found=True
if not found: print("  (none)")

print("\n--- kallsyms *waiter*/*wait_requeue* ---")
for n,(a,t) in syms.items():
    if 'waiter' in n.lower() or 'wait_requeue' in n.lower():
        print(f"  0x{a:016x} {t} {n}")

# analyze functions via ELF file offsets
def analyze(name):
    # prefer ELF symtab else kallsyms
    va = elf_syms.get(name) or (syms.get(name)[0] if syms.get(name) else None)
    if not va:
        print(f"\n[{name}] no address"); return None, None, None
    off = vaddr_to_off(va, segs)
    if off is None:
        print(f"\n[{name}] va 0x{va:016x} no PT_LOAD mapping"); return None, None, None
    f=open(VMLINUX,'rb'); f.seek(off); code=f.read(1200); f.close()
    print(f"\n[{name}] va 0x{va:016x} off 0x{off:x}")
    # capstone frame
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    # frame
    frame=0; stp_extra=0
    for insn in md.disasm(code[:300], va):
        op=insn.op_str
        if insn.mnemonic=='sub' and 'sp' in op and '#' in op:
            try: frame+=int(op.split('#')[-1].strip().rstrip(']'),0)
            except: pass
        if insn.mnemonic=='stp' and 'sp' in op and '-' in op and '!' in op:
            try: stp_extra+=int(op.split('#-')[-1].strip().rstrip(']!'),0)
            except: pass
        if frame>0 and insn.mnemonic not in ('sub','stp','mov','add','str','stur','stp','strb'):
            break
    total=frame+stp_extra
    print(f"  frame est 0x{total:x} ({total})  sub 0x{frame:x} stp_extra 0x{stp_extra:x}")
    # zero stores
    zeros=[]; adds=[]
    md2=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for insn in md2.disasm(code[:1800], va):
        op=insn.op_str
        if insn.mnemonic in ('str','stur') and 'xzr' in op and '[sp' in op and '#' in op:
            try: zeros.append(int(op.split('#')[-1].strip().rstrip(']'),0))
            except: pass
        if insn.mnemonic=='stp' and 'xzr, xzr' in op and '[sp' in op and '#' in op:
            try: v=int(op.split('#')[-1].strip().rstrip(']'),0); zeros.append(v); zeros.append(v+8)
            except: pass
        if insn.mnemonic=='add' and 'sp' in op and '#' in op:
            try:
                dst=op.split(',')[0].strip()
                if dst.startswith('x'): adds.append(int(op.split('#')[-1].strip().rstrip(']'),0))
            except: pass
    zeros=sorted(set(zeros)); adds=sorted(set(adds))
    print(f"  zero sp+ : {zeros[:30]}")
    print(f"  add sp # : {adds[:20]}")
    # disasm prologue 36 insns
    print("  prologue:")
    for i,insn in enumerate(md.disasm(code[:500], va)):
        if i>=28: break
        print(f"    {i:2d} 0x{insn.address:016x}: {insn.mnemonic:8s} {insn.op_str}")
        if i>10 and insn.mnemonic=='bl': 
            # continue a bit
            pass
    return total, zeros, adds

results={}
for func in ['futex_lock_pi','do_futex','core_sys_select','sys_pselect6','do_select','rt_mutex_init_waiter','task_blocks_on_rt_mutex','rt_mutex_adjust_prio_chain','rb_erase_cached']:
    fr, zs, ad = analyze(func)
    if fr is not None: results[func]=(fr,zs,ad)

# also check raw kernel decompressed via capstone if needed
# feasibility math for 4.14 compact waiter
print("\n" + "="*70)
print(" FEASIBILITY MATH (4.14 compact waiter)")
print("="*70)
# NFDS=320 => words per set 5, controllable 15 words (0-14), waiter compact needs lock at +7
# Need actual waiter_offset heuristics
# pick likeliest waiter zero region: largest contiguous zeros in futex_lock_pi

def largest_contig(lst):
    if not lst: return None
    cur=[lst[0]]; best=[lst[0]]
    for v in lst[1:]:
        if v - cur[-1] <= 16:
            cur.append(v)
        else:
            if len(cur)>len(best): best=cur
            cur=[v]
    if len(cur)>len(best): best=cur
    return best

for func in ['futex_lock_pi','core_sys_select','sys_pselect6']:
    if func not in results: continue
    fr, zs, ad = results[func]
    grp=largest_contig(zs) if zs else None
    if grp:
        print(f"{func:30s} frame 0x{fr:x}  largest zero-run sp+0x{grp[0]:x}..0x{grp[-1]+8:x} len {len(grp)} words={len(grp)}")
    else:
        print(f"{func:30s} frame 0x{fr:x}  no zero-run")

# estimate waiter vs fds if we can identify offsets
if 'futex_lock_pi' in results and 'core_sys_select' in results:
    fr_f, zs_f, _ = results['futex_lock_pi']
    fr_s, zs_s, _ = results['core_sys_select']
    gf=largest_contig(zs_f); gs=largest_contig(zs_s)
    if gf and gs:
        waiter_off=gf[0]; fds_off=gs[0]
        # heuristic for 4.14: waiter likely the large zero run in futex_lock_pi, fds large run in core_sys_select
        est = ((-fr_f + waiter_off) - (-fr_s + fds_off))//8
        print(f"\n[EST] waiter @ futex sp+0x{waiter_off:x} (frame 0x{fr_f:x})")
        print(f"[EST] fds    @ select sp+0x{fds_off:x} (frame 0x{fr_s:x})")
        print(f"[EST] waiter_word (same entry SP) = {est}")
        print(" controllable 0..14, need lock at word+7  => max waiter_word 7")
        print(" for compact waiter 0x50 (lock word 7), feasible if est <=7")
        for sp_diff in [-128,-64,-32,0,16,32,64,128]:
            w=est+sp_diff//8
            feasible = "FEASIBLE" if -2 <= w <= 7 else "INFEASIBLE"
            print(f"  SP_diff {sp_diff:+4d}: word {w:3d} {feasible}")
    else:
        print("cannot estimate - missing zero runs")

# also check sys_pselect6 vs core_sys_select - IonStack uses core_sys_select's stack_fds
if 'sys_pselect6' in results:
    fr, zs, _ = results['sys_pselect6']
    grp=largest_contig(zs)
    if grp: print(f"\nsys_pselect6 largest zero-run sp+0x{grp[0]:x} len {len(grp)} frame 0x{fr:x}")

print("\n=== done ===")
