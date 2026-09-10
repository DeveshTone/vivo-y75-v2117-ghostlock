#!/usr/bin/env python3
import re
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
CLEAN=Path('/home/loq/vivo/y75_clean')
VMLINUX=CLEAN/'vmlinux'/'vmlinux_new.elf'
KALL=CLEAN/'logs'/'kallsyms_output.txt'
syms={}
with open(KALL,encoding='utf-8',errors='replace') as f:
    for line in f:
        m=re.match(r'^\s*([0-9a-fA-F]+)\s+(\S+)\s+(\S+)',line)
        if m:
            a=int(m.group(1),16); n=m.group(3)
            if n not in syms: syms[n]=a
fe=open(VMLINUX,'rb'); elf=ELFFile(fe)
segs=[(s['p_vaddr'],s['p_memsz'],s['p_offset']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def va2off(va):
    for a,sz,off in segs:
        if a<=va<a+sz: return off+(va-a)
    return None
for name in ['__sys_recvmsg','___sys_recvmsg','__sys_sendmsg','___sys_sendmsg','sys_recvmsg','sys_sendmsg','__sys_recvmmsg','compat_sys_recvmsg','do_sys_poll','sys_poll','compat_sys_select']:
    va=syms.get(name)
    if not va:
        print(name+' NOT FOUND')
        continue
    off=va2off(va); fe.seek(off); code=fe.read(900)
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    frame=0; fp=None
    for insn in md.disasm(code[:500], va):
        if insn.mnemonic=='sub' and 'sp, sp' in insn.op_str:
            try: frame=int(insn.op_str.split('#')[-1].split(']')[0],0)
            except: pass
        if 'x29, sp' in insn.op_str and 'add' in insn.mnemonic:
            try: fp=int(insn.op_str.split('#')[-1].split(']')[0],0)
            except: pass
    print(name.ljust(22)+' va 0x%x frame 0x%x fp %s off 0x%x' % (va,frame,str(fp),off))
fe.close()
