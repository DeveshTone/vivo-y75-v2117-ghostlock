#!/usr/bin/env python3
"""Build a newc-format initramfs without the cpio tool (no root needed).
Contains /lab_init (PID1), /bin/race_oracle, /dev/console node."""
import struct, sys, os

def hdr(ino, mode, uid, gid, nlink, mtime, fsize, devmaj, devmin, rmaj, rmin, namesize):
    f = [ino, mode, uid, gid, nlink, mtime, fsize, devmaj, devmin, rmaj, rmin, namesize, 0]
    return ("070701" + "".join("%08X" % x for x in f)).encode()

def pad4(buf, off=0):
    while (len(buf) + off) % 4: buf += b"\0"
    return buf

def add_file(arc, path, name, mode=0o100755):
    data = open(path, "rb").read()
    ino = add_file.ino; add_file.ino += 1
    arc += hdr(ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1)
    arc += pad4(name.encode() + b"\0")
    arc += pad4(data)
    return arc
add_file.ino = 1

def add_node(arc, name, mode, rmaj, rmin):
    ino = add_file.ino; add_file.ino += 1
    arc += hdr(ino, mode, 0, 0, 1, 0, 0, 0, 0, rmaj, rmin, len(name)+1)
    arc += pad4(name.encode() + b"\0")
    return arc

def add_dir(arc, name):
    ino = add_file.ino; add_file.ino += 1
    arc += hdr(ino, 0o040755, 0, 0, 2, 0, 0, 0, 0, 0, 0, len(name)+1)
    arc += pad4(name.encode() + b"\0")
    return arc

LAB = "/home/loq/vivo/y75_clean"
arc = b""
arc = add_dir(arc, "lab")
arc = add_dir(arc, "bin")
arc = add_dir(arc, "proc")
arc = add_dir(arc, "sys")
arc = add_dir(arc, "dev")
arc = add_dir(arc, "tmp")
arc = add_file(arc, f"{LAB}/lab/lab_init", "lab_init")
arc = add_file(arc, f"{LAB}/lab/race_oracle", "bin/race_oracle")
arc = add_node(arc, "dev/console", 0o020600, 5, 1)
# trailer
name = b"TRAILER!!!"
arc += hdr(0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name)+1)
arc += pad4(name + b"\0")
# pad to 512-byte block
while len(arc) % 512: arc += b"\0"
open(f"{LAB}/lab/initramfs.cpio", "wb").write(arc)
print(f"initramfs.cpio written: {len(arc)} bytes")
