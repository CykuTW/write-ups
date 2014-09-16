# No cON Name CTF Quals 2014: inBINcible

**Category:** Binary
**Points:** 400
**Description:**

> Get the key. The flag is: "NcN_" + sha1sum(key)
>
> Url: https://ctf.noconname.org/chdownloads/inbincible

## Write-up

題目為 ELF 32bit 執行檔，執行後只會顯示 `Nope!` 訊息  
從 `_rt0_go()` 可以看出是 [Go](http://golang.org/) 的執行檔  

分析 `runtime_main()` 後可以發現重點的執行過程在於 `text()` 函數中，  
首先 `text()` 函數會判斷 argc == 2 且 argv[1] 長度為 16 bytes  

接著於迴圈中呼叫 `runtime_newproc()` 執行 16次 `main_func_001()`，  
再呼叫 `runtime_chanrecv1()` 等待 proc 回傳結果。  

在 `main_func_001()` 中，會將 argv[1] 的字元做某些運算，  
透過 `runtime_chansend1()` 回傳結果  

由於 `test()` 每次只透過 `main_func_001()` 處理一個字元，並回傳該字元是否正確，  
因此我們可以在關鍵處設下斷點，再根據程式是否有執行到關鍵處，一個字元一個字元的爆出密碼  

```
.text:0804910F                 call    runtime_chanrecv1
.text:08049114                 mov     edi, [esp+0C0h+var_A0]
.text:08049118                 cmp     [esp+0C0h+var_A5], 0
.text:0804911D                 jz      short loc_8049127
.text:0804911F                 mov     ecx, 1
```

`0x0804911D` 這裡是一個關鍵跳轉，當字元不正確時，將會跳轉掉

我們在 `0x0804911F` 上下一個斷點，  
測試輸入 `AAAAAAAAAAAAAAAA` `BBBBBBBBBBBBBBBB`...到 `ZZZZZZZZZZZZZZZZ`，  
會發現當輸入為 `GGGGGGGGGGGGGGGG` 時斷點被觸發一次  

嘗試猜測第二個字元，輸入 `G0GGGGGGGGGGGGGG` 時斷點會被觸發兩次，表示前兩位 key 為 `G0`  

接著就來開始進行暴力破解  


以下為 solution，搭配 [peda](https://github.com/longld/peda) ：

```python
#!/usr/bin/env python
import sys
import string

list = string.letters
list += string.digits
list += string.punctuation

peda.execute("file ./inbincible")
peda.execute("br *0x0804911F")

key = ""
for i in range(0):
    for c in list:
        guess_key = key + str(c) + 'A' * (15 - i)  
        sys.stderr.write("Testing %s...\n" % guess_key)   
        peda.execute("r " + guess_key)

        break_count = 0
        for j in range(i + 1):            # Testing key[0] needs to hit the bp for 1 time, key[1] for 2.. etc
            if peda.getpid() is not None: # still running?
                peda.execute("c")
                break_count += 1

        if break_count == i + 1:
            key += c
            break

sys.stderr.write("Done!!!\n")
sys.stderr.write("The key is:\n%s\n" % key)

peda.execute("q")
```
 
```bash
$ peda -x ./crack.py > /dev/null
Testing aAAAAAAAAAAAAAAA...
Testing bAAAAAAAAAAAAAAA...
Testing cAAAAAAAAAAAAAAA...
Testing dAAAAAAAAAAAAAAA...
Testing eAAAAAAAAAAAAAAA...
...
Testing G0w1n!C0ngr4t5!5...
Testing G0w1n!C0ngr4t5!6...
Testing G0w1n!C0ngr4t5!7...
Testing G0w1n!C0ngr4t5!8...
Testing G0w1n!C0ngr4t5!9...
Testing G0w1n!C0ngr4t5!!...
Done!!!
The key is:
G0w1n!C0ngr4t5!!
```
