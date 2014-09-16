# No cON Name CTF Quals 2014: imMISCible #

**Category:** Misc
**Points:** 200
**Description:**

> No hints :( Just go and get the flag.
> 
> Url: https://ctf.noconname.org/chdownloads/immiscible

## Write-up

題目檔案解壓縮後得到 ctf.py ，內容如下：  

```python
#!/usr/bin/env python
# -*- coding: rot13 -*-
vzcbeg bf
vzcbeg znefuny
vzcbeg arj

tybony synt

qrs s():
tybony synt
synt = "Abcr!".qrpbqr("rot13")

olgrpbqr = """
LjNNNNNNNNNNNjNNNRNNNNOmyjNNNTDNNTDONTjNNT0ONSbONNSxNNOxNtOfNtOgNjOnNjNOMDZN
MNZNMNDNtjVNMNHNnjVNpcZNMNLNLDDNqNDNMNpNA2RRNUDRNTDVNQquONO0ONOxPDN3LDDNqNDN
ntHNMNbNMNDNtjVNLDDNqNDNntLNMNfNtjRNLDDNMNjNMDRNqNDNtjRNntpNtjNNS2RRNT4NNTDA
NSZbQtNNNTa/////XNRNNNOmONNNNUAbLGRbNDNNNUZTNNNNM2I0MJ52pjfNNNOBG19QG05sGxSA
EKZNNNNNpjRNNNOMpmRNNNNtAGptAwttAwRtAmDtZwNtAwxtAmZtZwNtAmDtAwttAwHtZwNtAwRt
AwxtAmVtZzDtpmRNNNNtAmZtAmNtAwHtAwHtAwDtZwNtAmLtAwHtAzZtAzLtAwZtAwxtAmDtAmxt
ZwNtAzLtpmRNNNNtAwLtZwNtAwRtAzHtZwNtAmHtAzHtAzZtAwRtAwDtAwHtAzHtZwNtAmZtAmpt
AwRtpkNNNNNtAzZtAzZtAzLtAmptZ2LtpjRNNNNtpjZNNNObMKumNjNNNR5QGx4bPNNNNUZUNNNN
nTSmnTkcLaZRNNNNp2uuZKZPNNNNo3AmOtNNNTqyqTIhqaZRNNNNMzkuM3ZUNNNNpzIjoTSwMKZT
NNNNMTIwo2EypjxNNNObMKuxnJqyp3DbNNNNNPtNNNNNXNNNNNOmPNNNNQkmqUWcozp+pjtNNNN8
oJ9xqJkyCtVNNNOmRtNNNONORNRINtLOPtRXNDbORtRCND==
"""

vs __anzr__ != "__znva__".qrpbqr("rot13"):
pbqrbow = znefuny.ybnqf(olgrpbqr.qrpbqr("rot13"))
s = arj.shapgvba(pbqrbow, tybonyf(), "s".qrpbqr("rot13"), Abar, Abar)

s()

cevag synt
```

直接執行 ctf.py 會印出 `Nope!` 的訊息  
而從 `# -*- coding: rot13 -*-` 可以看出這是經過 ROT13 encoding 過的 python code  

經過 ROT13 decode 並拿掉 encode 部分之後的程式碼如下：  

```python
#!/usr/bin/env python
import os
import marshal
import new

global flag

def f():
    global flag
    flag = "Nope!"

bytecode = """
YwAAAAAAAAAAAwAAAEAAAABzlwAAAGQAAGQBAGwAAG0BAFoBAAFkAABkAgBsAgBtAwBaAwABZQMA
ZAMAZAQAgwIAZAUAawIAcpMAZAYAYQQAdAQAZAcAN2EEAHQEAGQIADdhBAB0BABkCQA3YQQAdAQA
agUAZAoAZAQAgwIAYQQAdAQAagYAZAsAgwEAYQQAZAwAZQEAdAQAgwEAagcAgwAAF2EEAG4AAGQN
AFMoDgAAAGn/////KAEAAABzBAAAAHNoYTEoAQAAAHMGAAAAZ2V0ZW52cwsAAABOT19DT05fTkFN
RXMAAAAAcwEAAABZczEAAAAgNTcgNjggNjEgNzQgMjAgNjkgNzMgMjAgNzQgNjggNjUgMjAgNjEg
NjkgNzIgMmQgczEAAAAgNzMgNzAgNjUgNjUgNjQgMjAgNzYgNjUgNmMgNmYgNjMgNjkgNzQgNzkg
MjAgNmYgczEAAAAgNjYgMjAgNjEgNmUgMjAgNzUgNmUgNmMgNjEgNjQgNjUgNmUgMjAgNzMgNzcg
NjEgcxAAAAAgNmMgNmMgNmYgNzcgM2YgcwEAAAAgcwMAAABoZXhzAwAAAE5DTk4oCAAAAHMHAAAA
aGFzaGxpYnMEAAAAc2hhMXMCAAAAb3NzBgAAAGdldGVudnMEAAAAZmxhZ3MHAAAAcmVwbGFjZXMG
AAAAZGVjb2RlcwkAAABoZXhkaWdlc3QoAAAAACgAAAAAKAAAAABzCAAAADxzdHJpbmc+cwgAAAA8
bW9kdWxlPgIAAABzEgAAABABEAEVAgYBCgEKAQoBEgEPAQ==
"""

if __name__ != "__main__":
    codeobj = marshal.loads(bytecode)
    f = new.function(codeobj, globals(), "f", None, None)

f()

print flag
```

可以看出是透過 marshal 執行 byte code，但這裡還有兩處需要修改  

必須修改 26 行的 `if __name__ != "__main__":`，直接執行 .py 時才會跑到load bytecode 的部分  
另一個地方是需要將 bytecode 做 base64 decode ，才能讓 marshal 讀取並執行  

修正完的程式碼如下：  

```python
#!/usr/bin/env python
import os
import marshal
import new

global flag

def f():
    global flag
    flag = "Nope!"

bytecode = """
YwAAAAAAAAAAAwAAAEAAAABzlwAAAGQAAGQBAGwAAG0BAFoBAAFkAABkAgBsAgBtAwBaAwABZQMA
ZAMAZAQAgwIAZAUAawIAcpMAZAYAYQQAdAQAZAcAN2EEAHQEAGQIADdhBAB0BABkCQA3YQQAdAQA
agUAZAoAZAQAgwIAYQQAdAQAagYAZAsAgwEAYQQAZAwAZQEAdAQAgwEAagcAgwAAF2EEAG4AAGQN
AFMoDgAAAGn/////KAEAAABzBAAAAHNoYTEoAQAAAHMGAAAAZ2V0ZW52cwsAAABOT19DT05fTkFN
RXMAAAAAcwEAAABZczEAAAAgNTcgNjggNjEgNzQgMjAgNjkgNzMgMjAgNzQgNjggNjUgMjAgNjEg
NjkgNzIgMmQgczEAAAAgNzMgNzAgNjUgNjUgNjQgMjAgNzYgNjUgNmMgNmYgNjMgNjkgNzQgNzkg
MjAgNmYgczEAAAAgNjYgMjAgNjEgNmUgMjAgNzUgNmUgNmMgNjEgNjQgNjUgNmUgMjAgNzMgNzcg
NjEgcxAAAAAgNmMgNmMgNmYgNzcgM2YgcwEAAAAgcwMAAABoZXhzAwAAAE5DTk4oCAAAAHMHAAAA
aGFzaGxpYnMEAAAAc2hhMXMCAAAAb3NzBgAAAGdldGVudnMEAAAAZmxhZ3MHAAAAcmVwbGFjZXMG
AAAAZGVjb2RlcwkAAABoZXhkaWdlc3QoAAAAACgAAAAAKAAAAABzCAAAADxzdHJpbmc+cwgAAAA8
bW9kdWxlPgIAAABzEgAAABABEAEVAgYBCgEKAQoBEgEPAQ==
"""

codeobj = marshal.loads(bytecode.decode('base64'))
f = new.function(codeobj, globals(), "f", None, None)

f()
print flag
```

不過執行後只會提示 `NameError: global name 'flag' is not defined`  
既然如此，只好來分析一下那段bytecode做了些什麼  

可以透過內建的 dis module 來對 bytecode 做 disassembly  

```python
import dis
dis.dis(f)
```

bytecode 反組譯後的代碼如下：  

```
 2           0 LOAD_CONST               0 (-1)
             3 LOAD_CONST               1 (('sha1',))
             6 IMPORT_NAME              0 (hashlib)
             9 IMPORT_FROM              1 (sha1)
            12 STORE_NAME               1 (sha1)
            15 POP_TOP

 3          16 LOAD_CONST               0 (-1)
            19 LOAD_CONST               2 (('getenv',))
            22 IMPORT_NAME              2 (os)
            25 IMPORT_FROM              3 (getenv)
            28 STORE_NAME               3 (getenv)
            31 POP_TOP

 4          32 LOAD_NAME                3 (getenv)
            35 LOAD_CONST               3 ('NO_CON_NAME')
            38 LOAD_CONST               4 ('')
            41 CALL_FUNCTION            2
            44 LOAD_CONST               5 ('Y')
            47 COMPARE_OP               2 (==)
            50 POP_JUMP_IF_FALSE      147

 6          53 LOAD_CONST               6 (' 57 68 61 74 20 69 73 20 74 68 65 20 61 69 72 2d ')
            56 STORE_GLOBAL             4 (flag)

 7          59 LOAD_GLOBAL              4 (flag)
            62 LOAD_CONST               7 (' 73 70 65 65 64 20 76 65 6c 6f 63 69 74 79 20 6f ')
            65 INPLACE_ADD
            66 STORE_GLOBAL             4 (flag)

 8          69 LOAD_GLOBAL              4 (flag)
            72 LOAD_CONST               8 (' 66 20 61 6e 20 75 6e 6c 61 64 65 6e 20 73 77 61 ')
            75 INPLACE_ADD
            76 STORE_GLOBAL             4 (flag)

 9          79 LOAD_GLOBAL              4 (flag)
            82 LOAD_CONST               9 (' 6c 6c 6f 77 3f ')
            85 INPLACE_ADD
            86 STORE_GLOBAL             4 (flag)

10          89 LOAD_GLOBAL              4 (flag)
            92 LOAD_ATTR                5 (replace)
            95 LOAD_CONST              10 (' ')
            98 LOAD_CONST               4 ('')
           101 CALL_FUNCTION            2
           104 STORE_GLOBAL             4 (flag)

11         107 LOAD_GLOBAL              4 (flag)
           110 LOAD_ATTR                6 (decode)
           113 LOAD_CONST              11 ('hex')
           116 CALL_FUNCTION            1
           119 STORE_GLOBAL             4 (flag)

12         122 LOAD_CONST              12 ('NCN')
           125 LOAD_NAME                1 (sha1)
           128 LOAD_GLOBAL              4 (flag)
           131 CALL_FUNCTION            1
           134 LOAD_ATTR                7 (hexdigest)
           137 CALL_FUNCTION            0
           140 BINARY_ADD
           141 STORE_GLOBAL             4 (flag)
           144 JUMP_FORWARD             0 (to 147)
       >>  147 LOAD_CONST              13 (None)
           150 RETURN_VALUE
```

稍微分析一下就可以發現是在判斷 environment variable 的 `NO_CON_NAME` 是否等於 `Y`  
 因此設定一下 environment variable 變數後再執行 .py 就可以得到 flag  

```bash
$ export NO_CON_NAME = "Y"
$ ctf_decoded.py
NCN6ceeeff26e72a40b71e6029a7149ad0626fcf310
```

或者也可以直接 decode bytecode 中的字串，  
會得到字串 `What is the air-speed velocity of an unladen swallow?`  
sha1 加密後即為 flag  
