<head>
<!-- MathJax Library - ref: http://www.mathjax.org -->
<script type="text/x-mathjax-config">
MathJax.Hub.Config({tex2jax: {inlineMath: [['$','$'], ['\\(','\\)']]}});
</script>
</head>

# HITCON CTF 2014: rsaha

**Category:** Crypto
**Points:** 200
**Description:**

> Can you break RSA?
> [https://dl.dropbox.com/s/xqkoamfvas1rdb7/rsaha-fe50cf1bcae41e8ec6eeebccf3f0de7c.py](rsaha-fe50cf1bcae41e8ec6eeebccf3f0de7c.py)
> [http://ctf.tw/rsaha-fe50cf1bcae41e8ec6eeebccf3f0de7c.py](rsaha-fe50cf1bcae41e8ec6eeebccf3f0de7c.py)
>
> ```bash
> $ nc 54.64.40.172 5454
> ```

## Write-up

By studying the given code we learn that we have to enter the correct number 10 times, after which the program will give us the flag. The most important part is the following:

```py
def encrypt(bits, m):
    p = random_prime(bits)
    q = random_prime(bits)
    n = p * q
    assert m < n
    print n
    print m ** 3 % n
    print (m + 1) ** 3 % n
```

The program gives us `n`, `m**3 %n` and `(m+1)**3 %n` and asks us `m` in return. After some research on RSA encryption we notice that this encryption can be broken because we are given two encrypted messages. We know those message are encrypted using the same key and related to each other. This is also known as a [Franklin-Reiter Related Message Attack](http://en.wikipedia.org/wiki/Coppersmith%27s_Attack#Franklin-Reiter_Related_Message_Attack). This lead us to the next formula:

```
((m + 1)**3 +  2*m**3 - 1)/((m + 1)**3 - m**3 + 2) = m mod n
```

After a while I figured out we can use the [extended Euclidean algorithm](http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) to calculate `m` from this formula. Here is a snippet of the Python code I wrote:

```py
# return a triple (g, x, y), such that ax + by = g = gcd(a, b).
def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

m_n1 = m_31 + 2*m_3 - 1
m_n2 = m_31 - m_3 + 2
f = m_n1%n
g = m_n2%n
sol1 = egcd(f,n)
sol2 = egcd((1-n*sol1[2])*g/f,n)
m = sol2[1]
m2 = -m
if m < 0:
  m += n
# If it’s not really `m`, it’s the mod inv of `m`.
if (m ** 3 % n) != m_3:
  m = m2
if m < 0:
  m += n
```

This decrypts our given strings into the message we need to return.

Finally the program gave us a final message holding the key. Of course we had to decrypt that one too.

The flag is `HITCON{RSA is a really secure algorithm, right?}`.

# 中文版 #
題目可以從 [writeup][0] 抓到，可以從它提供的 .py 檔中看到一些蛛絲馬跡。
從題目可以看到，在 encrypt 當中他會對 **m** 做 bits 長度的加密：

+ 產生兩個質數 $(p, q)$ 並且得到 $n = p * q$
+ 回傳 n、$m^3 % n$ 以及 $(m+1)^3 % n$

看到兩個條件就知道這是屬於偏數學 ([代數][8]) 的題目：目的就是在 [GF(n)][2]
中反推 m 是什麼值。一開始想到的，
是利用[費馬小定理][3]來找出[反元素][4]，不過卡在一個很蠢的數學問題：
$(m+1)^3 - m^3 = 3(m^2+m) + 1$，
但是突然不會找 $m^2+m$ 的反元素，所以卡了半小時多 (還出去買延長線+咖啡散散心)。

最後靠隊友提供一個簡單的高中數學解決了所有問題：
$m^3 - 1 = (m-1)(m^2 + m + 1)$
。根據上面的算式，我們就可以將 m 用所有已知道的東西代換成：

1. $m^2 + m = 3^{-1}((m+1)^3 - m^3 - 1)$
2. $m -1 = (m^3 - 1)(m^2 + m + 1) ^{-1}$
3. $m = 1 + (m^3 - 1)(3^{-1}((m+1)^3 - m^3 -1) + 1)^{-1}$

### 原理 ###

在代數理論當中，[Galois Field][2]很常用在密碼學的領域當中，
其中很重要的一個理論就是[費馬小定理][3]:

> 在 GF(p) 的 Field 中，任何一個元素在 $GF(p)$ 都滿足 $x^p \equiv x$

當然這只是基本的概念，主要是知道一定可以找到反元素
(只要你給的數字 x 跟 p [互質][5])。另外，在 Field 裡一定會滿足的[幾個定理][6]，
包含：

+ 加法分配律 (associativity)
+ 加法交換律 (commutativity)
+ 乘法分配律 (distributivity)

所以只需要將 $m$ 用 $(m+1)^3$、$m^3$、常數，以及使用加、減、乘和反元素，
就可以得到結果。


另外，如果不用 Library 提供的反元素運算，可以自己實作反元素的邏輯。
主要的演算法是計算 [GCD][7] 過程中獲得。計算 GCD 可以用簡單的算式來表示：
$ax + bp = 1$。只需要在 GF 中計算 $x$ 與 $p$ 的 GCD 就可以得到 $a$：
這也就是 $x$ 在 $GF(p)$ 的反元素。

### Write-UP ###

	:::python
	import sympy

	def crack(n, x, y):
		## Pure algebra problem on GF(n)
		tmp = (((y - x - 1) * sympy.invert(3, n)) + 1) % n
		m = (1 + ((x-1) * sympy.invert(tmp_1, n))) % n

		## HEX encoding for m
		## Remove first 0x prefix and L suffix
		m = hex(int(m))
		return m[2:-1].decode("hex")

## Other write-ups
* none yet

[0]: https://github.com/ctfs/write-ups/tree/master/hitcon-ctf-2014/rsaha
[1]: http://mathworld.wolfram.com/FermatsLittleTheorem.html
[2]: http://mathworld.wolfram.com/FiniteField.html
[3]: http://mathworld.wolfram.com/FermatsLittleTheorem.html
[4]: http://mathworld.wolfram.com/ModularInverse.html
[5]: http://en.wikipedia.org/wiki/Coprime_integers
[6]: http://mathworld.wolfram.com/FieldAxioms.html
[7]: http://en.wikipedia.org/wiki/Greatest_common_divisor
[8]: http://en.wikipedia.org/wiki/Algebra
