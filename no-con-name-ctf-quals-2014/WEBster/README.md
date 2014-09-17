# No cON Name CTF Quals 2014: inBINcible

**Category:** Web
**Points:** 200
**Description:**

> Super-secure cloud service.
>
> Url: https://ctf.noconname.org/webster/

## Write-up

進入網頁後只有帳號密碼輸入頁面，初步檢測沒有 SQL Injection 問題。
觀看原始碼發現註解：

```
<!-- Testing code, remember to remove testing users -->
```

直覺輸入 User: test Password: test 登入成功。
登入後進入到 list.php，下面 list 出四個檔案 `.htaccess` `list.php` `flag.txt` `README.md`。
其透過 `content.php?op=id` 將檔案內容呈現出來，但直接點擊 `flag.txt` 會出現：

```
Seems that you are not in the right place for that
```

一開始以為是要繞過 `.htaccess` 的設定，不過嘗試許久未成功。
結果發現 cookie 有個 `loc` 是 md5。
將其爆破後是登入 `list.php` 時所顯示的 IP，直覺猜測可能要將 `loc` 改為 `md5(127.0.0.1)`。

再次訪問 `flag.txt` 得到 flag：
```
NCN_f528764d624db129b32c21fbca0cb8d6
```
