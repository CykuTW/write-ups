# No cON Name CTF Quals 2014: cannaBINold #

**Category:** Binary
**Points:** 300
**Description:**

> Get the key. The flag is: "NcN_" + sha1sum(key)
> 
> Url: https://ctf.noconname.org/chdownloads/cannabinoid
> 

## Write-up

題目執行檔為 ELF32bit，稍微逆向一下：

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char* argv[])
{
    char input[128];
    int fd;
    void* buffer;

    if ( argc != 1 )
        return 1;
  
    if ( fread(input, 1, 128, stdin) == 128 ) {
        fd = open(argv[0], 0);
        if ( fd == -1 )
            return 1;

        buffer = mmap(0, 128, 1, 2, fd, 0);    
        if ( buffer == -1 )
            return 1;

        bool flag = true;
        for ( int i = 0; i < 128; ++i ) {
            flag &= input[i] == buffer[i];

        if ( flag )
            puts("You got it!");

        return 0;
    }
}
```

程式會從 argv[0] 字串所指向的檔案讀取 128 bytes，再與輸入比較。

因此執行檔的前 128 bytes 就是本題的 key。


```bash
$ python -c "import sys; sys.stdout.write(open('cannabinoid').read(128))" | sha1sum
effaf80a641b28a8d8a750b99ef740593bb3dcbd *-
```

Flag: NcN_effaf80a641b28a8d8a750b99ef740593bb3dcbd
