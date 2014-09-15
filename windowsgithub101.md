# Windows GUI 無腦更新 CTF WriteUP 方式
1. 灌個 [tortoisesvn](http://tortoisesvn.net/downloads.html)，記得要把cmd line tools打勾。
![Image of Step1](http://i.imgur.com/vWbYHPV.png) 
2. SVN可以針對單一目錄而不是整個git，這邊以 no-con-name-ctf-quals-2014 為例：<BR>
Windows 下找個目錄 , 輸入 <code>svn checkout https://github.com/hsttw/write-ups/trunk/no-con-name-ctf-quals-2014</code>
![Image of Step2](http://i.imgur.com/F4tE7KE.png)
3. 直接在資料夾裡面加檔案，改README.md寫writeup(可以裝個MarkdownPad來寫)。
![Image of Step3](http://i.imgur.com/pHHhs7f.png)
4. 要上傳 github 時，對整個資料夾按右鍵，SVN COMMIT即可。
![Image of Step4](http://i.imgur.com/3HQYOR0.png)
