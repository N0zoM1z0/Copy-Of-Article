FROM

```
https://xz.aliyun.com/t/15565?time__1311=Gqjxn7iti%3DiQdGNDQ0KBK0QDOU9IewOAbD#toc-4
```



自己实操真的找不到（）

怎么搞得到身份证号啊（）

---

## 0x1 前言

哈喽哇，师傅们！
又又到更新技术小文章的时间了，哈哈哈。
这篇文章呢，主要是讲如何通过信息收集进入门户网站的骚打法，然后文章里面写了很多的各种如何通过信息收集进行门户网站的姿势，写的很详细，因为渗透测试的最重要的一个环节就是信息收集，对目标资产的一个信息收集和资产的收集。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908202858-ebdf1d26-6ddd-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908202858-ebdf1d26-6ddd-1.png)

信息收集很重要，如确定资产，比如他有哪些域名、子域名、C 段、旁站、系统、微信小程序或者公众号，确定好站点或者目标系统之后，就是常规的指纹识别，像中间件、网站，扫目录，后台，确定功能然后分析每个功能点上会有哪些漏洞，就比如一个登录页面，我们可以考虑的是爆破账号密码，社工账号密码，SQL 注入，XSS 漏洞，逻辑漏洞绕过等。

## 0x2 利用好谷歌语法查找敏感信息

### 浅谈

针对我们在挖edusrc的时候遇见最大的问题就是如何突破一站式服务大厅的网站，要突破这一点，我们就需要拥有教师的gh 、sfz和 学生的sfz、 xh这些个人隐私信息，所以我们就需要做好信息收集。常见的Google语法网上有很多，然后我这里也给师傅们汇总好了部分常用的Google黑客语法

```
1.site:域名 intext:管理|后 台|登陆|用户名|密码|验证码|系统|帐号|manage|admin|login|system

2.site:域名 inurl:login|admin|manage|manager|admin_login|login_admin|system

3.site:域名 intext:"手册"

4.site:域名 intext:"忘记密码"

5.site:域名 intext:"工号"

6.site:域名 intext:"优秀员工"

7.site:域名 intext:"身份证号码"

8.site:域名 intext:"手机号"
```

### 简单入门

下面就来带师傅们深入体会下利用好谷歌语法查找敏感信息的骚操作

```
site:xxx.edu.cn   //最简单的查找edu站点的Google语法
```

这个语句是寻找这个学校的相关域名的站点，但是在这个后面加一些敏感信息就可以指定查找了，比如：`site:xxx.edu.cn sfz` `site:xxx.edu.cn xh`这样的等条件

下面就来拿北京大学做一个演示了，可以看到很简单一个学号检索的方法，但是对于你在测试某站点需要学号的时候，特别好用。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908202927-fd566802-6ddd-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908202927-fd566802-6ddd-1.png)

如上图一样，直接可以从这个pdf中获取很多信息，一般隐私信息都会以doc、pdf、xls 这些文件发布到网上，所以造成信息泄露（如果你不追求什么漏洞，上上rank 这一个都够你上几百rank）

就谷歌收：site:.edu.cn sfz filetype: pdf|xls|doc 即可。

```
site:xxx.edu.cn intitle:学号 filetype:pdf OR filetype:xls OR filetype:doc
```

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908202957-0f428b0e-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908202957-0f428b0e-6dde-1.png)

说不定还有一些意外的收获呢，就比如下面的这个站点，检索学号和密码相关的资产，发现这里存在一个系统默认密码的，那么是不是又可以上一波rank了 呢。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203010-1694b882-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203010-1694b882-6dde-1.png)

如果以上没有找到自己想要的信息，你就可以去找所在学校相关的教育局站点，因为助学金等奖励都会通过当地教育局进行展开

```
site:xxx.edu.cn ( "默认密码" OR "学号" OR "工号" OR "助学金")
```

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203025-1feb50a8-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203025-1feb50a8-6dde-1.png)

这样在相关教育局站点我们也可以收集到我们需要的信息，当然你也可以加入班群，表白墙等容易泄露信息的地方。（如果你语雀玩的好，你可以通过语雀去查找重要信息）

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203045-2bfc8a10-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203045-2bfc8a10-6dde-1.png)

包括使用抖音平台，可以去检索某某大学录取通知书之类的信息，很容易可以找到该学校的一些用户信息，比如常见的学号和身份证号，都是可以收集的，然后对于某些大学的门户网站，是不是可以进行渗透一波了。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203058-3374a958-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203058-3374a958-6dde-1.png)

## 0x3 利用谷歌语法查找脆弱的系统获取信息

### 系统初始密码获取

师傅们可以从上面的Google语法的操作来扩大危害，看看通过下面的语法可以查找许多相关弱口令系统，然后利用上面收集的信息，进行登录，从这些能登录进去的系统，我们也可以获取很多有用的信息，在进一步说，至少我们有学生权限的账号了，可以测试水平或者垂直漏洞，毕竟后台漏洞是要比前台多：

```
site:xxx.edu.cn ( "默认密码" OR "初始密码" OR "工号")
```

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203114-3cfb98f6-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203114-3cfb98f6-6dde-1.png)

### 真实案例分享

下面的这个案例也是我之前挖edusrc的案例，下面给师傅们分享下

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203130-468a6438-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203130-468a6438-6dde-1.png)

这里呢，也是先按照我上面的信息收集的手法去搞，然后利用我们收集的信息大量尝试登录即可

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203140-4c92285c-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203140-4c92285c-6dde-1.png)

这里是找到的这个大学的一个手机缴费系统的pdf操作指南手册，然后再利用我们的初始密码去尝试大量爆破弱口令用户

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203152-53cb963a-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203152-53cb963a-6dde-1.png)

此次是很顺利的获取的sfz 和xh 这些信息所以这个系统轻松登录，如果二者缺一可以思考如何获取，这一点自己思考。然后呢，上面的操作也是很详细，通过一个简单的Google语法去检索一些别人可能会忽略的重要信息以及一些学校也没有注意的信息，但是你收集的信息够多，那就很有可能可以打一个敏感信息泄露的操作了。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203208-5ce54b8a-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203208-5ce54b8a-6dde-1.png)

后面继续测试漏洞即可，不管出货不出货都可以获取自己想要的信息，上面即可看出大量的信息泄露

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203227-68b4b0d6-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203227-68b4b0d6-6dde-1.png)

这里在我们进入一站式服务大厅后，我们可以尝试登录vpn，如果可以进入vpn那么我们可以直接使用fscan对网段进行扫码。

## 0x4 针对某edu实战渗透

### 1、信息收集

首先我们先确定下目标资产，某某大学站点。

然后再利用信息收集的手法去收集一下该学校的一些站点信息

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203310-821f1c50-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203310-821f1c50-6dde-1.png)

确定目标之后就是对于该学校的信息收集，主要收集：xh、sfz、gh、电话号码等信息，因为信息收集是渗透的核心，如果信息收集几分钟，那么你挖洞就是几个星期或者几个月都不会出货，如果信息收集够多，那么挖洞就会很快出货。

#### 浅谈

对于高校，一般可以利用谷歌语法：filetype:xls site:xxx.edu xh gh sfz这些去收集我们所需要的东西，也可以去当地的教育局官网查看有没有敏感信息泄露，比如贫困生补助，奖学金补助等等文件很容易泄露重要信息的，再者就是在学校官网查看看有没有信息泄露，一般有公示文件，这些文件也特别容易泄露信息。

此次突破就是该学校的官网泄露，造成此次的渗透事件，所以高校在发文时一定要做好脱敏处理我们可以看到该学校的站点xxxx.edu.cn/xxx/info/xx.html页面(可以看出是主站泄露了同学的sfz，然后我们再利用该信息，反查xh，这样就可以利用sfz和学号的弱口令进入webvpn，然后开始挖掘漏洞）

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203349-9958a9cc-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203349-9958a9cc-6dde-1.png)

### 2、渗透测试

信息收集搞好后，就可以开始渗透之旅了，利用收集好的账号和sfz对官网一站式服务大厅进行爆破（高校网络安全意识差，肯定存在弱口令的），找到门户服务网站此时一定要注意门户网站的帮助说明这些，因为这里会告诉你默认密码的情况：

这里我主动去找找这个学校的门户网站，包括其实师傅们还可以去检索统一身份认证、学生登录后台、教师登录后台等关键字，然后去测一测（根据我们开始收集到的信息）

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203406-a3bd1556-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203406-a3bd1556-6dde-1.png)

这里咱们二话不多说，直接访问这个门户站点，然后去里面找到了下面的这个统一身份认证登录平台

不知道师傅们这里是否有点惊喜，看到下面的使用说明，是不是会有一点想点一点测试一下，看看里面的使用说明会泄露什么信息呢？

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203423-ad8eb6a2-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203423-ad8eb6a2-6dde-1.png)

当我们点开帮助说明的时候，几乎就可以露出笑容了，很清楚的写出来了初始密码；

而且还很清楚的告诉你比如身份证号是多少，然后初始密码是多少的，像这样的特别是在新生八九月分开学的时候，你去测试一般的大学站点，很多都会给你一个pdf文档，然后告诉你怎么进行登录学生管理后台。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203437-b61678fa-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203437-b61678fa-6dde-1.png)

这里给师傅们看看之前我找的一个企业公司的系统使用手册，然后也是通过信息收集找到了相关的账号密码信息

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203448-bcbac9cc-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203448-bcbac9cc-6dde-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203455-c0a8e8c0-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203455-c0a8e8c0-6dde-1.png)

#### 横向渗透

我们信息收集的也很顺利，其中很多账号都是默认口令，于是开始对系统进行挨个测试，然后扩大危害，提高我们提交的rank值，可以在edu打包提交一波

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203510-c9a35942-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203510-c9a35942-6dde-1.png)

然后开始对每一个系统都开始进行测试，当然，进去后我最喜欢的系统一般是人事系统，学生管理系统等等，这个师傅们应该知道吧，主要是这方面的安全系数相对底。

所以我第一个打的就是人事系统了，可以继续猜测，这个学校没有任何安全意识，于是这个人事系统也可以猜测大多数为弱口令，加上刚才收集的老师和学生账号开始测试：直接抓包爆破，果然在我猜测之中，该系统全体师生都是弱口令：admin666/admin888之类的

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203528-d477dcbc-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203528-d477dcbc-6dde-1.png)

#### 任意用户密码重置

此系统还有一个有趣的地方就是任意密码重置，可以直接将管理员密码重置

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203545-de99a446-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203545-de99a446-6dde-1.png)

这里的操作也很简单，师傅们可以直接看到左边的操作下面的重置密码的功能点，然后直接使用bp抓包，然后尝试重置admin超级管理员账户即可

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203557-e5be975e-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203557-e5be975e-6dde-1.png)

后面就可以尝试登录admin超级管理员的账户权限，高权限的账户看到的全校敏感的信息是不是更加多了呢。这里我就不给师傅们演示了，点到即可，不给这个学校的站点做破坏（害怕被搞，哈哈哈）

#### 大量敏感信息泄露

当进入这个系统后，就可以宣判这个学校结束了（当然这时候才是开始）全校师生的个人的信息全部都泄露了出来，这些泄露的敏感信息都可以汇总下，然后看看有多少条，一般edusrc收的敏感信息泄露，收公民三要素：姓名、手机号、身份证信息

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203618-f24e78a4-6dde-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203618-f24e78a4-6dde-1.png)

泄露多的都可以单独提交edu，泄露的信息少的话，可以和前面的几个漏洞一起提交，然后打包在一起，扩大rank值。

此系统因为弱口令泄露了很多信息，其余逻辑都测试和一些不重要的xss我就不写了，然后进行学工系统的测试。

然后这里我点击别的功能点去看学生的功能点的时候，看到了这个学生请假功能，点击该学校的教务系统，然后可以看到该系统的请假页面中，有一个附件上传的功能点。

这里像在学校的管理后台，应该很少有对这些上次的文件进行一个白名单过滤，很多学校都是前端验证，我之前也是碰到过完全没有任何过滤的上传功能点，然后直接上传jsp/php木马，然后拿到一次getshell的。

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203643-0147dd3c-6ddf-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203643-0147dd3c-6ddf-1.png)

这里我上传的php没有被拦截，直接打了一波phpinfo上去，懂的师傅都知道，这里都是学校的管理后台，也不去上传什么木马了，到时候直接提交phpinfo页面上去，证明下这个文件上传的功能点存在getshell即可

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20240908203745-26515568-6ddf-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240908203745-26515568-6ddf-1.png)

## 0x5 总结

这篇文章给师傅们分享的思路，师傅们可以去尝试下相关edu的门户网站的漏洞挖掘操作，多学多挖，然后多总结经验，有自己的一套打法，就很厉害了。

有时候简单的站点，你针对于该目标的信息收集全了，是很容易找到漏洞的，特别是一些逻辑漏洞之类的，师傅们要是信息收集几分钟就去打，那么你挖很久都可能出不了货的。灵活的运用各种大佬写好的工具，然后多尝试，总有一天，你也可以的！！！