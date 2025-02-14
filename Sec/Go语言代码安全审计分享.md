## 前言

**Go语言主要用作服务器端开发语言，适合于很多程序员一起开发大型软件，并且开发周期长，支持云计算的网络服务。Go语言能够让程序员快速开发，并且在软件不断的增长过程中，它能让程序员更容易地进行维护和修改。Go语言是强类型语言，它融合了传统编译型语言的高效性和脚本语言的易用性和富于表达性。**

由于Go语言代码审计资料较少，这里就把最近学习的对Vulnerability-goapp项目的审计过程分享一下。整个审计过程结合代码安全扫描工具和人工审计，期间也发现代码安全审计工具的漏报误报问题，以下将会细述。

## 审计对象

经过在github上查找，发现https://github.com/Snow-HardWolf/Vulnerability-goapp这个项目适合入门，涵盖了常见的go web安全漏洞。Gitclone之后在goland IDE里打开看到如下项目结构：

![img](https://image.3001.net/images/20200102/1577938746_5e0d6f3a7827c.png!small)

> Asserts目录是静态资源文件，跳过。
>
> Pkg目录是使用go实现的业务逻辑代码，重点关注。
>
> Runenv是数据库配置文件和生成数据库的脚本，简单看下就好。
>
> Trap目录是一个CSRF漏洞的演示，重点关注。
>
> Views目录是前端视图页面，简单看下就好。

## 代码安全扫描

首先我们使用代码安全扫描工具扫描，发现4类高危，2类中危漏洞，我们分别进行验证。

### 命令注入-数据流分析

在pkg/admin/admin.go的52行发现命令注入，直观可以看出取出cookie的内容拼接命令语句执行。

![img](https://image.3001.net/images/20200102/1577938960_5e0d70102093b.png!small)

![img](https://image.3001.net/images/20200102/1577939016_5e0d704802f76.png!small)

我们看一下污点跟踪过程：

![img](https://image.3001.net/images/20200102/1577939021_5e0d704de3d8f.png!small)

我们通过污点跟踪分析过程可以确认这是一个高危漏洞。

接下来在实际环境中演示一下，通过nc接收数据确认可执行shell命令。

![img](https://image.3001.net/images/20200102/1577939031_5e0d7057d04d9.png!small)

### 不安全的传输—语义分析

在main.go的156行，使用了http协议进行通信，存在明文传输数据的问题

![img](https://image.3001.net/images/20200102/1577939037_5e0d705d170bd.png!small)

### 秘钥硬编码-代码结构分析

在asserts/js/bootstrap.bundle.js文件的360行发现秘钥硬编码，不过人工确认这里不是秘钥，是工具的误报

![img](https://image.3001.net/images/20200102/1577939054_5e0d706ee0e04.png!small)

### 用户隐私泄露-数据流分析

在pkg/admin/admin.go的86行检测到用户隐私泄露，这里看到直接把用户输入的密码打印到控制台了，是一种不安全的处理方式。

![img](https://image.3001.net/images/20200102/1577939067_5e0d707bec989.png!small)

### cookie未启用httponly-代码结构分析

在pkg/admin/admin.go的110行检测到cookie未启用httponly，低危漏洞。

![img](https://image.3001.net/images/20200102/1577939079_5e0d7087f24cb.png!small)

### 不安全的随机数-代码结构分析

在asserts/js/bootstrap.bundle.js文件的135行发现使用了伪随机数，不过这个漏洞可以忽略，危害太小了。

![img](https://image.3001.net/images/20200102/1577939096_5e0d709849e16.png!small)

## 人工代码审计

经过对代码扫描工具识别出的漏洞进行分析，我们发现存在一些误报，那么是否存在漏报呢，毕竟我们工具的扫描规则只有400多条，我们接下来通过人工分析代码发现可能存在的漏报

### XSS-数据流分析

在pkg/post/post.go里我们发现Posts结构体，内有Uids、UserPosts、Created_at、UserImages结构体变量，猜测这里跟论坛发帖有关，我们人工进行一下污点数据跟踪分析：

通过ShowAddPostPage的post请求传入帖子内容写入数据库，然后通过ShowAddPostPage的get请求读出数据库内容写入前端页面，整个过程没有做特殊字符的净化处理，可以确定这里存在存储XSS中危漏洞。

![img](https://image.3001.net/images/20200102/1577939391_5e0d71bf68ce0.png!small)

我们在实际环境演示一下漏洞：

输入xss payload保存后再次刷新页面触发xss弹框

![img](https://image.3001.net/images/20200102/1577939402_5e0d71cad9f3a.png!small)

![img](https://image.3001.net/images/20200102/1577939420_5e0d71dc537c1.png!small)

反射xss低危漏洞分析过程类似，不再重复描述。

### Sql注入-数据流分析

在pkg/search/search.go里我们发现searchPosts方法，sql查询是直接拼接sql语句：

![img](https://image.3001.net/images/20200102/1577939437_5e0d71ed5ff99.png!small)

在拼接前并未对用户输入做净化处理，因此可确认这是一个sql注入的高危漏洞。

我们在实际环境中演示一下这个问题：

![img](https://image.3001.net/images/20200102/1577939443_5e0d71f394174.png!small)

![img](https://image.3001.net/images/20200102/1577939453_5e0d71fd669b5.png!small)

### Csrf-代码结构分析

对于CSRF的分析我找了两处写数据库的接口进行尝试，一个接口是存在csrf，一个接口不存在csrf，首先看修改密码的接口：

在pkg/user/usermanager.go里我们发现ConfirmPasswdChange方法，不过这里进行了referer（）的检查，在实战中referer校验虽然不像加token那样可以完全避免csrf，但伪造referer成本较高，所以这里不作为审计发现漏洞。

![img](https://image.3001.net/images/20200102/1577939466_5e0d720a1d201.png!small)

而在另一个更新用户个人信息的方法里却忽视了对referer的校验，可以确认存在csrf漏洞。

![img](https://image.3001.net/images/20200102/1577939473_5e0d7211c3f97.png!small)

我们在实际环境中进行演示确实存在csrf漏洞。

![img](https://image.3001.net/images/20200102/1577939483_5e0d721b665f1.png!small)

### 任意文件上传-数据流分析

在pkg/image/imageUploader.go里发现处理上传文件的方法，没有对文件名和文件内容进行校验

![img](https://image.3001.net/images/20200102/1577939498_5e0d722a5b269.png!small)

可以上传任意文件，不过由于web路由的限制好像解析不了go语言代码，解析静态资源文件是可以的，这里尝试着目录穿越写文件到其他目录。

以下在实际环境中进行漏洞演示：

![img](https://image.3001.net/images/20200102/1577939510_5e0d723634a8d.png!small)

利用条件挺苛刻，需要等着重启crontab服务，加载定时任务

![img](https://image.3001.net/images/20200102/1577939518_5e0d723ea43b8.png!small)

### 越权-数据流分析

以pkg/user/usermanager.go为例来看，这里的功能是展示用户个人信息，通过取出cookie里的uid在数据库进行查询得到用户基本信息，在查询前有对cookie的有效性进行校验，避免修改cookie实现水平越权。

![img](https://image.3001.net/images/20200102/1577939529_5e0d7249549bb.png!small)

CheckSessionId里有一个ValidateCorrectCookie的方法校验cookie

![img](https://image.3001.net/images/20200102/1577939537_5e0d72516ddca.png!small)

ValidateCorrectCookie通过将用户输入的cookie和后台数据库存储的信息进行比对，如发现uid被篡改就返回404页面。

![img](https://image.3001.net/images/20200102/1577939545_5e0d7259e3c73.png!small)

经过在实际环境验证，在读写操作数据库操作前使用cookie.CheckSessionID（）对cookie做校验是不会存在越权问题，而这个安全校验一旦去掉，越权问题就出现了。

### 服务器敏感信息泄露-代码结构分析

数据库异常，go的异常都有捕获在服务端打印log，没有向前端web页面返回，web页面报错统一跳转自定义404页面，服务器敏感信息泄露问题不存在。

如下是main.go里统一的记录http异常日志的代码：

![img](https://image.3001.net/images/20200102/1577939567_5e0d726f9899e.png!small)

### 不安全配置-配置文件分析

web路由配置正常，没有引用不安全的第三方库。

### 资源泄露、空指针分析-控制流分析

数据库、文件等资源文件使用完成后及时释放，未发现异常的控制流。

![img](https://image.3001.net/images/20200102/1577939589_5e0d72853288c.png!small)

## 总结

本次审计经过语义分析、数据流分析、代码结构分析、配置文件分析和控制流分析，共审计14类常见安全漏洞，发现存在10类漏洞，另外4类漏洞确认不存在，汇总信息如下：

![img](https://image.3001.net/images/20200102/1577939789_5e0d734dcfbdd.png!small)

目前代码安全扫描工具存在对golang的规则数量比较少，存在漏报问题，另外还有一定的误报，仍有比较大的优化提升空间。