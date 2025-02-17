---
created: 2025-02-17T23:26:35 (UTC +08:00)
tags: []
source: https://mp.weixin.qq.com/s/Y90mGgCqzjj0T1NX9E5wDw
author: FSRC-景明
---

# Java代码审计checklist（上）

> ## Excerpt
> 本文包括代码审计的概念、相关工具、FSRC整理的常见web漏洞的审计方式（包括搜索范围、内容、判断依据及修复方式）。

---
01

前言

FSRC经验分享”系列文章，旨在分享焦点安全工作过程中的经验和成果，包括但不限于漏洞分析、运营技巧、SDL推行、等保合规、自研工具等。

本文为焦点科技信息安全部日常工作中总结的代码审计相关checklist，整体分为上下两部分。本文为上部，内容包括代码审计的概念、相关工具、常见漏洞的审计方式（包括搜索范围、内容、判断依据及修复方式）。

欢迎各位安全从业者持续关注！

![图片](https://mmbiz.qpic.cn/mmbiz_png/xDBba1f2ZXKA1bENGfWdH3h0VC2lM2bzGf0bibtcQTFAkzQdrianFeMWwwHOp1hla5kjZFpuwibxp4eTsnDIV3ZyA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

7181字   阅读时间约18分钟

02

寻根问底代码审计

什么是代码审计？

代码审计是一种很常见的发现漏洞的方法，特别是甲方自行白盒审计。但是只要看代码就是代码审计么？什么才是专业的代码审计？

在FSRC看来，代码审计分为4部分：

谁：代码审计值得是具有**安全**和**开发**经验的人员

对象：阅读程序**源代码**或者经过**反编译**之后的代码

手段：借助**自动化代码分析工具**或者**人工阅读**的方式

目的：发现系统代码中存在的**安全风险**和**设计缺陷**，引导开发人员**修复**，保障系统运行安全

污点分析原理

污点分析是一种跟踪并分析污点信息在程序中流动的技术。在漏洞分析中通常将污点分析抽象成一个三元组的表示方式——<sources,sinks,sanitizers>

-   sources: 污点源，直接引入导致危险发生的不信任数据的位置，以SQL注入为例，`id=1`存在SQL注入，污点源为`id`参数；
    
-   sinks: 污点汇聚点，直接进行危险操作或者隐私泄露到外界的位置，以SQL注入为例，污染汇聚点为`executeQuery()`相关调用执行SQL语句的位置；
    
-   sanitizers: 无害化处理，使用转义、过滤、阻断、加密等手段不再对系统安全产生危害的位置，以SQL注入为例，无害化处理指的是SQL语句的过滤位置、或者SQL语句产生结果的判断位置（不完全）
    

![图片](data:image/svg+xml,%3C%3Fxml version='1.0' encoding='UTF-8'%3F%3E%3Csvg width='1px' height='1px' viewBox='0 0 1 1' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E%3Ctitle%3E%3C/title%3E%3Cg stroke='none' stroke-width='1' fill='none' fill-rule='evenodd' fill-opacity='0'%3E%3Cg transform='translate(-249.000000, -126.000000)' fill='%23FFFFFF'%3E%3Crect x='249' y='126' width='1' height='1'%3E%3C/rect%3E%3C/g%3E%3C/g%3E%3C/svg%3E)

污点分析就是分析程序中是否存在未经过无害化处理的污染源通过传播路径到达污点汇聚点，对系统产生危害。污点分析可以分成以下的几个阶段：

1.  判断列举污点汇聚点；
    
2.  寻找到污染汇聚点对应参数的污点来源；
    
3.  判断从污点源到五点汇聚点是否存在可能的通路；
    
4.  判断是否存在无害化处理、无害化处理是否能够完全处理污点源数据的所有情况。
    

污点分析是信息流分析技术中的一种实践的技术，广泛应用于静态分析安全测试中，是对人工代码审计的一种抽象。几乎所有的漏洞都可以按照污点分析的方式发现，但是分析的复杂度并不相同。对于SQL等常见的漏洞，污点汇聚点（危险函数）单一且容易发现，相对来说分析起来比较容易；但是对于逻辑漏洞、信息泄露、XSS等漏洞覆盖范围广、产生情况复杂、没有准确的危险函数，白盒发现较为困难且准确度不高。

代码审计流程

早期的代码审计由于目标系统规模小、代码量较少、代码之间的逻辑调用关系简单清晰，使用人工审计的方式就可以覆盖整个系统了。人工代码审计通常有三种思路：  

-   全文通读了解代码每部分的功能以及数据流向，结合具体的功能点发现代码中存在的问题。这种方式全面但是耗时耗力；
    
-   危险函数定位法，通过定位上面提到的sinks，找到危险函数之后向上排查，看危险函数数据来源，是否存在无害化处理，这种方式快捷方便，但不全面，对逻辑漏洞没有发现的能力；
    
-   对具体的功能点进行建模和审计，根据需求文档或者单一的功能点，分析可能出现的风险项，逐条排查。速度较快，对逻辑漏洞也能很好的把握。排查效果取决于安全人员的威胁建模能力和对目标的了解程度。
    

由于目标项目在发展的过程中逐渐复杂化以及代码量的指数级增长，系统和系统之间调用关系复杂，人工审计的方式已经无法做到全面的审计。一些对应的工具介入，极大的提高了代码审计人员的工作效率。静态代码审计工具原理发展如下：

-   关键字的匹配
    
-   基于AST代码分析
    
-   基于IR/CFG的代码分析
    
-   QL概念
    

03

代码审计常用工具

市面上常见的代码审计工具很多，主要分为以下四类。此处列举部分，没有好坏之分，大家根据习惯使用即可。

编辑器

各类代码编辑器，IDEA、VSCode、eclipse，顺手就行

反编译工具

Jd-gui、jadx、wJa（有动态调试功能），顺手就行

自动化代码审计工具

部分可以自动检测相关代码的工具，checkmarx、Seay、Fortify SCA、找八哥、CODESEC等

其它

一些辅助工具，CodeQL、soot、dependencyCheck、ysoserial、JNDI-Injection-Exploit等

04

基础漏洞代码审计方式

## 基础漏洞审计方式

基础漏洞审计方式

SQL注入

代码搜索范围

\*、Mapper.xml、\*.java、\*.xml(少部分开发人员Mapper文件编写不规范)

搜索字符串内容

```
<span>String sql = "</span>
```

判断依据

1.  原生JDBC是否存在直接拼接SQL语句（使用`+`，或者使用`StringBUilder append()`），未经过预编译；
    
2.  Mybatis使用`${}`；
    
3.  Hibernate、JPA默认是经过预编译的，但是如果开发自己编写的SQL语句，也需要进行检查；
    
4.  Java是强类型语言，当注入参数为long、int等数字类型时无法进行注入；
    
5.  找到危险函数位置之后，向上搜索，找函数、方法调用位置，直到请求入口（`controller层`），判断是否存在无害化处理、无害化处理是否严格；
    
6.  注意开发可能设置全局过滤。
    

修复方式

1.  参数固定为数字类型时，使用数字类型接收，或者转为数字类型；
    
2.  预编译，原生JDBC使用`?`参数占位，之后使用`.preparedStatement`，Mybatis使用`#{}`替换`${}`；
    
3.  对于Mybatis中无法使用`#{}`的场景：
    
1.  `like`：使用`CONCAT('%',#{},'%')`
    
2.  `in`：使用`<foreach`
    
3.  `order by`：代码上做白名单
    
5.  设置过滤器，严格限制传入参数
    

SSRF

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span><span>new</span> <span>URL</span>(</span>
```

判断依据

1.  该漏洞经常出现在客户端传入文件、图片的URL地址（通常存储在NAS、OSS上）通过URL获取相关的文件或者当前请求需要访问其他请求，请求地址由客户端传入；
    
2.  主要看参数是否可控，是否存在过滤，协议、端口等的限制措施、相关的限制措施是否完善；
    
3.  通常情况下，项目会封装一个用于发起请求的方法，除上述关键字还需要找该方法全部调用位置。
    

修复方式

1.  当目标请求为域名时，获取域名所对应的IP地址，防止内部解析绕过；
    
2.  设置内网地址黑名单或白名单；
    
3.  设置协议白名单；
    
4.  检查对应的IP地址是否为黑名单地址；
    
5.  禁止302跳转，或者存在302跳转时递归获取跳转的URL，判断是否为黑名单地址；
    
6.  禁止其他非必要的协议。
    

XXE

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span>XML</span>
```

XML解析常见的包

```
<span><span>javax</span><span>.xml</span><span>.parsers</span><span>.DocumentBuilderFactory</span>;</span>
```

判断依据

1.  解析器解析的XML需要外部可控；
    
2.  未禁用DTD或者允许外部实体；
    
3.  大多数项目都会封装一个用于解析XML的方法，因此除上述关键字以外，还需要寻找对应方法的调用位置逐个判断。
    

修复方式

XXE修复方式相对简单，禁用DTDs或者禁止使用外部实体即可。

```
<span>dbf.setFeature(<span>"http://apache.org/xml/features/disallow-doctype-decl"</span>, <span>true</span>); <span>//禁用DTDs (doctypes),几乎可以防御所有xml实体攻击</span></span>
```

任意文件操作

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span><span>new</span> File(</span>
```

判断依据

1.  未对文件路径、文件名称、文件类型做合理限制，上传文件路径或者文件名称可存在`../`目录跨越的操作；
    
2.  在解压缩文件时未对压缩包中的文件类型进行限制；
    
3.  未限制上传文件大小；
    
4.  通常情况下在解压缩文件时，开发一般都会创建一个临时目录，解压完成之后将临时文件夹删除，如果临时文件夹名称可以控制，则可以达到任意文件删除的目的；
    
5.  判断文件类型的操作时，开发一般先获取到文件名称，然后使用`filename.substring(filename.lastIndexOf("."));`获取文件后缀名，如果此处使用`filename.indexOf(".")`则可能存在绕过可能。
    

修复方式

1.  判断上传数据包的`content-type`
    
2.  设置上传文件类型白名单，上传文件后重命名，重命名类型不从上传文件中获取；
    
3.  限制文件上传的大小；
    
4.  当传递参数为文件路径时，需要判断路径中是否存在`../`跨目录操作；
    
5.  当参数同时存在`path`和`fileName`时，分别对`path`、`fileName`和拼接结果进行判断和限制；
    
6.  限制下载、删除可操作的根文件夹。
    

命令执行

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span><span>String</span> cmd</span>
```

判断依据

执行命令参数可控，为进行白名单或者过滤操作或不严格，未进行转义特殊字符操作或不严格。

修复方式

1.  非必要不调用系统命令；
    
2.  调用系统命令时不使用前台传入的命令，使用`id`的方式选择可执行的命令；
    
3.  设置可执行命令白名单，不允许使用 `&& || & | ;`等命令并列的特殊字符；
    
4.  控制执行命令用户权限；
    
5.  命令执行漏洞在实际工作中发现的较少。
    

不安全的反序列化

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span>readObject(</span>
```

判断依据

1.  反序列化数据可控，执行反序列化操作，反序列化对象readObject方法中存在危险操作。
    
2.  通常情况下是三方组件中存在漏洞，导致反序列化。因此只需要判断项目中是否引用了包含漏洞的三方组件版本即可，如果引入了则建议升级，如果无法升级，则看是否满足利用条件，并利用waf拦截相关的请求。
    

修复方式

1.  设置可反序列化的类白名单，不允许名单外的类进行反序列化；
    
2.  使用安全的三方组件。
    

URL跳转

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span><span>String</span> url</span>
```

判断依据

1.  跳转的URL地址用户可控，未经过过滤判断或过滤判断不严格；
    
2.  URL跳转漏洞可配合SSRF漏洞，当SSRF不完全校验地址时，可以利用URL跳转漏洞请求跳转之后的地址。
    

修复方式

1.  设置跳转地址白名单
    
2.  如果跳转地址是固定的，则可以使用`id`索引地址，防止用户直接传入；
    
3.  先生成跳转链接及其签名，跳转前进行签名验证。
    

硬编码

代码搜索范围

\*、\*.java

搜索字符串内容

```
<span>pass</span>
```

判断依据

代码中有明文的密码、密钥等信息（通常不包含单元测试java文件）

修复方式

1.  加密存储到配置文件中，然后代码中读取配置文件获取密码、密钥；
    
2.  使用配置中心或者存储到数据库中。
    

不安全的传输方式

代码搜索范围

\*.java、\*.properties、\*.yaml

搜索字符串内容

```
<span>DES</span>
```

判断依据

1.  使用不安全的加密方式加密数据；
    
2.  安全的加密方式密钥长度不符合要求
    
3.  开发人员经常在前端使用AES加密数据发送到后端，因为AES是对称加密的，前端必定存在AES密钥（JS或者请求获取）导致数据加密传输形同虚设；
    
4.  有些开发人员为了测试方便，会预留加解密接口，通常名称为`decrypt`和`encrypt`或者`jiami`和`jiemi`；
    
5.  **base64不是加密方式**，曾经见过请求头中的认证信息是base64编码的用户名和密码串。
    

修复方式

1.  使用安全的非对称加密算法
    
2.  加密算法密钥长度应该符合安全要求
    
3.  使用MD5加密存储密码信息时应当加盐（建议使用表中UUID、createDate等具有迷惑性质的随机盐）
    

日志伪造

代码搜索范围

\*.java

搜索字符串内容

```
<span><span>.info</span>(</span>
```

判断依据

1.  日志打印内容可控；
    
2.  日志内容未过滤
    

修复方式

1.  日志内容固定；
    
2.  过滤打印内容，设置可打印字符白名单，不允许打印换行`\n`
    

敏感信息泄露

代码搜索范围

\*.java

搜索字符串内容

```
<span><span>password</span></span>
```

判断依据

1.  是否存在统一报错返回；
    
2.  返回结果是否包含敏感内容。
    
3.  对于大型项目来说，返回的结果往往被封装成实体后返回，因此可以查找返回的结果封装中是否包含以上的字段，如果包含则追踪到对应的位置，查看是否进行脱敏或者清空。
    

修复方式

1.  定制统一报错页面或者统一报错json返回；
    
2.  只返回必要的信息，密码等字段不应返回，敏感字段脱敏返回。
    

安全配置问题

发现方式

看`pom`文件或者`lib`中是否存在可能有配置错误的组件，然后查看对应的配置。  

常见的有可能存在问题的组件如下：`Swagger 、Shiro、SpringSecurity、Druid、Spring boot actuator`

相对于白盒而言，这种配置错误导致的未授权问题黑盒审计更为方便。批量访问对应URL判断是否能够访问成功即可。

修复方式

1.  swagger不建议对公网开放；
    
2.  如果确实存在开放的必要，则必须进行身份认证和授权操作；
    
3.  可以配置密码密钥的组件需要配置密码和密钥，并保证密钥的复杂度。
    

XSS

发现方式

XSS漏洞覆盖范围较广，服务端向外发送数据的场景都有可能产生XSS。

XSS还和前端使用的框架相关，有些框架对于XSS有很好的防护性。因此白盒发现XSS较为复杂，可以看业务逻辑的位置辅助看看，发现存在可能性的位置后，配合黑盒在具体的站点上尝试是否可以成功。

此外，也可以看看是否存在过滤器，对XSS进行实体化转义或者过滤，转义或者过滤是否严谨和规范。

修复方式

1.  HTML实体化
    
2.  Cookie设置httponly
    
3.  过滤特殊字符、过滤事件标签
    

09

参考资料及免责声明

**污点分析技术的原理和实践应用（by 王蕾）**

https://www.cnki.com.cn/Article/CJFDTotal-RJXB201704009.htm

**JAVA代码审计之XXE与SSRF（by 皮皮鲁）**  

https://xz.aliyun.com/t/2761

**攻击JWT的一些方法（by Stefano）**  

https://xz.aliyun.com/t/6776

**浅谈Cookie和Cookie安全（by 浅海科技）**  

https://juejin.cn/post/6959830432519520292

本文中提到的相关资源已在网络公布，仅供研究学习使用，请遵守《网络安全法》等相关法律法规。

![图片](data:image/svg+xml,%3C%3Fxml version='1.0' encoding='UTF-8'%3F%3E%3Csvg width='1px' height='1px' viewBox='0 0 1 1' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E%3Ctitle%3E%3C/title%3E%3Cg stroke='none' stroke-width='1' fill='none' fill-rule='evenodd' fill-opacity='0'%3E%3Cg transform='translate(-249.000000, -126.000000)' fill='%23FFFFFF'%3E%3Crect x='249' y='126' width='1' height='1'%3E%3C/rect%3E%3C/g%3E%3C/g%3E%3C/svg%3E)

本文编辑：小错

![图片](data:image/svg+xml,%3C%3Fxml version='1.0' encoding='UTF-8'%3F%3E%3Csvg width='1px' height='1px' viewBox='0 0 1 1' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'%3E%3Ctitle%3E%3C/title%3E%3Cg stroke='none' stroke-width='1' fill='none' fill-rule='evenodd' fill-opacity='0'%3E%3Cg transform='translate(-249.000000, -126.000000)' fill='%23FFFFFF'%3E%3Crect x='249' y='126' width='1' height='1'%3E%3C/rect%3E%3C/g%3E%3C/g%3E%3C/svg%3E)

精彩推荐

[几个小技巧，绕过SSRF的黑白名单](http://mp.weixin.qq.com/s?__biz=MzI2ODY3MzcyMA==&mid=2247500152&idx=1&sn=2911597ab35632c0334763582d03cc01&chksm=eae976afdd9effb92a616b24624dac6320608ddbd474d044ad0b46b91e36078623ea35cfa38d&scene=21#wechat_redirect)

[PHP反序列化漏洞](http://mp.weixin.qq.com/s?__biz=MzI2ODY3MzcyMA==&mid=2247499881&idx=1&sn=a20f3a61f3de53576e9faf02544f80ea&chksm=eae977bedd9efea817439efd23f523633b77a03cb4e3a5eb57738aafb712a35a76a9a7f98f77&scene=21#wechat_redirect)

[管好你的API——API的安全防护](http://mp.weixin.qq.com/s?__biz=MzI2ODY3MzcyMA==&mid=2247490010&idx=1&sn=7c429cc3021707270e628342d9dec771&chksm=eaeaae0ddd9d271bc994000e02d006b226f89164bd8383eb61caac752c012921916636e5c6cd&scene=21#wechat_redirect)

焦点安全，因你而变  

焦点科技漏洞提交网址：https://security.focuschina.com