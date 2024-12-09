FROM

```
https://www.freebuf.com/news/193659.html
```

好文！

---

技术讨论 | 在HTTP协议层面绕过WAF

[bypassword](https://www.freebuf.com/author/bypassword)2019-01-17 09:00:541400178

![img](https://image.3001.net/images/20240308/1709876354_65eaa4828e91d155430d9.png)本文由bypassword创作，已纳入「FreeBuf原创奖励计划」，未授权禁止转载

**PS：本文仅作技术分析，禁止用于其它非法用途**

> 首先，自我介绍一下。小白一名，2017年才接触Web渗透测试，至于为啥，当然是自己的网站被攻破了……

**进入正题，随着安全意思增强，各企业对自己的网站也更加注重安全性。但很多web应用因为老旧，或贪图方便想以最小代价保证应用安全，就只仅仅给服务器安装waf。所以渗透测试过程中经常遇到惹人烦的web应用防火墙,只有突破这第一道防御，接下来的渗透才能顺利进行。本次从协议层面绕过waf实验用sql注入演示，但不限于实际应用时测试sql注入（命令执行，代码执行，文件上传等测试都通用）。**

**声明：这次实验的思路方法并非自己想出来的，是听了某大牛的公开课总结学习而来。**

## **原理**

给服务器发送payload数据包，使得waf无法识别出payload,当apache,tomcat等web容器能正常解析其内容。如图一所示

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190103/1546517507_5c2dfc03a7bd0.png!small)

图一

## **实验环境**

本机win10+xampp+某狗web应用防火墙最新版。为方便演示，存在sql注入的脚本中使用$_REQUEST["id"]来接收get,或者post提交的数据。waf配置为拦截url和post的and  or 注入，如图二所示。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546679837_5c30761d308ee.png!small)

图二

发送get请求或利用hackbar插件发送post请求payload均被拦截，如图三。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546684328_5c3087a8b64c9.png!small)图三

## 一·  利用pipline绕过[该方法经测试会被某狗拦截]

### **原理**：

http协议是由tcp协议封装而来，当浏览器发起一个http请求时，浏览器先和服务器建立起连接tcp连接，然后发送http数据包（即我们用burpsuite截获的数据），其中包含了一个Connection字段，一般值为close，apache等容器根据这个字段决定是保持该tcp连接或是断开。当发送的内容太大，超过一个http包容量，需要分多次发送时，值会变成keep-alive，即本次发起的http请求所建立的tcp连接不断开，直到所发送内容结束Connection为close为止。

\1. 关闭burp的Repeater的Content-Length自动更新，如图四所示，点击红圈的Repeater在下拉选项中取消update Content-Length选中。**这一步至关重要！！！**

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190103/1546519272_5c2e02e82e654.png!small)

图四

\2. burp截获post提交

```
id=1 and 1=1
```

,显示被waf拦截如图五所示。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546684814_5c30898e3ea2d.png!small)图五

\3. 复制图五中的数据包黏贴到

```
id=1 and 1=1
```

后面如图六所示。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546685172_5c308af40092c.png!small)图六

\4. 接着修改第一个数据包的数据部分，即将

```
id=1+and+1%3D1
```

修改为正常内容id=1，再将数据包的Content-Length的值设置为修改后的【id=1】的字符长度即4，最后将Connection字段值设为keep-alive。提交后如图七所示，会返回两个响应包，分别对应两个请求。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546694601_5c30afc948163.png!small)

图七

**注意：**从结果看，第一个正常数据包返回了正确内容，第二个包含有效载荷的数据包被某狗waf拦截，说明两数据包都能到达服务器，在面对其他waf时有可能可以绕过。无论如何这仍是一种可学习了解的绕过方法，且可以和接下来的方法进行组合使用绕过。

## 二.利用分块编码传输绕过[该方法可绕某狗]

### **原理：**

在头部加入 Transfer-Encoding: chunked 之后，就代表这个报文采用了分块编码。这时，post请求报文中的数据部分需要改为用一系列分块来传输。每个分块包含十六进制的长度值和数据，长度值独占一行，长度不包括它结尾的，也不包括分块数据结尾的，且最后需要用0独占一行表示结束。

\1. 开启上个实验中已关闭的content-length自动更新。给post请求包加入Transfer-Encoding: chunked后，将数据部分id=1 and 1=1进行分块编码（注意长度值必须为十六进制数），每一块里长度值独占一行，数据占一行如图八所示。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546696724_5c30b814eb553.png!small)图八

2.将上面图八数据包的

```
id=1 and 1=1
```

改为

```
id=1 and 1=2
```

 即将图八中所标的第4块的1改为2。如图九所示没有返回数据，payload生效。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546697069_5c30b96db44d7.png!small)

图九

注意：分块编码传输需要将关键字and,or,select ,union等关键字拆开编码，不然仍然会被waf拦截。编码过程中长度需包括空格的长度。最后用0表示编码结束，并在0后空两行表示数据包结束，不然点击提交按钮后会看到一直处于waiting状态。

## 三.利用协议未覆盖进行绕过[同样会被某狗拦截]

### **原理：**

HTTP头里的Content-Type一般有application/x-www-form-urlencoded，multipart/form-data，text/plain三种，其中multipart/form-data表示数据被编码为一条消息，页上的每个控件对应消息中的一个部分。所以，当waf没有规则匹配该协议传输的数据时可被绕过。

1.将头部Content-Type改为multipart/form-data; boundary=69  然后设置分割符内的Content-Disposition的name为要传参数的名称。数据部分则放在分割结束符上一行。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190105/1546701023_5c30c8df53897.png!small)图十

由于是正常数据提交，所以从图十可知数据是能被apache容器正确解析的，尝试1 and 1=1也会被某狗waf拦截，但如果其他waf没有规则拦截这种方式提交的数据包，那么同样能绕过。

2.一般绕waf往往需要多种方式结合使用，如图十的示例中，只需将数据部分1 and 1=1用一个小数点"."当作连接符即1.and 1=1就可以起到绕过作用。当然，这只是用小数点当连接符所起的作用而已。如图十一所示。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190106/1546706168_5c30dcf8e6717.png!small)图十一

## 四.分块编码+协议未覆盖组合绕过

1.在协议未覆盖的数据包中加入Transfer-Encoding: chunked ，然后将数据部分全部进行分块编码，如图十二所示(数据部分为1 and 1=1)。

![在HTTP协议层面绕过WAF](https://image.3001.net/images/20190106/1546710626_5c30ee620b7e9.png!small)图十二

**注意：**第2块，第3块，第7块，和第8块。

**第2块**中需要满足

```
长度值
空行
Content-Disposition: name="id"
空行
```

这种形式，且长度值要将两个空行的长度计算在内（空行长度为2）。

**第3块**，即数据开始部分需满足

```
长度值 
空行
数据
```

形式，且需将空行计算在内。

**第7块**即分割边界结束部分，需满足

```
长度值
空行
分割结束符
空行
```

形式，且计算空行长度在内。

**第8块**需满足

```
0  
空行
空行
```

形式。如果不同时满足这四块的形式要求，payload将不会生效。