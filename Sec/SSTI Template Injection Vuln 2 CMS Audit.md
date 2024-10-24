FROM 

```
https://www.cnblogs.com/bmjoker/p/13653563.html
```



---

以下cms的源码地址：https://github.com/bmjoker/Code-audit/

# 苹果CMS模板注入导致代码执行

先给出漏洞payload：

```
http://127.0.0.1/maccms_php_v8.x/index.php?m=vod-search&wd={if-x:phpinfo()}{endif-x}
```

通过搜索代码执行常用的字段（eval，assert...），定位到此处

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913201438636-509741868.png)

查看 maccms_php_v8.x\inc\common\template.php 文件，判断变量是否可控：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913201843952-1569066858.png)

可以看到如果想构造代码执行，需要控制变量 $strif ，通读上下文发现一条数据链：

最原本的传进来的数据是 $this->H ，经过 preg_match_all() 函数进行正则匹配，把匹配到的结果赋值给 $iar 这个二维数组，进入for循环遍历数组，将 $iar[2][$m] 所指的元素传入 asp2phpif() 方法进行安全过滤，最后的返回值就是 $strif 。 

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913210755159-1283977350.png)

这里看到 asp2phpif() 方法仅是对一些字符的替换。

先来追踪一下 ifex() 函数在哪里被调用：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913203629304-1233644285.png)

最后定位到了 maccms_php_v8.x\index.php 文件，发现了调用的地方 $tpl->ifex()，那么 $this->H 参数从哪里传进来呢？

最上面看到了这样一段代码：$m = be('get','m')，跟进 be() 这个方法：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913204321773-132304730.png)

再结合网站的请求：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913204517335-2132811594.png)

大概了解了网站接收参数的方法。 $m = be('get'，'m')：就是通过get请求获取m的参数。然后获取到的参数被 explode() 方法以 - 分割成数组传递给 $par，取数组的第一个元素赋值给$ac，判断 $ac 所指的元素是否在 $acs 的数组中，如果存在的话就使用 include 包含 /inc/module/ 目录下以 $ac 所指元素命名的php文件。

根据payload，进入vod.php文件，这里给出关键代码：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913205601355-790699209.png)

当我们调用 search 方法时，就会进入此分支，通过 be("all"，"wd") 获取用户传进来的wd的参数，传入 chkSql 方法，然后赋值给 $tpl->P["wd"]

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913210720583-1219766118.png)

仅是使用 htmlEncode() 方法对一些字符判空，转义。

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913205641857-1636411935.png)

$tpl->H 就是传入ifex() 方法中的 $this->H 参数，因为 $tpl = new AppTpl()。上图代码中 $tpl->H 加载文件 vod_search.html 然后展示给前端。

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913211606615-1017097915.png)

$colarr，$valarr两个参数数组，经过 str_replace() 方法，将 vod_seach.html 中的类似 {page:des} 的字段替换成 $tpl 所指向的字段，漏洞导致的关键是这个 $tpl->P["wd"] 是我们前端可控的参数。

执行完上面的赋值，回到index.php中下一步就调用 ifex() 方法

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913212441490-421531782.png)

$tpl->H 就是替换过后的 vod_search.html 文件

这样的话再倒过来看最初的 template.php 文件，是不是就清楚多了

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913212718322-301444794.png)

通过for循环一次一次的匹配到类似 {if-A:"{page:typepid}"="0"} 的字段，赋值给变量 $strif，传入eval方法导致代码执行漏洞 

下面就是如何构造合适的payload绕过正则表达式：{if-([\s\S]*?):([\s\S]+?)}([\s\S]*?){endif-\1}

 类似这样即可：

```
{if-dddd:phpinfo()}{endif-dddd}
```

真正代码调试过的人，可能有的人会有疑问，因为使用上面payload的话 if (strpos(",".$strThen,$labelRule2)>0)，if (strpos(",".$strThen,$labelRule3)>0) 两个循环都无法进入，所以真正的漏洞出发点在 else:

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913213629202-1396657382.png)

漏洞演示效果：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200913213716425-1166937431.png)

静态插桩打印 $iar 的值：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914155914332-1296461081.png)

打印 $strif 的值：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914160153093-1314969641.png)

参照上面打印 $iar 的值，第三个 phpinfo() 进入else分支的eval函数中，导致代码执行。

# OFCMS模板注入导致任意命令执行

ofcms是由JFinal开发的内容管理系统。

从pom.xml可以看到引入freemarker-2.3.21依赖

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914162617843-1543539601.png)

JFinal允许多模板共存，如果想要使用freemarker模板，需要在configConstant配置

```
me.setViewType(ViewType.FREE_MARKER);
```

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914163134616-1639494349.png)

然后再使用 JFinal.me() 调用模板，使用 put 用来替换原来输出response html代码输出到浏览器

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914164504355-745472682.png)

到这里我们是不是可以理解为网站的html文件由FreeMarker模板进行渲染。

ofcms后台模板文件

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914165030596-1526222511.png)

任意选择一个html文件，再文件中插入我们的payload：

```
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```

保存，在前台访问404.html界面

 ![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914165555377-191770410.png)

FreeMarker解析了404.html文件中我们插入的payload，导致命令执行

# 74CMS模板注入导致Getshell

由于74CMS是基于Thinkphp3的语法魔改而成。建议先去大概看一下Thinkphp3的开发手册：http://document.thinkphp.cn/manual_3_2.html#

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914200411870-771036110.png)

先来看一下漏洞代码：ThinkPHP\Library\Think\View.class.php

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914202109379-1440722894.png)

在第122行，include $templateFile 典型的文件包含，如果 $templateFile 可控就可以getshell。

通读 fetch() 函数代码，发现如果想要文件包含，传进来的参数 $content 必须为空，才能进入if循环与下面的三元表达式。把前端获取的 $templateFile 传进 parseTemplate() 方法：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914212503410-1376173293.png)

啊...这？传进来的参数 $template 经过 is_file() 仅仅是做了文件是否存在以及是否为正常的文件，就直接把 $template return ...

当使用PHP原生模板时会进入下面的if循环，紧接着就 include $templateFile 。

什么是PHP原生模板？

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200914235920704-425923996.png)

由开发者手册可知，如果要使用PHP代码时尽量采用php标签，也就是 <php>...</php> 这种形式

大概知道这些，我们就可以通过上传内容为PHP原生模板的文件，再使用 include 包含。

继续回溯代码，寻找哪里调用 fetch() 这个函数，包括参数从哪里传过来

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915000333339-203932168.png)

同文件下的 display() 方法里调用了fetch() 方法，看过模板手册的都知道，渲染模板输出最常用的是使用display方法，继续查找 display() 在哪里被调用

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915000729563-1795929100.png)

可以看到在 Controller.class.php 中有调用

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915000928522-1799869868.png)

直接在 MController.class.php 文件中就可以看到 display() 函数的调用

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915001129269-1911958835.png)

熟悉Tp框架的应该知道 I 方法时用来接收参数，而第20行 I('get.type'...) 说明 $type 可以通过get方式从前端获取

可见，这里将 $type 参数传入 display() 函数，display() 函数是 ThinkPHP 中展示模板的函数。然后又将参数传入 View 类的 display() 函数，最后调用 fetch() 函数，导致文件包含漏洞

使用自带的 favicon.ico 做下试验，看是否能成功包含：

```
http://127.0.0.1/74cms_v4.1.5/upload/index.php?m=&c=M&a=index&page_seo=1&type=../favicon.ico
```

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915002013832-985166447.png)

成功包含。

如果想要包含我们构造的恶意文件，需要满足两个条件：

　　1. 可以将恶意文件上传到服务器

　　2. 有文件的绝对路径

注册一个账户，登录后台寻找文件上传的地方：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915002313033-1831396971.png)

个人用户创建简历后支持上传 docx 格式的简历。上传一个内容为PHP原生模板的 docx 文件，将其作为模板。数据包如下：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915002532333-1040057043.png)

上传文件的绝对路径为：/74cms_v4.1.5/upload/data/upload/word_resume/2009/14/5f5f8bdb56593.docx

再将这个文件名作为type的值，成功执行代码：

```
http://127.0.0.1/74cms_v4.1.5/upload/index.php?m=&c=M&a=index&type=../data/upload/word_resume/2009/14/5f5f8bdb56593.docx
```

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200915002708449-603629587.png)

# PbootCms-2.0.7模板注入导致Getshell

首先通过搜索关键字定位到导致漏洞的代码：core\view\View.php　　——>　　parser()

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916230740543-8922021.png)

根据payload，参数大概调用过程如上图

漏洞的关键点是 include $tpl_c_file，文件包含模板文件导致getshell。

parser() 方法接受传过来的模板文件 $file，经过 preg_replace() 方法来过滤掉相对路径（例如：../，..\），这里使用了不安全的替换，因为 preg_replace() 匹配到不安全的字符不是直接exit，而是选择替换成空，利用这个可以尝试构造绕过，像下图这样：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916010031423-1033718162.png)

然后将替换过后的 $file 传入if 循环，第一个if判断 $file 是否是以 / 开头，第二个elseif判断 $file 是否包含 @ ，如果都不满足进入else拼接，$tpl_file = 模板路径 + / + $file。

$tpl_file 是模板文件，$tpl_c_file 是要编译的文件。

继续看代码发现在121行又做了一次拼接，$tpl_c_file = 模板路径 + / + md5($tpl_file) + .php。紧接这是一个if判断，判断文件是否存在，判断 $tpl_c_file 文件的修改时间是否小于 $tpl_file，判断读取配置文件是否成功，很尴尬，全都是false，直接跳过if循环，到达关键地方，直接 include 包含我们构造的文件，导致漏洞产生。

这里可能有的人会有疑问，因为在到达 include 的时候，$tpl_c_file是 模板路径 + / + md5($tpl_file) + .php 这种形式，我们构造的文件路径早已面目全非。这个地方需要注意这个漏洞的根本原因是PbootCMS2.07内核处理缺陷导致的一个前台任意文件包含漏洞，他的内核函数在生成编译文件的时候造成任意文件读取。

parser() 方法已经分析完毕，现在需要寻找调用了parser函数的地方，且参数可控

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916232531048-824123490.png)

进入 Controller.php 文件

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916232639174-1984079165.png)

这里看到显示模板，解析模板都有调用到 parser 方法，继续跟踪判断哪里调用

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916232925499-2115808857.png)

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916232944006-2012144543.png)

显示模板 display() 方法发现没有参数可控，但是解析模板 parser() 方法，发现有变量传入

先来看 SearchController.php 文件

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916233234362-505275805.png)

index() 方法中，接收前端传递过来的参数，进入正则匹配，这正则匹配任意的字符，还包括-，.，/，最后直接传入 parser() 方法中，直接构造利用读取robots.txt：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916233958880-61493019.png)

同样构造利用的还有 TagController.php 文件

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916234118281-1535142100.png)

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916234149270-808548143.png)

包含写入shell的txt文件：

![img](https://img2020.cnblogs.com/blog/1344396/202009/1344396-20200916234947430-1034938571.png)