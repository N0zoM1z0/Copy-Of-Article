# Java代码审计之jspxcms审计

发布于 2023-02-28 09:46:50

4K0

举报

文章被收录于专栏：红蓝对抗

#### **文章首发于：奇安信攻防社区**

**https://forum.butian.net/share/2068**

#### **环境搭建**

源码：https://www.ujcms.com/uploads/jspxcms-9.0.0-release-src.zip

下载之后解压

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/d8bbeea4c15a058ac62c684547cc41f5.png)

然后用idea导入

先创建[数据库](https://cloud.tencent.com/product/tencentdb-catalog?from_column=20065&from=20065)导入数据库文件

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/a7e01bd2ce7e4a2d8db8f035d4c890f8.png)

然后导入源码

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/2dfcb36948e037ec6ba0959b898fcffe.png)

然后配置好数据库连接

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/975a7c10639dc661bfd6ee01edcf79c6.png)

加载maven依赖

根据本地数据库版本情况 记得调整数据库依赖版本

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/d308c72dd98fba8771747691d89ed31b.png)

然后启动

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/5d7785dba31e113a14aa7ddb844c4fdf.png)

后台地址：http://127.0.0.1:8080/cmscp/index.do

因为刚开始代码也那么多就没有直接看代码  先熟悉熟悉有什么功能点

##### **XSS**

随便进入了一篇文章 然后评论

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/d857630855ef5ce88eb88adf5222eeab.png)

这里发现是没有xss的

但是后面来到“我的空间”

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/7dda0f254aa1978c7151534b562f9dd8.png)

点击评论的时候

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/d1bfee8faeb2df40f8457a077d2a7e16.png)

这里触发了xss

这里相当于是黑盒摸到的 单既然是审计  就要从代码来看   重新回到评论的地方  评论进行抓包 看看请求的路径是什么 先找到入口

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/a599424355385b14d9a3bbce2c1e47ee.png)

然后回到idea搜索comment_submit

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/5446188a7abffe48d9f78f2c27ec5a8a.png)

然后在这里打上断点

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/967ecdf8bb712ffb4dacaafed848a728.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/eb3203c5799dbcdd3850d86376da7e1a.png)

然后一步一步放

跟进submit

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/eec9e32195e8f270a27c874e987646ff.png)

主要是看传进来的text的走向

到这里text的值都没有变化

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/dddfe3e5d857ab685a8fa963ff2aa3c8.png)

然后来到最下面这里是save操作

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c4d8d9ca895b6953fc10ad5f6119e0ea.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/609a492c6853aa80df382e50604d6f4b.png)

这里也是直接进行存储 说明存入的时候是没有进行过滤的 那最开始没弹 肯定就是输入的问题了  因为摸到弹的情况

直接根据弹的情况来分析为什么回弹  先找到弹的页面的代码  因为路径有一个space 所以搜索space

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/da9614ac96677d30dcf98b0692028990.png)

打上断点 进行调试

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/96e1b51678b3460ec55378dc28731dfe.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/5bc61c6ef4997c19cff82f177744ffff.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/bb4ee7cfef3ba76b5d746bf76e22e2d5.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/b9879914618341050297f0e021474f7f.png)

这里最后返回了一个模板

发现这个是一个html 搜索这个html

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/a259b8d696cddc49586f8939827923eb.png)

通过pom.xml

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/5ade4d8b9b70234068eb033c3ccf1c07.png)

是freemarker模板

先搜搜这玩意是咋转义的

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/4dc0866fbc39d830cf75dab60749d800.png)

看到一个熟悉的

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/41417fa7c4e01b9abebb87b7bea60d28.png)

这个页面这里有填写这个 但是最终还是弹了  说明有漏网之鱼的页面

通过查找 发现一个没有写这个的页面

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c9c810c94d23c098044dc76273a3d55b.png)

搜索 看看哪里用到了这俩

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/49a02103c4e8afd7db5cca2432428ca1.png)

刚还这里的type=comment对应上之前访问时候的type

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/4ae1303e499d46f27d46cd5526d3af6a.png)

所以访问这个页面的时候能触发xss  payload没有进行任何过滤 这个页面也没有进行转义

##### **SSRF**

在审计ssrf的时候 一般都是搜索关键函数

代码语言：javascript

复制

```javascript
URL.openConnection()
URL.openStream()
HttpClient.execute()
HttpClient.executeMethod()
HttpURLConnection.connect()
HttpURLConnection.getInputStream()
HttpServletRequest()
BasicHttpEntityEnclosingRequest()
DefaultBHttpClientConnection()
BasicHttpRequest()
```

###### **第一处**

直接在idea里面搜索

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/76cc01f70efa1c557cb365bac977767b.png)

然后一个一个点进去分析

找到这里

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/1e7734ff4b285195deb806dba84d3d9d.png)

会进行连接  然后我们往上分析这个src的来源

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/adeea830c46293786f61207b518d0dff.png)

发现这里是从请求中获取source[]参数来的 说明这个是我们所能控制的

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c295adefe6c88e90e2afa550d74d263c.png)

在往上看 根据函数名能够大概猜出是编辑器图片相关的函数

看看哪里调用了这个函数

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/410c84913204b57ed59648bac3429936.png)

在uploadcontroller下  继续跟进ueditorCatchImage函数 看看那里调用

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c2d665a190a937a8f6d79900cca0002f.png)

发现在同一页的66行找到  也找到这个路由是在ueditor.do下

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/dcd11c8d9eb143efdaab04f491f34533.png)

最上面controller 是core

所以路径是/core/ueditor.do?action=catchimage

进行测试

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/1c68fd7827b7d6a03f3d5b99f7329bc5.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/d8b1f6810a794b4fe16ca422ceda11c7.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/62fcc30c3e2a5005cbc0a72aebfb4c50.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/6fe83501d2e525f012ee9b50d05ee58a.png)

但因为是在back下  所以是一个后台的洞

通过后面的代码可以看到 似乎是对一个图片的操作  直接就进行断点看看这里是到底执行了什么

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/fdbf1e0055a3f53115933046044cfe82.png)

测试：

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/f4686c9d4b3f19f3a64a1cb2aeda8996.png)

传入了一个jpg地址 但这个地址是不存在的 来到断点的地方

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/a6433efecdf1b25548e64fb380f65e65.png)

这里获取到source的值存入数组

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/70acc6578d0739277ded4d8593122f03.png)

这里获得后缀

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/3edff60270c6e6ef6b6f39c818b80dba.png)

这里判断请求的是不是图片 因为我们传入的是不存在也就不是 到这里也就直接结束了  在此输入一个存在的链接

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/1a3682b1b48905df94167a3fd66cf844.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/407b77f5756e9175785c1f792f96d283.png)

跟到这里是重新设置文件名

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/4ce1e4e2a6856cfa94e40444de2e6b04.png)

然后读取输入流

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/f806ff3249e55a7a9a0aba9216e52713.png)

然后跟进这里创建文件对象

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/11cda2eb6060105f377dae84e22c89a4.png)

然后这里直接保存文件  中间也没有任何过滤操作 就判断了是不是图片 然后就保存了文件  

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c2ab13697288fdf2495d995add5e94b9.png)

相当于这里就是一个进行 图片请求然后保存到本地的操作

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/b02bc4015e943b93b0f204986933c7d6.png)

那么这里是不是可以进行svg的xss呢  尝试一些

测试：

先创建一个svg xss

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/2b93619e94a7ec7ea0cd357234d667ae.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/7aea7c6769aab946944d52f7d9543692.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/44fd909dcc9f53716d0349d9a4b44bd9.png)

###### **第二处**

继续搜索ssrf的关键函数HttpClient.execute()

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/7071e51b679ed81467219124e1e22fbe.png)

然后查看哪里调用了这个函数

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/98ce27d5496c02c08df5a0217feddf70.png)

继续跟进

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/4e9fce24cab8b4439da831746dacdd03.png)

发现在这里进行的调用以及url的传入 而且这个url是 可控的

往上找到控制层

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/1e451aca8dd14ba522d1bb1a7041a194.png)

最后拼接 进行测试

http://192.168.1.2:8080/cmscp/ext/collect/fetch_url.do?url=http://127.0.0.1:8080

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/010ab5ac6f69d6598af07428227933a2.png)

直接能访问到服务

最后在页面找到位置

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/ac3b4ca4a5f96ea656687d2bf0281f50.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/444689979800a589b8976d7717b90283.png)

##### **RCE**

###### **第一处**

在逛后台的时候 发现上传的地方

可以任意上传东西 但是直接jsp这些传上去访问直接下载  无法利用  但是在上传zip的时候会自动解压 这就有意思了  于是乎 先抓包抓到路由 然后全局搜索

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/8b68824866f73651a6b745402383681d.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/23a038861ce1447afc4f5b8ce92222e2.png)

然后跟进来

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/24b309163c9095f03cb4fecf3a1ed0c1.png)

这里调用了这个zipupload 继续跟进

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c37ce6d7ca76316910721e6f09206c14.png)

经过简单代码跟进 发现 这一步才开始对参数进行利用

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/e8f34dc99d0082de497fb29ce1ee60e4.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/95a31284fe5dc917338a81aa35426dc1.png)

经过初步判断这个函数的作用是将zip里面的文件取出来 然后存入到文件夹里面  具体是不是  利用断点来进行详细的分析

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/0e9c1d57c4177d3281324757adfc2b45.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/1895bc369dcbf7da586f8b3fb914743a.png)

这里是将传进来的文件先写入了临时文件  然后将临时文件和一个路径传入到zip函数

继续跟进

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/ae0bd3c2846e0514cd7fcdb976bbacc2.png)

先判断传入的路径是不是文件夹 不是就直接报错

然后看下面 定义了一些相关变量

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c91cf94813c225e3f3462b8571d7c360.png)

这里创建了一个zipfile文件对象 目标正式传入的zip文件的临时存储文件

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/2a234a4cbfe9f6a72b5be3b79d923727.png)

这一步一个就是获取了文件的相关信息

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/054675d8190266c7469aae84b81de1b2.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/ccd1ee08cb2cc5ed74a3d710ec9b78b8.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/0095cebce4773b05423d767ee8907340.png)

然后走到这一步就直接将文件写入到文件里面  其中也没有任何的过滤  所以我们哪怕是文件里面放入jsp一句话也可以  

先试试

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/b76a2b27f1c1c40db86f0d2084c35172.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/5756fef8a7a6899b70d1988608c7fcce.png)

jsp文件访问不到 发现在uploads前面竟然多了一个/jsp 其他类型文件直接下载  但是文件又确实存在  那说明肯定是拦截器之类的

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/1eeff9bac9ae9b0eb81873a0e0201960.png)

经过搜索 找到这里  在这里打上断点

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c3fbff30a524c3048cb28a6e3d24948a.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/99f68234b0d41314a21969a7d8d8401f.png)

访问之后 确实是走到这里来了  所以直接jsp文件无法利用

那么这里  既然存入文件的过程没有什么过滤  直接利用跨目录的方式写一个war包到  但是这里前提得用tomcat搭建  因为我之前直接用的springboot的 重新切换到tomcat

- jspxcms安装包(部署到Tomcat)：https://www.ujcms.com/uploads/jspxcms-9.0.0-release.zip

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/4714de638e51045e530d398615c34e27.png)

也是有安装手册的

根据手册把配置文件改了   然后启动tomcat

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/eba8110d4c987faa480815c93fe8cde5.png)

然后来到上传的地方

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/f3af4f727996ef59bc3658833c9d6dff.png)

先准备恶意的zip包

把一句话打包成war包

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/b80c061f608bb782de568ce3e0b63ffe.png)

然后把war包压缩  这里得用到脚本来

代码语言：javascript

复制

```javascript
import zipfile

file = zipfile.ZipFile('shell.zip','w',zipfile.ZIP_DEFLATED)

with open('test.war','rb') as f:
    data = f.read()
    
file.writestr('../../../test.war',data)
file.close()
```

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/9502ad14b1e234a6d9148ab37faf78b0.png)

然后上传

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/9d33c9b52f1193645cde2f5b2f15b76c.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/e1290917357eaf916fc3f42963bbafd7.png)

冰蝎连接

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/c9ae05a748679cd833a38889d65af583.png)

###### **第二处**

在pom.xml中发现该系统用的shiro版本是1.3.2

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/d76ddac70865c0993b9186c8df333ec6.png)

符合shiro-721的条件  现在版本符合了  就需要寻找构造链了

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/9092e1dc164a2e9ab8a38f9c777f9f8a.png)

这是该系统的  和ysoserial的利用链的版本有些差异  但能不能用 先测试一下

要了一个payload

然后利用exp脚本 开始爆破

https://github.com/inspiringz/Shiro-721

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/747a44aa82bc65691d9b9674d7e7dce6.png)

爆破的时间有点久

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/398eacf4c303d34e24651e2b3dc10af4.png)

然后把cookie复制  我们来执行

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/f152790f0060eb3772d1de36763a183c.png)

![img](https://developer.qcloudimg.com/http-save/yehe-8600665/6551b51a83b149c383b32c65aafc3ca0.png)

反序列化的细节就不在这篇文章叙述了  请听下回分解

参考：https://www.freebuf.com/articles/others-articles/229928.html