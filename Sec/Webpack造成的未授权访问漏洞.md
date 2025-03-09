是一个比较少见的点，积累下姿势。

---

**0x01 前言**

Webpack是一个模块打包工具，主要用于将前端资源如JavaScript、CSS、图片等打包成静态文件，方便在浏览器中使用。

开发者在开发时启用了Webpack的devServer，并且配置不当，导致开发环境中的源码或其他敏感信息被暴露在公网上从而就造成了我们耳熟能详的未授权访问漏洞。



**0x02 信息收集/资产测绘**

首先通过扫子域和目录，发现了一个后台，通过wappalyzer发现是webpack打包的。

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXfvpy3MLjptsibmXoWickd7smBR14aFoxfHk4IQvrwNqKytm6Nd2W9qTJw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里为了保险起见，我看了下有没有暴露在外的.js.map文件，不难发现有很多。

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xDm1loruQWy5RCLpAGfOU2MwFiaicrwmD7crtKiakTDyKo0X91oWY8mamCmuBq2o7E5dJm7R4Dm1z3RA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

**0x03 渗透测试/漏洞挖掘**

我们打开这个.js.map文件看一下，然后下载下来，

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXf12nNEGw86ES45icdEUBRUdVHTSNic2EzR7djdibpyuUrTwiaiacibld1py0A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)接着我们把它的源码通过reverse-sourcemap反编译出来，

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXfgdALJj1aOicGg4lc8bwicGNKIO9X3Diccd7ttchUnWT71McfJYRuzCLiaQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXf5IiaibWW0ZkicVBf6nA6JT4EsMGywHM07szxGuP9LlUfXBLGqSR51hFLg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

我们使用IDEA或者VScode打开这个工程文件，这里也成功拿到了它的Vue源码，接下里我们就可以在这里进行审计一些api和敏感信息，或者直接跳转至后台的url。

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXfpOfmUc7PLibnVgE9ffb19TBrpibDCMH5MpvLjqZW6wAye6l3icQKqFmCA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

到这步我们直接提交漏洞也是可以的，因为毕竟是src嘛，点到为止。

在这里说一下如果直接交上去可能是个低危，但是如果审计到了敏感信息会给个中危欧~

**0x04 总结**

这个洞总得来说还是很简单的，大佬勿喷，常见于那种前后端分离的，开发人员在用webpack打包的时候配置不当，从而导致了该漏洞。

**在这里说一下测webpack泄露的方法有些？**

**方法一：**

Fn+12看源代码中是否存在webpack://

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXfoiafmrGo6ygJIPatpicibXicDTjosV2wSaicf75ibxZcM1pExCzRGUZT40BA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

**方法二：**

如果没有可以看一下没有webpack://可以通过一些关键字.js.map

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xDm1loruQWy5RCLpAGfOU2MwFiaicrwmD7crtKiakTDyKo0X91oWY8mamCmuBq2o7E5dJm7R4Dm1z3RA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXf12nNEGw86ES45icdEUBRUdVHTSNic2EzR7djdibpyuUrTwiaiacibld1py0A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

**方法三：**

通过wappalyzer工具即可

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xANQXjo1oLrmjn8pcxedyXfvpy3MLjptsibmXoWickd7smBR14aFoxfHk4IQvrwNqKytm6Nd2W9qTJw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)