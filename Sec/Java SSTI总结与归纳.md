## 服务器端模版注入SSTI分析与归纳

[abcdefg1234](https://tttang.com/user/abcdefg1234) 2022-01-27 10:19:00

[Java安全](https://tttang.com/sort/java/) [Web安全](https://tttang.com/sort/web-security/)

------

## [0x00 背景](https://tttang.com/archive/1412/#toc_0x00)

本文针对基于java的三种常见的模版引擎(FreeMarker、Velocity、Thymeleaf)所引起的服务端模版注入漏洞SSTI进行分析、整理和总结。所谓模版引擎，简单来讲就是利用模版语言的特定语法处理模版中的特定参数，帮助动态渲染数据到view层或生成电子邮件、配置文件、HTML网页等输出文本。

## [0x01 FreeMarker](https://tttang.com/archive/1412/#toc_0x01-freemarker)

模板文件存放在Web服务器上，当访问指定模版文件时， FreeMarker会动态转换模板，用最新的数据内容替换模板中 `${...}`的部分，然后返回渲染结果。

### [FreeMarker模版语言说明](https://tttang.com/archive/1412/#toc_freemarker)

文本：包括 HTML 标签与静态文本等静态内容，该部分内容会原样输出
插值：语法为 `${}`， 这部分的输出会被模板引擎计算的值来替换。
指令标签：`<# >`或者 `<@ >`。如果指令为系统内建指令，如assign时，用`<# >`。如果指令为用户指令，则用`<@ >`。利用中最常见的指令标签为`<#assign>`，该指令可创建变量。
注释：由 `<#--`和`-->`表示，注释部分的内容会 FreeMarker 忽略

### [FreeMarker模版注入分析](https://tttang.com/archive/1412/#toc_freemarker_1)

这里介绍FreeMarker的两个内置函数—— `new`和`api`。

#### [内置函数new](https://tttang.com/archive/1412/#toc_new)

可创建任意实现了`TemplateModel`接口的Java对象，同时还可以触发没有实现 `TemplateModel`接口的类的静态初始化块。
以下两种常见的FreeMarker模版注入poc就是利用new函数，创建了继承`TemplateModel`接口的`freemarker.template.utility.JythonRuntime`和`freemarker.template.utility.Execute`。

```
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc")</@value>
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc")}
```

**防御措施：**
从 **2.3.17**版本以后，官方版本提供了三种TemplateClassResolver对类进行解析：
1、UNRESTRICTED_RESOLVER：可以通过 `ClassUtil.forName(className)` 获取任何类。
2、SAFER_RESOLVER：不能加载 `freemarker.template.utility.JythonRuntime`、`freemarker.template.utility.Execute`、`freemarker.template.utility.ObjectConstructor`这三个类。
3、ALLOWS_NOTHING_RESOLVER：不能解析任何类。
可通过`freemarker.core.Configurable#setNewBuiltinClassResolver`方法设置`TemplateClassResolver`，从而限制通过`new()`函数对`freemarker.template.utility.JythonRuntime`、`freemarker.template.utility.Execute`、`freemarker.template.utility.ObjectConstructor`这三个类的解析。
[![11.png](https://storage.tttang.com/media/attachment/2022/01/18/c4819d36-d05d-474f-9d23-56683be7ba22.png)](https://storage.tttang.com/media/attachment/2022/01/18/c4819d36-d05d-474f-9d23-56683be7ba22.png)

#### [api内置函数](https://tttang.com/archive/1412/#toc_api)

value?api 提供对 value 的 API（通常是 Java API）的访问，例如 `value?api.someJavaMethod()` 或 `value?api.someBeanProperty`。可通过 `getClassLoader`获取类加载器从而加载恶意类，或者也可以通过 `getResource`来实现任意文件读取。
但是，当`api_builtin_enabled`为true时才可使用api函数，而该配置在**2.3.22版本**之后默认为false。

### [FreeMarker模版注入示例：](https://tttang.com/archive/1412/#toc_freemarker_2)

**测试版本——2.3.23**
[![12.png](https://storage.tttang.com/media/attachment/2022/01/18/a43e086e-3005-41fb-8b96-976797cf6310.png)](https://storage.tttang.com/media/attachment/2022/01/18/a43e086e-3005-41fb-8b96-976797cf6310.png)

**模版注入执行任意命令**
渲染内容：

```
<#assign value="freemarker.template.utility.Execute"?new()>${value("open /Applications/Calculator.app")}
```

[![13.png](https://storage.tttang.com/media/attachment/2022/01/18/f572ee9d-4c32-4eea-be45-3f6e8c0518ae.png)](https://storage.tttang.com/media/attachment/2022/01/18/f572ee9d-4c32-4eea-be45-3f6e8c0518ae.png)

若配置如下，执行命令失败。

```
cfg = new Configuration();
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
```

[![image.png](https://storage.tttang.com/media/attachment/2022/01/18/c8463067-edfd-41b7-893a-8123aff934b8.png)](https://storage.tttang.com/media/attachment/2022/01/18/c8463067-edfd-41b7-893a-8123aff934b8.png)

### [总结](https://tttang.com/archive/1412/#toc_)

FreeMarker模版注入已有不错的安全防御措施，可通过配置来禁止解析常见的危险类，同时限制对api函数的使用。

## [0x02 Velocity](https://tttang.com/archive/1412/#toc_0x02-velocity)

近年来，不少中间件服务器，如`Solr`、协同办公软件，如`confluence`、 `Jria`等被爆存在velocity模版注入漏洞（CVE-2019-17558、CVE-2019-3394、CVE-2021-43947等）。Velocity较FreeMarker而言更加常见。

### [基本语法](https://tttang.com/archive/1412/#toc__1)

`#` 关键字
Velocity关键字都是使用#开头的，如#set、#if、#else、#end、#foreach等
`$`变量
Velocity变量都是使用\$开头的，如：`$name`、`$msg`
`{}`变量
Velocity对于需要明确表示的Velocity变量，可以使用{}将变量包含起来。
`！`变量
如果某个Velocity变量不存在，那么页面中就会显示`$xxx`的形式，为了避免这种形式，可以在变量名称前加上！。如页面中含有`$msg`，如果msg有值，将显示msg的值；如果不存在就会显示`$msg`。这是我们不希望看到的，为了把不存在的变量显示为空白，可以使用`$!msg`。

### [Velocity模版注入示例](https://tttang.com/archive/1412/#toc_velocity)

[![111.png](https://storage.tttang.com/media/attachment/2022/01/18/b6965cf9-e32a-420f-8f3e-4fda7dad302d.png)](https://storage.tttang.com/media/attachment/2022/01/18/b6965cf9-e32a-420f-8f3e-4fda7dad302d.png)

Velocity 模版注入执行任意命令
[![222.png](https://storage.tttang.com/media/attachment/2022/01/18/b168322c-0c4b-46c8-8c9a-c74f7780069f.png)](https://storage.tttang.com/media/attachment/2022/01/18/b168322c-0c4b-46c8-8c9a-c74f7780069f.png)

有多种Velocity模版渲染进行命令执行的方式，可根据velocity模版的语法对poc进行变形利用，这里不进行详细阐述。

## [0x03 Thymeleaf](https://tttang.com/archive/1412/#toc_0x03-thymeleaf)

Thymeleaf是一款Spring官方支持的一款服务端模板引擎，一般用于Spring项目中渲染数据到View层。默认前缀：`/templates/`，默认后缀：`.html`。

### [Thymeleaf模版渲染示例](https://tttang.com/archive/1412/#toc_thymeleaf)

Controller代码：
[![121.png](https://storage.tttang.com/media/attachment/2022/01/18/e0a5b0f0-50d8-4a70-ba25-aded71bd4270.png)](https://storage.tttang.com/media/attachment/2022/01/18/e0a5b0f0-50d8-4a70-ba25-aded71bd4270.png)

根据`return "hello"`渲染 resources/templates/下的hello.html文件到view层。将参数name作为要渲染的内容放入Model中。
hello.html内容：
[![b82810d5-83ac-49bb-8a7c-1f95e04a31fe.png](https://storage.tttang.com/media/attachment/2022/01/18/3cff01dd-a032-40d3-9834-88686474f490.png)](https://storage.tttang.com/media/attachment/2022/01/18/3cff01dd-a032-40d3-9834-88686474f490.png)

渲染结果：
[![3.png](https://storage.tttang.com/media/attachment/2022/01/18/1b5ae938-1f1f-4bea-aee9-f031ada5e8f5.png)](https://storage.tttang.com/media/attachment/2022/01/18/1b5ae938-1f1f-4bea-aee9-f031ada5e8f5.png)

模版文件中使用`th:fragment、th:text`属性包含的内容才可以被`thymeleaf`进行渲染处理。渲染过程中在`${xx}`中的内容可执行SPEL表达式。

### [Thymeleaf模版注入漏洞原理和场景](https://tttang.com/archive/1412/#toc_thymeleaf_1)

Thymeleaf模版注入漏洞分两种场景，按照经Servlet处理后得到的`viewTemplateName`包含"**::**"和不包含"**::**"两种情况。
[![4.png](https://storage.tttang.com/media/attachment/2022/01/18/cb2c7faf-b97d-49ee-b606-9a06f55c7bfd.png)](https://storage.tttang.com/media/attachment/2022/01/18/cb2c7faf-b97d-49ee-b606-9a06f55c7bfd.png)
**1. 当不包含"::"时**
直接处理`viewTemplateName`对应的模版文件。如果模版文件中包含`th:text`等形式的属性且内容可控，即可通过向`th：text`属性值中注入SPEL表达式，经渲染后可执行该表达式。如下图所示：
[![image.png](https://storage.tttang.com/media/attachment/2022/01/18/63ecc12a-f571-4db7-99fc-dbc77c13ed47.png)](https://storage.tttang.com/media/attachment/2022/01/18/63ecc12a-f571-4db7-99fc-dbc77c13ed47.png)

**2. 当包含“::”时**
触发绝大多数Thymeleaf模版注入漏洞的场景是这种情况。

如果符合`__(.*?)__`正则匹配，则取出`(.*?)`的数据当作表达式解析执行。

[![10.png](https://storage.tttang.com/media/attachment/2022/01/18/c7796875-c702-4e83-9ce6-b81647df74f6.png)](https://storage.tttang.com/media/attachment/2022/01/18/c7796875-c702-4e83-9ce6-b81647df74f6.png)

由此可见，获取的`viewTemplateName`值是触发漏洞的关键。如果`viewTemplateName`可控，则可设计`viewTemplateName`值使之成功被渲染从而执行SPEL表达式。

#### [下面介绍2种用户可控viewTemplateName的场景：](https://tttang.com/archive/1412/#toc_2viewtemplatename)

#### [1、return 语句中包含用户可控数据](https://tttang.com/archive/1412/#toc_1return)

比如 return语句中包含**请求参数**或者**路径变量**
[![5.png](https://storage.tttang.com/media/attachment/2022/01/18/f2808f12-ef2e-476b-898c-5f326298c2c4.png)](https://storage.tttang.com/media/attachment/2022/01/18/f2808f12-ef2e-476b-898c-5f326298c2c4.png)

#### [2、没有return语句且路由可控](https://tttang.com/archive/1412/#toc_2return)

形如：
[![6.png](https://storage.tttang.com/media/attachment/2022/01/18/1441fc72-23d0-4225-8264-82cda34761f9.png)](https://storage.tttang.com/media/attachment/2022/01/18/1441fc72-23d0-4225-8264-82cda34761f9.png)
没有return语句的情况下，会通过`org.springframework.web.servlet.view.DefaultRequestToViewNameTranslator#getViewName`方法从请求路径中获取`ViewName`。处理逻辑如下：

总结该逻辑，取路由中第一个`/`和最后一个`.`之间的部分，因此在路由可控的情况下，设计路由形如：
`::__spel__.xx`即可实现模版注入从而执行任意表达式。
[![7.png](https://storage.tttang.com/media/attachment/2022/01/18/62d1b299-07f6-4b93-8d37-c0e40ea473e5.png)](https://storage.tttang.com/media/attachment/2022/01/18/62d1b299-07f6-4b93-8d37-c0e40ea473e5.png)

### [防御措施](https://tttang.com/archive/1412/#toc__2)

1、配置`@ResponseBody`或者`@RestController`
经以上注解后不会进行View解析而是直接返回。
2、在方法参数中加上 `HttpServletResponse`参数
此时spring会认为已经处理了response响应而不再进行视图解析。
3、在返回值前面加上 "`redirect:`"——经`RedirectView`处理。

## [0x04 总结](https://tttang.com/archive/1412/#toc_0x04)

本文抛砖引玉，对Java常见的三种服务端模版引擎的渲染原理和模版注入场景进行简单说明和总结。其中每种引擎在渲染过程中，如何绕过安全沙箱，如何进行表达式的各种变形从而实现更多利用等仍然是很值得研究和探讨的问题。