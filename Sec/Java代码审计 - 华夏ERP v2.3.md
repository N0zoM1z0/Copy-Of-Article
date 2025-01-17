# Java 代码审计之华夏 ERP CMS v2.3

项目地址: [Release 华夏ERP_v2.3](https://github.com/jishenghua/jshERP/releases/tag/2.3)

## 0x01 前言

这个 CMS 被用于了蓝帽杯的比赛当中，是让我们进行修洞了，当时因为自己环境的一些问题没有把这道题目修好，感觉到非常遗憾。

趁着自己最近学了一会儿的代码审计，想尝试自己审计一遍。

## 0x02 环境

简单搭即可，导 sql，修改端口为 8081，方便测试。

## 0x03 代码审计

### 1. 审计准备

我个人的习惯是先看一看 pom.xml，再看一些 Filter

#### pom.xml

![fastjson1255.png](https://image.3001.net/images/20221018/1666070178_634e36a26e197808fcd0f.png!small)

这里有个 fastjson 1.2.55 的洞，或许可以进行反序列化的攻击，不确定，cy 一下。

还有一个 log4j2 的漏洞，我们后续会提到

其他组件基本就没啥了，我们去看 Filter

#### Filter 审计

![NotFilter.png](https://image.3001.net/images/20221018/1666070179_634e36a35db2881d40c56.png!small)

使用`@WebInitParam`注解配置多个 name，对`.css#.js#.jpg#.png#.gif#.ico`，`/user/login#/user/registerUser#/v2/api-docs`资源请求的时候不会进行拦截。

再来看具体的 Filter 做了什么工作，关于 Filter：[Java内存马系列-01-基础内容学习)](https://drun1baby.github.io/2022/08/19/Java内存马系列-01-基础内容学习/)

- 我们需要去到`doFilter()`方法中去看

![doFilter.png](https://image.3001.net/images/20221018/1666070180_634e36a46ea268d61573c.png!small)

这个`doFilter()`方法，先是做了一个很基础的拦截器，代码如下

```
HttpServletRequest servletRequest = (HttpServletRequest) request;  
HttpServletResponse servletResponse = (HttpServletResponse) response;  
String requestUrl = servletRequest.getRequestURI();  
//具体，比如：处理若用户未登录，则跳转到登录页  
Object userInfo = servletRequest.getSession().getAttribute("user");
```

这里有几种情况是不阻止的：register.html，login.html，以及 doc.html；因为如果这几个网站被 ban，业务都跑不了了。

继续往下看，其中定义了一个`verify()`方法，这是拿来自己添加不被拦截的网页的，可能是当时开发者想要测试功能性，所以就多了这么一个`verify()`方法。

![ignoredList.png](https://image.3001.net/images/20221018/1666070181_634e36a55eebddfe4bce2.png!small)

这里也和上面的`@WebInitParam`注解对应起来了，当我们不处于登录的状态下，也可以直接访问`.css，.js`这些文件，测试如图。

![ignoredSuccessTest.png](https://image.3001.net/images/20221018/1666070182_634e36a689fbb3a6c5b3a.png!small)

再往下看，是关于`allowUrls`的一个判断，简单来说`allowUrls`就是加白，这也和我们上面讲的`@WebInitParam`注解对上了，如图

![allowUrls.png](https://image.3001.net/images/20221018/1666070183_634e36a75683f17cf4121.png!small)

- 现在我们把`Filter`全部都解读完了，做个小结，并且思考

#### 关于审计完 Filter 后的思考

**小总结**

1、加了白，对应的资源加白在`ignoredUrl`中，以`#`分割，看似没什么问题；还有对应的 Path 加白，加了`/user/login`，`/user/registerUser`以及`/v2/api-docs`

2、没有进行 XSS 的转义过滤和 SQL 注入的恶意字符过滤，一般来说，以 RuoYi 的项目为例：都会存在一个专门过滤的 Filter，但是这里面没有，或许会埋下部分伏笔。

**思索**

对于加白的思索：是否会存在潜在的未授权访问？对于资源加白 ————`ignoredList`的判断只是进行了正则的判断，这并不符合开发的安全性，正确的写法应该使用`endsWith()`来判断 URL 是否以`.css`；`.js`等资源后缀结尾

对于 URL 加白的思考：使用`startsWith()`方法来判断 URL 是否是白名单开头的时候，可以使用目录穿越来骗过判断，导致可以绕过认证请求。这种方式比较神奇，后续会打断点调试看看。

#### 审计准备小结

先看 pom.xml，再看 Filter。

这里总结出来，单看 Filter 就看出来几个隐藏的漏洞了：比如可能存在的 SQL 注入，比如可能存在的 XSS；还有一些越权的漏洞

### 2. SQL 注入

- 关于 SQL 注入在 Java 当中的代码审计可以看我这篇文章：[Java OWASP 中的 SQL 注入代码审计](https://drun1baby.github.io/2022/09/14/Java-OWASP-中的-SQL-注入代码审计/)

根据 pom.xml 我们可以知道这是个 mybatis，所以对于 mybatis 的 SQL 注入，我们可以直接在`mapper_xml`文件夹内进行全局搜索`$`以及`like`，`in`以及`order by`。

当然，前提是有问题的 SQL 语句当中，输入是可控的。

我们在`mapper_xml`文件夹下全局搜索`like`关键字

![SQLike.png](https://image.3001.net/images/20221018/1666070184_634e36a83da7604f72163.png!small)

出师及其顺利！（后面发现并不是）

#### 失败的 SQL 注入

我们先点进去看看，大致分析如图

![AccoutMapperEx.png](https://image.3001.net/images/20221018/1666070185_634e36a90c17e5e9cc6df.png!small)

实际开发当中，对应`AccountMapperEx.xml`的一般都是定义在`AccountMapperEx`接口中（如果封装的好的话

![AccountMapperEx.png](https://image.3001.net/images/20221018/1666070185_634e36a9f21a2e0182474.png!small)

对应的 controller 文件应该是`AccoutController`。对应的 service 文件是`AccoutService`，这里一步步逆推，根据反序列化的链子的思维似乎是要出点问题。

问题在于，最后总是会指向一个`ResourceController`，有师傅的文章说可以一直找，我个人认为这种是错误的。

根据 MVC 架构思维，我们先看 Service 层，定位如图

![selectByConditionAccount.png](https://image.3001.net/images/20221018/1666070186_634e36aae03374cb8f19e.png!small)

但是到这个地方就断掉了，说明其实这里，name 并不是可控的，算是一个小失败。

> 总结一下这次的 SQL 注入失败原因，输入并非可控。

#### 成功的 SQL 注入

这里我们就直接去找`UserMapperEx.xml`，因为这个业务点我认为是非常非常直接的，显山露水的，找可控点更为容易。在`UserMapperEx.xml`里面搜索`like`这一关键字

![UserMapper.png](https://image.3001.net/images/20221018/1666070187_634e36abc9299d6e8da00.png!small)

对应的，我们去到接口：`UserMapperEx.java`

![UserMapperEx.png](https://image.3001.net/images/20221018/1666070188_634e36ac9e7a429e61140.png!small)

对应的 Service 接口与 Controller 接口如图

![countsByUser.png](https://image.3001.net/images/20221018/1666070189_634e36ad6d8385e79733b.png!small)

![controller.png](https://image.3001.net/images/20221018/1666070190_634e36aeaf0822a194409.png!small)

那么试想一下运用到这个 SQL 语句的场景该是什么？很明显在`/addUser`这个情况下是可以触发的。

我这里访问了`/user/list`页面，抓包后看到了`search`后跟着一堆参数，这堆参数进行 URL 解码后是`userName`与`loginName`的值。

![nothing.png](https://image.3001.net/images/20221018/1666070191_634e36af9484e9bfc839f.png!small)

看到这里我立马明白了，其实`countsByUser()`这个有问题的 SQL 语句并不是说只有后端处理`/addUser`接口的时候才会用到，而是只要我以 userName 和 loginName 作为参数进行搜索就会用到。

我们的 payload 如下

```
{"userName":"","loginName":"' AND SLEEP(5)-- jsh"}
```

一个简单的盲注，成功！同时我们在控制台可以看到有如图的 SQL 语句

![logs.png](https://image.3001.net/images/20221018/1666070192_634e36b073b888be46157.png!small)

在 Burpsuite 中亦测试成功

![Sleep.png](https://image.3001.net/images/20221018/1666070193_634e36b11c55593c939b4.png!small)

- 相类似的 SQL 注入在这个项目里面还有很多很多，师傅们在学习的时候可以尝试自己挖掘并测试。

#### SQL 注入的修复

详见这篇文章 [Java OWASP 中的 SQL 注入代码审计](http://localhost:4000/2022/09/14/Java-OWASP-中的-SQL-注入代码审计)

如果对于应急处理，比如很多 AWD Plus 的情况下，建议是写一个 FIiter 来防御，代码如下

```
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;


/**
 @ author: Drunkbaby
 @ usages: 用于 SQL 注入的自定义防护
 需要加入相应的 Servlet 环境，因为我这里是纯代码，就不打环境了
 @ 过滤 url：在 WebFilter 当中添加 urlPatterns
 */

@Component
@WebFilter(urlPatterns = "/system/role/list", filterName = "sqlInjectFilter")
public class sqlFilter implements Filter {
    public void destroy() {
    }

    public void init(FilterConfig arg0) throws ServletException {
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        // 获得所有请求参数名
        Enumeration params = request.getParameterNames();
        String sql = "";
        while (params.hasMoreElements()) {
            // 得到参数名
            String name = params.nextElement().toString();
            // 得到参数对应值
            String[] value = request.getParameterValues(name);
            for (int i = 0; i < value.length; i++) {
                sql = sql + value[i];
            }
        }
        if (sqlValidate(sql)) {
            throw new IOException("您发送请求中的参数中含有非法字符");
        } else {
            chain.doFilter(request, response);
        }
    }

    /**
     * 参数校验
     * @param str
     */
    public static boolean sqlValidate(String str) {
        str = str.toLowerCase();//统一转为小写
        String badStr = "select|update|and|or|delete|insert|truncate|char|into|substr|ascii|declare|exec|count|master|into|drop|execute|table";
        String[] badStrs = badStr.split("\\|");
        for (int i = 0; i < badStrs.length; i++) {
            //循环检测，判断在请求参数当中是否包含SQL关键字
            if (str.indexOf(badStrs[i]) >= 0) {
                return true;
            }
        }
        return false;
    }
}
```

我们可以自定义过滤的恶意字符，比如`--+`；`'`这些非业务需要的字符。

### 3. 两个白名单的越权（权限校验绕过）

- 看完了 SQL 注入，看一下关于前文提到的白名单越权的

#### 正常业务 URL 加白

资源加白的问题在前面已经说过了，我们现在直接来复现一遍

当我们没有处于登录态的时候，发包/访问时得到的是一个 302 的重定向回显，如图

![Login302.png](https://image.3001.net/images/20221018/1666070194_634e36b20c04e5e170d1e.png!small)

前文说到，这几种请求是不会被拦截的：`/doc.html`，`/register.html`，`/login.html`

所以我们构造如下 payload

```
/login.html/../home.html
```

![ingoreBypass.png](https://image.3001.net/images/20221018/1666070194_634e36b2ef8d9aab893a9.png!small)

成功 Bypass

#### 资源加白

同上面是一样的，因为没有做严格的`endsWith()`的判断

payload 如下

```
/1.css/../home.html
```

![cssBypass.png](https://image.3001.net/images/20221018/1666070195_634e36b3dfcfc3281128d.png!small)

#### URL 加白

同样的攻击手段

```
/user/login/../../home.html
```

这个攻击不如前两种好用，它要求你知道文件的路径

![URLBypass.png](https://image.3001.net/images/20221018/1666070196_634e36b4ca49c9d89ff0c.png!small)

#### 漏洞修复

最简单的应急方法应该是过滤`../`，也就是寻常的目录遍历防御手段一直，这种防御可以直接加在 Filter 里面，代码如下

```
package PathTravelFilter;

import java.util.regex.Pattern;

/**
 @ author: Drunkbaby
 @ usages: 用于目录遍历的单个字符防御
 */

public class PathFilter {

    //private static Pattern FilePattern = Pattern.compile("[\\\\/:*?\"<>|]");

    private static Pattern FilePattern = Pattern.compile("[\\s\\.:?<>|]"); //过滤规则

    public static String filenameFilter(String str) {
        return str==null?null:FilePattern.matcher(str).replaceAll("");
    }

    public static void main(String[] args) {
        String str="home/..  <>|logs/../:edata?";
        //String filenameFilter = filenameFilter(str);
        String filenameFilter = fileNameValidate(str);
        System.out.println(filenameFilter);
    }

    private static String fileNameValidate(String str) {

        String strInjectListStr ="../|./|/..| |<|>|:|?";
        if(null!=strInjectListStr && !"".equals(strInjectListStr))
        {
            str = str.toLowerCase();
            String[] badStrs = strInjectListStr.split("\\|");
            for (int i = 0; i < badStrs.length; i++) {
                if (str.indexOf(badStrs[i]) >= 0) {
                    str= str.replace(badStrs[i], "");
                }
            }
        }
        return str;
    }
}
```

### 4. 存储型 XSS

在之前审计`Filter`的时候并未发现针对 XSS 进行了些许过滤

XSS 本质上是把我们输入的东西拼接到 HTML 语句里面去，这一块我们先随意选取一个界面

```
http://127.0.0.1:8081/index.html#/pages/financial/item_in.html
```

在备注当中插入即可，今年蓝帽杯决赛的时候也是出了这个题目，这道题目名叫《赌怪》，我个人对于这道题目的理解就是，这是一个洞很多的 CMS，最好就全修了，但是当时上 Filter 防御失败了。

![XSS.png](https://image.3001.net/images/20221018/1666070197_634e36b5aa85da0a5dace.png!small)

每一次访问的时候都会造成 XSS

![StoredXSS.png](https://image.3001.net/images/20221018/1666070198_634e36b67ddad80a848c6.png!small)

在很多界面都存在这个问题，比如说用户管理这里，添加用户，也会造成存储型 XSS

![DrunkbabyInfo.png](https://image.3001.net/images/20221018/1666070199_634e36b7470dec2c3201b.png!small)

![StoredXSSTwo.png](https://image.3001.net/images/20221018/1666070200_634e36b806e1a29a59e7c.png!small)

#### 漏洞修复

直接添加 Filter 的方式会比较直接

```
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.List;

/**
 @ author: Drunkbaby
 @ usages: 用于 XSS 的自定义防护
 */
public class XSSFilter implements Filter {

    FilterConfig filterConfig = null;
    private List urlExclusion = null;
    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

    public void destroy() {
        this.filterConfig = null;
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String servletPath = httpServletRequest.getServletPath();
        if (urlExclusion != null && urlExclusion.contains(servletPath)) {
            chain.doFilter(request, response);
        } else {
            chain.doFilter((ServletRequest) new XssHttpServletRequestWrapper((HttpServletRequest) request), response);
        }
    }

    public List getUrlExclusion() {
        return urlExclusion;
    }

    public void setUrlExclusion(List urlExclusion) {
        this.urlExclusion = urlExclusion;
    }
}

class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {
    public XssHttpServletRequestWrapper(HttpServletRequest servletRequest) {
        super(servletRequest);
    }

    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
        if (values == null) {
            return null;
        }

        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = cleanXSS(values[i]);
        }
        return encodedValues;
    }

    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
        if (value == null) {
            return null;
        }
        return cleanXSS(value);
    }

    public String getHeader(String name) {
        String value = super.getHeader(name);
        if (value == null)
            return null;
        return cleanXSS(value);
    }

    private String cleanXSS(String value) {
//You'll need to remove the spaces from the html entities below
        value = value.replaceAll("\\(", "& #40;").replaceAll("\\)", "& #41;");
        value = value.replaceAll("'", "& #39;");
        value = value.replaceAll("eval\\((.*)\\)", "");
        value = value.replaceAll("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']", "\"\"");
        value = value.replaceAll("script", "");
        return value;
    }
}
```

通过转义恶意字符的方式进行修复，但是我个人认为这里这么修不算是一种好的修法，算是俗修。

真正修法应该是写一个 Utils 的工具类，把一些输入进行处理，并且因为这里不存在反射型 XSS，还有一种修法，可以把这些要存入数据库的数据进行过滤。这个在实际开发里面用的比较多。

### 5. Fastjson 反序列化 RCE

因为在项目中`Fastjson`版本是 1.2.55，存在 RCE 的漏洞，这里反序列化的地方很多，我们要去找的地方一定是要输入可控的。

这里我思考了一下，应该直接去找关于`search`的，也就是和上面 SQL 注入的一样，全局搜索`parseObject`，找到了`StringUtil`这个工具类

![parseObject.png](https://image.3001.net/images/20221018/1666070200_634e36b8c66db66465880.png!small)

它的`getInfo()`方法中，是存在一个`parseObject()`反序列化的语句，我们接下来去找谁调用了`StringUtil.getInfo()`

![getInfoUsages.png](https://image.3001.net/images/20221018/1666070201_634e36b9c55719969ef80.png!small)

- 这一个`UserComponent.getUserList()`其实和我们之前在 SQL 注入漏洞里面看到的是一样的，所以对于攻击来说，我们依旧可以把它作为攻击的入口。

构造一个 URLDns 的请求，payload 如下

```
search={"@type":"java.net.Inet4Address","val":"xtuit14cnmcrndt2043mwlxoafg74w.oastify.com"}
```

发包如图

![fastjsonBag.png](https://image.3001.net/images/20221018/1666070202_634e36bab45af3e952a87.png!small)

收到了 DNS 请求

![FastjsonDNS.png](https://image.3001.net/images/20221018/1666070204_634e36bc935c63cbec678.png!small)

- 证明存在 Fastjson 漏洞，然后我们进一步构造 payload，进行弹 shell 实践。

这里对 jdk 版本是要低一些，并且要先开启`AutoTypeSupport`

![checkAutoType.png](https://image.3001.net/images/20221018/1666070205_634e36bd57c90f5480a2a.png!small)

师傅们可以现在本地进行测试。

先开启恶意`.class`和 Ldap

![OpenCalc.png](https://image.3001.net/images/20221018/1666070206_634e36be1d7666108d787.png!small)

弹计算器成功

![SuccessFastjson.png](https://image.3001.net/images/20221018/1666070207_634e36bf1fa9747eca88e.png!small)

#### 漏洞修复

- 我个人认为这里并不算漏洞，因为并未开启`checkAutoType`

### 6. 越权漏洞

#### 越权密码重置

对应这里，先去看它的接口

![updateUserController.png](https://image.3001.net/images/20221018/1666070208_634e36c02bc7d50502ce7.png!small)

发现这个业务逻辑的代码是写在 Service 层里面的，跟进一下 Service 层的代码

![ProblemReset.png](https://image.3001.net/images/20221018/1666070209_634e36c100fb37ceefc9c.png!small)

这里只是简单判断了`"admin".equals(loginName)`，从开发的角度上来说，我个人这里可能更偏向于使用 JWT，或者说加一个 Admin 的白名单，诸如此类的设计思维。

在判断完`"admin".equals(loginName)`之后，如果不是 admin，这里就直接进行`user.setPassword()`了，并未将 ID 与 loginName 一一对应。

漏洞操作如图，先进行密码重置

![OriId.png](https://image.3001.net/images/20221018/1666070210_634e36c203673062c04cf.png!small)

接着，修改 userId 为其他用户的，这里可以进行批量发包，会导致所有普通用户的密码全部被修改

![changePwdAttack.png](https://image.3001.net/images/20221018/1666070210_634e36c2eb680ce770cf1.png!small)

- 这里的这个漏洞，可以和之前我们说的未授权漏洞结合起来。

#### 越权删除用户

- 先去看`deleteUser`对应的接口

![deleteUser.png](https://image.3001.net/images/20221018/1666070211_634e36c3e05b2d04a310a.png!small)

同样，去看 Service 层的业务代码

![BatDeleteUser.png](https://image.3001.net/images/20221018/1666070212_634e36c4c9329d2e6e14f.png!small)

这里其实这么写是也有道理的，我们可以发现普通用户是没有管理用户这个界面的，所以对于代码来说，也是情有可原。

但是问题就出在`doc.html`中，这个接口文档在被未授权读取之后，能够看到所有的 URL，配合之前的未授权可以进行删库的操作，但是可利用性并不大。

我们先用 admin 的账户抓一个`deleteUser`的包

![deteleUserByID.png](https://image.3001.net/images/20221018/1666070213_634e36c5a4d26ad015187.png!small)

再用我们普通用户权限去抓包，替换 Session，替换 ID，成功删除 admin 的账户。这里的水平越权与垂直越权都是存在的。

![deleteAdmin.png](https://image.3001.net/images/20221018/1666070214_634e36c67e4865fb0b110.png!small)

再登录，就是用户不存在了

![FailedLogin.png](https://image.3001.net/images/20221018/1666070215_634e36c74c434934a9760.png!small)

#### 越权修改用户信息

对应的接口是`updateUser`

![updateUserController.png](https://image.3001.net/images/20221018/1666070216_634e36c84d18680c58306.png!small)

去到 Service 层，这里有一个`checkUserNameAndLoginName(ue);`的语句，跟进去看一下

![updateUserNoJudge.png](https://image.3001.net/images/20221018/1666070218_634e36ca02dfc6f89c1e9.png!small)

`checkUserNameAndLoginName()`做了一个什么业务呢，它进行`UserName`与`loignName`是否为空的判断

我们先看`loginName`是否为空的判断

![getUserListByloginName.png](https://image.3001.net/images/20221018/1666070218_634e36cad88bd1b6901c8.png!small)

再看`userName`

![getUserListByUserName.png](https://image.3001.net/images/20221018/1666070219_634e36cbc70528201b400.png!small)

> 乍一看代码好像没啥问题，这里最大的问题是没有把`loginName`或是`UserName`与 ID 进行一个匹配。

我之前在学开发的时候也被人这么说过，大致意思就是 "这种操作你怎么会不进行一个 ID 与 userName 的判断的啊？亏你还是学安全的"；

具体的复现就先不复现了，我们重点关注越权漏洞的修复

#### 漏洞修复

实现方式也很简单，在 Mapper 的 SQL 语句中加上`selectIdByUserName`就可以了，这样的话我们只需要进行如下判断

```
Long userId=userEx.getId();
String loginName=userEx.getLoginName();

if (userId.equals(getIdByLoginName(loginName))){  
    // 这里面判断匹配，进行业务代码实现  
} else {  
    return;  
}
```

### 7. 经测试，不存在 log4j2 漏洞

之前看其他师傅的文章说，看组件还是有 log4j2 的漏洞的，其实根本没有啊，对应的 maven 仓库，并不显示存在 log4j2 漏洞

![MVN.png](https://image.3001.net/images/20221018/1666070221_634e36cd60fd6f2ad7860.png!small)

## 0x04 关于蓝帽杯决赛 awd Plus 对于这个 CMS 变样考法的思考

- 当时因为我自己的一些原因没有修出来，赛后看其他队伍的 WP 是这么修的。

![ban.png](https://image.3001.net/images/20221018/1666070222_634e36ce0fa1342459032.png!small)

其实我是有点不太理解的，如果只是一个单纯的入口的话要开启 AutoType 才可以吧，不明白为什么这里算是漏洞点了。

在请教过 Y4tacker 师傅之后这里总算是明白了！

### 重要点

`AutoType`为 false 时 :先黑名单过滤，再白名单过滤，若白名单匹配上则直接加载该类，否则报错

`AutoType`为 true 时 :先白名单过滤，匹配成功即可加载该类，否则再黑名单过滤

- 所以`AutoType`一般都为 false，这样的防御更加严格。

1.2.55 的版本也是存在能够不开启`AutoType`的 PoC 的，而且也不少，所以这里也是存在漏洞的。具体的 PoC 可以参考这个仓库 https://github.com/safe6Sec/Fastjson

要用的 PoC 是 fastjson<=1.2.68 的攻击方法，正好这里也有`hikari`的库，所以这个题目应该是这么打的。

至于在比赛当中的修复，直接把这个入口类 ban 掉即可。有一些其他接口也是存在`parseObject()`的反序列化入口，但是输入并不可控，就没有必要管了。

## 0x05 小结

审计 Java 项目可以直接通过全局搜索进行白盒的代码审计，尤其是 SQL 注入，fastjson 反序列化这种漏洞，尤为明显。

刚入门 Java 不久，还很菜，文章中如有写的不好的地方还望请师傅们指出，感激不尽！

## 0x06 参考资料

https://www.cnblogs.com/bmjoker/p/14856437.html