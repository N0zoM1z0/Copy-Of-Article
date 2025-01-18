# Java代码审计(五)-JXC企业级进销存管理系统

**Funsiooo** 

2022-12-01 (Updated: 2022-12-02) 

 [代码审计](https://funsiooo.github.io/categories/代码审计/) 

 [Java代码审计](https://funsiooo.github.io/tags/Java代码审计/)

## 一、前言

JXC 企业级进销存管理系统，采用 SpringBoot+Shiro+MyBatis+EasyUI，项目采用 Maven 构建，数据库文件存放在 sql/jxc.sql。项目地址：https://github.com/wangjiangfei/JXC

## 二、环境搭建

1、利用 PHPstudy 中的 Mysql 作为数据库

![image-20221126134752778](https://funsiooo.github.io/images/Java/jxc/image-20221126134752778.png)

这里使用 navicat 进行数据库操作，比较直观一点，创建名为 jxc 的数据库

![image-20221126135324816](https://funsiooo.github.io/images/Java/jxc/image-20221126135324816.png)

导入源码中的 /sql/jxc.sql 文件

![image-20221126135554168](https://funsiooo.github.io/images/Java/jxc/image-20221126135554168.png)

![image-20221126151230703](https://funsiooo.github.io/images/Java/jxc/image-20221126151230703.png)

2、IDEA 导入源码，注意导入的是源码是文件夹里面的 jxc 目录，否则双层目录项目会运行不起来

![image-20221126162720625](https://funsiooo.github.io/images/Java/jxc/image-20221126162720625.png)

导入项目后 Maven 会自动加载依赖，然后配置数据库账号密码

![image-20221126163003323](https://funsiooo.github.io/images/Java/jxc/image-20221126163003323.png)

运行即可启动项目

![image-20221126163415477](https://funsiooo.github.io/images/Java/jxc/image-20221126163415477.png)

![image-20221126163612166](https://funsiooo.github.io/images/Java/jxc/image-20221126163612166.png)

访问 8080 端口登录后台，账号密码为：admin/admin123

![image-20221126163955805](https://funsiooo.github.io/images/Java/jxc/image-20221126163955805.png)

## 三、代码审计

### 1、pom.xml 框架审计

项目使用 Maven 添加依赖，审计 pom.xml 分析其项目框架，得知项目使用了如下框架

```
| 框架名称     | 版本号         |
| ----------- | ------------- |
| Spring-Boot | 2.1.0.RELEASE |
| Mybatis     | 1.3.2         |
| Mysql       | 5.1.40        |
| Shiro       | 1.4.0         |
```

![image-20221126203907217](https://funsiooo.github.io/images/Java/jxc/image-20221126203907217.png)

项目使用了 Shiro 1.4.0 版本，我们知道 Shiro 框架是存在多个漏洞的，我们通过 Google serach 其历史漏洞，通过查找得知部分 Shiro 历史漏洞如下:

| 版本                                                         | 漏洞                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------- |
| Shiro < 1.2.5                                                | CVE-2016-4437（Apache Shiro 反序列化漏洞）           |
| Shiro < 1.5.2                                                | CVE-2020-11989（Apache Shiro 权限绕过）              |
| Shiro < 1.5.3                                                | CVE-2020-1957 （Apache Shiro 权限绕过漏洞）          |
| Apache Shiro 1.2.5, 1.2.6, 1.3.0, 1.3.1, 1.3.2, 1.4.0-RC2, 1.4.0, 1.4.1 | CVE-2016-4437（Shiro-721 Apache Shiro 反序列化漏洞） |



### 2、代码审计

通过访问后台，我们发现这些功能点与平时实战遇到的项目大同小异，我们可以通过审计功能点代码进行挖掘漏洞

![image-20221126213111483](https://funsiooo.github.io/images/Java/jxc/image-20221126213111483.png)

审计初期，先初略通读一下代码，了解其代码结构及其功能点。通读过后，一般没开发经验的其实也是一脸懵，所以我们可以考虑定点审计，比如审计SQL注入，我们只需要搜索特定的关键字，然后再分析其代码是否存在漏洞比较快速。



------

#### Shiro 权限绕过（不存在）

我们知道 Shiro 框架本身是用来作身份认证和权限管理的一款框架，其通过拦截器功能来实现对用户访问权限的控制和拦截，Shiro 中常见的拦截器有 anon、authc 拦截器。

```
anon 为匿名拦截器，不需要登录就能访问，一般用于静态资源,或者移动端接口；
authc 为登录拦截器，需要登录认证才能访问的资源，需要在配置文件配置需要登录的 URL 路径；
```

authc 拦截器匹配规则如下：

```
| 通配符 | 说明                  |
| ------ | ------------------- |
| ？     | 匹配任意一个字符       |
| *      | 匹配任意字符，包括0个   |
| **     | 匹配任意层路径，包括0个 |
```

通过分析我们知道该 Shiro 版本可能存在权限绕过漏洞，那我们就转到 Shiro 配置文件审计其代码，文件名为 `ShiroConfig.java`，通过审计代码可知，系统对 `/static/**`,`/user/login`,`/drawImage` 使用了 anon 拦截器，即对这几个路径不会进行拦截，无需权限即可访问；对 `/**` 使用了 authc 拦截器，即对任意层路径进行拦截，需进行权限认证。综合得知，除了`/static/**`,`/user/login`,`/drawImage` 路径不需要认证，其他均需要权限认证。

![image-20221126211906103](https://funsiooo.github.io/images/Java/jxc/image-20221126211906103.png)

综上分析得知，开发者对 `/**` (任意层路径)使用了 authc 拦截器进行了拦截，所以该项目不存在 Shiro 权限绕过漏洞。

------

#### SQL注入（不存在）

由上面的 pom.xml 审计中，我们发现系统使用 Mybatis 框架，通过以往的文章学习，我们知道 Mybatis 审计 SQL 注入关键点在与语句是否使用了 `${}` 和 `#{}`,若使用了`#{}` 即采取了预编译，则是不存在注入了，若使用了 `${}` 则为直接拼接，如果不存在过滤则可能存在SQL注入。

在 Spring Boot 框架中，一般为 Controller 层接收前端请求然后调用 Service 层，然后 Service 层的业务逻辑去调用 Dao 访问数据库做增删改查操作，Dao 再调用 resources 中的对应的 .xml 文件做具体的 SQL 语句，SQL 语句都是在 .xml 文件中写的，而不是在 Java 代码中直接利用 Connection 连接数据库进行查询，这样层次更清晰，代码也更容易维护。因为具体的 SQL 语句都在 .xml 文件中，所以我们审计时可以直接搜索 .xml 文件中是否存在的 ${ 符号，以快速寻找是否存在 SQL 注入漏洞。

![image-20221128103655415](https://funsiooo.github.io/images/Java/jxc/image-20221128103655415.png)

![image-20221128103844420](https://funsiooo.github.io/images/Java/jxc/image-20221128103844420.png)



------

#### 验证码绕过（存在）

审计验证码是否可绕过，我们先定位其路由，然后根据其位置一步步分析其代码是否存在验证码绕过的可能。我们通过抓包定位其路由为 `/user/login`

![image-20221128105602081](https://funsiooo.github.io/images/Java/jxc/image-20221128105602081.png)

所以 IDEA 中搜索 `/user` 或者`/login` 定位到该位置

![image-20221128110144473](https://funsiooo.github.io/images/Java/jxc/image-20221128110144473.png)

通过审计定位到代码为 Controller 层的 `UserController.java`，有两个参数，通过上面注释可知道，session 用于取出系统生成的验证码。两个参数使用 `login` 方法去调用，我们跟进 `login` 方法进一步审计

![image-20221128111023068](https://funsiooo.github.io/images/Java/jxc/image-20221128111023068.png)

`Ctrl + 鼠标左键` 跟进方法，我们来到了 `Service` 接口层，也就是 `Dao` 层的 UserService.java，因为 Service 接口调用的是 Dao 层的接口，接下来我们就应该找接口的具体实现代码进行审计

![image-20221128111444927](https://funsiooo.github.io/images/Java/jxc/image-20221128111444927.png)

`Ctrl + 鼠标左键` UserService 接口，找到具体的实现代码

![image-20221128111929222](https://funsiooo.github.io/images/Java/jxc/image-20221128111929222.png)

![image-20221128111953407](https://funsiooo.github.io/images/Java/jxc/image-20221128111953407.png)

接下来的工作就是审计该代码即可，通过审计我们得知 `if(!userLogin)` 如果、非，即如果输出的验证码非系统验证码则返回 ServiceVO 里面的错误，正确则跳进下一步进行登录校验。这里的代码没有定义刷新验证码机制，使我们只需要输入一次正确的验证码即可继续使用该验证码。

```
// 校验图片验证码是否正确
if(!userLogin.getImageCode().toUpperCase().equals(session.getAttribute("checkcode"))){
	return new ServiceVO(ErrorCode.VERIFY_CODE_ERROR_CODE, ErrorCode.VERIFY_CODE_ERROR_MESS);
}
```

![image-20221128112759128](https://funsiooo.github.io/images/Java/jxc/image-20221128112759128.png)

漏洞复现，我们输入正确的验证码，抓包进行爆破

![image-20221128114103675](https://funsiooo.github.io/images/Java/jxc/image-20221128114103675.png)

![image-20221128114130277](https://funsiooo.github.io/images/Java/jxc/image-20221128114130277.png)

![image-20221128114152465](https://funsiooo.github.io/images/Java/jxc/image-20221128114152465.png)

![image-20221128114229865](https://funsiooo.github.io/images/Java/jxc/image-20221128114229865.png)



------

#### 存储型XSS（存在）

我们知道只要存在输入点，就有可能存在 XSS 漏洞，所以审计时我们首先审计是否存在XSS全局过滤器。一般搜索 filter 进行分析，这里我们知道使用的是 Spring boot 框架并使用了 Shiro，所以我们直接转到 Shiro 中的 filter 过滤器查看是否对 XSS 进行了过滤。

![image-20221128125843474](https://funsiooo.github.io/images/Java/jxc/image-20221128125843474.png)

通过分析，发现系统只对部分的路径进行了过滤，并没有对XSS进行过滤

![image-20221128130003820](https://funsiooo.github.io/images/Java/jxc/image-20221128130003820.png)

这时，我们就可以尝试在功能点处输入 XSS 语句进行尝试，查看是否能触发漏洞。首先我们在页面搜索功能点并不能触发漏洞

![image-20221128130137222](https://funsiooo.github.io/images/Java/jxc/image-20221128130137222.png)

经过测试，我们发现在系统的搜索功能并不能触发 XSS，在修改功能，可以将数据插入数据库的功能可触发漏洞

![image-20221128130626302](https://funsiooo.github.io/images/Java/jxc/image-20221128130626302.png)

![image-20221128130607082](https://funsiooo.github.io/images/Java/jxc/image-20221128130607082.png)

进一步测试发现，只要是插入数据库的功能点都能触发漏洞

![image-20221128131010064](https://funsiooo.github.io/images/Java/jxc/image-20221128131010064.png)

![image-20221128130953106](https://funsiooo.github.io/images/Java/jxc/image-20221128130953106.png)

当我们使用其他账号登录，发现也能触发 XSS，证明该 XSS 为存储型 XSS

![image-20221128131225694](https://funsiooo.github.io/images/Java/jxc/image-20221128131225694.png)

通过抓包找到该路由为 /supplier/list

![image-20221128131433784](https://funsiooo.github.io/images/Java/jxc/image-20221128131433784.png)

IDEA 全局搜索定位到 Controller 层 `SupplierController.java`

![image-20221128131630406](https://funsiooo.github.io/images/Java/jxc/image-20221128131630406.png)

![image-20221128131818693](https://funsiooo.github.io/images/Java/jxc/image-20221128131818693.png)

通过对比，参数 page、rows 对应 Burp 抓到到参数基本一致，确定为该路径

![image-20221128132127301](https://funsiooo.github.io/images/Java/jxc/image-20221128132127301.png)

![image-20221128132225563](https://funsiooo.github.io/images/Java/jxc/image-20221128132225563.png)

`Ctrl + 鼠标左键` 跟进 list 方法，我们来到了 Service 层的 `SupplierService.java`,定位到 `SupplierService` 接口

![image-20221128132450975](https://funsiooo.github.io/images/Java/jxc/image-20221128132450975.png)

```
Ctrl + 鼠标左键` 进行跟进该接口，找到具体实现代码位置为 `SupplierServiceImpl.java
```

![image-20221128132721752](https://funsiooo.github.io/images/Java/jxc/image-20221128132721752.png)

代码逻辑清晰，没有对输入进行过滤

![image-20221128132640798](https://funsiooo.github.io/images/Java/jxc/image-20221128132640798.png)

![image-20221128132902071](https://funsiooo.github.io/images/Java/jxc/image-20221128132902071.png)

XSS实战中的使用,使用 XSS 平台，创建一个项目

![image-20221128141001324](https://funsiooo.github.io/images/Java/jxc/image-20221128141001324.png)

![image-20221128141022057](https://funsiooo.github.io/images/Java/jxc/image-20221128141022057.png)

这里选择默认模块

![image-20221128141043009](https://funsiooo.github.io/images/Java/jxc/image-20221128141043009.png)

![image-20221128133535652](https://funsiooo.github.io/images/Java/jxc/image-20221128133535652.png)

随便选择一个代码插入到存在漏洞的框框中

![image-20221128141147400](https://funsiooo.github.io/images/Java/jxc/image-20221128141147400.png)

![image-20221128133858249](https://funsiooo.github.io/images/Java/jxc/image-20221128133858249.png)

返回 XSS 平台这里已经返回部分信息

![image-20221128133752931](https://funsiooo.github.io/images/Java/jxc/image-20221128133752931.png)

## 四、总结

这次项目审计进一步了解 Shiro 登录认证机制，再通过审计功能点进一步了解审计基础，审计的漏洞数量虽然不多，但加深了审计的技巧。

## 五、参考

```
https://www.freebuf.com/vuls/283810.html
https://mp.weixin.qq.com/s/Y90mGgCqzjj0T1NX9E5wDw
https://www.bilibili.com/video/BV1R24y1f7PY/?spm_id_from=333.999.0.0&vd_source
```