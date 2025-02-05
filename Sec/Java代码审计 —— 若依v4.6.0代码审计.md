# Java代码审计(六)-若依管理系统V4.6.0

**Funsiooo** 

2023-03-02 (Updated: 2023-03-07) 

 [代码审计](https://funsiooo.github.io/categories/代码审计/) 

 [Java代码审计](https://funsiooo.github.io/tags/Java代码审计/), [SQL注入](https://funsiooo.github.io/tags/SQL注入/), [Shiro反序列化](https://funsiooo.github.io/tags/Shiro反序列化/), [任意文件读取](https://funsiooo.github.io/tags/任意文件读取/)

## 一、前言

若依管理系统是基于 SpringBoot 开发的轻量级 JAVA 开发框架，，本篇文章基于 V4.6.0 版本的基础上对部分历史漏洞进行审计分析。项目地址：https://gitee.com/y_project/RuoYi/tree/v4.6.0

## 二、环境搭建

这里依然使用 Phpstudy 作为数据库源，利用 navicat 导入数据表

![image-20221128193032129](https://funsiooo.github.io/images/Java/ruoyi/image-20221128193032129.png)

创建数据库

![image-20221128193140018](https://funsiooo.github.io/images/Java/ruoyi/image-20221128193140018.png)

导入数据表

![image-20221128193247668](https://funsiooo.github.io/images/Java/ruoyi/image-20221128193247668.png)

![image-20221128193314048](https://funsiooo.github.io/images/Java/ruoyi/image-20221128193314048.png)

IDEA导入项目源码，注意源码路径不要有中文，等待 Maven 下载项目依赖

![image-20221128194601780](https://funsiooo.github.io/images/Java/ruoyi/image-20221128194601780.png)

我这边修改了几处，一为数据库账号密码及数据库名称（**注意：修改为自己的本地数据库账号密码**），二是将项目端口 80 改为 8888 ，路径改为了本机能访问的路径，因为本人环境是虚拟机，没有设置D盘

![image-20221128202414458](https://funsiooo.github.io/images/Java/ruoyi/image-20221128202414458.png)

![image-20221128201751385](https://funsiooo.github.io/images/Java/ruoyi/image-20221128201751385.png)

修改如下

![image-20221128202005935](https://funsiooo.github.io/images/Java/ruoyi/image-20221128202005935.png)

点击运行项目，访问 http://localhost:8888/login 成功搭建，默认账号为 `admin/admin123`

![image-20221128202131048](https://funsiooo.github.io/images/Java/ruoyi/image-20221128202131048.png)

![image-20221128202451155](https://funsiooo.github.io/images/Java/ruoyi/image-20221128202451155.png)

## 三、代码审计

### 1、pom.xml 审计

老套路，存在 pom.xml，先审计其使用了哪些框架，框架组件是否存在历史漏洞。这个与以往的项目不一样的是，系统存在多个 pom.xml，我们只需要审计最外层的 pom.xml 即可

![image-20221128212237103](https://funsiooo.github.io/images/Java/ruoyi/image-20221128212237103.png)

第三方组件如下，这一篇笔者不打算展开组件漏洞的审计，可自行根据版本网上 search 复现

```
| 组件名称           | 组件版本 |
| ------------------ | -------- |
| shiro              | 1.7.0    |
| thymeleaf          | 2.0.0    |
| druid              | 1.2.2    |
| bitwalker          | 1.21     |
| kaptcha            | 2.3.2    |
| swagger            | 2.9.2    |
| pagehelper         | 1.3.0    |
| fastjson           | 1.2.74   |
| oshi               | 5.3.6    |
| jna                | 5.6.0    |
| commons.io         | 2.5      |
| commons.fileupload | 1.3.3    |
| poi                | 4.1.2    |
| velocity           | 1.7      |
```



### 2、漏洞审计

#### **SQL注入**

SpringBoot中 使用了 Mybatis 的 SQL 注入一般都是因为使用了 $ ，所以全局搜索 .xml 的 `${`。（注：搜索.xml文件的原因是该系统使用了 Mybatis 中的`配置文件开发-》编写 xml 配置文件来映射相应的代码`）

![image-20221129125159545](https://funsiooo.github.io/images/Java/ruoyi/image-20221129125159545.png)

![image-20221129125130419](https://funsiooo.github.io/images/Java/ruoyi/image-20221129125130419.png)

这边先对第一个可疑点进行审计 `${params.dataScope}`

因为该项目使用了 `mybatis` 并且利用了配置文件开发，所以会在 `resource` 目录下出现映射的 `.xml` 配置文件。我们在 `SysRoleMapper.xml` 文件中找到了可疑参数 `${params.dataScope}`，并定位到映射语句 `id=selectRolelist`

![image-20221129131526187](https://funsiooo.github.io/images/Java/ruoyi/image-20221129131526187.png)

通过上面我们定位到文件 `resources` 目录下的 `SysRoleMapper.xml` 配置文件中的映射语句 `id=selectRolelist`，根据以往文章的学习已知 `resources` 层对应 `dao` 层的接口，文件名也一致，所以我们定位到 `dao` 层的 `SysRoleMapper.java` ，找到 `selectRolelist` 接口

![image-20221129132412165](https://funsiooo.github.io/images/Java/ruoyi/image-20221129132412165.png)

然后 `Ctrl + 鼠标左键` 跟进 `selectRolelist` 接口，看是谁调用这个接口。我们来到了 `service` 层的实体类 `SysRoleServiceImpl.java` 文件

![image-20221129132823022](https://funsiooo.github.io/images/Java/ruoyi/image-20221129132823022.png)

然后我们将光标放到 `selectRoleList` 方法处，快捷键 `Ctrl + u` 进入该方法父类/接口定义的位置 Service 层的接口 `ISysRoleService.java` **（这里也可以直接鼠标右键方法名找到其调用链直接定位到 controller 层接口）**

![image-20221129133452563](https://funsiooo.github.io/images/Java/ruoyi/image-20221129133452563.png)

最后 `Ctrl + 鼠标左键` ，定位到具体的实现代码,由下图可知，59行、69行均有调用该函数

![image-20221129133753389](https://funsiooo.github.io/images/Java/ruoyi/image-20221129133753389.png)

通过代码定位到 `Controller` 层的 `SysRoleController.java` 第59行 ,这个就是我们最终需要审计的代码，/list 有两个参数，SysRole 和 role ，最终 return 为 list ，而 `List<SysRole> list = roleService.selectRoleList(role);`,所以参数值为 `SysRole` 参数定义的实体类

![image-20221129142906434](https://funsiooo.github.io/images/Java/ruoyi/image-20221129142906434.png)

```
Ctrl + 鼠标左键` 跟进 `SysRole` 参数，具体实体类如下，具体参数值为：`roleId=&roleName=&roleKey=&roleSort=&dataScope=&status=&delFlag=&flag=&menuIds=&deptIds=
```

![image-20221129135057213](https://funsiooo.github.io/images/Java/ruoyi/image-20221129135057213.png)

`dataScope` 参数没有过滤直接返回

![image-20221129144458616](https://funsiooo.github.io/images/Java/ruoyi/image-20221129144458616.png)

尝试漏洞复现，定位路由从上到下 `/system/role/list`

![image-20221129142133925](https://funsiooo.github.io/images/Java/ruoyi/image-20221129142133925.png)

且通过注解可知道 /list 为 POST 请求方式

![image-20221129141948518](https://funsiooo.github.io/images/Java/ruoyi/image-20221129141948518.png)

直接后台浏览，找到 `/system/role/list` 路径

![image-20221129150602128](https://funsiooo.github.io/images/Java/ruoyi/image-20221129150602128.png)

我们看到这里是没有 `dataScope` 参数的，我们自己加上即可

![image-20221129181626999](https://funsiooo.github.io/images/Java/ruoyi/image-20221129181626999.png)

漏洞 payload: `pageSize=&pageNum=&orderByColumn=&isAsc=&roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&params[dataScope]=and+updatexml(1,concat(0x7e,(SELECT+version()),0x7e),1)%2523`

添加参数后，随便输入字符返回报错

![image-20221129182031431](https://funsiooo.github.io/images/Java/ruoyi/image-20221129182031431.png)

![image-20221129181939916](https://funsiooo.github.io/images/Java/ruoyi/image-20221129181939916.png)

成功查询版本信息，证明存在SQL注入

![image-20221129182436018](https://funsiooo.github.io/images/Java/ruoyi/image-20221129182436018.png)

可直接发包到 sqlmap 跑数据

![image-20221129182906151](https://funsiooo.github.io/images/Java/ruoyi/image-20221129182906151.png)

至此，`selectRolelist` 接口的SQL注入审计就结束了，整个审计流程为 `SysRoleMapper.xml -》SysRoleMapper.jave -》SysRoleServiceImpI.java -》ISysRoleService.java -》SysRoleController.java -》SysRole.java`

简单概况就是 ${ 定位漏洞点 -》resource 目录下的 Mybatis 映射语句配置文件 -》通过映射语句定位 Service 层的实体类接口 -》再定位到 Service 层的接口文件 -》通过接口定位到 Controller 层最终调用接口 -》最后定位到接口的具体实现代码 -》分析参数是否有过滤

![image-20230220220920253](https://funsiooo.github.io/images/Java/ruoyi/image-20230220220920253.png)

我们亦可以通过对比官方更新文件找到漏洞点进行审计

![image-20230216125250617](https://funsiooo.github.io/images/Java/ruoyi/image-20230216125250617.png)

![image-20230216125414063](https://funsiooo.github.io/images/Java/ruoyi/image-20230216125414063.png)

修改前

![image-20230216130127701](https://funsiooo.github.io/images/Java/ruoyi/image-20230216130127701.png)

修改后

![image-20230216130102638](https://funsiooo.github.io/images/Java/ruoyi/image-20230216130102638.png)



#### Shiro组件漏洞

若依系统使用了 Shiro ，我们知道 Shiro < 1.2.4 存在反序列化漏洞， Shiro 1.4.2 到 1.8.0 存在权限绕过漏洞，本项目使用的 Shiro 版本为 1.7.0。

**1）Shiro 反序列化**

这里通过 Burp 插件找到了 Shiro 默认密钥 `zSyK5Kp6PZAAjlT+eeNMlg==`

![image-20221129200200219](https://funsiooo.github.io/images/Java/ruoyi/image-20221129200200219.png)

这边使用 [Github](https://github.com/Ares-X/shiro-exploit) 上工具进行了复现，第一次尝试并没成功，后面换了一个工具，发现又可以了，所以平常在实战中遇到 Shiro Key 泄露的情况，多换几个工具尝试一下，没准会有收获

![image-20221129200510839](https://funsiooo.github.io/images/Java/ruoyi/image-20221129200510839.png)

进行命令执行 `python3 shiro-exploit.py echo -g CommonsCollectionsK1 -u http://192.168.114.160:8888/ -v 2 -k zSyK5Kp6PZAAjlT+eeNMlg== -c whoami`

![image-20221129200614230](https://funsiooo.github.io/images/Java/ruoyi/image-20221129200614230.png)

![image-20221129200636926](https://funsiooo.github.io/images/Java/ruoyi/image-20221129200636926.png)

**漏洞审计：**

Shiro AES 秘钥在 1.2.4 版本及之前版本是存在密钥硬编码的，1.2.5 版本以后 Shiro 提供了 AES 密钥的随机生成代码，但如果仅进行 Shiro 版本升级，AES 密钥仍硬编码在代码中，仍然会存在反序列化风险。在审计中我们可以全局搜索 `setCipherKey` ,该方法是用于修改密钥的，若存在 `setCipherKey` 方法则说明存在默认key，进一步搜索 `cipherKey` 可查看具体密钥值

![image-20221129210227296](https://funsiooo.github.io/images/Java/ruoyi/image-20221129210227296.png)

密钥硬编码在 `application.yml` 文件处

![image-20221129210304172](https://funsiooo.github.io/images/Java/ruoyi/image-20221129210304172.png)

**2）Shiro 权限绕过审计**

此漏洞也只需要审计 `ShiroConfig.java` 配置文件里面的过滤器有没有对目录进行限制。由上一篇系列文章我们知道 `anon` 为匿名拦截器，不需要登录就能访问，一般用于静态资源,或者移动端接口；`authc` 为登录拦截器，需要登录认证才能访问的资源，需要在配置文件配置需要登录的 URL 路径

authc 拦截器匹配规则如下：

```
| 通配符 | 说明                    |
| ------ | ----------------------- |
| ？     | 匹配任意一个字符        |
| *      | 匹配任意字符，包括0个   |
| **     | 匹配任意层路径，包括0个 |
```

以下静态资源进行匿名登录，不需要认证即可访问

![image-20221129212610780](https://funsiooo.github.io/images/Java/ruoyi/image-20221129212610780.png)

对需要认证的页面进行了 `/**` 限制，需要登录认证才能访问

![image-20221129212641545](https://funsiooo.github.io/images/Java/ruoyi/image-20221129212641545.png)

#### 任意文件读取

若依系统任意读取文件影响版本为 `RuoYi < v4.5.1` ，本环境为 `4.6.0`，这边重新部署了[v4.5.0](https://gitee.com/y_project/RuoYi/repository/archive/v4.5.0.zip) 的环境，学习该漏洞，部署方法如上。

![image-20221130134353409](https://funsiooo.github.io/images/Java/ruoyi/image-20221130134353409.png)

通过对比 V4.5.0 与 V4.5.1 的代码分析定位漏洞点

![image-20230206215406546](https://funsiooo.github.io/images/Java/ruoyi/image-20230206215406546.png)

![image-20230206215514857](https://funsiooo.github.io/images/Java/ruoyi/image-20230206215514857.png)

V4.5.0 漏洞未修复前源码

![image-20230206215622205](https://funsiooo.github.io/images/Java/ruoyi/image-20230206215622205.png)

V4.5.1漏洞修复后更新后的代码

![image-20230206215726171](https://funsiooo.github.io/images/Java/ruoyi/image-20230206215726171.png)

根据官方代码可知漏洞位置为

```
ruoyi-admin/src/main/java/com/ruoyi/web/controller/common/CommonController.java
```

![image-20230207211853841](https://funsiooo.github.io/images/Java/ruoyi/image-20230207211853841.png)

由代码可知，在下载资源时没有任何的过滤，可直接下载本地资源

```
/**
 * 本地资源通用下载
 */
@GetMapping("/common/download/resource")
public void resourceDownload(String resource, HttpServletRequest request, HttpServletResponse response)
        throws Exception
{
    // 本地资源路径
    String localPath = Global.getProfile();
    // 数据库资源地址
    String downloadPath = localPath + StringUtils.substringAfter(resource, Constants.RESOURCE_PREFIX);
    // 下载名称
    String downloadName = StringUtils.substringAfterLast(downloadPath, "/");

    response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
    FileUtils.setAttachmentResponseHeader(response, downloadName);

    FileUtils.writeBytes(downloadPath, response.getOutputStream());
}
```

审计初步请求路径为 `/common/download/resource?resource=`，使用的方法为 GET（因为使用的注解是 @GetMapping）

![image-20230207214447968](https://funsiooo.github.io/images/Java/ruoyi/image-20230207214447968.png)

![image-20230207221539853](https://funsiooo.github.io/images/Java/ruoyi/image-20230207221539853.png)

本地资源路径为开始时我们设置的 `uploadPath` 路径，这段代码下载的文件就是这个路径下的文件

![image-20230207214512267](https://funsiooo.github.io/images/Java/ruoyi/image-20230207214512267.png)

![image-20230207214258149](https://funsiooo.github.io/images/Java/ruoyi/image-20230207214258149.png)

分析代码 `String downloadPath = localPath + StringUtils.substringAfter(resource, Constants.RESOURCE_PREFIX);`，其中 `localPath` 为本地资源路径 + `StringUtils.substringAfter()` 方法，其中方法中定义了请求参数为 `resource` 和请求前缀 `Constants.RESOURCE_PREFIX`

![image-20230207214603424](https://funsiooo.github.io/images/Java/ruoyi/image-20230207214603424.png)

我们跟进 `Constants.RESOURCE_PREFIX` `Ctrl + 鼠标左键` 查看文件下载资源时的请求前缀是什么，由下图可知，请求下载前的资源前缀为 `/profile`

![image-20230207215525136](https://funsiooo.github.io/images/Java/ruoyi/image-20230207215525136.png)

`downloadName = StringUtils.substringAfterLast(downloadPath, "/");` 即下载名称为先执行 `downloadPath` 方法，再用 `separator"/"`(分隔符+下载文件的名称)

![image-20230207220732139](https://funsiooo.github.io/images/Java/ruoyi/image-20230207220732139.png)

整合上面分析的，得到整体路由为：`/common/download/resource?resource=/profile/下载文件的名称`,使用方法为GET

漏洞复现

1、我们现在 `localPath` 即 `C:/Tools/enviroment/RuoYi-v4.5.0/ruoyi/uploadPath` 目录下创建一个文件用于测试

![image-20230207221912564](https://funsiooo.github.io/images/Java/ruoyi/image-20230207221912564.png)

![image-20230207222514373](https://funsiooo.github.io/images/Java/ruoyi/image-20230207222514373.png)

2、构造请求连接为 `/common/download/resource?resource=/profile/flag.txt`，需在后台访问

![image-20230207222626156](https://funsiooo.github.io/images/Java/ruoyi/image-20230207222626156.png)

3、由于代码没有对下载的路径进行限制，我们尝试利用目录穿越任意下载系统文件 `windows/win.ini`，由下图可知，我们到达 C盘下的 `windows/win.ini` 有六层，所以我们需要六个 ../ 进行目录穿越

![image-20230207222906262](https://funsiooo.github.io/images/Java/ruoyi/image-20230207222906262.png)

成功利用目录穿越漏洞实现任意文件下载

![image-20230207223141156](https://funsiooo.github.io/images/Java/ruoyi/image-20230207223141156.png)

## 四、参考

```
https://blog.csdn.net/qq_44029310/article/details/125296406
https://gitee.com/y_project/RuoYi/releases
https://power7089.github.io/2022/08/22/JavaWeb%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE
```