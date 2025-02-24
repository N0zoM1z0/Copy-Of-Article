# [java反序列化——XMLDecoder反序列化漏洞](https://www.cnblogs.com/hetianlab/p/13534535.html)

本文首发于“合天智汇”公众号 作者：Fortheone

# 前言

最近学习java反序列化学到了weblogic部分，weblogic之前的两个反序列化漏洞不涉及T3协议之类的，只是涉及到了XMLDecoder反序列化导致漏洞，但是网上大部分的文章都只讲到了触发XMLDecoder部分就结束了，并没有讲为什么XMLDecoder会触发反序列化导致命令执行。于是带着好奇的我就跟着调了一下XMLDecoder的反序列化过程。

# xml序列化

首先了解一下java中的XMLDecoder是什么。XMLDecoder就是jdk中一个用于处理xml数据的类，先看两个例子。

这里引用一下浅蓝表哥的（强推浅蓝表哥的博客https://b1ue.cn/

```
import java.beans.XMLEncoder;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * @author 浅蓝
 * @email blue@ixsec.org
 * @since 2019/4/24 12:09
 */
public class Test {

    public static void main(String[] args) throws IOException, InterruptedException {

        HashMap<Object, Object> map = new HashMap<>();
        map.put("123","aaaa");
        map.put("321",new ArrayList<>());

        XMLEncoder xmlEncoder = new XMLEncoder(System.out);
        xmlEncoder.writeObject(map);
        xmlEncoder.close();

    }
}
```

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/8239909110e6423ab0792a7264583c59)

这样就把map对象变成了xml数据，再使用XMLDecoder解析一下。

```
/**
 * @author 浅蓝
 * @email blue@ixsec.org
 * @since 2019/4/24 12:09
 */
public class Test {

    public static void main(String[] args) throws IOException, InterruptedException {
        String s = "<java version=\"1.8.0_131\" class=\"java.beans.XMLDecoder\">\n" +
                " <object class=\"java.util.HashMap\">\n" +
                "  <void method=\"put\">\n" +
                "   <string>123</string>\n" +
                "   <string>aaaa</string>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>321</string>\n" +
                "   <object class=\"java.util.ArrayList\"/>\n" +
                "  </void>\n" +
                " </object>\n" +
                "</java>";
        StringBufferInputStream stringBufferInputStream = new StringBufferInputStream(s);
        XMLDecoder xmlDecoder = new XMLDecoder(stringBufferInputStream);
        Object o = xmlDecoder.readObject();
        System.out.println(o);

    }
}
```

![img](https://p3-tt-ipv6.byteimg.com/large/pgc-image/ddf716e9a208411abf3e5167869034d6)

就可以把之前的xml数据反序列化回map对象，那么如果对xml数据进行修改，使其变成一个执行命令的数据。比如说：

```
<java version="1.7.0_80" class="java.beans.XMLDecoder">
 <object class="java.lang.ProcessBuilder">
  <array class="java.lang.String" length="1">
    <void index="0"><string>calc</string></void>
  </array>
  <void method="start"></void>
 </object>
</java>
```

然后对其反序列化即可执行命令弹出计算器。

![img](https://p6-tt-ipv6.byteimg.com/large/pgc-image/75194daffb484657a0706b989f228eaa)

现在我们知道了如果使用XMLDecoder去反序列化xml数据，数据中包含的命令会被执行。接下来就对其进行分析一下。

# XMLDecoder反序列化漏洞成因

# 一、XML数据解析前的函数处理

![img](https://p26-tt.byteimg.com/large/pgc-image/1684f881b73c4350b9c0129f46dc9e1e)

在readObject处打上断点开始debug

![img](https://p9-tt-ipv6.byteimg.com/large/pgc-image/23e1d9c47bcb4dc48dde5b787404b85c)

进入了parsingComplete方法，跟进。

![img](https://p9-tt-ipv6.byteimg.com/large/pgc-image/c8691456a2604e6086c0ce7b1f6ad1a1)

其中使用XMLDecoder的handler属性DocumentHandler的parse方法，并且传入了我们输入的xml数据，跟进。

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/0be2d974fcd84413b4ec705c238853c9)

这里调用了SAXParserImpl类的parse方法。

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/abfa4ada487440ce97abd9d403ce083e)

然后又进了xmlReader的parse方法。

![img](https://p3-tt-ipv6.byteimg.com/large/pgc-image/0891fa959a3449a0a18dd3368fc3be66)

这里又调用了xmlReader父类AbstractSAXParser的parser方法。

![img](https://p6-tt-ipv6.byteimg.com/large/pgc-image/76f460e3f0d444df9fde45a408b069a3)

最后进入了XML11Configuration类的parse方法。

# 二、XML数据的处理

![img](https://p26-tt.byteimg.com/large/pgc-image/8bcedea31435490bae5d0ed758a74f31)

在XML11Configuration中进行了很多解析XML之前的操作，我们不去仔细研究，看到处理XML数据的函数scanDocument。跟进查看

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/b33323182c3f4da6a1f3311fb91e2b68)

这个函数通过迭代的方式对XML数据的标签进行解析，网上有些文章写道“解析至END_ELEMENT时跟进调试”，但是我看了一下我这里的END_ELEMENT。

![img](https://p9-tt-ipv6.byteimg.com/large/pgc-image/58982a120ea14a699c8cd56336afafc7)

里面没有函数可以跟进啊，然后搜了一些其他的文章，是因为jdk版本的问题，处理的逻辑放在了next函数里。在do while循环里跳了大概十次，就开始解析了xml的标签。

![img](https://p6-tt-ipv6.byteimg.com/large/pgc-image/a943073b221c409c95889c41592b8ab8)

跳到XMLDocumentScannerImpl中的next方法

![img](https://p9-tt-ipv6.byteimg.com/large/pgc-image/a49247aaeb494c6a8bd1a04ac3fc2453)

跳到XMLDocumentFragmentScannerImpl中的next方法，解析到endtag时会走到scanEndElement方法里。

然后就到了网上说的endElement方法里，跟进。

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/82627968366941589094f8cf3e292d81)

这一部分的解析可以参考下图：

![img](https://p6-tt-ipv6.byteimg.com/large/pgc-image/c76c37008908441290f38b2746b432f2)

也就是说解析时会按照标签一个一个解析。

![img](https://p9-tt-ipv6.byteimg.com/large/pgc-image/e4794dc7536e4a5b85f393637d9f72d5)

这里调用了DocumentHandler的endElement方法。**接下来就是很重要的部分**

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/fea8baaaac404e3f94a2ce3cdb67d694)

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/eea789015c9546cabdbba587865bbe64)

这里的handler是StringElementHandler，但是这个类没有重写endElement方法，所以调用的是父类ElementHandler的endElement方法，其中调用了getValueObject来获取标签中的value值，这里的标签是string标签，所以获取到的值是calc。

![img](https://p26-tt.byteimg.com/large/pgc-image/fe289b09df604f3aa2f8fb76c2ca9dec)

![img](https://p26-tt.byteimg.com/large/pgc-image/22584a129f1043a6baa10a6d9fd4c47c)

然后将其添加到其父类标签VoidElementHandler的Argument属性中。

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/26563f89a95848889c6a25b6496d46dd)

然后将handler指向其父类VoidElementHandler。

![img](https://p26-tt.byteimg.com/large/pgc-image/35d947643bf3493da6c21e39bca30e32)

继续解析到void标签，此时的handler就是VoidElementHandler，接着调用getValueObject。但是因为没有重写该方法，所以调用父类NewElementHandler的getValueObject。

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/dc22bbd6b7e14652a480f46fb3a0770f)

![img](https://p9-tt-ipv6.byteimg.com/large/pgc-image/a7f2f51c031b4eabaa1b1fc94c5ef49a)

继续跟进发现实现了反射调用invoke方法，也就是执行了set方法。接着再解析Array标签，按照上面的步骤解析，就完成了这一部分参数的解析。

```
<array class="java.lang.String"length="1">
  <void index="0">
      <string>calc</string>
  </void>
</array>
```

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/e26028890e824f8cb56d3ce721a0748f)

那么再按照上面的步骤解析object标签，然后调用new 方法实例化 ProcessBuilder类。

![img](https://p26-tt.byteimg.com/large/pgc-image/f8ec591d721c48b390cde5bbc057cbd5)

然后解析到void标签获取到start方法，然后通过调用start方法实现了命令执行，弹出计算器。

也就相当于最后拼接了 new java.lang.ProcessBuilder(new String[]{"calc"}).start();

![img](https://p1-tt-ipv6.byteimg.com/large/pgc-image/7ab873981fa842618aff5407399b9cad)

文章有说的不对的地方请师傅们指点，刚开始学java，大佬们轻喷。。。

# 参考文章

https://b1ue.cn/archives/239.html

https://zhuanlan.zhihu.com/p/108754274

https://blog.csdn.net/SKI_12/article/details/85058040