## 前言

**随着网络强国、工业4.0，工控安全市场今年明显有相当大的改善，无论从政策还是客户需求，都在逐步扩大中。但是，搞工控安全研究的人员却寥寥无几，一方面，没有可以研究和学习的便利的环境；另一方面工控安全是个跨学课的技术，需要了解多方面的知识，有比较高的技术上的门槛。特别是工控系统中通信协议，在工控系统中通信协议存在众多标准，也存在众多私有协议，如果你有过使用组态软件的经历，你便会发现，在第一步连接设备时除连接设备的方式有以太网/串行等方式外，各家基本上都存在自己的私有通信协议。比如：西门子的是S7Comm协议。**

上一篇文章[《工控安全 | 西门子通信协议S7COMM（Part 1）》](https://www.freebuf.com/articles/ics-articles/188159.html)带来了**西门子PLC系统构成**、**S7协议结构**、**TPKT协议**、**COTP协议**、**S7Comm协议**五大块内容，本文紧接着上文中的**S7Comm协议**章节继续开展，没看过上一篇的小伙伴需要补补课哦，不然会不知所云~

**5.2.4下载**

下载是Step7发送块数据给PLC（图25）。在西门子设备上，程序代码和（大部分）程序数据存储在块中，这些块有自己的头和编码格式。

在西门子设备中有8种不同类型的功能块，具体的请参考[6.7](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-7)。

这些块在上/下载请求中用特殊的ASCII文件名寻址。这个文件名的结构如下：

```
1 (1 byte): File identifier（ASCII），文件标识符。其有_ (Complete Module)、$ (Module header for up-loading)两种文件标识符；2 (2 bytes): Block type，块类型。具体类型，请参考6.7；3 (5 bytes): Block number，块编号；4 (1 byte): Destination filesystem（ASCII），目标的文件系统。其有三种文件系统：  P（Passive (copied, but not chained) module)：被动文件系统  A (Active embedded module)：主动文件系统  B (Active as well as passive module)：既主既被文件系统
```

例如：文件名为_0A00001P（文件标识是_，块类型为DB，块的编号为00001，目标块的文件系统是P。），用于将DB 1复制到被动文件系统或从被动文件系统复制。

下载有3中不同的功能类型：

```
请求下载（Request download [0x1A]）下载块（Download block [0x1B]）下载结束（Download ended [0x1C]）
```

在下载过程中，先是Step7向PLC发送一个请求下载的Job，PLC收到后则回复一个Ack_Data。在发送完所有字节后，Step7向PLC发送一个下载结束的Job来关闭下载会话。 时序图如下：

![图25 下载时序图（图片来源：互联网）](https://image.3001.net/images/20181106/1541486101_5be136157f60d.png!small)

图25 下载时序图（图片来源：互联网）

好了，开始介绍下载的结构啦！

如图26所示，即为一个完整的下载过程：

![完整的下载过程](https://image.3001.net/images/20181106/1541486132_5be13634a2a1a.jpg!small)

图26 一个完整的下载过程例子

5.2.4.1请求下载（Request download [0x1A]）

先来介绍，当PDU类型为Job时，Request download [0x1A]没有Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): for all unknown bytes in blockcontrol；3 (4 bytes): 无意义，一般为0x00000000；4 (1 byte): filename length，文件名长度；5 (? bytes): filename, default is 9 byte，文件名，长度一般为9个字节；  1 (1 byte): File identifier（ASCII），文件标识符。其有_ (Complete Module)、$ (Module header for up-loading)两种文件标识符；  2 (2 bytes): Block type，块类型。具体类型，请参考6.7；  3 (5 bytes): Block number，块编号；  4 (1 byte): Destination filesystem（ASCII），目标的文件系统。其有P（Passive (copied, but not chained) module)、A (Active embedded module)、B (Active as well as passive module)三种文件系统；6 (1 byte): Length part 2 in bytes，参数的第二部分长度，也就是接下来的字段长度；7 (1 byte): Unknown char（ASCII）；8 (6 bytes): Length load memory in bytes（ASCII）；9 (6 bytes): Length of MC7 code in bytes（ASCII）。
```

其实就是告诉PLC要下载块。举个例子：

![图27 请求下载_0800001P的作业请求](https://image.3001.net/images/20181106/1541486179_5be13663093c3.jpg!small)

图27 请求下载_0800001P的作业请求

如图27所示，文件标识是_ (Complete Module)，块类型为OB，块的编号为00001，目标块的文件系统是P (Passive (copied, but not chained) module)，所以文件名为_0800001P。

那PDU类型为Ack_Data时，Request download [0x1A]的Parameter中只有一个function。下图即为图27的响应：

![图28 请求下载_0800001P的确认数据响应](https://image.3001.net/images/20181106/1541486210_5be1368256009.jpg!small)

图28 请求下载_0800001P的确认数据响应

OK，请求下载完成后，接下来就可以Download block了！

5.2.4.2下载块（Download block [0x1B]）

上面说了，下载是Step7发送块数据给PLC。

当PDU类型为Job时，Download block [0x1B]也没有Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): for all unknown bytes in blockcontrol；3 (4 bytes): 无意义，一般为0x00000000；4 (1 byte): filename length，文件名长度；5 (? bytes): filename, default is 9 byte，文件名，长度一般为9个字节；  1 (1 byte): File identifier（ASCII），文件标识符。其有_ (Complete Module)、$ (Module header for up-loading)两种文件标识符；  2 (2 bytes): Block type，块类型。具体类型，请参考6.7；  3 (5 bytes): Block number，块编号；  4 (1 byte): Destination filesystem（ASCII），目标的文件系统。其有P（Passive (copied, but not chained) module)、A (Active embedded module)、B (Active as well as passive module)三种文件系统；
```

是的，Download block [0x1B]的Parameter比Request download [0x1A]的Parameter的第一部分相同！

为了更好比较，举个例子：

![图29 下载块_0800001P的作业请求](https://image.3001.net/images/20181106/1541486263_5be136b708274.jpg!small)

图29 下载块_0800001P的作业请求

上图是下载_0800001P的作业请求。

那PDU类型为Ack_Data时，Download block [0x1B]有Parameter和Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；
```

而其Data的结构，如下：

```
1 (Unsigned integer, 2 bytes): Length，数据长度；2 (Unsigned integer, 2 bytes): Unknown byte(s) in blockcontrol，未知字节；3 (Label，data_length-4 bytes): Data，数据；
```

下图即为图29的响应：

![图30 下载块_0800001P的响应](https://image.3001.net/images/20181106/1541486283_5be136cb1fd08.jpg!small)

图30 下载块_0800001P的响应

5.2.4.3下载结束（Download ended [0x1C]）

当PDU类型为Job时，Download ended [0x1C]也没有Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): for all unknown bytes in blockcontrol；3 (4 bytes): 无意义，一般为0x00000000；4 (1 byte): filename length，文件名长度；5 (? bytes): filename, default is 9 byte，文件名，长度一般为9个字节；  1 (1 byte): File identifier（ASCII），文件标识符。其有_ (Complete Module)、$ (Module header for up-loading)两种文件标识符；  2 (2 bytes): Block type，块类型。具体类型，请参考6.7；  3 (5 bytes): Block number，块编号；  4 (1 byte): Destination filesystem（ASCII），目标的文件系统。其有P（Passive (copied, but not chained) module)、A (Active embedded module)、B (Active as well as passive module)三种文件系统；
```

是的，Download ended [0x1C]跟Download block [0x1B]的Parameter和Request download [0x1A]的Parameter的第一部分相同！

举个例子：

![图31 结束下载_0800001P的作业请求](https://image.3001.net/images/20181106/1541486311_5be136e7b9ace.jpg!small)

图31 结束下载_0800001P的作业请求

那PDU类型为Ack_Data时，Download ended [0x1C]的Parameter中只有一个function。下图即为图31的响应：

![图32 结束下载_0800001P的响应](https://image.3001.net/images/20181106/1541486332_5be136fccca00.jpg!small)

图32 结束下载_0800001P的响应

这样，整个下载过程就完成了！

下载到这就介绍完了，接着就介绍上传啦！

**5.2.5上传**

上传是PLC发送块数据给Step7（如图33）。

上传有3中不同的功能类型：

```
开始上传（Start upload [0x1D]）上传（Upload [0x1E]）上传结束（End upload [0x1F]）
```

在上传过程中，先是Step7向PLC发送一个开始上传的Job，PLC收到后则回复一个Ack_Data，并告诉Step7块的长度、上传会话ID。然后PLC继续上传块数据到Step7，直到Step7收到所有字节。最后，Step7发送结束上传的作业请求来关闭上传会话。时序图如下：

![图33 上传的时序图（图片来源：互联网）](https://image.3001.net/images/20181106/1541486356_5be13714867d9.png!small)

图33 上传的时序图（图片来源：互联网）

好了，开始介绍上传的结构啦！

如图34所示，即为一个完整的下载过程：

![图34 一个完整的上传过程例子](https://image.3001.net/images/20181106/1541486378_5be1372a9fba7.jpg!small)

图34 一个完整的上传过程例子

5.2.5.1 开始上传（Start upload [0x1D]）

先来介绍，当PDU类型为Job时，Start upload [0x1D]没有Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): for all unknown bytes in blockcontrol；3 (4 bytes): 上传的会话ID，此时为0x00000000；4 (1 byte): filename length，文件名长度；5 (? bytes): filename, default is 9 byte，文件名，长度一般为9个字节；  1 (1 byte): File identifier（ASCII），文件标识符。其有_ (Complete Module)、$ (Module header for up-loading)两种文件标识符；  2 (2 bytes): Block type，块类型。具体类型，请参考6.7 功能块；  3 (5 bytes): Block number，块编号；  4 (1 byte): Destination filesystem（ASCII），目标的文件系统。其有P（Passive (copied, but not chained) module)、A (Active embedded module)、B (Active as well as passive module)三种文件系统；
```

其实就是告诉PLC你上传的位置。举个例子：

![图35 开始上传的作业请求](https://image.3001.net/images/20181106/1541486543_5be137cf95c7d.jpg!small)

图35 开始上传的作业请求

如图35所示，文件标识是_ (Complete Module)，块类型为0B（SDB），块的编号为00000，目标块的文件系统是A (Active embedded module)，所以文件名为_0B00000A。

那PDU类型为Ack_Data时，Start upload [0x1D]的Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): for all unknown bytes in blockcontrol；3 (4 bytes): 上传的会话ID，告诉Step7上传会话ID；4 (Unsigned integer, 1 byte): Blocklengthstring Length；5 (Character string): Blocklength，块的长度；
```

下图即为图35的响应：

![图36开始上传的响应](https://image.3001.net/images/20181106/1541486587_5be137fb3b7a9.jpg!small)

图36开始上传的响应

图36中，其上传会话ID为0x00000007。

5.2.5.2 上传（Upload [0x1E]）

上面说了，上传是PLC发送块数据给Step7。

当PDU类型为Job时，Upload [0x1E]也没有Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): for all unknown bytes in blockcontrol；3 (4 bytes): 上传的会话ID，告诉Step7上传会话ID；
```

为了更好比较，举个例子：

![图37 上传的作业请求](https://image.3001.net/images/20181106/1541486615_5be13817603db.jpg!small)

图37 上传的作业请求

那PDU类型为Ack_Data时，Upload [0x1E]有Parameter和Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；
```

而其Data的结构，如下：

```
1 (Unsigned integer, 2 bytes): Length，数据长度；2 (Unsigned integer, 2 bytes): Unknown byte(s) in blockcontrol，未知字节；3 (Label，data_length-4 bytes): Data，数据；
```

下图即为图37的响应：

![图38 上传的确认数据响应](https://image.3001.net/images/20181106/1541486633_5be138295e9c0.jpg!small)

图38 上传的确认数据响应

5.2.5.3 上传结束（End upload [0x1F]）

上传结束的过程，即为所有数据上传完成后，Step7发送结束上传的作业请求，PLC收到后就关闭会话，然后返回一个响应。

当PDU类型为Job时，End upload [0x1F]也没有Data，其Parameter的结构，如下：

```
1 (1 byte): Function Status，功能码状态；2 (2 bytes): Error code，错误代码：
```

详细的Error code，参考[6.1.2 Error code in parameter part](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-1-2)；

```
3 (4 bytes): 上传的会话ID，告诉Step7上传会话ID；
```

举个例子：

![图39 上传结束的作业请求](https://image.3001.net/images/20181106/1541486656_5be13840a3fca.jpg!small)

图39 上传结束的作业请求

那PDU类型为Ack_Data时，End upload [0x1F]的Parameter中只有一个function。

图40所示，即为图39的响应：

![图40 上传结束的响应](https://image.3001.net/images/20181106/1541486677_5be1385584951.jpg!small)

图40 上传结束的响应

这样，整个上传过程就完成了！

**5.2.6 程序调用服务（PI service [0x28]）**

程序调用是用于在PLC执行修改执行/内存状态的日常工作。这些命令可以用于启动或停止PLC控制程序、激活或删除程序块。

当PDU类型为Job时，PI service [0x28]没有Data，只有Parameter，那Parameter的结构，如下：

```
1 (7 bytes): Unknown；2 (Unsigned integer, 2 bytes): Parameter block length；3 (?bytes): Parameter block，参数；4 (Unsigned integer, 1 byte):String length，PI service的字符串长度；5 (Character string, ASCII):PI (program invocation) Service name，程序调用服务名，参考6.8 程序调用服务名（PI service names）。
```

Parameter包含两个主要部分：

> 服务名称
>
> 参数：取决于方法类型，可以将它们看作是它的参数

服务名称及其相关参数的示例：

> _INSE：激活设备上下载的块，参数是块的名称（比如：OB 1）。
>
> _DELE：从设备的文件系统中删除一个块，该参数也是该块的名称。
>
> P_PROGRAM：设置设备的运行状态（启动、停止、复位）。
>
> _GARB：压缩PLC内存。
>
> _MODU：将ram复制到ROM，参数包含文件系统标识符（A/E/P）。

如果服务调用的参数是块的话，那么Parameter block的结构如下：

```
1 (1 byte): Number of block；2 (1 byte): Unknown，默认为0x00；3 (? bytes): filename，文件名：  1 (2 bytes, ASCII): Block type，块类型。具体类型，请参考6.7 功能块；  2 (5 bytes, ASCII): Block number，块编号；  3 (1 byte, ASCII): Destination filesystem（ASCII），目标的文件系统。其有P（Passive (copied, but not chained) module)、A (Active embedded module)、B (Active as well as passive module)三种文件系统；
```

举个例子，如图41所示：

![图41 _INSE（激活PLC模块）的作业请求](https://image.3001.net/images/20181106/1541486738_5be138926dc45.jpg!small)

图41 _INSE（激活PLC模块）的作业请求

上图可知服务名称是_INSE，参数是0B0004P（SDB4），那么它的作业请求是激活PLC中SDB 4，那么它的请求响应又是如何呢？如图42所示：

![图42 _INSE（激活PLC模块）的响应](https://image.3001.net/images/20181106/1541486759_5be138a737658.jpg!small)

图42 _INSE（激活PLC模块）的响应

而另一种情况，如图43所示：

![图43_MODU（复制RAM到ROM）的作业请求](https://image.3001.net/images/20181106/1541486774_5be138b66d350.jpg!small)

图43_MODU（复制RAM到ROM）的作业请求

上图中，其Parameter block中只有Argument。

**5.2.7 PLC STOP [0x29]**

PLC STOP 基本上跟[5.2.6 程序调用服务（PI service [0x28\]）](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#5-2-6)一致，唯一的区别就是它没有Parameter block，而它的PI service为P_PROGRAM。搞不明白为啥单独占用一个功能码~~~

看个例子吧，如图44所示：

![图44 PLC STOP的作业请求](https://image.3001.net/images/20181106/1541486800_5be138d0a3471.jpg!small)

图44 PLC STOP的作业请求

到此为此JOB和ACK_DATA类型下的功能码都介绍完了，接下来介绍S7commm协议的扩展。

### 5.3 协议拓展（Userdata）

上面介绍了S7Comm的JOB和ACK_DATA两个PDU类型，那接着将介绍PDU类型是UserData的内容，它用于编程/调试、读取SZL、安全功能、时间设置，循环读取等，可以说是S7Comm中最复杂的一部分。

大家不要慌哈，Are u ready?

Okay，当PDU类型为UserData时，其S7Comm结构，如图45所示：

![图45 S7Comm的结构（UserData）](https://image.3001.net/images/20181106/1541486860_5be1390c90f94.png!small)

图45 S7Comm的结构（UserData）

图45中蓝色部分为S7Comm头部，橘色为Parameter部分，具体的Parameter结构如下：

```
1 (3 bytes)：参数头（Parameter head）；2 (1 byte)：参数长度（Parameter length），它的可能是8字节或12字节；3 (1 byte)：未知定义；4 (1/2 byte，高位)：参数类型（Type），常见的类型可参考《6.9 拓展协议的参数类型》；5 (1/2 byte，Low nibble)：功能组（Function group），常见的功能组可参考《6.10 拓展协议的功能组》；6 (1 byte)：子功能码（SubFunction）；7 (1 byte)：序号。
```

接着就是一一介绍各个功能组。

**5.3.1 转换工作模式（Mode-transition [0x0]）**

当功能组为转换工作模式（Mode-transition）时，请求报文中是没有Data部分的，而主要起作用的是子功能码（Subfunction），常见的子功能码有：

```
STOP（0x00）：STOP模式；Warm Restart（0x01）：暖启动；RUN（0x02）：RUN模式；Hot Restart（0x03）：热启动；HOLD（0x04）：HOLD模式；Cold Restart（0x06）：冷启动；RUN_R (H-System redundant)（0x09）：H-System冗余运行；LINK-UP（0x0B）：LINK-UP模式；UPDATE（0x0C）：UPDATE模式。
```

关于暖启动、冷启动、热启动的区别可参考：[S7-400 CPU 启动(暖启动)，冷启动和热启动的区别是什么？ - ID: 34053758 - Industry Support Siemens](https://support.industry.siemens.com/cs/document/34053758/s7-400-cpu-启动(暖启动)，冷启动和热启动的区别是什么？?dti=0&lc=zh-CN)，至于冗余可参考： [何为冗余-找答案-工业支持中心-西门子（中国）有限公司（SLC）](http://wap.siemens.com.cn/service/answer/solved/29593.html)。

来看个栗子消化一下吧，如图46所示：

![图46 工作模式转换为暖启动](https://image.3001.net/images/20181106/1541486889_5be13929f3dbc.png!small)

图46 工作模式转换为暖启动

如图46中绿色部分为参数类型（Type）和功能组（Function group），蓝色框内容是子功能码（SubFunction），值是0x01，即为暖启动。

**5.3.2 程序员命令（Programmer commands [0x1]）**

程序员命令（Programmer commands）主要是工程师用于编程或调试，比如：监视/修改变量、读取修改诊断数据。所有的子功能码有：

```
请求诊断数据（Request diag data (Type 1)）：0x01;变量表（VarTab）：0x02;读取诊断数据（Read diag data）：0x0c;移除诊断数据（Remove diag data）：0x0e;清除（Erase）：0x0f;强制（Forces）：0x10;请求诊断数据（Request diag data (Type 2)）：0x13;
```

这里的请求报文和响应报文都和图45有点不一样，具体如图47所示：

![图47 功能码组为Programmer commands的报文结构](https://image.3001.net/images/20181106/1541486916_5be139442606c.png!small)

图47 功能码组为Programmer commands的报文结构

下面以变量表为例，变量表如图48所示：

![图48 变量表](https://image.3001.net/images/20181106/1541486933_5be13955b9f07.jpg!small)

图48 变量表

如果对 DB100.DBW 2进行监视，那么他的请求报文如图49所示：

![图49 监视变量表的请求报文](https://image.3001.net/images/20181106/1541486953_5be139692e3cd.png!small)

图49 监视变量表的请求报文

图49中的Header、Parameter在前面已经介绍了，重点介绍Data部分的结构，请求报文的结构如下：

```
1 (1 byte) : 返回码，具体的可参考6.6.1；2 (1 byte) :Transport sizes，指的数据类型，通常有bit、byte等，具体可参考6.4.2；3 (2 bytes) : 往后的数据长度，如图49为32个字节；4 (1 byte) : Unknown；5 (1 byte) : 报文类型（type of data），分为请求（0x14）、响应（0x04）；6 (2 bytes) : Item count和Item data的长度（Byte count）；7 (20bytes) : Unknown；8 (2bytes) : Item个数；9 (varibalebytes) : Item 1；  1 (1 byte) : 区域（Area）;  2 (1 byte) : 长度（Length (repetition factor)）；  3 (2 bytes) : 模块号（DB number）;  4 (2 bytes) : 偏移地址（Startaddress）。...n (varibalebytes) : Item n；
```

响应报文跟请求非常的像，但是还是有所不一样，响应报文结构如下：

```
1 (1 byte) : 返回码，具体的可参考6.6.1；2 (1 byte) :数据类型（Transport sizes），通常有bit、byte等，具体可参考6.4.2；3 (2 bytes) : 往后的数据长度，如图49为32个字节；4 (1 byte) : Unknown；5 (1 byte) : 报文类型（type of data），分为请求（0x14）、响应（0x04）；6 (2 bytes) : Item count和Item data的长度（Byte count）；7 (4bytes) : Unknown；8 (2bytes) : Item个数；9 (varibalebytes) : Item 1；  1 (1 byte) : 返回码，具体的可参考6.6.1；  2 (1 byte) :数据类型（Transport sizes），通常有bit、byte等，具体可参考6.4.2；  3 (2 bytes) : 往后的数据长度；  4 (varibale bytes) : Data。...n (varibalebytes) : Item n；
```

![img](https://image.3001.net/images/20181106/1541487155_5be13a338685b.jpg!small)

图50 监视变量表的响应报文

从图50中，得知DB100.DBW 2的值是61a8。

其它的子功能都比监视/修改变量表（VarTab）简单，在这就不一一介绍了，感兴趣的可以去研究研究。