**随着网络强国、工业4.0，工控安全市场今年明显有相当大的改善，无论从政策还是客户需求，都在逐步扩大中。但是，搞工控安全研究的人员却寥寥无几，一方面，没有可以研究和学习的便利的环境；另一方面工控安全是个跨学课的技术，需要了解多方面的知识，有比较高的技术上的门槛。特别是工控系统中通信协议，在工控系统中通信协议存在众多标准，也存在众多私有协议，如果你有过使用组态软件的经历，你便会发现，在第一步连接设备时除连接设备的方式有以太网/串行等方式外，各家基本上都存在自己的私有通信协议。比如：西门子的是S7Comm协议。**

所以，本文主要介绍西门子的S7Comm协议（适用于S7-300、S7-400、S7-1200）。本文中S7Comm协议结构都是逆向而来，如有错误之处，请拍砖。

## 一、西门子PLC系统构成

在介绍西门子S7Comm协议，首先得明白西门子PLC的大概构造。虽然我们不必像专门编写PLC程序员那样。下图1就是一个组态完毕的西门子S7 300的模型：

![siemens-s7-300.jpg](https://image.3001.net/images/20181101/1541039511_5bda65976b35f.jpg!small)图1 西门子S7-300

根据标号，各模块分别是：

1.电源模块（PS），供电专用

2.CPU模块（CPU），负责处理信息

3.通信模块（IM）

4.数字量输入模块（DI）

5.数字量输出模块（DO）

6.模拟量输入模块（AI）

7.模拟量输出模块（AO）

想具体了解的，请阅读[西门子S7-300教程 第2章](https://wenku.baidu.com/view/86d25c104431b90d6c85c7cf.html)。

## 二、S7协议结构

S7Comm（S7 Communication）是西门子专有的协议，是西门子S7通讯协议簇里的一种。

S7协议的TCP/IP实现依赖于面向块的ISO传输服务。S7协议被封装在TPKT和ISO-COTP协议中，这使得PDU（协议数据单元）能够通过TCP传送。

它用于PLC编程，在PLC之间交换数据，从SCADA（监控和数据采集）系统访问PLC数据以及诊断目的。

S7Comm以太网协议基于OSI模型：

|      OSI layer       |        Protocol         |
| :------------------: | :---------------------: |
| 7 Application Layer  |    S7 communication     |
| 6 Presentation Layer | S7 communication (COTP) |
|   5 Session Layer    | S7 communication (TPKT) |
|  4 Transport Layer   |  ISO-on-TCP (RFC 1006)  |
|   3 Network Layer    |           IP            |
|  2 Data Link Layer   |        Ethernet         |
|   1 Physical Layer   |        Ethernet         |

其中，第1-4层会由计算机自己完成（底层驱动程序），关于这些神马的定义，大家可以上网查一下；

第5层TPKT，应用程数据传输协议，介于TCP和COTP协议之间。这是一个传输服务协议，主要用来在COTP和TCP之间建立桥梁；

第6层COTP，按照维基百科的解释，COTP 是 OSI 7层协议定义的位于TCP之上的协议。COTP 以“Packet”为基本单位来传输数据，这样接收方会得到与发送方具有相同边界的数据；

第7层，S7 communication，这一层和用户数据相关，对PLC数据的读取报文在这里完成。

可能会对TPKT和COPT迷惑，其实在具体的报文中，TPKT的作用是包含用户协议（5~7层）的数据长度（字节数）；COTP的作用是定义了数据传输的基本单位（在S7Comm中 PDU TYPE：DT data）。

![s7comm-osi.png](https://image.3001.net/images/20181101/1541039685_5bda664510a04.png!small)

图2 S7Comm协议OSI模型

## 三、TPKT协议

TPKT协议是应用程数据传输协议，介于TCP和COTP协议之间。这是一个传输服务协议，主要用来在COTP和TCP之间建立桥梁。

其英文介绍如下：

TPKT is an "encapsulation" protocol. It carries the OSI packet in its own packet's data payload and then passes the resulting structure to TCP, from then on, the packet is processed as a TCP/IP packet. The OSI programs passing data to TPKT are unaware that their data will be carried over TCP/IP because TPKT emulates the OSI protocol Transport Service Access Point(TSAP).

TPKT结构如图3：

![tptk-structure.png](https://image.3001.net/images/20181101/1541039741_5bda667d6e8c0.png!small)

图3 TPKT协议结构

其中，TPKT的结构为：

0 (Unsigned integer, 1 byte): Version，版本信息。

1 (Unsigned integer, 1 byte): Reserved，保留(值为0x00)。

2-3 (Unsigned integer, 2 bytes): Length，TPKT、COTP、S7三层协议的总长度，也就是TCP的payload的长度。

举个例子，如图4所示：

![tpkt-example.jpg](https://image.3001.net/images/20181101/1541039777_5bda66a140083.jpg!small)

图4 一个TPKT的例子

从图4中可知，其version=3，length=25（0x0019）。

## 四、COTP协议

COTP（[ISO 8073/X.224 COTP Connection-Oriented Transport Protocol](http://standards.iso.org/ittf/PubliclyAvailableStandards/index.html)）是OSI 7层协议定义的位于TCP之上的协议。COTP以“Packet”为基本单位来传输数据，这样接收方会得到与发送方具有相同边界的数据。

COTP协议分为两种形态，分别是COTP连接包（COTP Connection Packet）和COTP功能包（COTP Fuction Packet）。

### 4.1 COTP Connection Packet

COTP连接包（COTP Connection Packet）也就是S7Comm的握手包，其格式如图5所示。

![cotp-connection-structure.png](https://image.3001.net/images/20181101/1541039849_5bda66e965d8a.png!small)

图5 COTP连接包的结构

其中， COTP连接包的头结构为：

0 (Unsigned integer, 1 byte): Length，COTP后续数据的长度（注意：长度不包含length的长度），一般为17 bytes。

1 (Unsigned integer, 1 byte): PDU typ，类型有：

> 0x1: ED Expedited Data，加急数据
>
> 0x2: EA Expedited Data Acknowledgement，加急数据确认
>
> 0x4: UD，用户数据
>
> 0x5: RJ Reject，拒绝
>
> 0x6: AK Data Acknowledgement，数据确认
>
> 0x7: ER TPDU Error，TPDU错误
>
> 0x8: DR Disconnect Request，断开请求
>
> 0xC: DC Disconnect Confirm，断开确认
>
> 0xD: CC Connect Confirm，连接确认
>
> 0xE: CR Connect Request，连接请求
>
> 0xF: DT Data，数据传输

2~3 (Unsigned integer, 2 bytes): Destination reference.

4~5 (Unsigned integer, 2 bytes): Source reference.

6 (1 byte): opt，其中包括Extended formats、No explicit flow control，值都是Boolean类型。

7~? (length-7 bytes, 一般为11 bytes): Parameter，参数。一般参数包含Parameter code(Unsigned integer, 1 byte)、Parameter length(Unsigned integer, 1 byte)、Parameter data三部分。

算了，还是来个例子，更加明了：

![cotp-connection-request.jpg](https://image.3001.net/images/20181101/1541039884_5bda670cb6954.jpg!small)

图6 连接请求包

图6中，PDU类型为连接请求（0x0e），表示该数据包是一个连接请求包。为了更好对比，图7为图6的连接请求的响应包：

![cotp-connection-confirm.jpg](https://image.3001.net/images/20181101/1541039914_5bda672a5bf89.jpg!small)

图7 连接确认包

### 4.2 COTP Fuction Packet

相对而言，COTP Fuction Packet比COTP Connection Packet简单多了，其结构如图8所示：

![cotp-fuction-structure.png](https://image.3001.net/images/20181101/1541039951_5bda674fb735e.png!small)

图8 COTP功能包的格式

其中， COTPP功能包的头结构为：

0 (Unsigned integer, 1 byte): Length，COTP后续数据的长度（注意：长度不包含length的长度），一般为2 bytes。

1 (Unsigned integer, 1 byte): PDU type，类型有：

> 0x1: ED Expedited Data，加急数据
>
> 0x2: EA Expedited Data Acknowledgement，加急数据确认
>
> 0x4: UD，用户数据
>
> 0x5: RJ Reject，拒绝
>
> 0x6: AK Data Acknowledgement，数据确认
>
> 0x7: ER TPDU Error，TPDU错误
>
> 0x8: DR Disconnect Request，断开请求
>
> 0xC: DC Disconnect Confirm，断开确认
>
> 0xD: CC Connect Confirm，连接确认
>
> 0xE: CR Connect Request，连接请求
>
> 0xF: DT Data，数据传输

2 (1 byte): opt，其中包括Extended formats、No explicit flow control，值都是Boolean类型。

举个例子，如图9所示：

![cotp-dt-data.jpg](https://image.3001.net/images/20181101/1541039993_5bda677937094.jpg!small)

图9 数据传输包

上图中，PDU类型为连接请求（0x0f），表示该数据包是一个数据传输的包。

OK，COTP的两中结构介绍完了，接下来的S7Comm协议才是本文的重点。

## 五、S7Comm协议

上面，介绍了TPKT和COTP协议，现在开始介绍S7Comm协议，Are u ready？

S7Comm数据作为COTP数据包的有效载荷，第一个字节总是0x32作为协议标识符。

S7Comm协议包含三部分：

> Header
>
> Parameter
>
> Data

![s7comm-structure.png](https://image.3001.net/images/20181101/1541040032_5bda67a068b1f.png!small)

图10 S7Comm协议结构

根据实现的功能不同，S7 comm协议的结构会有所不同。

### 5.1 S7Comm Header

S7Comm的头，定义了该包的类型、参数长度、数据长度等，其结构如图11所示：

![s7comm-header-structure.png](https://image.3001.net/images/20181101/1541040058_5bda67ba4ed5b.png!small)

图11 S7Comm Header结构

所以，S7Comm Header的格式为：

0 (unsigned integer, 1 byte): Protocol Id，协议ID，通常为0x32；

1 (unsigned integer, 1 byte): ROSCTR，PDU type，PDU的类型，一般有以下值：

> 0x01 - JOB(Request： job with acknowledgement)：作业请求。由主设备发送的请求（例如，读/写存储器，读/写块，启动/停止设备，设置通信）；
>
> 0x02 - ACK(acknowledgement without additional field)：确认响应，没有数据的简单确认（未遇到过由S7 300/400设备发送得）；
>
> 0x03 - ACK_DATA(Response： acknowledgement with additional field)：确认数据响应，这个一般都是响应JOB的请求；
>
> 0x07 - USERDATA：原始协议的扩展，参数字段包含请求/响应ID（用于编程/调试，读取SZL，安全功能，时间设置，循环读取...）。

2~3 (unsigned integer, 2 bytes): Redundancy Identification (Reserved)，冗余数据，通常为0x0000；

4~5 (unsigned integer, 2 bytes): Protocol Data Unit Reference，it's increased by request event。协议数据单元参考，通过请求事件增加；

6~7 (unsigned integer, 2 bytes): Parameter length，the total length (bytes) of parameter part。参数的总长度；

8~9 (unsigned integer, 2 bytes): Data length，数据长度。如果读取PLC内部数据，此处为0x0000；对于其他功能，则为Data部分的数据长度；

来看一个例子解释一下，如图12所示：

![s7comm-header-1.jpg](https://image.3001.net/images/20181101/1541040362_5bda68ead2c39.jpg!small)

图12 一个S7Comm头结构的例子

其中最重要的字段就是ROSCTR，它决定了后续参数的结构，这个后面的章节中有详细的介绍。

在响应数据包中，还有可能存在错误信息。就拿图12为例，如果出错了，其响应包如图13所示：

![s7comm-header-2.jpg](https://image.3001.net/images/20181101/1541040570_5bda69ba2d38d.jpg!small)

图13 带有错误信息的响应包

其错误信息结构为：

10 (unsigned integer, 1 bytes): Error class，错误类型：

> 其详细的Error class，参考[6.1.1 头结构的错误类型](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-1-1)；

11 (unsigned integer, 1 bytes): Error code，错误代码；

由此，可见图13的错误类型是No error，至于错误代码，啥含义我也母知道。

为了更好理解，接下来就不按照Parameter、Data的顺序介绍，而是按照PDU类型进行介绍，尿急的赶紧上厕所哈！

### 5.2 作业请求（Job）和确认数据响应（Ack_Data）

上面介绍了S7Comm PDU的结构和通用协议头其头部结构。

S7Comm中Job和Ack_Data中的Parameter项的第一个字段是function（功能码），其类型为Unsigned integer，大小为1 byte，其详细的功能码，请参考[6.2.1 Job和Ack_Data的功能码](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-2-1)。决定了其余字段的结构、消息的目的。

所以接下来，将进一步介绍各功能码对应的结构和作用。

**5.2.1 建立通信（Setup communication [0xF0]）**

建立通信在每个会话开始时被发送，然后可以交换任何其他消息。它用于协商ACK队列的大小和最大PDU长度，双方声明它们的支持值。ACK队列的长度决定了可以同时启动而不需要确认的并行作业的数量。PDU和队列长度字段都是大端。

先说Job吧！当PDU类型为Job时，建立通信功能中Parameter的结构，如下图：

![s7comm-setup-communication-job.png](https://image.3001.net/images/20181101/1541040896_5bda6b000b968.png!small)

图14 S7comm的结构（建立通信的作业请求）

具体的Parameter结构，如下：

1 (Unsigned integer, 1 byte): Parameter part: Reserved byte in communication setup pdu，保留字节；

2 (Unsigned integer, 2 bytes): Max AmQ (parallel jobs with ack) calling；

3 (Unsigned integer, 2 bytes): Max AmQ (parallel jobs with ack) called；

4 (Unsigned integer, 2 bytes): Parameter part: Negotiate PDU length。协商PDU长度。

举个例子：

![s7comm-setup-communication-job.jpg](https://image.3001.net/images/20181101/1541040931_5bda6b23d08ab.jpg!small)

图15 建立通信的请求

那么其确认响应的结构如何呢？跟请求时一样的，如图14所示。那么图16为图15的确认响应：

![s7comm-setup-communication-ack_data.jpg](https://image.3001.net/images/20181101/1541040948_5bda6b3457c82.jpg!small)

图16 建立通信的确认响应

如图15、16所示，其协商结果为：ACK队列的大小为1；最大PDU长度为240。

**5.2.2 读取值（Read Var [0x04]）**

数据读写操作通过指定变量的存储区域（参考[6.3 区域（Area names）](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-3)），地址（偏移量）及其大小或类型（参考[6.4.1 Transport sizes in item data](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-4-1)）来执行。

先说Job吧！当PDU类型为Job时，那么其S7Comm结构，如图17所示：

![s7comm-read-var-job.png](https://image.3001.net/images/20181101/1541041049_5bda6b9984de4.png!small)

图17 S7comm的结构（读取值的作业请求）

所以，接下来的Parameter字段是item count（项目个数），其类型为Unsigned integer，大小为1 byte。

那么一个item的结构是咋样的呢？如下（图17中item1）：

0 (Unsigned integer, 1 byte): Variable specification，确定项目结构的主要类型，通常为0x12，代表变量规范；

1 (Unsigned integer, 1 byte): Length of following address specification，本Item其余部分的长度；

2 (Unsigned integer, 1 byte): Syntax Ids of variable specification，确定寻址模式和其余项目结构的格式；

> 其详细的Syntax Id，参考[6.5 Syntax Ids of variable specification](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-5)；

3(Unsigned integer, 1 byte): Transport sizes in item data，确定变量的类型和长度：

> 其详细的Transport size，参考[6.4.1 transport sizes in item data](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-4-1)；

4~5 (Unsigned integer ,2 byte): Request data length，请求的数据长度；

6~7 (Unsigned integer, 2 byte): DB number，DB模块的编号，如果访问的不是DB区域，此处为0x0000；

8 (Unsigned integer, 1 byte)：: Area，区域类型：

> 其详细的区域类型，参考[6.3 区域（Area names）](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-3)；

9~11(Unsigned integer, 3 byte): Address，地址。

头晕了吧？哈哈哈~~先举个例子：

![s7comm-read-var-job.jpg](https://image.3001.net/images/20181101/1541041076_5bda6bb49f29f.jpg!small)

图18 读值操作的作业请求

图17中item1是读取DB1的0x000010（DB1.DBX 2.0 BIT 1）值，并且类型为BIT的请求。

PDU类型为Job时，S7Comm结构介绍完了，那PDU类型为Ack_Data时，其S7Comm的结构如何呢？

![s7comm-read-var-ack-data.png](https://image.3001.net/images/20181101/1541041196_5bda6c2ca5c1f.png!small)

图19 S7comm的结构（读取值的确认数据响应）

是的，其Parameter只有function、item count两个字段。

继续，那么接下来的是Data啦！其结构如下：

0 (Unsigned integer, 1 byte): Return code，返回代码：

> 详细的Return code，请参考[6.6.1 Return values of an item response](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-6-1)；

1 (Unsigned integer, 1 byte): Transport size，数据的传输尺寸：

> 其详细的Transport size，参考[6.4.2 Transport sizes in data](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-4-2)；

2~3 (Unsigned integer, 2 bytes): Length，数据的长度；

4~4+length (?): Data，数据；

? (Unsigned integer, 1 byte): Fill byte，填充字节。

继续看图18响应的数据包，如图20所示：

![s7comm-read-var-ack_data.jpg](https://image.3001.net/images/20181101/1541041212_5bda6c3ca6319.jpg!small)

图20 读值操作的确认数据响应

图20中，item1是读取DB1的0x000010（DB1.DBX 2.0 BIT 1）值，并且类型为BIT的响应，其响应的数据为01

**5.2.3 写入值（Write Var [0x05]）**

Write Var中Parameter的结构跟[5.2.2 读取值（Read Var[0x04\]）](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#5-2-2)一样，但是Write Va还需写入值，所以Write Var比Read Var多Data项。结构如下：

![s7comm-write-var-job.png](https://image.3001.net/images/20181101/1541041304_5bda6c9816e82.png!small)

图21 S7comm的结构（写入值的作业请求）

由此，Data的结构为：

0 (Unsigned integer, 1 byte): Return code，返回代码，这里是未定义，所以为Reserved（0x00）；

1 (unsigned integer, 1 byte): Transport size，确定变量的类型和长度：

> 详细的Transport size，参考[6.4.2 Transport sizes in data](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-4-2)；

2-3 (unsigned integer, 2 bytes): Length，写入值的数据长度；

4 (1 byte): Data，写入的值；

5 (unsigned integer, 1 byte): Fill byte，填充字节，如果数据的长度不足Length的话，则填充；

举个例子：

![s7comm-write-var-job.jpg](https://image.3001.net/images/20181101/1541041321_5bda6ca9ca10e.jpg!small)

图22 向地址为0x000008的Flags（M）写入0x00的作业请求

图22中，是一个向地址为0x000008的Flags（M）写入0x00的作业请求。

那PDU类型为Ack_Data时，其S7Comm的结构如何呢？

![s7comm-write-var-ack-data.png](https://image.3001.net/images/20181101/1541041338_5bda6cbae6046.png!small)

图23 S7comm的结构（写入值的确认数据响应）

对的，Parameter也只有function、item count两个字段。而Data中也只有一个Return code字段，其结构如下：

0 (Unsigned integer, 1 byte): Return code，返回代码：

> 详细的Return code，请参考[6.6.1 Return values of an item response](https://laucyun.com/3aa43ada8cfbd7eca51304b0c305b523.html#6-6-1)；

继续看图22的响应数据包，如图24所示：

![s7comm-write-var-ack-data.jpg](https://image.3001.net/images/20181101/1541041354_5bda6ccae0f39.jpg!small)

图24 向地址为0x000008的Flags（M）写入0x00的确认响应

图24中的item1，说明向地址为0x000008的Flags（M）写入0x00成功！

未完待续。