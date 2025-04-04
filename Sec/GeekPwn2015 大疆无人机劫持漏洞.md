# 0x00 背景

------

在2015年GeekPwn的开场项目中，笔者利用一系列漏洞成功演示劫持了一架正在飞行的大疆精灵3代无人机，夺取了这台无人机的控制权，完成了可能是全球首次对大疆无人机的劫持和完整控制。GeekPwn结束后，组委会立即将漏洞通知给官方，而大疆也很快完成了漏洞的修复。今年的3月15号，大疆发布了全新一代的精灵4代无人机，精灵3代从此退居二线；同时央视315晚会也对去年GeekPwn的这个劫持项目进行了详细的报道。

考虑到这些漏洞的修复已经过了足够长的时间，我们决定公开漏洞的完整细节和利用流程，希望能为国内的方兴未艾的射频安全研究圈子贡献自己的一份力量。

本文争取以零基础的角度对整个发现和利用过程抽丝剥茧，并尽量详细阐述这个过程中涉及的技术细节。本文涉及的技术细节适用大疆精灵3代，2代和1代，不适用最新的精灵4代无人机。由于行文时间仓促，如有疏漏敬请斧正。

# 0x01 攻击场景讨论：风险真实存在但可控

------

可能是因为近两年无人机的曝光率颇高，去年GeekPwn上完成无人机劫持项目后感兴趣的电视台和媒体并不少，也引发了普通群众的讨论和担心。

虽然我们已经证明并演示了精灵系列无人机是可以被劫持和完整控制的，但想要在实际环境中的直接将公园、景区、街道上空飞行的无人机据为己有，信号增益和劫持后的稳定控制仍然是需要深入研究的问题。或许在官方遥控器上加载自己的万能遥控器ROM，然后直接借用官方遥控器的信号增益和控制系统，会是一个可行的方案。

此外，造成劫持的漏洞已经得到合理的修复，新版ROM发布也已经超过4个月。随着安全研究者的攻防研究以及官方的重视，实际能攻击的精灵无人机也会越来越少。

所以，我们的结论是，普通群众不用过于担忧无人机的安全问题，反而应该更关注越来越多的走入普通人家的智能设备的安全问题。顺便提一下，这块我们团队亦有关注（比如同样是参加了GeekPwn 2015和央视315晚会的烤箱和POS机），后续还会有更多的研究成果放出。

好了，现在开始我们的无人机劫持之旅。

# 0x02 抽丝剥茧：精灵系列遥控原理全解析

------

### 0.射频硬件初探

要黑掉无人机，第一步要做的是信息收集。我们先来了解一下精灵3代所使用的射频硬件。

![p1](http://drop.zone.ci/images_result/images/2016032414254844813179.png) 图1 拆开的精灵3代遥控器（左图）和无人机主机（右图）

左翻右翻，经过了一系列艰难的电焊拆解和吹风机刮除保护膜后，终于找到了负责射频通信的芯片和负责逻辑的主控芯片，并识别出了它们的型号。看得出来大疆对电路板刻意做了一些防拆解和信息保护。

从下面的图中能识别出来，主控芯片选择的是知名大厂NXP的LPC1765系列，120MHz主频，支持USB 2.0，和射频芯片使用SPI接口进行通讯。而射频芯片则是国产BEKEN的BK5811系列，工作频率为5.725GHz – 5.852GHz或者5.135GHz – 5.262GHz，共有125个频点，1MHz间隔，支持FSK/GFSK调制解调，使用ShockBurst封包格式，并且支持跳频，使用经典的SPI接口进行控制。

![p2](http://drop.zone.ci/images_result/images/2016032414255030203239.png) 图2 主控芯片

![p3](http://drop.zone.ci/images_result/images/2016032414255216522336.png) 图3 射频芯片

而这个参数强大的国产射频芯片激起了我们的兴趣，经过一些挖掘，发现这个芯片原来山寨自NORDIC的nRF24L01+，没错，就是这个号称性价比之王的nRF24L01+ 2.4GHz射频芯片的5.8GHz版本，更有意思的是这两个不同厂家芯片的datasheet中绝大部分内容都是通用的。

通过这些基本的硬件信息确定了射频的频段后，我们马上拿出HackRF在gqrx中观察5.8GHz的信号。看着瀑布图（下图4）中跳来跳去的小黄线，我们意识到精灵3的射频通讯应该是跳频的，而在不知道跳频序列的情况下，无法对射频信号进行完整解调。此时HackRF的射频分析基本上派不上用处，唯有通过逻辑分析仪来看看射频芯片是如何跳频的。

![p4](http://drop.zone.ci/images_result/images/2016032414255633884418.png) 图4 使用gqrx观察射频信号

### 1.不得已的控制逻辑追踪

从上一节获得的硬件信息中，我们已经知道主控芯片和射频芯片之间是采用SPI接口进行通讯和控制的，因此只要从BK5811的引脚中找到SPI需要的那四个引脚，连上逻辑分析仪，对这四个引脚的电位变化进行采样分析，我们就能看到主控芯片是如何控制射频芯片的跳频了。

**SPI接口定义**

SPI协议本身其实挺简单的，在CS信号为低电位时，SCK通过脉冲控制通讯的时钟频率，每个时钟周期里，SI为输入，SO为输出，通过SI和SO在每个时钟里高低电位的切换构成一个bit，每八个时钟周期构成一个字节，从而形成一个连续的字节流，一个字节流代表一个命令，由射频芯片的datasheet约定好。SPI协议通讯示意图如下所示，其中四个引脚分别为：

- SO（MISO）：主设备数据输出，从设备数据输入。
- SI（MOSI）：主设备数据输入，从设备数据输出。
- SCK（CLK）：时钟信号，由主设备产生。
- CS（CSN）：从设备使能信号，由主设备控制。

![p5](http://drop.zone.ci/images_result/images/2016032414255859259512.jpg) 图5 SPI协议通讯示意图

**连接逻辑分析仪**

通过BK5811的datasheet，我们定位到了SPI通信的那几个引脚（如图6），通过万用表确认引脚连通性，然后在可以电焊的地方通过飞线连上逻辑分析仪的测试钩，折腾了很久总算连上了（如图7）。

![p6](http://drop.zone.ci/images_result/images/2016032414260091197615.png) 图6 BK5811中SPI引脚定义

![p7](http://drop.zone.ci/images_result/images/2016032414260343151715.png) 图7 通过电焊和飞线将BK5811的SPI引脚连上逻辑分析仪

随后，从逻辑分析仪中，我们得到了作为安全人员来说最喜欢的二进制数据流。

**射频芯片控制命令解析**

在BK5811的datasheet中，明确定义了它所支持的每一条SPI命令。通过连续的电位变化传过来一个完整的SPI命令如下所示：

![p8](http://drop.zone.ci/images_result/images/2016032414260545855813.png) 图8 逻辑分析仪中的一个SPI命令

其中0x30是命令号，高3位代表操作是写BK5811的寄存器，而寄存器id由这个字节中的低5位决定，是0x10，而0x10代表写的内容是ShockBurst的发送地址（类似以太网的mac地址）。而后面五字节（0x11 0x22 0x33 0x44 0x19）则是发送地址本身。

**跳频逻辑总结**

通过一段时间的观察，我们发现SPI命令颇为简单，为了方便观察大量命令的序列，我们按照datasheet中的定义写了一个解析脚本，在脚本的帮助下终于整理清楚了跳频的流程。

![p9](http://drop.zone.ci/images_result/images/2016032414260727302913.png) 图9 SPI命令解析脚本

在大疆的定义下，完整的跳频序列有16个频点，这些频点在遥控器和无人机主机配对（一般发生在出厂前）时通过随机产生，一旦确定后就存储固定起来，除非手动重新配对。

遥控器打开后，会以7ms的周期，按照跳频序列指定的顺序来变化射频发射的频率，16次（112ms）一个循环，而在每一个周期内，发射一次遥控的控制数据。一个典型的SPI命令序列如：`<跳频> 1ms <发包> 6ms`

![p10](http://drop.zone.ci/images_result/images/20160324142608130291012.png) 图10 遥控器SPI命令数字逻辑示意图

对于无人机主机，则是以1ms的周期来变化接收信号的频率，一旦收到来自遥控器的射频信号（BK5811会使用上文所说的发送和接收地址来识别通过），则转而进入7ms的周期，和遥控器保持同步。一旦信号丢失，马上又恢复1ms的跳频周期。一个典型的SPI命令序列如：`<跳频> <查包> 1ms <查包> 1ms <查包> 1ms <查包> 1ms <查包> 1ms <查包> 1ms <查包>`。

![p11](http://drop.zone.ci/images_result/images/20160324142610799301117.png) 图11 无人机主机SPI命令数字逻辑示意图

从上面的分析我们能注意到，遥控器只负责发送数据，无人机主机只负责接收数据，两者之间并无射频上的交互。这为我们后面覆盖遥控器的信号打好了基础。

### 2.模拟信号到数字信号的鸿沟

在搞清楚遥控的工作流程后，我们知道是可以对其进行完全的模拟（先假设射频序列已知），创造出一个以假乱真的遥控来。但在加工二进制命令前，如何完成二进制命令中数字化的数据和真实世界中连续的电磁波之间的转换困扰了我们很久，笔者甚至很长一段时间都在想重回大学修满通信专业的科目。

**电磁波和GFSK制式的基本原理**

先补一点从学通信的同事那里偷师回来的基本常识。

电磁波在我们的世界中连续的传播，通过特定的方式可以使其携带二进制信息，这个方式称为调制解调。发送数据时，一般是将的调制好的基带信号（含二进制信息）和载波信号叠加后进行发送，通常基带信号的频率会比载波信号频率低很多，如BK5811的载波信号频率在5.8GHz左右，但基带信号的频率仅为2MHz。而接收方通过解调和滤波，将基带信号从接收到的载波信号中分离出来，随后进行采样和A/D转换得到二进制数据。

FSK（Frequency-shift keying）是一种经典的基于频率的调制解调方式，其传递数据的方式也很简单。例如约定500KHz代表0，而1000KHz代表1，并且以1ms作为采样周期，如果某1ms内基带信号的频率是500KHz，这表明这是一个0，而如果下1ms内基带信号的频率为1000KHz，那表明下一位二进制比特是1。简单来说，FSK制式就是通过这样连续的电磁波来连续的传递二进制数据。

![p12](http://drop.zone.ci/images_result/images/20160324142612912191214.png) 图12 FSK调制解调示意图

而GFSK制式仅仅是在FSK制式的基础上，在调制之前通过一个高斯低通滤波器来限制信号的频谱宽度，以此来提升信号的传播性能。

**GFSK解调和IQ解调**

在理解了GFSK制式的原理后，接下来我们尝试在HackRF的上写出GFSK解调脚本，从一段遥控实际发出的电磁波中提取二进制数据（如下图13）。需要注意的是HackRF收发的射频数据另外采用了IQ调制解调，代码上也需要简单处理一下。

![p13](http://drop.zone.ci/images_result/images/20160324142614649161312.png) 图13 在空中传播的GFSK电磁波（IQ制式）

由于没有找到现成的解调代码，只好在MATLAB上（如下图14）摸爬滚打了许久，并恶补了许多通信基础知识，折腾出（如下图15）GFSK解调脚本，并成功模拟遥控器的跳频逻辑，能够像无人机那样获取每一次跳频的数据。至此， 我们再次得到了作为安全人员来说最喜欢的二进制数据流。

![p14](http://drop.zone.ci/images_result/images/2016032414261669665144.jpg) 图14 MATLAB中模拟GFSK解调

![15](http://drop.zone.ci/images_result/images/20160324142619448111511.png) 图15 GFSK解调脚本工作图

**遥控控制数据总结**

经过分析，一条典型的遥控控制数据如下（图16）所示（最新版本固件和稍旧版本的固件协议，格式略有不同）：

![p16](http://drop.zone.ci/images_result/images/20160324142620965431610.png) 图16 两种类型的遥控控制数据

最开始的5个字节为发送方的ShockBurst地址，用于给无人机验证是不是配对的遥控器。

接下来的26字节为遥控数据本身（上下，左右，油门，刹车等遥控器上的一切操作），我们详细来讲解下。

遥控器上的控制杆的一个方向（如上+下，左+右）由12bit来表示。如表示左右方向及力度的数值`power_lr`由上数据的第5个字节和第6个字节的低4位决定，控制杆居中时`power_lr`为0x400（1024），控制杆拉至最左时`power_lr`为0x16C（364），而拉至最右时`power_lr`为0x694（1684）。也就是说，遥控器可以将控制杆左和右，力度可分为660级，并在控制数据中占用12bit传输给无人机主机，主机针对不同的力度执行不同的飞行行为。

![p17](http://drop.zone.ci/images_result/images/20160324142622783551710.png) 图17 遥控控制数据解析代码片段

其他遥控控制杆的数据也非常类似，故不再赘述。值得注意的是，所有26字节的遥控控制数据是一次性的发给无人机的，故上下，左右，前进后退，油门刹车等所有行为都是并行无干扰的。这也是无人机遥控性能指标中经常说的支持6路信号，12路信号的含义。

控制数据中最后的1个字节位CRC8校验位（旧版是CRC16），是前面的31字节的CRC8/CRC16校验结果，校验错误的数据将被抛弃。

### 3.遥控器和无人机通讯逻辑总结

通过以上漫长的分析过程，我们总算完全搞懂了在遥控器上拨动控制杆的行为，是如何一步步反馈到无人机的飞控程序来完成对应的飞行行为。简单整理下：

1. 遥控器和无人机开机后，遥控器负责发送数据，无人机负责接收数据。它们通过共同的跳频序列的高速跳频来保持一个数据链路，链路故障有一定能力能迅速恢复。
2. 无人机每7ms就会收到一次遥控器发出的32字节控制数据，控制数据只有一条命令一种格式，所有控制杆和开关的状态会一次性发送到无人机。无人机收到数据后会进行地址校验和CRC校验，确保数据是正确无误的。
3. 用户在操纵遥控器的过程中，操控的行为和力度都会在7ms内通过那32字节控制数据反馈至无人机，接着由无人机的飞控程序来完成对应的飞行行为。

# 0x03 各个击破：完全控制无人机

------

从遥控器的通讯逻辑来看，想要通过HackRF这类SDR设备覆盖遥控器发出的射频数据来劫持无人机。必须解决以下几个问题：

1. 虽然通过HackRF来收发GFSK数据已经没有问题，但不知道跳频序列根本无法和无人机保持同步。
2. 如何打断遥控器原本和无人机之间的稳定射频链路，并同时建立和无人机之间新的稳定链路。
3. 大疆遥控器的射频功率做了大量优化，有效控制距离达一公里，HackRF的射频频率难以企及。

下面我们来看看如何逐个击破这几个问题。

### 0.伪造遥控器：信道的信息泄漏漏洞

在通过脚本对遥控器信号进行GFSK解调时，我们发现了BK5811芯片一个奇怪的现象：芯片在某个频道发送数据时，会同时向临近的特定频道发送同样内容数据内容。举个例子来说，同在+7ms这一时刻，除了会向13号频道发送属于这个频道的数据外，还会向其他一些特定的频道发送原本属于13号频道的数据。

```
#!bash
+ 7ms: Channel 13,
+ 7ms: Channel 09,
+ 7ms: Channel 21,
```

这个奇怪的现象虽然不会影响射频的功能，只是多了一些冗余数据，但却成了我们得到遥控器跳频序列的突破点，实实在在的构成了一个信息泄露漏洞。

我们可以通过脚本，从5725MHz到5850MHz进行遍历，每次隔1MHz，刚好覆盖BK5811的每一个频道。遍历监听时，考虑单个频点的情况，我们能得到冗余数据（假设监听61号频道）如下：

```
#!bash
+ 0ms: Channel 61,
+ 7ms: Channel 13,
+ 21ms: Channel 09,
+ 112ms: Channel 61,
```

因为我们已经明确112ms是一次跳频序列的循环，那么从冗余数据中我们可以推论：

```
#!bash
ch61 + 1 Step(7ms) = ch13
ch13 + 3 Step(21ms) = ch09
ch09 + 12 Step(84ms) = ch61 
```

换成文字结论即是：如果61号频道是跳频序列的第1个，那么13号频道是第2个，9号频道是第4个，一个一个频道的去遍历，就可以把这个序列补充完整。实际遍历时我们发现，HackRF脚本仅需要30到120秒，不需要遍历全部127个频道，即可推论和补齐完整的16个频点及跳频序列（如下图所示）。

![p18](http://drop.zone.ci/images_result/images/2016032414262452986187.png) 图18 HackRF脚本遍历后得到完整的跳频序列

通过这个特殊的信息泄露漏洞，配合遥控器的调频规律可快速得到跳频序列，但我们也不清楚为什么BK5811芯片会存在这样的信息泄露漏洞。随后我们拿nRF24L01+也做了类似的测试，发现nRF24L01+也同样会产生同样的问题。

### 1.劫持无人机：信号覆盖漏洞

下面来看看信号覆盖的问题如何解决。有个关键的前提是遥控器只发数据，无人机只收数据，它们之间没有交互。

在之前进行逻辑分析的时候我们发现，不管无人机是1ms跳频一次还是7ms跳频一次，它实际上只会接收跳频完毕后最早发给它的合法数据包。正常情况下可能是跳频完毕后的第5ms时，收到了遥控器发过来的数据，再下一次跳频后的5ms时，再收到遥控器发过来的下一次数据。

那如果我们能一直早于遥控器发出数据，无人机岂不是就直接使用我们的数据了？确实是这样的。假设我们的控制脚本中设置为6ms跳频，我们很快能夺取无人机的控制权（7次跳频内）。但遥控器也会夺回控制权，最终就会出现无人机有1/7的数据来自遥控，6/7的来自黑客的局面。

这其实是一场信号争夺战，那么有没有办法让无人机更稳定的更稳定接收我们的信号呢？如果我们把跳频时间设置为 6.9ms，跳频后每隔0.4ms（Arduino UNO R3的速度极限）发送一次遥控控制数据的话，虽然夺取无人机控制权需要更长的时间（约10s），但一旦获得控制权，在0.4ms发送一次数据的高刷新率覆盖之下，遥控器基本没可能夺回控制权。

![p19](http://drop.zone.ci/images_result/images/2016032414262684909197.png) 图19 伪造遥控器的SPI命令数字逻辑

至此，劫持无人机的基本技术问题已经通过一个信息泄漏漏洞和一个信号覆盖漏洞解决了。

### 2.稳定性 & 可用性优化

------

在实现控制脚本的过程中，HackRF存在的两个严重限制：一方面HackRF使用USB通讯接口决定了它的通讯延迟巨大（指令延迟约为30ms），上文中动辄0.4ms的控制精度HackRF做不到；另外一方面，HackRF在5.8GHz频段的信号衰减严重（信号强度仅为遥控器的1%，可能是通用天线在高频段增益偏低），估计只有在贴着无人机射频芯片的情况下才有作用。天线问题故无法使用HackRF劫持无人机。

灵机一动，我们想到了和遥控器类似的做法：通过Arduino UNO R3单片机平台来操作BK5811芯片，直接在Arduino上实现我们的控制逻辑。当然，再加一个某宝上淘的有源信号放大器，如下图所示。根据测试，有效控制范围为10米左右。

![p20](http://drop.zone.ci/images_result/images/2016032414263221791207.png) 图20 无人机劫持模块全家福

最终，通过了漫长的分析和各种漏洞利用方法的尝试后，我们完成了对大疆无人机的劫持。通过HackRF遍历和监听，然后将序列输入到Arduino中，在Arduino中完成对无人机信号的劫持，最后来通过Arduino上连接的简易开关来控制无人机。控制效果可以参看这个央视315中的视频片段。

# 0x04 后记：攻是单点突破，防是系统工程

------

从漏洞分析和利用的过程来看，大疆在设计无人机和射频协议时确实考虑了安全性的问题，其中跳频机制虽然很大程度上提升了协议的破解难度，但却被过度的依赖。笔者和团队长期从事腾讯产品的漏洞研究工作，深知如所有其他漏洞攻防场景一样，分散而孤立的防御机制跟本无法抵御黑客的突破或绕过，指望一个完美的系统来抵御黑客，如同指望马奇诺防线来抵御德国军队的入侵一样不现实。而更现实情况是攻和守的不对称，攻击者利用单点的突破，逐层的推进，往往会领先防御者一大截。

防御者就无计可施了吗？当然不是。聪明的防御者一定懂得两个系统性的思路：未知攻焉知防和借力。一方面防守者必须是优秀的攻击者，才有可能嗅得到真正攻击者的蛛丝马迹，才有可能在关键节点上部署符合实际情况；另外一方面防守者必须借助自己是在企业内部这一优势和业务并肩作战，利用业务的资源和数据这些攻击者拿不到的资源，配合对攻击的理解，建立对攻击者来说不对称的防御系统。

另外一个层面，智能硬件行业各个厂商对安全的重视令人堪忧。作为无人机行业绝对第一的大疆，尚且存在严重的安全问题，更不要说其他公司——笔者和TSRC物联网安全研究团队近两年业余时间对智能硬件安全的研究也印证了这个结论。二进制漏洞的复杂性和门槛决定了这种漏洞类型很少有机会出现在公众的视野中，但在更隐晦的地下，二进制漏洞攻击者的力量正在以防御者无法企及的速度悄然成长。也许等到阿西莫夫笔下《机械公敌》中的机器人社会形态形成时，我们要面对的不是人工智能的进化和变异，而是漏洞攻击者这种新时代的恐怖分子。

最后，感谢我有一把刷子、zhuliang、泉哥、lake2在整个破解过程中的支持。

# 0x05 相关链接

------

1. http://v.qq.com/iframe/player.html?vid=m0019do4elt&width=670&height=502.5&auto=0
2. http://2015.geekpwn.org/
3. http://www.dji.com/cn/newsroom/news/dji-statement-15mar
4. http://www.bekencorp.com/Botong.Asp?Parent_id=2&Class_id=8&Id=14
5. https://github.com/mossmann/hackrf
6. https://www.arduino.cc/en/Main/ArduinoBoardUno
7. https://github.com/JiaoXianjun/BTLE
8. http://blog.kismetwireless.net/2013/08/playing-with-hackrf-keyfobs.html