TIA博途是全集成自动化软件TIA portal的简称，是西门子工业自动化集团发布的一款全新的全集成自动化软件。它是业内首个采用统一的工程组态和软件项目环境的自动化软件，几乎适用于所有自动化任务。



##### Part1 漏洞状态



![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2Ffff97ab2p00rysjxh0001c000j0002cm.jpeg)





##### Part2 漏洞描述



![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2Fb7fc3e3dj00rysjxh002rc000j100lmm.jpeg)



**分析环境:**

Win10

TIA Portal 15.1 Update 3



##### Part3 漏洞复现



\1. 安装TIA15.1和安装Update 3 更新

\2. 查看是否开启服务进程CCAgent.exe和端口8910

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2F8429a9c0p00rysjxh0001c000i7001um.jpeg)



![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2F9c030165p00rysjxh0001c000om001pm.jpeg)



\3. 运行测试脚本，查看进程是否崩溃

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2F407141c9p00rysjxh0001c000gr000pm.jpeg)



\4. 进程崩溃，复现成功！

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2Fc9d86f6dp00rysjxh0003c000j1002xm.jpeg)





##### Part4 漏洞分析



\1. 这里判断是否是加密通讯，如果非加密通讯函数流程走不到崩溃的点。需要注意。

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2Fbd848c90j00rysjxh0034c000rd00elm.jpeg)



\2. 这里校验HdrSize + BodySize 是否等于 MsgSize。如果它不相等，则被视为错误，并且不会处理消息。但是，攻击者可以在数据中自定义数据头大小和正文大小。

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2F467b364bj00rysjxh0094c000u000chm.jpeg)



\3. 由于把0xFFFF FFFF 用作有符号数，即-1。所以看到原本的ecx(0x74) 加 0xFFFF FFFF后变成 0x73 。所以通过这个校验流程。

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2Fca236dbaj00rysjxh0092c000u000bmm.jpeg)



\4. 这个流程又把0xFFFF FFFF用作无符号数，导致判断超过预设缓冲区大小0x1000，走到异常流程，导致程序崩溃。

![img](./西门子TIA Portal拒绝服务漏洞研究/images/url=http%3A%2F%2Fdingyue.ws.126.net%2F2023%2F0803%2F98eedefej00rysjxh001zc000mp0098m.jpeg)



分析完毕。



##### Part5 修复缓解建议



\1. 软件升级到最新版本

\2. 检测读取函数是否溢出