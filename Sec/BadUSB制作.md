# 玩转树莓派之zero w配合P4wnP1 ALOA实现badusb

 发表于 2023-10-13 分类于 [树莓派](https://zikh26.github.io/categories/树莓派/) ， [探究](https://zikh26.github.io/categories/树莓派/探究/)

## 前言

最近浅玩了一下树莓派，本以为要焊接电路板，搞硬件。也算是为之后拆路由器读芯片练练手，接触后发现给树莓派烧录完系统，基本还是玩的软件层（也可能是境界不够🤔）。本文记录了我用树莓派 `zero w` 配合 [P4wnP1 ALOA](https://github.com/RoganDawes/P4wnP1_aloa) 做了一个 **badusb** ，最终配合 `Cobalt Strike` 生成的木马以及红队大哥做的免杀，可以达到插谁，谁成肉鸡的效果😎



**声明**：文中所涉及的技术、思路和工具仅供以安全为目的的学习研究使用，任何人不得将其用于非法用途以及盈利等目的，由此产生的任何后果，自行承担！

## 效果演示



## 给树莓派烧录系统

在京东上买了个树莓派 `zero w` ，到手后看到是长这个样子的

![_-1234400694_IMG_20231012_145519_1697093734000_xg_0](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310121457256.jpg)

再准备一张内存卡（我用的 `16G` ）和读卡器

![_2131233179__cd67aa62f855909728f1bd3210ca6ed2_347696290_IMG_20231012_150450_0_xg_0](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310121505064.jpg)

下载 `SDFormatter` ，先格式化内存卡

![image-20230928125302819](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202309281253959.png)

这里确定选好盘后，直接点击格式化即可

然后去下载想要烧录的镜像，我这里是直接用的 [P4wnP1_aloa](https://github.com/RoganDawes/P4wnP1_aloa/releases/tag/v0.1.1-beta) ，它是一个基于 `kali` 的系统

![image-20231012151057467](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310121510600.png)

将镜像解压出来后，下载 `Win32DiskImager` ，用其将镜像烧录到内存卡中

![image-20230928125821950](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202309281258994.png)

选择好镜像和要写入的设备，点击写入即可

![image-20230928125854421](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202309281258475.png)

这里会有一个弹框，点击 `yes` ，等待十分钟左右烧录完毕

## 启动和访问树莓派

将烧录完系统的内存卡插入到树莓派，拿一根 `USB` 数据线插到图中标红的接口，这个接口既可以给树莓派供电又可以传输数据，而左边看起来相同的接口只可以供电

![image-20231012152802290](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310121528649.png)

如此树莓派就启动了，可以选择用一个转接头加上扩展坞连接键盘，并插上一根 `HDMI` 线连接一个显示器，当做正常的电脑来使用。也可以选择只插一根 `USB` 数据线进行供电，然后连接树莓派自身热点（密码为 `MaMe82-P4wnP1`），热点名称就是很显眼的这个

![image-20231012153230886](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310121532933.png)

通过 `ssh` 连接（用户名 `root`，密码 `toor`）

![image-20231012154234134](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310131221162.png)

因为我手头正好有显示器和扩展坞，所以这两种方法我都用过了。

## HIDScript

```
P4wnP1_aloa` 的 `web` 端其实做的挺好的，访问 `172.24.0.1:8000
```

![image-20231012155258706](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310131221640.png)

这里其他的选项，看名称或者查看官方说明都能知道个七七八八。我直接记录好玩的地方，选择这个 `HIDSCRIPT`

![image-20231012155641198](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310131222755.png)

这里我们可以编辑代码，让树莓派来充当 **badusb** 的作用，模拟键盘的输入。因为我玩的也比较浅，这里记住这五个的用法其实就差不多了

```
layout('us'); //键盘布局，这里运行脚本时一定要切成英文的输入法，最好用成美式键盘，不然可能会输出中文导致命令错误
typingSpeed(标准间隔,随机值); //ms为单位，标准间隔是每个字符敲击的间隔，随机值是敲击每个字符所落下的时间
delay(time); //ms为单位，等待时间
type('xxxxx\n'); //输入字符串，模拟键盘敲击按键
press('GUI r'); //按下按键再松开 ，这个按的是windows+r键
```

编写一段代码，用 `powershell` 来打开记事本，并写下几个字符串试试

```
layout('us');
typingSpeed(0,0);
press('GUI r');
delay(500);
type('notepad\n');
delay(800);
type('hello world\nit is test!\n');
type("it's cool!\n");
```

确实全程自动输入指定内容（注意：最好用成美式键盘，别忘记 `\n` 来模拟敲击回车）

![image-20231012161126193](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310131222369.png)

整个的过程也可以遥控，就是将树莓派插到主机 `A` 中，然后用另一台设备（手机也可以）连接树莓派的热点，来运行编写好的 `HIDScript` ，这样主机 `A` 的鼠标和键盘就可以自己动了

### HIDScript 执行始终处于 Running jobs问题

注意：我开始做的时候，点击 `RUN` 是无法成功执行 `HIDScript` 的，会始终处于 `Running jobs` 状态（如下）

![image-20231012161904822](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310121619986.png)

折腾了两天，并查阅资料，无果。并且在 `github` 的项目上有相关的 [Issues](https://github.com/RoganDawes/P4wnP1_aloa/issues/206) ，阅读之后也没发现到底是哪出了问题。最终我找同学借了六根 `USB` 数据线，逐一试过后，惊喜的发现有一根插上后运行 `HIDScript` 成功，其余五根均失败。这六根线都是可以传输数据和充电的，如此确定是数据线的某些未知原因导致的 `HIDScript` 执行是卡住（应该就是数据没传给主机）

## Badusb + 远控木马

为了当一把黑客小子😎，我打算一不做二不休，最终想实现这个树莓派插入一台电脑，就能直接对其进行控制（只是找同学的电脑进行学习测试😆）

思路：我选择用 `Cobalt Strike` （下文简称 `CS`）来生成一个远控木马（并找红队大哥做了下免杀…），然后将木马上传至自己的服务器，通过直接访问链接就可以进行下载。最后用 **badusb** 模拟键盘输入，执行下载木马的命令

`CS` 分为服务端和客户端，如果自己没有服务器的话，就只能把客户端和服务端部署在同一个局域网里，同一局域网的肉鸡上线后，通过服务端的转发，来实现客户端对其间接控制。如果有服务器的话，那服务端就可以部署到公网中，即使肉鸡和客户端处于两个不同局域网中，客户端依然可以通过服务端的转发，实现间接控制（前提是客户端和肉鸡都能上网😅）

利用 `nginx` 将服务器上的静态文件（恶意木马）通过 `HTTP` 协议展现给客户端，以便于用户直接下载。我是先安装了 `nginx` ，然后把几个恶意程序都放到了 `/var/www/html` 目录下，然后启动 `nginx` 服务。写一个测试文件，看下效果。这里在 `/var/www/html` 目录下放的是一个文本文件，通过 `ip + port` 直接访问这个文件就能查看到（如下图），如果是 `exe` 文件的话，访问其路径会自动下载文件。

![image-20231013094534872](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310130945972.png)

攻击的完整过程如下图，至于为什么不能让 **badusb** 插入后直接执行下载木马的命令，这是因为做完免杀后，实际上要下载三个文件。如果都写到 `HIDScript` 里的话，**badusb** 模拟键盘输入会出现错误，字符会乱序并且重复打印（具体原因不知道，经过测试姑且猜测是脚本太长了），为了缩短命令，我就做了一个启动脚本，真正下载木马并执行写在了启动脚本里。而 **badusb** 只需要下载启动脚本并执行即可

![image-20231013112141288](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202310131121410.png)