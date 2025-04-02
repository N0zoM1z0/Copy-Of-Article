# 前言

由于工作需要，特意翻查了MQTT的相关漏洞，并一一学习复现，在此做以学习记录，没有恶意，如有抄袭，请私信作者删除。

**技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**

# 介绍

MQTT协议我就不介绍了，[这里](https://zhuanlan.zhihu.com/p/421109780)讲得很详细，点击即可跳转。

# 环境搭建

在这里我是用ubuntu来搭建MQTT服务器。

```
安装MQTT服务：
sudo apt-get install mosquitto mosquitto-clients -y安装完成后查看是否安装成功：sudo systemctl status mosquitto.service
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231221113338731-1733176956.png)

可以看到MQTT服务已经在运行了，接下来是修改配置文件。

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
MQTT的配置文件叫mosquitto.conf ，一般存放在 /etc/mosquitto 目录下

sudo vim /etc/mosquitto/mosquitto.conf 

在文件最底下添加如下内容：

listener 1883
allow_anonymous true
password_file /etc/mosquitto/pwfile.example
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

内容解析：

listener是MQTT监听的端口号，可以自行修改。

allow_anonymous是匿名访问漏洞的罪魁祸首，当为true时，便支持匿名访问，为false则禁止匿名访问。

password_file是存放MQTT账号密码的文件参数。

修改完后文件内容如下：

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231221115128262-640196078.png)

使用 mosquitto_passwd 可以添加账号密码。

```
使用方法： mosquitto_passwd 存放密码文件路径 账号命令如下：
sudo mosquitto_passwd /etc/mosquitto/pwfile.example test
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231221115738572-1118324880.png)

原来内置了一些账号，如果不想用内置账号，也可以使用 -c 来指定创建存放密码文件路径，需要在配置文件中修改password_file。

配置完MQTT协议后需要重启MQTT服务。

```
命令如下：
sudo systemctl restart mosquitto.service
```

接下来运行MQTT协议 发布和订阅 主题就行了。

```
订阅主题命令：
sudo mosquitto_sub -h 服务器ip -t 订阅的主题 -u 用户名 -P 密码

发布主题命令：
sudo mosquitto_pub -h 服务器ip -t 订阅的主题 -u 用户名 -P 密码 -m 发布的消息
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231221140324945-1216984963.png)

这就算成功了。

# 工具安装

这里使用mqtt-pwn工具做复现。

```
sudo git clone https://mirror.ghproxy.com/https://github.com/akamai-threat-research/mqtt-pwn.git
```

下载完成后进到mqtt-pwn目录，使用 chmod 赋予整个目录权限（没有权限可能会导致运行报错）。

```
sudo chmod -R 777 *
```

mqtt-pwn是使用docker部署的，所以需要先安装docker容器。

```
sudo apt-get install docker-compose docker.io -y
```

 cd进入mqtt-pwn的目录进行安装

```
sudo docker-compose up --build --detach
```

运行过程中会报错，报错如下：

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231222130914939-1765946071.png)

这报错原因是因为debian的jessie版本已经不维护了。

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231222132412054-1309776292.jpg)

修改Dockerfile

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
sudo vim Dockerfile

在 RUN apt-get update 前加入如下代码：

RUN mv /etc/apt/sources.list /etc/apt/sources.list.bak && echo "deb http://archive.debian.org/debian/ jessie main" >/etc/apt/sources.list && echo "deb-src http://archive.debian.org/debian/ jessie main" >>/etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security jessie/updates main" >>/etc/apt/sources.list && echo "deb-src http://archive.debian.org/debian-security jessie/updates main" >>/etc/apt/sources.list在install中添加 --force-yes
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231222140656126-109246333.png)

修改完Dockerfile文件后，需要删除docker中报错的镜像，即 <none> 和 python。

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
先使用 sudo docker images 查看所有镜像信息
然后使用删除命令进行镜像删除：

sudo docker rmi -f [IMAGE ID]

这里的 IMAGE ID 为 images 中的 IMAGE ID
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

再重新运行 sudo docker-compose up --build --detach 即可。

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223104109181-1431426280.png)

看到successfully就是成功了。

```
运行启动命令：
sudo docker-compose run cli
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223105253678-1840884556.png)

# 攻击复现

## 一、匿名访问漏洞

### 漏洞描述

由于MQTT默认开启匿名访问，或者在配置文件中配置 allow_anonymous 参数不正确导致可被匿名访问。

### 漏洞复现

使用MQTT-PWN尝试匿名访问。

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
匿名连接命令：

connect -o 192.168.111.131

验证命令：

system_info
```

[![复制代码](https://assets.cnblogs.com/images/copycode.gif)](javascript:void(0);)

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223110921459-1103416048.png)

出现MQTT协议基础信息，证明存在MQTT匿名访问漏洞。

```
先执行 discovery 
待出现 finished! 的字样
再执行 scans 查看发现了哪些主题，使用 -i 参数接 id 订阅
scans -i 1
最后执行 messages  可查看通信的消息
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223114340553-1557765584.png)

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223114353958-1429713933.png)

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223114405095-4658354.png)

具体是怎么执行的，我还没研究，就先到这吧。

### 修复建议

在配置文件中将 allow_anonymous 参数修改为 flase，若配置文件中没有该参数，添加一个即可。

### 二、暴力破解攻击

MQTT-PWN自带有暴力破解功能，我们先把MQTT协议的匿名访问配置禁用了，再进行暴力破解测试。

```
打开mqtt配置文件，修改allow_anonymous参数为false即可，重启mqtt协议即可
sudo vim /etc/mosquitto/mosquitto.conf
sudo systemctl restart mosquitto.servicesudo mosquitto_sub -h 192.168.111.131 -t test -u "test" -P "test"
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223115339799-1688655926.png)

重启MQTT协议后，启动MQTT-PWN进行暴力破解。

```
sudo docker-compose run cli

暴力破解的命令如下：
bruteforce --host ip --port port
默认为 1883 端口
```

MQTT-PWN会根据自带的用户名字典和密码字典进行暴力破解，自带的字典在 mqtt-pwn/resources/wordlists/ 目录下，当然你也可以自定义字典，只需将字典进行替换即可。

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223120217135-394856378.png)

得到账号密码，进行账号密码连接即可。

```
connect -o 192.168.111.131 -u test -w test
```

![img](https://img2023.cnblogs.com/blog/2798961/202312/2798961-20231223120329393-91488451.png)

完结！撒花！

# 结语

MQTT-PWN的其他参数还有待研究，对于MQTT协议，截止到发文，我所知道的漏洞即利用方式均已解释完，其实难点不在漏洞复现，而在攻击工具的搭建上，搭建过程中会报错，我翻阅了无数资料均无法解决，最后在debian的官网得到了解决思路，所以在此做一下总结和记录。