# 花指令

> 本文重点标题：
>
> - 原理—反编译器的线性反编译(理解花指令的重点)※
> - 原理—对于出题人
> - 栈指针平衡(引子)
> - 花指令分类—进阶花指令(自定义花指令)
> - 花指令分析实操
> - 花指令练习※
> - 编写脚本自动化去除花指令

> 前言：因为备课的时间比较短，笔者之前又没有系统学习整理过花指令，所以该篇略微混乱。但对于初学者来说仍是很好的阅读资料，笔者下次讲课时会再仔细整理的有条理一些。
>
> 对初学者说的话：时间比较紧的初学者建议阅读完原理直接转到文中较为偏后的花指令分类及花指令练习阅读，当然还是建议完整阅读完本文，你会有很大的收获。
>
> 对出题人说的话：对于像我一样只会做题不会出题的师傅，建议直接阅读文中较为偏后的花指令练习部分，里面重点阐述了如何由编写含有花指令的程序到反汇编分析花指令程序，并且该部分含有些我自己的一些出题的理解和思路及一些对疑问的解答，阅读完该部分后你也可以完成独立出题的工作。
>
> 为了使目录稍微完整，笔者在花指令练习里已经出现过的IDC脚本自动去花又加在了后面的目录中，意图是使脚本自动去花更为醒目一些防止读者学习时的遗漏。

关于指令类型推荐阅读如下两篇

https://blog.csdn.net/abel_big_xu/article/details/117927674

https://blog.csdn.net/m0_46296905/article/details/117336574

## 概念

花指令是企图隐藏掉不想被逆向工程的代码块(或其它功能)的一种方法, 在真实代码中插入一些垃圾代码的同时还保证原有程序的正确执行, 而程序无法很好地反编译, 难以理解程序内容, 达到混淆视听的效果。

花指令通常用于加大静态分析的难度。

## 原理

### 反编译器的线性反编译(理解花指令的重点)

反编译器的工作原理是，从exe的入口AddressOfEntryPoint处开始，依序扫描字节码，并转换为汇编，比如第一个16进制字节码是0xE8，一般0xE8代表汇编里的CALL指令，且后面跟着的4个字节数据跟地址有关，那么反编译器就读取这一共5个字节，反编译为`CALL 0x地址` 。

对应的，有些字节码只需要一个字节就可以反编译为一条指令，例如0x55对应的是`push ebp`，这条语句每个函数开始都会有。同样，有些字节码又需要两个、三个、四个字节来反编译为一条指令。

也就是说，如果中间只要一个地方反编译出错，例如两条汇编指令中间突然多了一个字节0xE8，那反编译器就会将其跟着的4个字节处理为CALL指令地址相关数据给反编译成一条`CALL 0x地址`指令。但实际上0xE8后面的四个字节是单独的字节码指令。这大概就是**线性反编译**。

### 线性扫描和递归下降

线性扫描：
线性扫描的特点：从入口开始，一次解析每一条指令，遇到分支指令不会递归进入分支。

递归下降：
当使用线性扫描时，比如遇到call或者jmp的时候，不会跳转到对应地址进行反汇编，而是反汇编call指令的下一条指令，这就会导致出现很多问题。
递归下降分析当遇到分支指令时，会递归进入分支进行反汇编。

### 使反汇编引擎解析错误

X86指令集的长度是不固定的，有一些指令很短，只有1个字节，有些指令比较长，可以达到5字节，指令长度不是固定的。如果通过巧妙的构造，引导反汇编引擎解析一条错误的指令，扰乱指令的长度，就能使反汇编引擎无法按照正常的指令长度一次解析邻接未解析的指令，最终使反汇编引擎输出错误的反汇编结果。

### 机器码

0xE8 CALL 后面的四个字节是地址 0xE9 JMP 后面的四个字节是偏移 0xEB JMP 后面的二个字节是偏移 0xFF15 CALL 后面的四个字节是存放地址的地址 0xFF25 JMP 后面的四个字节是存放地址的地址

0x68 PUSH 后面的四个字节入栈 0x6A PUSH 后面的一个字节入栈

### 对于出题人

从出题人的角度来看，构造有效花指令的关键思路就是构造使源程序逻辑不受影响的内联汇编代码，同时在内联汇编代码中嵌入jmp call+ret之类的对应机器码指令，使反汇编软件在反汇编时错误地识别这些机器码为汇编指令，从而影响反汇编出来的程序的正常流程。

## 写花指令的原则

**保持堆栈的平衡**

## 常用指令含义

push ebp ----把基址指针寄存器压入堆栈
pop    ebp ----把基址指针寄存器弹出堆栈
push eax ----把数据寄存器压入堆栈
pop    eax ----把数据寄存器弹出堆栈
nop        -----不执行
add esp,1-----指针寄存器加1
sub esp,-1-----指针寄存器加1
add esp,-1--------指针寄存器减1
sub esp,1-----指针寄存器减1
inc ecx    -----计数器加1
dec ecx    -----计数器减1
sub esp,1 ----指针寄存器-1
sub esp,-1----指针寄存器加1
jmp 入口地址----跳到程序入口地址
push 入口地址---把入口地址压入堆栈
retn        ------ 反回到入口地址,效果与jmp 入口地址一样
mov eax,入口地址 ------把入口地址转送到数据寄存器中. 
jmp eax        ----- 跳到程序入口地址 
jb 入口地址
jnb 入口地址   ------效果和jmp 入口地址一样,直接跳到程序入口地址
xor eax,eax   寄存器EAX清0
CALL 空白命令的地址  无效call

## 栈指针平衡(引子)

![image-20230815094310227](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150943319.png)

当使用IDA分析伪代码时，有花指令会发生

![image-20230815094348064](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150943101.png)

无法查看伪代码

需要去给出的地址查看具体发生的问题

这里，我们要设置一下IDA，让它显示出栈指针

`（Options-General-Disassembly-"Stack pointer"）`

![image-20230815094454421](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150944472.png)

程序段结束后，不应发生mov esp,ebp的操作，因为在pop出栈后，esp和ebp的值相等，这一步是多余的，因为栈指针已经正确地回到了调用函数前的位置，这会引起栈指针不平衡。

这就需要修改栈指针

### 手动修改地址

> 注意：每条语句前的栈指针是这条语句未执行的栈指针。

找到函数段的开始地址

![image-20230815094801422](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150948449.png)

计算结束地址的栈指针应为多少：

0x21E-0x4 = 0x21A

修改最后两句应为的栈指针：

Alt+k：

![image-20230815095110085](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150951119.png)

![image-20230815095119159](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150951184.png)

栈指针平衡

### 使用插件nop掉

通过前面知道，经过pop栈针已经平衡，所以这两句汇编代码是没有必要的

![image-20230815095303010](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150953130.png)

删除这两条指令的目的是在已经发生了出栈操作并且栈指针ESP与基址指针EBP相等的情况下，不再手动调整栈指针。这是因为栈指针已经回到了调用函数之前的位置，不需要再额外的指令来处理栈平衡。

![image-20230815095343701](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308150953752.png)



## 花指令的编写

> 此处笔者踩了个大坑，值得一提的是，win下的gcc只支持x86下的内联汇编。

环境：VS2022  x86架构 C++

reference

[内联汇编官方文档](https://learn.microsoft.com/zh-cn/cpp/assembler/inline/asm?view=msvc-170)

### asm

> **`__asm`** 关键字用于调用内联汇编程序，并且可在 C 或 C++ 语句合法时出现。 它不能单独显示。 它后面必须跟一个程序集指令、一组括在大括号中的指令，或者至少是一对空大括号。 此处的术语“**`__asm`** 块”指任何指令或指令组（无论是否在大括号中）。

### asm语法

asm-block:
 **`__asm`** assembly-instruction**`;`**opt
 **`__asm {`** assembly-instruction-list**`}`****`;`**opt

assembly-instruction-list:
  assembly-instruction**`;`**opt
  assembly-instruction**`;`**assembly-instruction-list**`;`**opt

### asm示例

1.括在大括号里的简单 **`__asm`** 块：

```
__asm {
   mov al, 2
   mov dx, 0xD007
   out dx, al
}
```

2. **`__asm`** 放在每个程序集指令前面：

```
__asm mov al, 2
__asm mov dx, 0xD007
__asm out dx, al
```

3.由于 **`__asm`** 关键字是语句分隔符，因此还可将程序集指令放在同一行中：

```
__asm mov al, 2   __asm mov dx, 0xD007   __asm out dx, al
```

这三个示例将生成相同的代码，但第一个样式（用大括号括起 **`__asm`** 块）具有一些优势。 大括号可清楚地将程序集代码与 C 或 C++ 代码分隔开，并避免了不必要的 **`__asm`** 关键字重复。 大括号还可防止二义性。 如果要将 C 或 C++ 语句放在与 **`__asm`** 块相同的行上，则必须将此块括在大括号中。 如果没有大括号，编译器无法判断程序集代码停止的位置以及 C 或 C++ 语句的开始位置。

### 花指令实现

reference：

https://www.anquanke.com/post/id/236490#h2-1

1.插入字节：这里就提到汇编里一个关键指令：`_emit 立即数`

```c
//C语言中使用内联汇编
__asm
{
    _emit 0xE8
}
//代表在这个位置插入一个字节数据0xE8
```

2.保证不被执行：通过构造一个永恒的跳转

```c
__asm
{
jmp Label1
  db thunkcode1;  垃圾数据
//垃圾数据例如：_emit 0xE8
Label1:
}
```

例如这样：

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161552688.png)

我对这反编译器对花指令的反编译稍作修改

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161552807.png)

**去掉花指令-> nop(0x90)**

这部分是通过IDA手动去掉花指令，也可以在IDA里用IDApython/IDC写脚本去，或者在OD调试的时候去掉，原理都一样。

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161554790.png)

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161554861.png)

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161554813.png)

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161554805.png)

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161554782.png)

### 花指令分类

> ### emit指令的作用：
>
> 1. 编译器不认识的指令，拆成机器码来写。
> 2. 插入垃圾字节来反跟踪，又称花指令。
>    用emit就是在当前位置直接插入数据（实际上是指令），一般是用来直接插入汇编里面没有的特殊指令，多数指令可以用asm内嵌汇编来做，没有必要用emit来做，除非你不想让其它人看懂你的代码。
>    我们来看用IDA反汇编的效果吧。

#### 1.最简单的花指令

##### a.最简单的jmp

```asm
jmp Label1
  db thunkcode1;垃圾数据
Labe1:
```

不过很可惜，反编译器能直接识别这种简单花指令，遇到这种能轻松过掉并反编译。

##### b.过时的多节形式与多层乱序

这两周都是通过多次跳转，把垃圾数据和有用代码嵌套在一起，不过这种形式也比较老套了，反编译器依然能够轻松过掉并成功反汇编。

```asm
#多节形式
JMP Label1
  Db thunkcode1
Label1:
  ……
  JMP Label2
  Db thunkcode2
Label2:
  ……
JMP Label1
  Db thunkcode1
Label2:
  ……
  JMP Label3
  Db thunkcode3
Label1:
  …….
  JMP Label2
  Db thunkcode2
Label3:
  ……
```

#### 2.简单花指令

##### a.互补条件代替jmp跳转

```asm
asm
{
  Jz Label
  Jnz Label
  Db thunkcode;垃圾数据
Label:
}
```

类似这种，无论如何都会跳转到label1处，还是能骗过反编译器。

##### b.跳转指令构造花指令

1.简单跳转

```asm
     __asm {
         push ebx;
         xor ebx, ebx;
         test ebx, ebx;
         jnz LABEL7;
         jz    LABEL8;
     LABEL7:
         _emit 0xC7;
     LABEL8:
         pop ebx;
     }
```

很明显，先对ebx进行xor之后，再进行test比较，zf标志位肯定为1，就肯定执行`jz LABEL8`，也就是说中间0xC7永远不会执行。

不过这种一定要注意：记着保存ebx的值先把ebx压栈，最后在pop出来。

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161557606.png)

2.永真永加

> 通过设置永真或者永假的，导致程序一定会执行，由于ida反汇编会优先反汇编接下去的部分（false分支）。也可以调用某些函数会返回确定值，来达到构造永真或永假条件。ida和OD都被骗过去了

```
__asm{
    push ebx
    xor ebx,ebx
    test ebx,ebx
    jnz label1
    jz label2
label1:
    _emit junkcode
label2:
   pop ebx//需要恢复ebx寄存器    
}

__asm{
	clc
	jnz label1:
	_emit junkcode
label1:
}
```

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161614833.png)

##### c.call&ret构造花指令

```asm
     __asm {
         call LABEL9;
         _emit 0x83;
     LABEL9:
         add dword ptr ss : [esp] , 8;
         ret;
         __emit 0xF3;
     }
```

> call指令的本质：`push 函数返回地址`然后`jmp 函数地址`
>
> ret指令的本质：`pop eip`

代码中的esp存储的就是函数返回地址，对[esp]+8，就是函数的返回地址+8，正好盖过代码中的函数指令和垃圾数据。（这部分建议自己调试一下）

#### 3.进阶花指令(自定义花指令)

前面几种花指令都是比较老套的，入门花指令还能勉勉强强骗过反编译器，不过有经验的逆向者一眼就能识破，以下几种花指令形式，可以任由自己构造。

##### a.替换ret指令

```asm
    _asm
    {
        call LABEL9;
        _emit 0xE8;
        _emit 0x01;
        _emit 0x00;
        _emit 0x00;
        _emit 0x00;

     LABEL9:
        push eax;
        push ebx;
        lea  eax, dword ptr ds : [ebp - 0x0];
        #将ebp的地址存放于eax        

        add dword ptr ss : [eax-0x50] , 26;
        #该地址存放的值正好是函数返回值，
        #不过该地址并不固定，根据调试所得。
         #加26正好可以跳到下面的mov指令，该值也是调试计算所得

        pop eax;
        pop ebx;
        pop eax;
        jmp eax;
        _emit 0xE8;
        _emit 0x03;
        _emit 0x00;
        _emit 0x00;
        _emit 0x00;
        mov eax,dword ptr ss:[esp-8];
        #将原本的eax值返回eax寄存器
    }
```

由于：

> call指令的本质：`push 函数返回地址`然后`jmp 函数地址`
>
> ret指令的本质：`pop eip`

两者都是对寄存器eip中存放的地址的操作。

所以我们可以在call指令之后，清楚的明白函数返回地址存放于esp，可以将值取出，用跳转指令跳转到该地址，即可代替ret指令。

当然，这种构造跳转指令可以变化多样。

##### b.控制标志寄存器跳转

这一部分需要精通标志寄存器，每一个操作码都会对相应的标志寄存器产生相应的影响，如果我们对标志寄存器足够熟练，就可以使用对应的跳转指令**构造永恒跳转**！。

##### c.利用函数返回确定值

有些函数返回值是确定的，比如我们自己写的函数，返回值可以是任意非零整数，就可以自己**构造永恒跳转**。

还有些api函数也是如此：

一方面可以传入一些错误的参数，如[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)

```apl
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
);
```

如果我们故意传入一个不存在的模块名称，那么他就会返回一个确定的值**NULL**，我们就可以通过这个**构造永恒跳转**

另一方面，某些api函数，我们既然使用他，肯定就是一定要调用成功的，而这些api函数基本上只要调用成功就就会返回一个确定的零或者非零值，如[MessageBox](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox)

```apl
int MessageBox(
  HWND    hWnd,
  LPCTSTR lpText,
  LPCTSTR lpCaption,
  UINT    uType
);
```

该api只有在其调用失败的时候才能返回零，那么我们也可以通过这一点**构造永恒跳转**

PS：利用MessageBox实现花指令也是我在**1.花指令简介**中用到的源码

####  4.花指令原理另类利用

当我们理解了花指令的原理后，我们可以在将花指令中的垃圾数据替换为一些特定的**特征码**，可以对应的$“定位功能”$，尤其在**[SMC自解码](https://blog.csdn.net/dontbecoder/article/details/8754729?utm_source=app)**这个反调试技术中可以运用。例如：

```asm
asm
{
  Jz Label
  Jnz Label
  _emit 'h'
  _emit 'E'
  _emit 'l'
  _emit 'L'
  _emit 'e'
  _emit 'w'
  _emit 'o'
  _emit 'R'
  _emit 'l'
  _emit 'D'
Label:
}
```

将这串特征码`hElLowoRlD`嵌入到代码中，那我们只需要在当前进程中搜索`hElLowoRlD`字符串，就可以定位到当前代码位置，然后对下面的代码进行SMC自解密。

### 花指令 指令小结

#### jz jnz/jmp

```
__asm { 
    _emit 075h    #jmp $+4
    _emit 2h
    _emit 0E9h
    _emit 0EDh
}
```

![image-20230816110539561](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161105602.png)

9是jmp指令对应的机器码，当反汇编器读取到E9时，接着会往下读取四个字节的数据作为跳转地址的偏移，所以才会看到错误的汇编代码。

#### call ret

> call+pop/add esp/add [esp] + retn

```
#include <iostream.h>
#include <windows.h>
void main()
{
    DWORD p;
    _asm
    {
        call l1
l1:
        pop eax
        mov p,eax//确定当前程序段的位置
        call f1
        _EMIT 0xEA//花指令，此处永远不会执行到
        jmp l2//call结束以后执行到这里
f1://这里用F8OD会终止调试，F7跟进的话就正常,why?
        pop ebx
        inc ebx
        push ebx
        mov eax,0x11111111
        ret
l2:
        call f2//用ret指令实现跳转
        mov ebx,0x33333333//这里永远不会执行到
        jmp e//这里永远不会执行到
f2:
        mov ebx,0x11111111
        pop ebx//弹出压栈的地址
        mov ebx,offset e//要跳转到的地址
        push ebx//压入要跳转到的地址
        ret//跳转
e:
        mov ebx,0x22222222
    }
    cout<<hex<<p<<endl;
}
```

call指令可以理解为jmp + push ip 因此如果通过add esp,4来降低栈顶即可去除push ip的影响，从而使call等价于jmp 但IDA会认为这是函数的分界，从而导致函数的范围识别错误

##### reference

https://el-z10.github.io/2020/05/17/flower.html

### 实例

#### 源码

```
#include <stdio.h>

void func1()
{
    __asm
    {
        lea eax, lab1
        jmp eax
            _emit 0x90
    };
lab1:
    printf("func1\n");
}

void func2()
{
    __asm
    {
        cmp eax, ecx
        jnz lab1
        jz lab1
           _emit 0xB8
    };
lab1:
    printf("func2\n");
}

int main()
{
    func1();
    func2();
    return 0;
}
```

![image-20230816093751805](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308160937878.png)

此外还有更多形式的花指令，读者请根据指令含义自行探索。

#### 花指令逆向分析

> IDA有栈跟踪的功能，它在函数内部遇到ret(retn)指令时会做判断：栈指针的值在函数的开头/结尾是否一致，如果不一致就会在函数的结尾标注"sp-analysis failed"。一般编程中，不同的函数调用约定(如stdcall&_cdcel call)可能会出现这种情况；另外，为了实现代码保护而加入代码混淆(特指用push/push+ret实现函数调用)技术也会出现这种情况。

对上文编写的花指令程序进行逆向分析：

![image-20230816103200617](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161032729.png)

加入花指令改变了esp的空间而实际有效代码的空间并没有这么大，在esp恢复时（出栈），会加上比实际值大的数字，从而导致栈指针不平衡。



## 花指令分析实操

### 1._emit 0xe8

以下内容摘自ctfwiki

```
// 正常的函数代码
int add(int a, int b){
  int c = 0;
  c = a + b;
  return c;
}
// 添加花指令的函数代码
int add_with_junk(int a, int b){
    int c = 0;
    __asm{
        jz label;
        jnz label;
        _emit 0xe8;    call 指令，后面加4bytes的地址偏移，因此导致反汇编器不能正常识别
label:
    }
    c = a + b;
    return c;
}
```

使用 ida 的反编译时，添加了花指令的函数不能正常识别，结果如下：

伪代码：

```asm
// 添加了花指令
.text:00401070 loc_401070:                             ; CODE XREF: sub_401005↑j
.text:00401070                 push    ebp
.text:00401071                 mov     ebp, esp
.text:00401073                 sub     esp, 44h
.text:00401076                 push    ebx
.text:00401077                 push    esi
.text:00401078                 push    edi
.text:00401079                 lea     edi, [ebp-44h]
.text:0040107C                 mov     ecx, 11h
.text:00401081                 mov     eax, 0CCCCCCCCh
.text:00401086                 rep stosd
.text:00401088                 mov     dword ptr [ebp-4], 0
.text:0040108F                 jz      short near ptr loc_401093+1
.text:00401091                 jnz     short near ptr loc_401093+1
.text:00401093
.text:00401093 loc_401093:                             ; CODE XREF: .text:0040108F↑j
.text:00401093                                         ; .text:00401091↑j
.text:00401093                 call    near ptr 3485623h
.text:00401098                 inc     ebp
.text:00401099                 or      al, 89h
.text:0040109B                 inc     ebp
.text:0040109C                 cld
.text:0040109D                 mov     eax, [ebp-4]
.text:004010A0                 pop     edi
.text:004010A1                 pop     esi
.text:004010A2                 pop     ebx
.text:004010A3                 add     esp, 44h
.text:004010A6                 cmp     ebp, esp
.text:004010A8                 call    __chkesp
.text:004010AD                 mov     esp, ebp
.text:004010AF                 pop     ebp
.text:004010B0                 retn
```

在上面这个例子中，把混淆视听的花指令 patch 成 nop 即可修复，然后正常分析。

值得注意的是，ida 对于栈的判定比较严格，因此 push，ret 一类的花指令会干扰反汇编器的正常运行，下面给出一个具体的例子，读者可以自己编译复现：

```asm
#include <stdio.h>
// 使用 gcc/g++ 进行编译
int main(){
    __asm__(".byte 0x55;");          // push rbp   保存栈 
    __asm__(".byte 0xe8,0,0,0,0;");  // call $5;    
    __asm__(".byte 0x5d;");          // pop rbp -> 获取rip的值 
    __asm__(".byte 0x48,0x83,0xc5,0x08;"); // add rbp, 8
    __asm__(".byte 0x55;");          // push rbp -> 相当于将call的返回值修改到下面去
    __asm__("ret;");
    __asm__(".byte 0xe8;");          // 这是混淆指令不执行
    __asm__(".byte 0x5d;");          // pop rbp 还原栈     
    printf("whoami \n");
    return 0;
} 
```



### 2.`看雪.TSRC 2017CTF秋季赛`第二题

这里以`看雪.TSRC 2017CTF秋季赛`第二题作为讲解. 题目下载链接: [ctf2017_Fpc.exe](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/anti-debug/2017_pediy/ctf2017_Fpc.exe)

程序写了几个函数混淆视听, 将关键的验证逻辑加花指令防止了 IDA 的静态分析. 我们用 IDA 打开 Fpc 这道题, 程序会先打印一些提示信息, 然后获取用户的输入。

![image-20230816143658327](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161436392.png)

这里使用了不安全的`scanf`函数, 用户输入的缓冲区只有`0xCh`长, 我们双击`v1`进入栈帧视图

![stack.png](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161436918.png)

因此我们可以通过溢出数据, 覆盖掉返回地址, 从而转移到任意地址继续执行.

这里我还需要解释一下, 就是`scanf`之前写的几个混淆视听的函数, 是一些简单的方程式但实际上是无解的. 程序将真正的验证逻辑加花混淆, 导致 IDA 无法很好的进行反编译. 所以我们这道题的思路就是, 通过溢出转到真正的验证代码处继续执行.

我们在分析时可以在代码不远处发现以下数据块.

![](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161444253.png)

因为 IDA 没能很好的识别数据, 因此我们可以将光标移到数据块的起始位置, 然后按下`C`键 (code) 将这块数据反汇编成代码

![image-20230816144445545](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161444714.png)

值得注意的是, 这段代码的位置是`0x00413131`, `0x41`是`'A'`的 ascii 码，而`0x31`是`'1'`的 ascii 码. 由于看雪比赛的限制, 用户输入只能是字母和数字, 所以我们也完全可以利用溢出漏洞执行这段代码

用 OD 打开, 然后`Ctrl+G`到达`0x413131`处设下断点, 运行后输入`12345612345611A`回车, 程序成功地到达`0x00413131`处. 然后`右键分析->从模块中删除分析`识别出正确代码

![entry.png](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161436314.png)

断在`0x413131`处后, 点击菜单栏的`"查看"`, 选择`"RUN跟踪"`, 然后再点击`"调试"`, 选择`"跟踪步入"`, 程序会记录这段花指令执行的过程, 如下图所示:

![trace.png](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161436957.png)

这段花指令本来很长, 但是使用 OD 的跟踪功能后, 花指令的执行流程就非常清楚. 整个过程中进行了大量的跳转, 我们只要取其中的有效指令拿出来分析即可.

需要注意的是, 在有效指令中, 我们依旧要满足一些条件跳转, 这样程序才能在正确的逻辑上一直执行下去.

比如`0x413420`处的`jnz ctf2017_.00413B03`. 我们就要重新来过, 并在`0x413420`设下断点

![jnz.png](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161436030.png)

通过修改标志寄存器来满足跳转. 继续跟踪步入 (之后还有`0041362E jnz ctf2017_.00413B03`需要满足). 保证逻辑正确后, 将有效指令取出继续分析就好了

![register.png](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161436306.png)

### 3._asm _emit 0E9 + 可执行花指令

#### reference

https://www.anquanke.com/post/id/208682

如下有tea加密算法

```
#include <stdio.h>
#include <stdint.h>

void encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}
int main() {
    int a = 1;
    uint32_t flag[] = { 1234,5678 };
    uint32_t key[] = { 9,9,9,9 };
    encrypt(flag, key);
    printf("%d,%d", flag[0], flag[1]);
    return 0;
}
```

#### 加入花指令

接下来我们加入两个花指令

第一个花指令在main函数中，就是我们上面提供的最简单的花指令编写方法

第二个花指令在encrypt函数中，是一个可执行花指令，下面我会具体分析这个花指令以及对应的去除方法

```C
#include <stdio.h>
#include <stdint.h>
#define JUNKCODE __asm{
    __asm jmp junk1 
    __asm __emit 0x12 
    __asm junk2: 
    __asm ret 
    __asm __emit 0x34 
    __asm junk1: 
    __asm call junk2  
}

void encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                       /* basic cycle start */
        JUNKCODE
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}
int main() {
    int a = 1;
    uint32_t flag[] = { 1234,5678 };
    uint32_t key[] = { 9,9,9,9 };
    __asm { 
        _emit 075h
        _emit 2h
        _emit 0E9h
        _emit 0EDh
    }
    encrypt(flag, key);
    printf("%d,%d", flag[0], flag[1]);
    return 0;
}
```

**第一个花指令**

首先ida打开查看main函数：

![image-20200616235743442](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161524586.png)

虽然还是反编译成功了，但是可以看到内容已经完全错误，我们再来看main函数的汇编代码，也就是我们加入的第一个花指令

![image-20200616235852756](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161524373.png)

可以看到这里出现的红色就是我们的第一处花指令，patch方法同上，我们主要看第二处花指令。

**第二个花指令**

f5反编译直接报错

![image-20200617000152860](https://i.loli.net/2020/06/17/NFG2ck1tTsA7XwV.png)

可以发现花指令的混淆作用还是很明显的，那我们继续跟进到花指令的反汇编代码处

![image-20200617000420510](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161524567.png)

这里框出的指令就是我们加入的花指令，逻辑其实特别清晰，就是先跳转到junk1，再call junk2，call junk2的时候会把地址0x004118D3压栈，然后进入junk2中执行retn指令又会把地址0x004118D3 pop到eip中，然后接下来程序继续正常执行。

#### **去除方法**

这种连续的可执行花指令的去除方法特别简单，直接整块nop掉即可。

但是真正的复杂程序里这种花指令的数量很多，人工nop很耗时，同时极容易出错，所以我们真正应该掌握的是自动化的方法，编写脚本匹配花指令模板进行去除。





## 花指令练习

### jz jnz/jmp

> 现在许多的花指令采用生成确定标志位并搭配两个互补的条件跳转指令替代一个强制跳转指令(如jmp)以增加汇编难度的方式。
> 其实如果一个程序出现下面互补跳转代码，而且跳转代码前某一个标志位一定是确定值，同时指令下方还出现报错的情况，基本可以断定是花指令（可以作为花指令起始或者存在的标志，是充分不必要条件）。
> 而且运行过程中必然不发生跳转的那一个指令的目标地址或者标号是干扰项。

#### 花指令1

> E8 --> call

形式：

```
		xor eax, eax        
		test eax, eax       //产生确定标志位
		je LABEL1           
		jne LABEL2           
LABEL2 :
       /*干扰项所在*/
LABEL1:
       /*正常代码*/
```

含有花指令的代码

```
#include<stdio.h>
#include<windows.h>
int a = 0;
int main()
{

	//MessageBox(NULL, "未加花指令", "YQC", 0);
	int n, m, result = 1;
	printf("请输入n和m:\n");
	scanf_s("%d%d", &n, &m);
	__asm {
		xor eax, eax
		test eax, eax
		je LABEL1
		jne LABEL2
		LABEL2 :
		_emit 0xe8
	
			LABEL1 :
	}
	for (int i = 0; i < m; i++)
		result *= n;
	printf("结果为%d", result);
	return 0;
}
```

IDA打开：

![image-20230817112338453](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171123653.png)

我们分析一下

因为E8指令(对应汇编call指令)的存在，E8之后的汇编指令被错误的识别成了地址

![image-20230817144205603](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171442653.png)

按D键转换成数据

![image-20230817144238492](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171442581.png)

![image-20230817144300841](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171443926.png)

然后把E8指令nop掉

![image-20230817144351642](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171443729.png)

把整段花指令nop掉也可以

![image-20230817145240157](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171452297.png)

![image-20230817145248451](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171452509.png)

再按C键将错误识别的数据转换成指令

![image-20230817144440327](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171444515.png)

最后从函数的结尾到函数的开始重新编译 按P键

`retn` --> `int __cdecl main`

![image-20230817144633355](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171446480.png)

最后Tab或F5

![image-20230817144740904](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171447954.png)

#### 花指令2

编写：

```c
#include<stdio.h>
#include<windows.h>
int a = 0;
int main()
{
	//MessageBox(NULL, "未加花指令", "YQC", 0);
	int n, m, result = 1;
	printf("请输入n和m:\n");
	scanf_s("%d%d", &n, &m);
	__asm {
		xor eax, eax
		test eax, eax
		je LABEL1
		jne LABEL2
		LABEL2 :
		_emit 0x5e     //与pop si机器码相同
			and eax, ebx
			_emit 0x50     //与push ax机器码相同
			xor eax, ebx
			_emit 0x74     //与汇编助记符 jz 机器码相同
			add eax, edx
			LABEL1 :
	}
	for (int i = 0; i < m; i++)
		result *= n;
	printf("结果为%d", result);
	return 0;
}
```

因为ZF标志位的存在，lable2的花指令部分并不会被执行，会直接跳转到label1执行正确的程序流程，所以正确的程序执行并不会出错

分析一下反汇编部分：

![image-20230817094651890](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308170946122.png)

可以看到IDA把我们加入的机器码当做了汇编指令来执行。（`0x5e`与`pop si`机器码相同，`0x50`与`push ax`机器码相同，`0x74`与汇编助记符 `jz`机器码相同

```
		xor eax, eax   //eax寄存器置零
		test eax, eax  //ZF=1,是确定标志位【test不会将结果放在寄存器上,它只影响ZF的状态，如果EAX == 0,那么ZF = 1】
		je LABEL1      //ZF=1时触发跳转到正常指令处LABEL1 
		jne LABEL2     //ZF=0时触发跳转到干扰项处LABEL2，与上面的指令形成互补跳转
LABEL2 :
        /*干扰项所在*/
LABEL1:
        /*正常代码*/

```

那么回到当前花指令分析，这个花指令最主要起作用的地方是让IDA将机器码`0x74`翻译成了`jz`指令，致使这个指令的**下一个本该翻译成指令（即add eax, edx）的机器码却被翻译成了跳转的地址**，进而出现了后面的指令不正常反汇编的情况。

![image-20230817095410879](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308170954019.png)

去花：

只需要把花指令部分nop掉即可

![](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171515145.png)

按D先转换成数据

![image-20230817151540581](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171515628.png)

nop

![image-20230817151533938](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171515091.png)

加上未识别的数据重新反汇编

![image-20230817151618118](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171516236.png)

![image-20230817151632843](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171516913.png)

重新反编译

![image-20230817151653048](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171516150.png)

##### IDC去花

先获取`jz short loc_45E421`的字节码如下图，我们只要取`74 03`即可，因为`0x74`代表jz助记符，而`add reg16,reg16`的字节码刚好为 `0x03`，对应了`add eax,eax`

![image-20230817151924552](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171519649.png)

![image-20230817151952590](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171519625.png)

根据idc的`API`和语法写出如下`idc脚本`

```
#include<idc.idc>
static main()
{
	auto StartVa, StopVa, Size, i;
	StartVa=0x00411960;
	StopVa=0x00411A27;
	Size=StopVa-StartVa;
	for (i=0; i<Size; i++){
		if (Byte(StartVa)==0x74)
		{
			if(Byte(StartVa+1)==0x03)
			{
				PatchByte(StartVa, 0x90);
				MakeCode(StartVa);
				StartVa++;
				Message("Find FakeJmp Opcode!!\n");
				continue;
			}
		}
		StartVa++;
	}
	Message("Clear FakeJmp Opcode Ok\n");
}
```

在IDA里运行

![image-20230817152102477](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171521535.png)

![image-20230817152124837](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171521919.png)

![image-20230817152348358](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171523441.png)

![image-20230817152410567](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171524656.png)

但不足的是这个脚本没有实现自动反汇编成汇编代码，运行了该脚本之后依旧有一些没有反汇编成正常汇编代码的部分。依旧`需要手动改成数据后再改成代码，最后申明函数`

### call ret

> 需要先了解一下一些汇编转移指令`call`和`ret`的原理

#### 1、call指令

> 看不懂CS:IP的同学可以先去笔者的[8086汇编](https://dua0g.top/archives/327)一文中学习，本文不再赘述。

（1）call + label
这个指令是先将call + 标号的下一条语句的IP放入栈中，然后使当前的IP+16位位移，相当于

```
push IP
jmp near ptr 标号
```

（2）call far ptr + label
这个指令是先将call指令的下一个指令的代码段地址入栈，再把call下一条指令的偏移地址入栈，然后使其跳到标号所在处，相当于

```
push CS
push IP
jmp far ptr 标号
```

（3）call + reg16
这个指令先将call的下一条指令的IP入栈，然后再以寄存器的值为IP的代码处

```
push IP
jmp reg16
```

（4）call word ptr + 内存单元地址
这个指令的是先将call指令的下一条指令的IP入栈，然后跳到以内存单元地址为IP的代码处

```
push IP
jum word ptr 内存单元地址
```

（5）call dword ptr + 内存单元地址
这个指令先将call指令的下一条指令的CS入栈，再将call指令的下一条指令的IP入栈，然后跳到以内存单元的高位为CS，低位为IP的代码处

```
push CS
push IP
jmp dword ptr 内存单元地址
```

#### 2、ret指令

与上面的call指令对应把由call指令入栈的地址数据都出栈给（CS和）IP，相当于

```
(pop CS)
pop IP
```

#### 花指令1

简单样例1

```
//实现求n^{m}
#include<stdio.h>
#include<windows.h>
int a = 0;
int main()
{
	//MessageBox(NULL, "未加花指令", "YQC", 0);
	int n, m, result = 1;
	printf("请输入n和m:\n");
	scanf_s("%d%d", &n, &m);

    __asm {
        call LABEL9;
        _emit 0x83;
    LABEL9:
        add dword ptr ss : [esp] , 8;
        ret;
        __emit 0xF3;
    }
    
	for (int i = 0; i < m; i++)
		result *= n;
	printf("结果为%d", result);
	return 0;
}
```

样例2

```
__asm {
		push eax;
		xor eax, eax;
		test eax, eax;
		jnz  LABEL1;
		jz LABEL2;
	LABEL1:
		_emit 0xE8;    //与call助记符的机器码相同
	LABEL2:
		mov byte ptr[a], 0;
		call LABEL3;
		_emit 0xFF;     //与adc助记符的字节码相同
	LABEL3:
		add dword ptr ss : [esp], 8;
		ret;
		__emit 0x11;
		mov byte ptr[a], 2;
		pop eax;
	}

```

加花后的程序源码

```
//实现求n^{m}
#include<stdio.h>
#include<windows.h>
int a = 0;
int main()
{
	//MessageBox(NULL, "未加花指令", "YQC", 0);
	int n, m, result = 1;
	printf("请输入n和m:\n");
	scanf_s("%d%d", &n, &m);
	__asm {
		push eax;
		xor eax, eax;
		test eax, eax;
		jnz  LABEL1;
		jz LABEL2;
	LABEL1:
		_emit 0xE8;
	LABEL2:
		mov byte ptr[a], 0;
		call LABEL3;
		_emit 0xFF;
	LABEL3:
		add dword ptr ss : [esp] , 8;
		ret;
		__emit 0x11;
		mov byte ptr[a], 2;
		pop eax;
	}
	for (int i = 0; i < m; i++)
		result *= n;
	printf("结果为%d", result);
	return 0;
}
```

反汇编

![image-20230817154813486](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171548655.png)

分析：

```
__asm {
		push eax;
		xor eax, eax;
		test eax, eax;
		jnz  LABEL1;
		jz LABEL2;
	LABEL1:
		_emit 0xE8;           //与call助记符的字节码相同
	LABEL2:
		mov byte ptr[a], 0;
		call LABEL3;          //相当于push IP;jmp near ptr LABEL3
		_emit 0xFF;           //干扰项，与adc助记符的字节码相同
	LABEL3:
		add dword ptr ss : [esp], 8;   //sp寄存器（栈顶寄存器）的值（IP）自增8
		ret;
		__emit 0x11;          //干扰项
		mov byte ptr[a], 2;
		pop eax;
	}
```

LABEL1标号的是干扰项，跟1号花指令效果一样，不再赘述。

直接从LABEL2开始分析，调用了函数LABEL3，把_emit 0xFF;的指令地址入栈（push IP），此时栈顶指针sp指向的是call指令的下一条指令的地址，即0xFF这个干扰项的地址，但执行add dword ptr ss : [esp], 8;给这个地址值加了8，指向了mov byte ptr[a], 2的地址，巧妙地修改了这个地址，所以接下来的ret指令将该指令的地址出栈到IP寄存器（pop IP），以至于在调用完LABEL3函数之后，下一个指令变成了mov byte ptr[a], 2，这样程序运行不会受到干扰项的影响。

##### 对一些疑问的回答：

**1.汇编是怎么绕过干扰项的？**

我们首先要理解**干扰项是0xFF,及jmp**，所以我们的目的是绕过0xFF。

在调用 LABEL3 函数后，`ret` 指令会将栈顶指针的值弹出到 IP 寄存器中，从而改变了代码执行的下一条指令。

在原始代码中，`add dword ptr ss:[esp], 8` 的作用是将栈顶指针加上 8，这实际上是**跳过了 `_emit 0xFF` 这个干扰项的地址**。因此，`ret` 指令弹出的是 `mov byte ptr[a], 2` 的地址，而不是干扰项的地址。由于 `ret` 指令会将 IP 寄存器中的值作为下一条指令的地址，所以**程序执行的下一条指令就变成了 `mov byte ptr[a], 2`**。

因此，通过修改栈中的内容和利用 `ret` 指令的行为，程序在运行时成功避免了干扰项（`_emit 0xFF`）的影响，实现了预期的逻辑。

**2.为什么下一条指令变成了 mov byte ptr[a], 2，程序运行就不受干扰项的影响？**

在调用 LABEL3 函数后，`ret` 指令会将栈顶指针的值弹出到 IP 寄存器中，从而改变了代码执行的下一条指令。

执行 `mov byte ptr[a], 2` 指令可以将值 2 移动到地址 a 所对应的内存位置上。该指令不会直接影响后续的代码逻辑，因为它只是修改了一个内存位置的值，并没有改变程序流程。

同时因为代码后面的内存和地址a也毫不相关，所以程序的运行不受干扰项的影响。

##### 反汇编分析

> 回归到IDA分析部分

就当前这个花指令而言，我们注意到有一个`push eax`，然后紧跟着垃圾指令，所以推断最后势必有个`pop eax`，所以完全可以以`push eax`（0x50）为起始，`pop eax`（0x58）为中止，中间的代码全部nop，从而达到去花的目的。

![image-20230817162527744](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171625853.png)

按P重新申明一下函数

![image-20230817162606813](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171626923.png)

##### IDC去花

```
#include <idc.idc>
/*匹配字符串的函数*/
static matchBytes(StartAddr, Match) 
{ 
	auto Len, i, PatSub, SrcSub; 
	Len = strlen(Match);
	while (i < Len) 
	{ 
		PatSub = substr(Match, i, i+1); 
		SrcSub = form("%02X", Byte(StartAddr)); 
		SrcSub = substr(SrcSub, i % 2, (i % 2) + 1); 
		if (PatSub != "?" && PatSub != SrcSub)    //以问号作为匹配函数中止条件
			return 0;  
		if (i % 2 == 1) StartAddr++; 
		i++; 
	}
	return 1; 
}
static main() 
{ 
   auto Addr, Start, End, Condition, i;

	Start = 0x411960; //起始地址
	End = 0x11A3B;   //中止地址
	Condition = "5033C085C07502????";  //目标字符串

	for (Addr = Start; Addr < End; Addr++)    //遍历区域内字节码
	{ 
		if (matchBytes(Addr, Condition)) 
		{ 
			Message("Find FakeJmp Opcode!!\n");  
			for (i = 1; Byte(Addr+i)!=0x58; i++) //出现pop eax则停止patch
			{
				PatchByte(Addr+i, 0x90); //nop填充
				MakeCode(Addr+i); //反汇编转代码
			} 
		} 
	}
	AnalyzeArea(Start, End); 
	Message("Clear FakeJmp Opcode Ok "); 
}
```

#### 花指令2

> 与花指令1类似

```
	__asm {
		call LABEL9;
		_emit 0x83;
	LABEL9:
		add dword ptr ss : [esp], 8;
		ret;
		__emit 0xF3;
	}
```

### 配合裸函数的花指令(笔者未分析 转载)

> 此部分未经验证。

```
void __declspec(naked)__cdecl cnuF(int* a)//裸函数，开辟和释放堆栈由我们自己写。
{

	//55 8b ec 83
	__asm
	{
	   /*保留栈底*/
		push ebp
		/*开辟栈空间*/
		mov ebp, esp
		sub esp, 0x40//0x40是缓冲区大小
		/*保留现场（寄存器状态）*/
		push ebx
		push esi
		push edi
		/*缓冲区写入数据*/
		mov eax, 0xCCCCCCCC    //0xCCCC在gb2312中是'烫'字
		mov ecx, 0x10          //cx为下面填'烫'操作计数
		lea edi, dword ptr ds : [ebp - 0x40]
		rep stos dword ptr es : [edi]
	}
	/*执行的操作*/
	*a = 1;
	 //花指令
	_asm    
	{
		call LABEL9;
		_emit 0xE8;
		_emit 0x01;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;

	LABEL9:
		push eax;
		push ebx;
		lea  eax, dword ptr ds : [ebp - 0x0]
			add dword ptr ss : [eax - 0x50], 26;

		pop eax;
		pop ebx;
		pop eax;
		jmp eax;
		__emit 0xE8;
		_emit 0x03;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		mov eax, dword ptr ss : [esp - 8];
	}
	__asm
	{
	    /*恢复现场*/
		pop edi
		pop esi
		pop ebx
		/*释放栈空间*/
		mov esp, ebp
		pop ebp
		ret
	}
}
```

在`无函数返回值的裸函数`中加花后的源程序源码如下

```
//实现求n^{m}
#include<stdio.h>
#include<windows.h>
int a = 0;
void __declspec(naked)__cdecl cnuF(int* a)//裸函数，开辟和释放堆栈由我们自己写。
{
	//55 8b ec 83
	__asm
	{
		/*保留栈底*/
		push ebp
		/*开辟栈空间*/
		mov ebp, esp
		sub esp, 0x40   //0x40是缓冲区大小

		/*保留现场（寄存器状态）*/
		push ebx
		push esi
		push edi

		/*缓冲区写入数据*/
		mov eax, 0xCCCCCCCC    //0xCCCC在gb2312中是'烫'字
		mov ecx, 0x10          //cx为下面填'烫'操作计数
		lea edi, dword ptr ds : [ebp - 0x40]
		rep stos dword ptr es : [edi]  //用烫填充
	}


	/*执行的操作*/
	*a = 1;
	MessageBox(NULL, "加花指令8", "YQC", 0);
	//MessageBox(NULL, "未加花指令", "YQC", 0);
	int n, m, result, i;
	printf("请输入n和m:\n");
	scanf_s("%d%d", &n, &m);
	/*花指令*/
	_asm
	{
		call LABEL9;
		_emit 0xE8;    //垃圾指令
		_emit 0x01;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;

	LABEL9:
		push eax;
		push ebx;
		lea  eax, dword ptr ds : [ebp - 0x0]
		add dword ptr ss : [eax - 0x50], 26;

		pop eax;
		pop ebx;
		pop eax;
		jmp eax;
		__emit 0xE8;
		_emit 0x03;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		mov eax, dword ptr ss : [esp - 8];

	}
	for (result = 1, i = 0; i < m; i++)
		result *= n;
	printf("结果为%d", result);
	
	__asm
	{
		/*恢复现场*/
		pop edi
		pop esi
		pop ebx

		/*释放栈空间*/
		mov esp, ebp
		pop ebp
		ret
	}
	
}
int main()
{
	cnuF(&a);
	return 0;
}
```

#### （一）反汇编代码比对与分析

给出用`加花的程序`的关键函数部分的反汇编代码。

```
.text:004613F0 sub_4613F0      proc near               ; CODE XREF: sub_45A8EF↑j
.text:004613F0
.text:004613F0 var_14          = byte ptr -14h
.text:004613F0 var_8           = byte ptr -8
.text:004613F0 arg_0           = dword ptr  8
.text:004613F0
.text:004613F0                 push    ebp
.text:004613F1                 mov     ebp, esp
.text:004613F3                 sub     esp, 40h
.text:004613F6                 push    ebx
.text:004613F7                 push    esi
.text:004613F8                 push    edi
.text:004613F9                 mov     eax, 0CCCCCCCCh
.text:004613FE                 mov     ecx, 10h
.text:00461403                 db      3Eh
.text:00461403                 lea     edi, [ebp-40h]
.text:00461407                 rep stosd
.text:00461409                 mov     eax, [ebp+arg_0]
.text:0046140C                 mov     dword ptr [eax], 1
.text:00461412                 mov     esi, esp
.text:00461414                 push    0               ; uType
.text:00461416                 push    offset Caption  ; "YQC"
.text:0046141B                 push    offset Text     ; "加花指令8"
.text:00461420                 push    0               ; hWnd
.text:00461422                 call    ds:MessageBoxA
.text:00461428                 cmp     esi, esp
.text:0046142A                 call    j___RTC_CheckEsp
.text:0046142F                 push    offset aNM      ; "请输入n和m:\n"
.text:00461434                 call    sub_45748D
.text:00461439                 add     esp, 4
.text:0046143C                 lea     eax, [ebp+var_14]
.text:0046143F                 push    eax
.text:00461440                 lea     ecx, [ebp+var_8]
.text:00461443                 push    ecx
.text:00461444                 push    offset aDD      ; "%d%d"
.text:00461449                 call    sub_4584E6
.text:0046144E                 add     esp, 0Ch
.text:00461451                 call    sub_46145B
.text:00461456                 call    sub_46145C
.text:00461456 sub_4613F0      endp ; sp-analysis failed
.text:00461456
.text:0046145B
.text:0046145B ; =============== S U B R O U T I N E =======================================
.text:0046145B
.text:0046145B
.text:0046145B sub_46145B      proc near               ; CODE XREF: sub_4613F0+61↑p
.text:0046145B                 push    eax
.text:0046145B sub_46145B      endp ; sp-analysis failed
.text:0046145B
.text:0046145C
.text:0046145C ; =============== S U B R O U T I N E =======================================
.text:0046145C
.text:0046145C
.text:0046145C sub_46145C      proc near               ; CODE XREF: sub_4613F0+66↑p
.text:0046145C                 push    ebx
.text:0046145D                 db      3Eh
.text:0046145D                 lea     eax, [ebp+0]
.text:00461461                 add     dword ptr ss:[eax-50h], 1Ah
.text:00461466                 pop     eax
.text:00461467                 pop     ebx
.text:00461468                 pop     eax
.text:00461469                 jmp     eax
.text:00461469 sub_46145C      endp ; sp-analysis failed
.text:00461469
.text:0046146B ; ---------------------------------------------------------------------------
.text:0046146B                 call    loc_461473
.text:0046146B ; ---------------------------------------------------------------------------
.text:00461470                 db 36h, 8Bh, 44h
.text:00461473 ; ---------------------------------------------------------------------------
.text:00461473
.text:00461473 loc_461473:                             ; CODE XREF: .text:0046146B↑j
.text:00461473                 and     al, 0F8h
.text:00461475                 mov     dword ptr [ebp-20h], 1
.text:0046147C                 mov     dword ptr [ebp-2Ch], 0
.text:00461483                 jmp     short loc_46148E
.text:00461485 ; ---------------------------------------------------------------------------
.text:00461485
.text:00461485 loc_461485:                             ; CODE XREF: .text:004614A0↓j
.text:00461485                 mov     eax, [ebp-2Ch]
.text:00461488                 add     eax, 1
.text:0046148B                 mov     [ebp-2Ch], eax
.text:0046148E
.text:0046148E loc_46148E:                             ; CODE XREF: .text:00461483↑j
.text:0046148E                 mov     eax, [ebp-2Ch]
.text:00461491                 cmp     eax, [ebp-14h]
.text:00461494                 jge     short loc_4614A2
.text:00461496                 mov     eax, [ebp-20h]
.text:00461499                 imul    eax, [ebp-8]
.text:0046149D                 mov     [ebp-20h], eax
.text:004614A0                 jmp     short loc_461485
.text:004614A2 ; ---------------------------------------------------------------------------
.text:004614A2
.text:004614A2 loc_4614A2:                             ; CODE XREF: .text:00461494↑j
.text:004614A2                 mov     eax, [ebp-20h]
.text:004614A5                 push    eax
.text:004614A6                 push    offset aD_0     ; "结果为%d"
.text:004614AB                 call    sub_45748D
.text:004614B0                 add     esp, 8
.text:004614B3                 pop     edi
.text:004614B4                 pop     esi
.text:004614B5                 pop     ebx
.text:004614B6                 mov     esp, ebp
.text:004614B8                 pop     ebp
.text:004614B9                 retn
```

这个程序的花指令是放到裸函数中的方式，先简单了解一下`裸函数`

> 裸函数
> 对于一个裸函数而言，就是编译器不会为这个函数生成代码，如开辟和释放栈空间还有ret，这些指令在裸函数中都需要我们自己写，且最后一定不能缺少ret指令。
> 一般在函数名前面加上 __deplspec(naked)，此时这个函数便是裸函数，同时编译器对裸函数也不会进行任何处理。
> 下面以实现两个传入参数相加的功能为例给出不同裸函数的基本框架（如果对这些指令不是很理解可以参考堆栈图）：
> （1）无参数无返回值的函数框架
>
> ```
> void __declspec(naked) Fun()
>  {
>      __asm
>      {
>          //提升堆栈
>          push ebp
>          mov ebp,esp
>          sub ebp,0x40
>          //保护现场
>         push ebx
>         push esi
>         push edi
>         //向缓冲区填充数据
>         lea edi,dword ptr ds:[ebp-0x40]
>         mov eax,0xCCCCCCCC
>         mov ecx,0x10
>         rep stosd　　;rep stos dword ptr es:[edi]
>         //恢复现场
>         pop edi
>         pop esi
>         pop ebx
>         //降低堆栈
>         mov esp,ebp
>         pop ebp
>         //返回函数调用前的下一行地址
>         ret
>     }
> }
> ```
>
> #### （2）有参数有返回值的函数框架
>
> ```
> int __declspec(naked) plus(int x, int y)
> {
>     __asm
>     {
>         //提升堆栈
>         push ebp
>         mov ebp,esp
>         sub esp,0x40
>         //保护现场
>          push ebx
>         push esi
>         push edi
>         //向缓冲区填充数据
>         lea edi,dword ptr ds:[ebp-0x40]
>         mov eax,0xCCCCCCCC
>         mov ecx,0x10
>         rep stos dword ptr es:[edi]
> 
>         //函数核心功能块
>         mov eax,dword ptr ds:[ebp+0x8]
>         add eax,dword ptr ds:[ebp+0xC]
> 
>         //恢复现场
>         pop edi
>         pop esi
>         pop ebx
> 
>         //降低堆栈
>         mov esp,ebp
>         pop ebp
>         //返回函数调用前的下一行地址
>         ret
>     }
> }
> ```
>
> #### （3）带局部变量的函数框架
>
> ```
> int __declspec(naked) plus(int x, int y)
> {
>     __asm
>     {
>         //提升堆栈
>         push ebp
>         mov ebp,esp
>         sub esp,0x40
>         //保护现场
>         push ebx
>         push esi
>         push edi
>         //向缓冲区填充数据
>         lea edi,dword ptr ds:[ebp-0x40]
>         mov eax,0xCCCCCCCC
>         mov ecx,0x10
>         rep stos dword ptr es:[edi]
> 
>         //局部变量入栈
>         mov dword ptr ds:[ebp-0x4]
>         mov dword ptr ds:[ebp-0x8]
> 
>         //函数核心功能块
>         mov eax,dword ptr ds:[ebp+0x8]
>         add eax,dword ptr ds:[ebp+0xC]
> 
>         //恢复现场
>         pop edi
>         pop esi
>         pop ebx
>         //降低堆栈
>         mov esp,ebp
>         pop ebp
>         //返回函数调用前的下一行地址
>         ret
>     }
> }
> ```

下面用OD分析花指令，从`call LABEL9`处单步执行，注意观察，如下图。

对call入栈的指令地址进行了修改

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171700666.png)

修改之后变成`mov eax, dword ptr ss : [esp - 8];`（在OD中没有反汇编成功）的地址

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171700962.png)

一共三次出栈操作，第三次是将修改后的指令地址出栈到eax，下面有个jmp无条件跳转语句，程序自动跳到`mov eax, dword ptr ss : [esp - 8];`，绕过垃圾指令

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171700475.png)

#### （二）去花

**1.反汇编器手动改字节**

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171701745.png)

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171701103.png)

然后再把位于`jmp eax`下面的`call`语句`nop`掉

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171701291.png)

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171701143.png)

效果如下

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171702499.png)

但光这样会出现问题就是因为`jmp eax`的存在，`反汇编引擎`不知道跳转的位置，所以部分代码会丢失，被分隔开，产生如下情况；

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171702933.png)

所以还需要把`jmp eax`用`nop`填充掉，这样就可以F5了

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171702801.png)

#### IDC去花

```
#include <idc.idc>
static matchBytes(StartAddr, Match) 
{ 
	auto Len, i, PatSub, SrcSub; 
	Len = strlen(Match);
	while (i < Len) 
	{ 
		PatSub = substr(Match, i, i+1); 
		SrcSub = form("%02X", Byte(StartAddr)); 
		SrcSub = substr(SrcSub, i % 2, (i % 2) + 1); 
		if (PatSub != "?" && PatSub != SrcSub) 
			return 0;  
		if (i % 2 == 1) StartAddr++; 
		i++; 
	}
	return 1; 
}
static main() 
{ 
   auto Addr, Start, End, Condition, junk_len, i;

	Start = 0x004613F0; 
	End = 0x004614B9;
	Condition = "E805000000E801000000????";

	for (Addr = Start; Addr < End; Addr++) 
	{ 
		if (matchBytes(Addr, Condition)) 
		{ 
			Message("Find FakeJmp Opcode!!\n");
			for (i = 0;!matchBytes(Addr+i,"368B44????"); i++)
			{
			    PatchByte(Addr+i, 0x90); 
				MakeCode(Addr+i); 
			}
		} 
	}
	AnalyzeArea(Start, End); 
	Message("Clear Fake-Jmp Opcode Ok "); 
}
```

![在这里插入图片描述](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171704091.png)

最后再重新反汇编处理一下

### and

> 0x21对应汇编and，原理跟0xe8相同，此部分不再过多讲解

#### 花指令

```
__asm {
		push ebx;
		xor ebx, ebx;   
		test ebx, ebx;
		jnz LABEL5;
		jz	LABEL6;
	LABEL5:
		_emit 0x21;     //与and助记符的机器码相同
	LABEL6:
		pop ebx;
	}
```

加花源码

```
//实现求n^{m}
#include<stdio.h>
#include<windows.h>
int a = 0;
int main()
{
	//MessageBox(NULL, "未加花指令", "YQC", 0);
	int n, m, result = 1;
	printf("请输入n和m:\n");
	scanf_s("%d%d", &n, &m);
	__asm {
		push ebx;
		xor ebx, ebx;
		test ebx, ebx;
		jnz LABEL5;
		jz	LABEL6;
	LABEL5:
		_emit 0x21;
	LABEL6:
		pop ebx;
	}
	for (int i = 0; i < m; i++)
		result *= n;
	printf("结果为%d", result);
	return 0;
}
```

IDA分析

![image-20230817164108385](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171641461.png)

![image-20230817164124171](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171641290.png)

![image-20230817164132287](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171641330.png)

![image-20230817164331190](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171643254.png)

![image-20230817164344960](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171643048.png)

#### IDC去花

先确定nop的范围，我们注意到代码`xor ebx, ebx；test ebx, ebx； jnz short loc_45E417； jz short near ptr loc_45E417+1`前面有个 `push ebx`，那就以`pop ebx`为中止，中间代码为花指令全部nop。

```
#include <idc.idc>
static matchBytes(StartAddr, Match) 
{ 
	auto Len, i, PatSub, SrcSub; 
	Len = strlen(Match);
	while (i < Len) 
	{ 
		PatSub = substr(Match, i, i+1); 
		SrcSub = form("%02X", Byte(StartAddr)); 
		SrcSub = substr(SrcSub, i % 2, (i % 2) + 1); 
		if (PatSub != "?" && PatSub != SrcSub) 
			return 0;  
		if (i % 2 == 1) StartAddr++; 
		i++; 
	}
	return 1; 
}
static main() 
{ 
   auto Addr, Start, End, Condition, junk_len, i;

	Start = 0x0045E3A0; 
	End = 0x0045E480;
	//"xor ebx, ebx；test ebx, ebx； jnz short loc_45E417；jz short loc_45E418"的字节码作为识别花指令的标识。
	Condition = "33DB85DB7502740121????";

	for (Addr = Start; Addr < End; Addr++) 
	{ 
		if (matchBytes(Addr, Condition)) 
		{ 
			Message("Find FakeJmp Opcode!!\n");
			Message(Addr);
			for (i = 1; Byte(Addr+i)!=0x21; i++);
			PatchByte(Addr+i, 0x90); 
			MakeCode(Addr+i); 
		} 
	}
	AnalyzeArea(Start, End); 
	Message("Clear Fake-Jmp Opcode Ok "); 
}
```



### 其余(随笔者做题更新)

1

```
void example4()
{
	__asm {
		push ebx;
		xor ebx, ebx;
		test ebx, ebx;
		jnz LABEL7;
		jz	LABEL8;
	LABEL7:
		_emit 0xC7;
	LABEL8:
		pop ebx;
	}
	a = 4;
}
```

2

```
if (a > 0)
		return 1;
	else
		return 0;
	_asm {
		cmp eax, 0;
		jc LABEL7_1;
		jz LABEL7_2;
	LABEL7_1:
		_emit 0xE8;
	LABEL7_2:
	}
```



### reference

https://blog.csdn.net/m0_46296905/article/details/117336574

## 编写IDC脚本自动化去除花指令

> 针对花指令较多的情况，建议采用idc脚本去花

**此部分反汇编代码来自上一目录花指令练习的jz jnz/jmp的花指令1**

首先先来了解几个ida python的重要函数

> ```
> MakeCode(ea) #分析代码区，相当于ida快捷键C
> ItemSize(ea) #获取指令或数据长度
> GetMnem(ea) #得到addr地址的操作码
> GetOperandValue(ea,n) #返回指令的操作数的被解析过的值
> PatchByte(ea, value) #修改程序字节
> Byte(ea) #将地址解释为Byte
> MakeUnkn(ea,0) #MakeCode的反过程，相当于ida快捷键U
> MakeFunction(ea,end) #将有begin到end的指令转换成一个函数。如果end被指定为BADADDR（-1），IDA会尝试通过定位函数的返回指令，来自动确定该函数的结束地址
> ```

先获取`jz short loc_45E421`的字节码如下图，我们只要取`74 03`即可，因为`0x74`代表jz助记符，而`add reg16,reg16`的字节码刚好为 `0x03`，对应了`add eax,eax`

![image-20230817151924552](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171519649.png)

![image-20230817151952590](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171519625.png)

根据idc的`API`和语法写出如下`idc脚本`

```
#include<idc.idc>
static main()
{
	auto StartVa, StopVa, Size, i;
	StartVa=0x00411960;
	StopVa=0x00411A27;
	Size=StopVa-StartVa;
	for (i=0; i<Size; i++){
		if (Byte(StartVa)==0x74)
		{
			if(Byte(StartVa+1)==0x03)
			{
				PatchByte(StartVa, 0x90);
				MakeCode(StartVa);
				StartVa++;
				Message("Find FakeJmp Opcode!!\n");
				continue;
			}
		}
		StartVa++;
	}
	Message("Clear FakeJmp Opcode Ok\n");
}
```

在IDA里运行

![image-20230817152102477](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171521535.png)

![image-20230817152124837](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171521919.png)

![image-20230817152348358](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171523441.png)

![image-20230817152410567](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308171524656.png)

但不足的是这个脚本没有实现自动反汇编成汇编代码，运行了该脚本之后依旧有一些没有反汇编成正常汇编代码的部分。依旧`需要手动改成数据后再改成代码，最后申明函数`

## 某些摘录

### 1.阅读

https://www.52pojie.cn/thread-1512089-1-1.html

### 2.以下内容出自[逆向工程入门指南](https://wizardforcel.gitbooks.io/re-for-beginners/content/Part-III/Chapter-50.html)

#### 50.1 文本字符串(提供了隐藏文本字符串的思路)

我发现在文本字符串使用可能会很有用，程序员意识某字符串不想被逆向工程的时候，可能会试图隐藏掉该字符串，让IDA或者其他十六进制编辑器无法找到。 这里说明一个简单的方法，那就是怎么去构造这样的字符串的实现方式：

```
mov byte ptr [ebx], ’h’
mov byte ptr [ebx+1], ’e’
mov byte ptr [ebx+2], ’l’
mov byte ptr [ebx+3], ’l’
mov byte ptr [ebx+4], ’o’
mov byte ptr [ebx+5], ’ ’
mov byte ptr [ebx+6], ’w’
mov byte ptr [ebx+7], ’o’
mov byte ptr [ebx+8], ’r’
mov byte ptr [ebx+9], ’l’
mov byte ptr [ebx+10], ’d’
```

当两个字符串进行比较的时候看起来是这样：

```
mov ebx, offset username
cmp byte ptr [ebx], ’j’
jnz fail
cmp byte ptr [ebx+1], ’o’
jnz fail
cmp byte ptr [ebx+2], ’h’
jnz fail
cmp byte ptr [ebx+3], ’n’
jnz fail
jz it_is_john
```

在这两种情况下，是不可能通过十六进制编辑器中找到这些字符串的。

顺便提一下，这种方法使得字符串不可能被分配到程序的代码段中。在某些场合可能会用到，比如，在PIC或者在shellcode中。

另一种方法是，我曾经看到用sprintf()构造字符串。

```
sprintf(buf, "%s%c%s%c%s", "hel",’l’,"o w",’o’,"rld");
```

代码看起来比较怪异，但是做为一个简单的防止逆向工程确实一个有用的方法。 文本字符串也可能存在于加密的形式，那么所有字符串在使用前比较闲将字符串解密了。

#### 50.2 可执行代码

##### 50.2.1 插入垃圾

可执行代码花指令的意思是在真实的代码中插入一些垃圾代码，但是保证原有程序的执行正确。

举个简单的例子：

```
add eax, ebx
mul ecx
```

代码清单29.1： 花指令

```
xor esi, 011223344h ; garbage
add esi, eax ; garbage
add eax, ebx
mov edx, eax ; garbage
shl edx, 4 ; garbage
mul ecx
xor esi, ecx ; garbage
```

这里的花指令使用原程序代码中没有使用的寄存器(ESI和EDX)。无论如何，增加花指令之后，原有的汇编代码变得更为枯涩难懂，从而达到不轻易被逆向工程的效果。

##### 50.2.2 替换与原有指令等价的指令

```
mov op1, op2可以替换为 push op2/pop op1这两条指令。
jmp label可以替换为 push label/ret这两条指令，IDA将不会显示被引用的label。
call label可以替换为push label_after_call_instruction/push label/ref这三条指令。
push op可以替换为 sub esp, 4(或者8)/mov [esp], op这两条指令。
```

##### 50.2.3 绝对被执行的代码与绝对不被执行的代码

如果开发人员肯定ESI寄存器始终为0：

```
    mov esi, 1
    ... ; some code not touching ESI
    dec esi
    ... ; some code not touching ESI
    cmp esi, 0
    jz real_code
    ;fakeluggage
real_code:
```

逆向工程需要一段时间才能够执行到real_code。这也被称为opaque predicate。 另一个例子(同上，假设可以肯定ESI寄存器始终为0):

```
add eax, ebx ; real code
mul ecx ; real code
add eax, esi ; opaque predicate. XOR, AND or SHL, etc, can be here instead of ADD.
```

##### 50.2.4打乱执行流程

举个例子，比如执行下面这三条指令：

```
instruction 1
instruction 2
instruction 3
```

可以被替换为：

```
begin: 
    jmp ins1_label
ins2_label: 
    instruction 2
    jmp ins3_label
ins3_label: 
    instruction 3
    jmp exit
ins1_label: 
    instruction 1
    jmp ins2_label
exit:
```

##### 50.2.4使用间接指针

```
dummy_data1 db 100h dup (0)
message1 db ’hello world’,0

dummy_data2 db 200h dup (0)
message2 db ’another message’,0

func proc
    ...
    mov eax, offset dummy_data1 ; PE or ELF reloc here
    add eax, 100h
    push eax
    call dump_string
    ...
    mov eax, offset dummy_data2 ; PE or ELF reloc here
    add eax, 200h
    push eax
    call dump_string
    ...
func endp
```

IDA仅会显示dummy_data1和dummy_data2的引用，但无法引导到文本字符串，全局变量甚至是函数的访问方式都可能使用这种方法以达到混淆代码的目地。

#### 50.3 虚拟机/伪代码

程序员可能写一个PL或者ISA来解释程序(例如Visual Basic 5.0与之前的版本, .NET, Java machine)。这使得逆向工程不得不花费更多的时间去了解这些语言它们的所有ISP指令详细信息。更有甚者，他们可能需要编写其中某些语言的反汇编器。

#### 50.4 其它

我为TCC(Tiny C compiler)添加一个产生花指令功能的补丁：http://blog.yurichev.com/node/58。

#### 50.5练习

- http://challenges.re/29

## 结尾

重点：**构造永恒跳转，添加垃圾数据！**

![img](https://image-1311319331.cos.ap-beijing.myqcloud.com/image/202308161608409.png)