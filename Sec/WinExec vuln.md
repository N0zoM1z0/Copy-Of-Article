# WinExec 函数 (winbase.h)

- 项目
- 2024/03/03

反馈

本文内容[语法](https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-winexec#syntax)[参数](https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-winexec#parameters)[返回值](https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-winexec#return-value)[注解](https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-winexec#remarks)显示另外 2 个

运行指定的应用程序。

**注意** 提供此函数只是为了与 16 位 Windows 兼容。 应用程序应使用 [CreateProcess](https://learn.microsoft.com/zh-cn/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessa) 函数。

 



## 语法

C++复制

```cpp
UINT WinExec(
  [in] LPCSTR lpCmdLine,
  [in] UINT   uCmdShow
);
```



## 参数

```
[in] lpCmdLine
```

命令行 (文件名以及要执行的应用程序) 可选参数。 如果 *lpCmdLine* 参数中的可执行文件的名称不包含目录路径，则系统会按以下顺序搜索可执行文件：

1. 从中加载应用程序的目录。
2. 当前目录。
3. Windows 系统目录。 [GetSystemDirectory](https://learn.microsoft.com/zh-cn/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 函数检索此目录的路径。
4. Windows 目录。 [GetWindowsDirectory](https://learn.microsoft.com/zh-cn/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 函数检索此目录的路径。
5. PATH 环境变量中列出的目录。

```
[in] uCmdShow
```

显示选项。 有关可接受的值的列表，请参阅 [ShowWindow](https://learn.microsoft.com/zh-cn/windows/desktop/api/winuser/nf-winuser-showwindow) 函数的 *nCmdShow* 参数的说明。



## 返回值

如果函数成功，则返回值大于 31。

如果函数失败，则返回值为以下错误值之一。

展开表

| 返回代码/值              | 说明                 |
| :----------------------- | :------------------- |
| 0                        | 系统内存或资源不足。 |
| **ERROR_BAD_FORMAT**     | .exe 文件无效。      |
| **ERROR_FILE_NOT_FOUND** | 找不到指定的文件。   |
| **ERROR_PATH_NOT_FOUND** | 未找到指定路径。     |



## 注解

当启动的进程调用 [GetMessage](https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/fax/-mfax-faxaccountincomingarchive-getmessage-vb) 函数或达到超时限制时，**WinExec** 函数将返回 。 为了避免等待超时延迟，请尽快在调用 **WinExec** 启动的任何进程中调用 **GetMessage** 函数。

# <font color="red">VULN！！！</font>

### 安全备注

可执行文件名称被视为 *lpCmdLine* 中第一个空格分隔的字符串。 如果可执行文件或路径名称中有空格，则存在运行其他可执行文件的风险，因为函数分析空格的方式。 下面的示例很危险，因为函数将尝试运行“Program.exe”（如果存在），而不是运行“MyApp.exe”。

syntax复制

```syntax
WinExec("C:\\Program Files\\MyApp", ...)
```

如果恶意用户在系统上创建名为“Program.exe”的应用程序，则任何错误地使用 Program Files 目录调用 **WinExec** 的程序都将运行此应用程序而不是预期的应用程序。

若要避免此问题，请使用 [CreateProcess](https://learn.microsoft.com/zh-cn/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessa) 而不是 **WinExec**。 但是，如果出于旧原因必须使用 **WinExec** ，请确保应用程序名称用引号引起来，如以下示例所示。

syntax复制

```syntax
WinExec("\"C:\\Program Files\\MyApp.exe\" -L -S", ...)
```