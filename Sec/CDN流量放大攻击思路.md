WooYun DROP真神了。

---

## 0x00 背景

------

大家好，我们是[OpenCDN团队](https://web.archive.org/web/20131219070448mp_/http://ocdn.me/)，专注于CDN技术的开发和研究。

首先，为了对CDN进行攻击，我们必须清楚CDN的工作原理，这里我们再来简单介绍一下CDN的工作模型。



![Wx519Kv6-ML-9-cOl7IWmzetAmI4zcPuswT94LWh](https://web.archive.org/web/20131219070448im_/https://lh3.googleusercontent.com/Wx519Kv6-ML-9-cOl7IWmzetAmI4zcPuswT94LWhT89_W3yEAydZlsj-34_zl491aiSPCuW35L2r7HZfPs4gG1cFBGQLHvE7MrI354HSm5iS_jEi8qWriv5T)

CDN的全称是Content Delivery Network（内容分发网络），通过在网络各处的加速节点服务器来为网站抵挡恶意流量，把正常流量进行转发。用简单点的话来说，CDN一般有三个作用

```
1. 跨运营商加速：我们自己的网站常常只属于一个运营商(比如：电信)，而加速节点遍布每家运营商，于是和网站不同运营商（比如：联通）的用户访问起来就不会那么慢了。
2. 缓存加速：很多的静态资源以及一部分页面更新都是比较慢的（比如首页），这个时候CDN就会根据浏览器的max-age和last-modified值以及管理员的预设值来进行缓存，于是很多流量CDN节点就不会每次都来向网站请求，CDN节点可以直接自作主张地将命中的缓存内容返回。  
3. 恶意流量过滤：这是CDN非常重要的一个作用，也是很多网站会用CDN的原因，因为CDN能为我们抵挡攻击大流量攻击、普通的攻击（比如注入等），只有正常流量才会转发给网站。
```

这里还要说明几个名词：

```
源站：我们自己的那个网站就被称为是源站。 
反向代理：CDN节点向源站请求数据的方式就叫反向代理，也就是上文所说的转发。 
回源：CDN节点向源站请求数据的行为就叫做回源。 
```

## 0x01 探究之旅

------

我们在做OpenCDN测试的时候，遇到了一些小问题。发现一个没有人访问的网站居然会有流量，并且有着惊人的访问次数。

![FYLJ-BwLQug58TP3usUE7-7uhu3xDzixsPm1XwOH](https://web.archive.org/web/20131219070448im_/https://lh5.googleusercontent.com/FYLJ-BwLQug58TP3usUE7-7uhu3xDzixsPm1XwOHtWXIh2ilwFX5hHqqd9GcX1KZDagInZzAgpdcfj4PbZ1NJf1bXPwxcBjD9zTSbg92KzvaSvhzjD4a2ukr)

我们的OpenCDN有2分钟一次的反向代理检测，但是这次数加起来也就区区的720次，而这400万的访问次数是哪里冒出来的？然后我们查看了日志，发现单个域名的日志到达了58G之多，而将其打开之后发现X-Forwarded-For字段中（X-Forwarded-For机制是通过一层代理后记录一个IP，让源站在使用CDN后能够获得真实的访客IP而不是CDN节点IP）充斥着大量有的IP，而且都是本服务器IP。我们瞬间明白了什么，然后去管理端上验证了一下，果不其然地，我们一不小心把源站IP设成了CDN节点的IP，不过当时我们并没有发现。于是这么大的流量也好解释了，由于2分钟一次的检测触发CDN节点的回源，而这个站点的源站是CDN节点本身，于是CDN就开始不断自身反向代理死循环，这样一个请求就被无限地放大了。当超时或者HEADER太大（就是X-Forwarded-For字段导致HEADER溢出）的时候，请求会被丢弃。

```
把站点的源站IP设为CDN节点本身，能够让CDN节点进行自我的反向代理死循环，然后放大流量。
```

貌似有点意思，小伙伴们于是马上就行动起来了，进行了实验。

我们在安全宝上成功地将源站IP设置成了某个为我们加速的CDN节点IP，然后在美帝的一台小vps上开webbench用2000个线程去打这个这个站点（无论是哪个CDN节点收到请求，请求最终都会汇聚到那个无辜的被设源站的CDN节点），不过实验结果并不理想，节点没有宕机，通过IP反查找到一台和我们公用一个CDN节点的网站，通过这个CDN节点反向代理访问那个网站，出现了卡顿和打不开情况，仅此而已。由于没法采集到安全宝的这个节点的性能数据，我们也没法对我们的攻击做出评估。而且我们这个实验缺少了一个对照组，到底是因为死循环把流量放大导致CDN节点卡顿，还是这个2000线程本身就能把CDN节点打卡。

于是我们总结了一下，猜想这种节点反向代理自身的攻击手法可能可以适用于这样的场景

```
你想要攻击某个CDN节点，但是如果打404页面消耗不了太多，而如果打CDN中的某个站点，因为流量会穿透过去，可能还没有把CDN节点打掉，背后的站点早被穿透死了。这个时候，如果让节点进行自身反向代理死循环，他就会把所有的流量给吃进去，并且没法吐出来，这个时候可以产生一定量的流量杠杆效应，可以使得CDN节点出现异常。
```

不过话说回来，这种攻击的防御方式也异常简单，只要在设置源站IP的时候，不让设置CDN节点IP就行了，只要在网站前端交互输入的时候加点验证就行了。

我们考虑到我们没法对不是我们的CDN节点的带宽上限，性能上限有个很好的评估，黑盒式的摸索可能带来不了什么，于是我们拿我们自己的CDN节点开刀。

同时我们继续对这个思路进行探索。我们发现，既然一个节点能死循环，那两个节点怎么样？结果是肯定的，并且产生了质的变化。我们假设了这样的一个场景

```
我们的opencdn.cc在甲CDN服务商注册服务，并且在乙CDN服务商注册服务，然后我们得到甲CDN服务商的一个CDN加速节点1.1.1.1，然后又得到乙CDN服务商的一个CDN加速节点2.2.2.2。 然后聪明的你一定已经猜到了。我们把在甲CDN服务商设置源站为乙的加速节点2.2.2.2，在乙CDN服务商设置源站为甲的加速节点1.1.1.1，然后甲会问乙去索取源站，乙又来问甲索取源站，于是1.1.1.1和2.2.2.2就很开心地并且不停地交流了起来~
```

![qYRVpnlSKDQn9Q6ZWaDr79MZRESrrtH5FXj1zF6x](https://web.archive.org/web/20131219070448im_/https://lh6.googleusercontent.com/qYRVpnlSKDQn9Q6ZWaDr79MZRESrrtH5FXj1zF6xOUS3RBPAQfjyHMUT4MPDvtam22n6XPKN3SUIFk7aCGKTJAb0E_ytgURVVkUKxHqyyvPS1Fr2hx8sHikD)

于是我们也进行了实验。这次我们采用POST包进行测试。

![FwQ5nijy4-us0fYEY2NqSxxpzh8PZUQAMhRDxvW8](https://web.archive.org/web/20131219070448im_/https://lh5.googleusercontent.com/FwQ5nijy4-us0fYEY2NqSxxpzh8PZUQAMhRDxvW82YdPuxFnq2UBlcvfva71H9NBOEWHSF5anklhZP1rY_NrJ2DMc7SmOZB5deqRwPNwog5uSK1XmVqsjCGT)

用POST包的原因有两个

```
1.CDN节点是会有缓存机制的，刚刚你请求的地址命中缓存，那么就直接返回，不会成为死循环了，而POST包则有一个很好的特性，绝对回源，一点也不含糊。
2.POST包可以扩大体积，在同等连接数的情况下让效应更加明显。
```

我们本次测试发送500个POST包，每个体积大概为10k左右。然后总共发送的流量为5M。

然后让我们来看下两个节点的反应

![p3iV2pGk-nHNW_eZnTRHq0Yf8SGgxV0VDy7qOYgM](https://web.archive.org/web/20131219070448im_/https://lh5.googleusercontent.com/p3iV2pGk-nHNW_eZnTRHq0Yf8SGgxV0VDy7qOYgMPD9sboUYKvu1Q3ZnSmducIsbHKa-WcxSp44DkfAgPXtIkZXhUav-yO7MlsurkIkKiI1msf28VXqKQf1v)

不过似乎到了带宽上限。因为我们手中的机器毕竟也不是很给力。

然后让我们来看下这500个POST包产生的效果

```
58.215.139.124
RX bytes:5473847154 (5.0 GiB) TX bytes:17106340685 (15.9 GiB)
RX bytes:6014294496 (5.6 GiB) TX bytes:17717990777 (16.5 GiB)
流入 540447342(515MB) 流出 611650092(583MB)
112.65.231.233
RX bytes:5583125549 (5.1 GiB) TX bytes:5022744608 (4.6 GiB)
RX bytes:6133578284 (5.7 GiB) TX bytes:5649798353 (5.2 GiB)
流入 550452735(524MB) 流出 627053745(598MB) 
```

我们拿最小的进行测算吧，大概把流量扩大了100倍左右，然后如果把流入流出加起来就是扩大了200倍左右。

这一种攻击方式和前一种相比有两个优点

```
1.CDN服务商不能把源站IP做限制来防御，因为他无法知道别家的CDN节点IP。
2.能借刀杀人，可以用一家CDN服务商的CDN节点来打另外一家CDN服务商。
```

然后我们还进行了一些联想，一个站点可以把两个节点陷入死循环，如果把更多的节点来进来呢？

我们可以这样。让多个CDN节点和一个CDN节点死循环，把中间的CDN节点带宽耗尽。

![DQsw0uL69ptLW6kbgMG1tzT1dVySjJzlk7WxQ3CN](https://web.archive.org/web/20131219070448im_/https://lh4.googleusercontent.com/DQsw0uL69ptLW6kbgMG1tzT1dVySjJzlk7WxQ3CNHcSjZshauWk4HmfY3PgZrJlpkjnOlVqK7VfUb9t0t1F2QZt7f2auhdziPNilqWxCNGZ33DuEpgBKAsNV)

我们还可以这样。让三个CDN节点死循环，如果有做流量上的流入流出探测限制，这样能保证流入流出不为一个IP。

![C_1QXRpUKnzTxXrG-DnNUYQBzdxsf_mqfw79zrhW](https://web.archive.org/web/20131219070448im_/https://lh6.googleusercontent.com/C_1QXRpUKnzTxXrG-DnNUYQBzdxsf_mqfw79zrhW3vhn4nD5a-bpgZja_Og7k-Me4-e4m1XtqmnbIyD7wWx1I7JR5hJftePCtMU8O8-e0X21ycckwb1hJLoM)

毕竟在CDN服务商添加一个域名的代价是很小的（免费），我们可以用一个一个域名将节点串起来，然后啪一下开始流量死循环震荡。

好了，让我们用四个字总结一下这次的漏洞的特点：借力打力。

## 0x02 防御方法

------

那么如何来防御这种以及可能演化出来的攻击呢？

```
1. 禁止把源站IP设为CDN节点本身（这是必须的）。
2. 限制每个站点的带宽。  
3. 对请求超时的源站做一定限制。  
4. 通过X-Forwarded-For来进行限制，超过多少层自动丢弃。
```

以及CDN节点已经存在的一系列的软硬防都可以让一部分的攻击流量无法成型，自然也无法形成死循环震荡。

本文仅为一种CDN流量放大攻击的思路，只是做过一些小规模的实验，也欢迎大牛们进行验证。如有不足之处或者逻辑上的错误还请提出，谢谢您的阅读。

by OpenCDN成员 [囧思八千](https://web.archive.org/web/20131219070448mp_/http://weibo.com/jelope) [Twwy.net](https://web.archive.org/web/20131219070448mp_/http://twwy.net/)http://twwy.net/)