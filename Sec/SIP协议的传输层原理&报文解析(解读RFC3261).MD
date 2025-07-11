FROM https://www.cnblogs.com/shuiguizi/p/11201224.html

---

**一，SIP协议简述**

源文：[https://datatracker.ietf.org/doc/rfc3261/?include_text=1](https://datatracker.ietf.org/doc/rfc3263/?include_text=1)

简单说，就是我想给你打电话，我俩怎么建立这个对话连接，于是SIP协议就是用来约定这个行为的

 

**二：RFC中的关键术语的解析**

1，UAC/UAS/UA

UAC：User Agent Client用户代理客户端

UAS：User Agent Server用户代理服务端

UA：A logical entity that can act as both a user agent client and user agent server.

水鬼：何为User，我们都是用户，我们如果想要打电话怎么利用SIP协议建立连接呢？当然要有个小程序，所以这个小程序就是UA, 在建立连接的时候总有一个人是发起者，那么他就扮演了Client的角色，被访问的就是服务端

​      所以UA是实体，而UAC和UAS表示的是扮演的角色

2， TU:Transaction User

SIP协议的工作方式是以事物为单位的，一旦一个人想要打电话，要经历拨号，连接，应答等，中间有多次交互，这样一整套交互就是一个事物。

事物在工作过程中就是调用传输层的协议为我发数据，所以这个TU就是位于传输层的上层，在SIP协议中扮演了和传输层打交道的那个。

这个用户包含如下三个核心(core): UAC core, UAS core, and proxy core.

这些core其实是代码层面的概念，因为要实现sip协议，肯定要为不同的功能编写函数，于是

UAC core:对于UA在行使其作为client的角色时，需要实现的功能函数

UAS core：server的角色

proxy core: 针对其proxy的功能的实现，何为proxy，类似与移动联通，我给小名打电话，中间肯定有很多proxy帮我们转发

 

二，事务的工作原理简介

sip是一个事务协议， 即两个组件之间的交互需要一系列独立的message交换。进一步说就是，一个sip事务，包括一个请求和针对这个请求的多个应答，这些应答包括0个或多个临时的应答以及一个或多个最终的应答。

具体的场景就是，一个事务从一个INVITE请求开始，如果最终应答不是2xx，那事务还包括一个ACK，否则ACK不认为是事务的一部分。

 

```
The 2xx response and its ACK receive special treatment.  This
   response is retransmitted only by a UAS, and its ACK generated only
   by the UAC.  This end-to-end treatment is needed so that a caller
   knows the entire set of users that have accepted the call.  Because
   of this special handling, retransmissions of the 2xx response are
   handled by the UA core, not the transaction layer.  Similarly,
   generation of the ACK for the 2xx is handled by the UA core.  Each
   proxy along the path merely forwards each 2xx response to INVITE and
   its corresponding ACK.
```

## SIP Uniform Resource Locators

```
   SIP URLs are used within SIP messages to indicate the originator (From), current destination (Request-URI) and final recipient (To) of
   a SIP request, and to specify redirection addresses (Contact). A SIP URL can also be embedded in web pages or other hyperlinks to indicate
   that a particular user or service can be called via SIP. When used as a hyperlink, the SIP URL indicates the use of the INVITE method.

wxy：sip类型的url是用来定位sip请求消息是来自哪里(from),当前的目的地(Request-URI),和最终的接收端(to)，以及用来指定redirection地址(contact).    一个sip url也可以被嵌入到网页中，或者其他超连接上，用一指示某特定的用户或者服务可以通过sip协议去呼叫该地址。当使用了超链接，sip url嗲标INVITE 方法。
Request-URI 
The Request-URI is a SIP URL as described in Section 2 or a general URI. It indicates the user or service to which this request is being
   addressed. Unlike the To field, the Request-URI MAY be re-written by proxies.
   wxy：Request-URI可以是sip url(上一节说的),也可以是一个通用uri.他代表请求应该如何被寻址，不像To field，这个Request-URI是可以被proxy重写的。
When used as a Request-URI, a SIP-URL MUST NOT contain the transport-param, maddr-param, ttl-param, or headers elements. A
   server that receives a SIP-URL with these elements removes them before further processing.    wxy：当sip url作为Request-URI，他必须包含传输参数，广播参数，或者头元素。一个服务器在接收到sip-url后会首先除去这些元素再做进一步处理
Typically, the UAC sets the Request-URI and To to the same SIP URL, presumed to remain unchanged over long time periods. However, 
if the UAC has cached a more direct path to the callee, e.g., from the Contact header field of a response to a previous request, 
the To would still contain the long-term, "public" address, while the Request-URI would be set to the cached address. Proxy and 
redirect servers MAY use the information in the Request-URI and request header fields to handle the request and possibly rewrite 
the Request-URI. For example, a request addressed to the generic address sip:sales@acme.com is proxied to the particular person,
 e.g., sip:bob@ny.acme.com , with the To field remaining as sip:sales@acme.com. At ny.acme.com , Bob then designates Alice as the
temporary substitute. The host part of the Request-URI typically agrees with one of the host names of the receiving server. 
If it does not, the server SHOULD proxy the request to the address indicated or return a 404 (Not Found) response if it is unwilling 
or unable to do so. For example, the Request-URI and server host name can disagree in the case of a firewall proxy that handles 
outgoing calls. This mode of operation is similar to that of HTTP proxies. If a SIP server receives a request with a URI indicating
a scheme other than SIP which that server does not understand, the server MUST return a 400 (Bad Request) response. It MUST do this 
even if the To header field contains a scheme it does understand. This is because
proxies are responsible for processing the Request-URI; the To field is of end-to-end significance.
  wxy:典型的，uac设置R-URI 和 To为同一个sip URL，然而如果uac已经该

```

 

**三，报文解析**

**1.first line**

**例子：INVITE sip:bob@biloxi.com SIP/2.0** 

**含义：INVITE类型的请求，使用sip协议/服务，向位于\**biloxi.co这个sip服务器上的bob发邀请，版本为\**SIP/2.0**

***\*------------------------\*\*\*\*+ /r/n，作为分隔，不属于任何------------------------\*\*\*\*\****

 

**2，message header**

**每一个header由 \**\*\*/r/n结束\*\**\*，即一个header field包含了 \**/r/n\****

**via：**

​    While the Via header field tells other elements where to send the response, 

​    (via是用来告诉其他人向哪里发送应答)

```
   The Via header field indicates the transport used for the transaction
   and identifies the location where the response is to be sent.  A Via
   header field value is added only after the transport that will be
   used to reach the next hop has been selected (which may involve the
   usage of the procedures in [4]).   （当transport选择了下一跳到哪里后，就添加一个via）

   When the UAC creates a request, it MUST insert a Via into that
   request.  The protocol name and protocol version in the header field
   MUST be SIP and 2.0, respectively.  The Via header field value MUST
   contain a branch parameter.  This parameter is used to identify the
   transaction created by that request.  This parameter is used by both
   the client and the server.    （当一个UA创建一个请求时，他必须在请求中insert一个via，并且这个via必须包含一个branch 参数，     这个参数用来定位此次事物是由哪个请求创建的，这个参数既给client用，也给server用，必须是全空间唯一的）
Request Forwarding：
The proxy MUST insert a Via header field value into the copy before the existing Via header field values. 
Forward response：

The proxy removes the topmost Via header field value from the response.
If no Via header field values remain in the response, the response was meant for this element and MUST NOT be forwarded.
 This will result in the
         response being sent to the location now indicated in the
         topmost Via header field value. 
```

### Route

```
   The Route request-header field determines the route taken by a request. Each host removes the first entry and then proxies the
   request to the host listed in that entry, also using it as the Request-URIwxy：路由字段用于确认请求向哪里发送，每一个host在接收到这个请求后，首先移除最上层的条目，然后根据接下来的条目确认向哪里转发这个请求，一般用这个ip作为Request-URI。
The Record-Route request and response header field is added to a request by any proxy that insists on being in the path of subsequent
requests for the same call leg. It contains a globally reachable Request-URI that identifies the proxy server. Each proxy server adds
its Request-URI to the beginning of the list.wxy：the path of subsequent requests for the same call leg。这是什么意思，我的理解就是一次通话，从最开始的invite请求，之后还要有ring请求，bye请求等，所以叫做subsequent request    请求每到一个proxy，就会把自己的ip添加到请求中，这个ip是一个全局可达的Request-URI类型地址，添加的方式是添加到list的beginning上
The server copies the Record-Route header field unchanged into the response. (Record-Route is only relevant for 2xx responses.) The calling user agent client
 copies the Record-Route header into a Route header field of subsequent requests within the same call leg, reversing the order of requests, so that the first 
entry is closest to the user agent client. If the response contained a Contact header field, the calling user agent adds its content as the last Route header. 
Unless this would cause a loop, any client MUST send any subsequent requests for this call leg to the first Request-URI in the Route request header field and 
remove that entry. The calling user agent MUST NOT use the Record-Route header field in requests that contain Route header fields. Some proxies, such as those 
controlling firewalls or in an automatic call distribution (ACD) system, need to maintain call state and thus need to receive any BYE and ACK packets for the call.
wxy：服务器在接收到请求后，会不做任何改变将route拷贝到response中(route只用于2xx对应的response)。这时候打电话的那个uac接收到应答后，把应答中的这些route翻转过来，最下面的一个变成最上面的
     后续的请求，也就按照从上到下的路由转发请求
     即   A(请求)-->张三--李四-->王五--->B,  收到的请求，route从最里层到最外层分别是3，4，5； B封装应答的时候，原样不变
                  A<------------------B(应答)
         A收到应答后，把route翻转，从最外层到最里层是3，4，5，这样A再发请求到B的时候，还是会沿着3，4，5这条路径走下去
 
```

### Stateless Proxy

对于无状态proxy，转发请求和转发应答的原则跟上面说的一致，但更多的还有如下的规则：

```
When a response arrives at a stateless proxy, the proxy MUST inspect the sent-by value in the first (topmost) Via header field value.  
If that address matches the proxy, (it equals a value this proxy has inserted into previous requests) the proxy MUST remove that header 
field value from the response and forward the result to the location indicated in the next Via header field value.
当一个应答到达了无状态proxy，proxy必须期待 first via的sent-by值是匹配自己，因为这样意味者当初请求就是从我这里转发出去的，然后proxy必须要将这个via从response中移除
然后根据下一个via中的值去定位，接下来应答应该向哪里转发

wxy：uac创建请求，添加第一个via，这个via实际就是自己，到了第一个proxy，
     proxy会将自己的位置信息封装到一个新via中并添加到header中，via-proxy，via-origin
     
     最后，请求到达了终点服务器uas根据接收到的请求，via保持原来的，生成应答后，发送给proxy
     proxy接收到带有两个via的应答后，首先取出topmost via，也就是via-proxy进行比对看看是不是自己，然后剥离，然后根据via-origin将应答转发给origin
     uac接收到应答，检查via-origin必须是自己
```

**例子：Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds**

1， the address (pc33.atlanta.com) at which Alice is expecting to receive responses to this request

 

```
2，the Contact header field tells other elements where to send future requests.
```

***\**\*\*\*\*\*\*\*------------------------\*\*\*\*+ /r/n，作为分隔，不属于任何，另外如果没有body，也是需要由这个结束的分隔-------\*\*\*\*\*\*\*\*--------(也就是说header的结束有两个 \*\*\*\*\*\*\*\*/r/n，一个属于行的，一个属于header的\*\*\*\*\*\*\*\*)\*\*\*\*\****

 3,message body

每一个filed之间***\**\*\*\*\*\*\*\*------\*\*\*\*+ /r/n，作为分隔，不属于任何filed，最后一个filed之后也是有\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*/r/n，\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*------\*\*\*\*\*\*\*\*\*\*\*\*\****

***\**\*\*\*\*\*\*\*\*\*\*\*整个body的长度是只所有的内容 + 所有的\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*/r/n，这个值等同header中的content_length的值\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\****

 

 

\---------------------------------

#### REGISTER报文

```
 The REGISTER request allows a client to let a proxy or redirect server know at which address(es) it can be reached. 
 A client MAY also use it to install call handling features at the server.
  客户通过发注册请求让proxy或者重定向服务器知道去哪里找客户，客户也可以使用这个请求在这个服务器上安装一些call handling功能
  
   wxy：我们有13xxx这个电话号码，但是得让基站知道我们物理位置在哪，那么通过的方式就是我的电话到达某个区域，就会在这个区域的基站上注册
A client uses the REGISTER method to register the address listed in the To header field with a SIP server.
Clients may register from different locations, by necessity using different Call-ID values. Thus,the CSeq value cannot be used to enforce ordering. Since registrations are additive, ordering is less of a problem than if each REGISTER request completely replaced all earlier ones.
一个客户，可能位于不同的地方去注册，所以不可避免的会使用不同的Call-ID值，所以不能用Cseq的值去作为一个顺序的标记。由于注册机制是一个增量的，所以顺序号不够用的问题要比注册请求会完全覆盖掉之前的麻烦
We define "address-of-record" as the SIP address that the registry knows the registrand,typically of the form "user@domain" rather than "user@host". In third-party registration, the entity issuing the request is different from the entity being registered.我们用aor即address-of-rocord作为登记者的sip地址，这是一个registry即注册服务器用来识别登记者的一个地址,典型的格式是 用户@域名，而不是 用户@主机名。对于第三方注册，表示注册请求请求报文的发起者和想要注册的那个不是一人

   To: The To header field contains the address-of-record whose registration is to be created or updated.
       该头域存放的是一个将要添加或更新的aor
   From: The From header field contains the address-of-record of the person responsible for the registration.         For first-party registration, it is identical to the To header field value.       该头域存放的是一个aor条目，用来代表是谁负责这次注册。对于first-party注册，这个字段域to字段相同

   Request-URI: The Request-URI names the destination of the registration request, i.e., the domain of the registrar.         The user name MUST be empty. Generally, the domains in the Request-URI and the To header field have the same value;         however, it is possible to register as a "visitor", while maintaining one's name. For example, a traveler         sip:alice@acme.com (To) might register under the Request-URI sip:atlanta.hiayh.org , with the former as the To header         field and the latter as the Request-URI. The REGISTER request is no longer forwarded once it has reached
        the server whose authoritative domain is the one listed in the Request-URI.        Request-URI表示的是注册请求的目的地，即注册服务器的域名。用户名部分必须要是空的。一般来说，Request-URI中的域名和To头域中的域名相同。        然后，如果是一个"visitor"要注册，这时候就要携带用户名。比如sip：alice@acme.com (TO 头域中的内容是这样的) ，而Request-URI中的内容是：        sip:atlanta.hiayh.org。一旦请求报文到达某个服务器，而这个服务器的认证域名就是Ruest-URI列表中的一个域名，那么请求就算是到了....

   Call-ID: All registrations from a client SHOULD use the same Call-ID header value, at least within the same reboot cycle.
       wxy:这个call-id和之后的invite没有什么关系
   Cseq: Registrations with the same Call-ID MUST have increasing CSeq header values. However, the server does not reject out-of-order requests.

   Contact: The request MAY contain a Contact header field; future non-REGISTER requests for the URI given in the To header field
        SHOULD be directed to the address(es) given in the Contact header.        对于之后的非registry请求，如果想发请求给我(To 字段中的URI)，则请求因该被转发到contact中给定的地址。
```

 小小结：我alice是个移动客户端，别人想给我发请求并不知道我具体在哪里，所以我需要提前向sip服务供应商报备我的信息，即注册

​       1，首先是Rquest-Line，也就是first line，主要说明注册大厅是谁，即我要向谁注册，具体说就是传输层我将请求发给服务器，应用层我告知我是想向这个域名对应的注册服务器注册

​          一般情况下，我们是不是想，我向谁发报文，自然而然这个目的地的域名不就自动有了么，但是貌似上层应用可能包含多个域名，所以这里还是要指定下

​         包含三部分 1)Method:REGISTRY 2)Request-URI:表示注册服务器的域名 3)

 

​      2，然后是Message Header

​        TO表示是谁要注册，From表示这个注册请求是从谁那里发出来的，如果是第三方帮忙注册，则二者不同。 注册的内容是一个aor形式的条目，是 用户名@注册服务器域名，用这个aor代表用户，是用户的对外地址

​        Contact表示这个注册用户的实际物理地址，内容的格式是 用户名@用户自己的host

 

终极小例：

```
A user at host saturn.bell-tel.com registers on start-up, via multicast, with the local SIP server named bell-tel.com.   In the example, the user agent on saturn expects to receive SIP requests on UDP port 3890.
  某用户的主机域名是saturn.bell-tel.com，然后想要在udp:3890上接收其他人的sip请求  wxy：这里不知道你是否有疑惑，为什么用户的域名和sip注册服务器的域名有这么重和，我的理解是域名这东西是一个级连形式，一层层由域名服务器提供服务       而我们在注册的时候，往往都是向我们最近的sip服务器(比如手机向基站注册，就是我的范围内最近的基站)注册，逐个服务器同事具备域名解析功能，       所以我这么已注册，既得到一个专有的sip名字，也得到一个这个专网的域名，当然saturn是我真正网络内host名
   C->S: REGISTER sip:bell-tel.com SIP/2.0
         Via: SIP/2.0/UDP saturn.bell-tel.com
         From: sip:watson@bell-tel.com
         To: sip:watson@bell-tel.com
         Call-ID: 70710@saturn.bell-tel.com
         CSeq: 1 REGISTER
         Contact: <sip:watson@saturn.bell-tel.com:3890;transport=udp>
         Expires: 7200
         用户watson向注册服务中心bell-tel.com发注册请求，注册名称为：watson@bell-tel.com,对应实际的物理地址是saturn.bell-tel.com:2890


   The registration expires after two hours. Any future invitations for watson@bell-tel.com arriving at sip.bell-tel.com will    now be redirected to watson@saturn.bell-tel.com, UDP port 3890.

   If Watson wants to be reached elsewhere, say, an on-line service he uses while traveling, he updates his reservation after first
   cancelling any existing locations:
   如果watson想要能够被别的其他访问，

   C->S: REGISTER sip:bell-tel.com SIP/2.0
         Via: SIP/2.0/UDP saturn.bell-tel.com
         From: sip:watson@bell-tel.com
         To: sip:watson@bell-tel.com
         Call-ID: 70710@saturn.bell-tel.com
         CSeq: 2 REGISTER
         Contact: *
         Expires: 0

   C->S: REGISTER sip:bell-tel.com SIP/2.0
         Via: SIP/2.0/UDP saturn.bell-tel.com
         From: sip:watson@bell-tel.com
         To: sip:watson@bell-tel.com
         Call-ID: 70710@saturn.bell-tel.com
         CSeq: 3 REGISTER
         Contact: sip:tawatson@example.com



   Now, the server will forward any request for Watson to the server at example.com, using the Request-URI tawatson@example.com.   For the server at example.com to reach Watson, he will need to send a REGISTER there, or inform the server of his current location   through some other means.

   It is possible to use third-party registration. Here, the secretary jon.diligent registers his boss, T. Watson:
   使用第三方代注册，由jon代替他的老板watson去注册
   C->S: REGISTER sip:bell-tel.com SIP/2.0
         Via: SIP/2.0/UDP pluto.bell-tel.com
         From: sip:jon.diligent@bell-tel.com
         To: sip:watson@bell-tel.com
         Call-ID: 17320@pluto.bell-tel.com
         CSeq: 1 REGISTER
         Contact: sip:tawatson@example.com



   The request could be sent to either the registrar at bell-tel.com or the server at example.com.    In the latter case, the server at example.com would proxy the request to the address indicated in the
   Request-URI. Then, Max-Forwards header could be used to restrict the registration to that server.
```

 

 

\---------------------------------

INVITE报文：

我们知道，客户端在和sip server交互使用的端口号可以是任意的，根据实验发现如下规律

1，注册报文只是注册地址，不包括端口号，即核心就是Contact字段，这个字段并没有端口号

   所以，客户端使用哪个端口号去注册，发出去的INVITE报文都不是说一定会和注册的使用一个------这个还需要等会再实验一下，

   但是，一般情况下，因为注册完就会发请求，所以往往时使用相同的端口号！！！！！

   而是默认都会使用5060，一旦被占用就会使用别的udp端口  -----但是有一次实验，好想也使用了5060，所以这个还有待于进一步验证。

2，使用任意端口号发INVITE报文时，受影响header field包括：Contact，Via，他们的uri中port部分和传输层的端口号相同。

3，当有uac呼叫我的时候，常常会看到server会转发过来两个INVITE请求，第一个是向着我的5060端口，第二个是向着我的实际端口号

​    这两个INVITE请求内容除了上述字段的port不同之外，包括body再内(rtp/rtcp)，其余都是相同的

   

注:以上是实验所得，还未来得及去rfc中找理论支撑。

 

 

Ring报文：

ring报文中的Contact是被呼叫者的实际(具体)的联系方式，

wxy:当呼叫发起方得到这个信息后，并不会直接以sip协议和被呼叫者通信，而是拿着这个联系方式给sip服务器发消息，告诉他我要和这个人通话....

 

 

\---------------------------------

 

**四，客户端UAC的行为特点(或者是实现的要求)**

1，有关状态机

我要打电话了，我首先会发送INVITE请求，在发送前，TU首先会创建一个事物，初始状态为“calling”，然后发请求，如何发？

1）如果是基于不可靠的连接，他会先起一个定时器A，时常为T1，然后发请求，如果T1时间内没有收到应答，则重发，此时定时器设置为2T1，再之后为double上一次的时间，但最长不能长于定时器B(64个T1)

2)如果是基于可靠的连接，没有定时器A，但有定时器B，因为是基于连接的，所以不怕收不到应答，但是一旦收不到，B时间到了，一样完蛋

 

2，有关连接(connection)

对于使用TCP,SCTP,或者TLS协议的，都是基于连接的，所以再进行传输之前，首先要建立连接。

对于传输层来说，需要管理这些连接，无论是自己主动发起的还是被动连接的，当然这个连接是双方一起建立的，所以对于这些连接信息，sip协议是share的。

sip协议针对每一个连接用一个index来记录，一个index由连接的远端(另一头)的地址，port，协议类型 这三元组来生成。有以下几个特点

1)对于连接的发起者index=目的ip + 目的port + 传输协议

2)对于连接的接收者index=源ip + 源port + 传输协议，

对于这些已经建立好的连接，sip的两个UA在有传输任务的时候，其实是可以复用的。但由于源port往往是随机的，所以无法复用，那么如果之前的接收者想作为发起者发送数据了

他就需要重新建立一条连接。最终，对于经常有交互的UA之间，会存在两条建立好的连接，然后不断不断的复用着

 

**四，关于sip如何使用传输层的**

(一)，客户端发送请求

 1，客户端在构造请求报文的时候，会在 Via 字段的头域中嵌入一个"sent-by"字段，这个字段包含两部分：ip地址或域名， 端口号。这个字段用来指导服务器向哪里回应答，如果没有port，则会使用缺省端口(udp/tcp/sctp:5060； tls:5061)

   1)如果是可靠传输

​     因为是基于连接的，所以从哪里接收就向哪里回应。

​      但如果server接收请求后，如果连接断了，那server就会重起连接，所以发送端必须在自己"sent-by"中指定的地址：端口上时刻准备着，准备着被连接

   2)如果是不可靠的传输

​     发送端嵌入了"sent-by"字段，那么你就应该在"sent-by"字段中指定的地址+port上时刻准备着，准备着接收服务端的应答

 

(二)，客户端接收应答

当应答回来了，客户端会检查应答中的 VIa 头域中的"sent-by"字段，一般来说这个字段是来自当初请求中的该字段，所以我回检查他是否和我的配置匹配，如果不匹配则销毁之

 

(三)，服务端接收请求

1，作为服务器，你要注意在可能的接口上做好被连接的准备。所谓可能的接口，举个例子:你对外说xx域名代表我，那么这个域名背后的ip：port一定是可以被连接，说白了就是发布出去的路，自己一定保证路是通的。

2，所有接口上的udp/tcp/sctp:5060, tls:5061必须是可以接收连接的。（不过也有例外，私网环境和一个机器上部署多实例sip服务器的场景）

 

3，如果一个服务器为UDP协议在一个port上listen了，那么他必须也要为TCP协议在该port上监听，那是因为当包很大时，双方可能随时切换协议进行传输。

   反之，则不必。

  而且一般来说，服务端不需要为udp监听某个地址和port，因为已经在为tcp监听了，当然也有写特殊的需求

  水鬼子：这里着实有点蒙，udp为什么要监听？ tcp监听了udp就不需要了么？ 原文是：

```
A server need not listen for UDP on a particular address and port just because it is listening on that same address and port for TCP.  
There may, of course, be other reasons why a server needs to listen for UDP on a particular address and port.
```

4，如果接收到的包的源ip和"sent-by"字段指定的ip不同，则server需要在Via 的头上增加一个字段，叫"received",表示实际接收包的ip，这个字段用来帮助传输层去回复应答，也就是说这个应答必须要回给接收到请求的那个源地址，说白了就是哪里收到回哪里

 

 

(四)，服务端发送应答

1，如果是基于可靠传输的（比如tcp，sctp，tls），如果在发送应答时连接还在，则基于连接回复应答

​                                        如果连接没有了，则server重新和received“建立连接，然后再send response

2，如果Via header字段中包含“maddr”参数，则需要回给列表中所有的地址，使用的端口号就是"sent-by"中指定的端口号，如果没有指定，那么就是5060端口号

3，如果基于不可靠的传输的单播传输，回应答给“received“指定的地址 和 "sent-by"中指定的端口号，如果端口号没有指定，那么就是5060

4，如果没有“received“标识，则应答会给 "sent-by"中指定的地址 + 端口号

 

====================================================================

终极例子

0: atlanta.com是Ailce所属的sip服务器， 简称 A 和A侧代理

```
biloxi是bob所属的sip服务器，简称B和B侧代理
```

 *--------------begin--->*

 

```
F1 INVITE Alice -> atlanta.com proxy

INVITE sip:bob@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
Max-Forwards: 70
To: Bob <sip:bob@biloxi.com>
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.atlanta.com>
Content-Type: application/sdp
Content-Length: 142

(Alice's SDP not shown)

1，Alice要向bob发邀请，首先会把请求发给自己的sip服务供应商atlanta，bob所在的sip服务供应商为biloxi，Alice自己的主机地址(这里面使用的是域名)是pc33.atlanta.com   via：将自己的地址添加到via上，为了让接下来的proxy知道一回回应答的时候回给哪里（这个哪里是细化到应用进程，即ip:port，当然port要是没有那就是缺省port）   contact：表示如果bob想要和我联系，你应该知道我是谁，或者说我的联系方式是什么。  wxy:bob的主机地址或者说网络地址Alice是不知道的，所以他只管将请求发给sip服务器，sip服务器是知道bob在哪里的      至于如何知道的，那当然后registry报文的功劳，因为各个uac都会将自己的地址信息注册到所属的sip服务供应商，或者叫服务器那里      而Alice自己当然知道自己的主机地址，所以报文中会携带具体的地址信息      所以pc33.atlanta.com 和 alice@atlanta.com是两个概念       A  ---> A侧代理  invite
----------------------------------F2 100 Trying atlanta.com proxy -> Alice

SIP/2.0 100 Trying
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Content-Length: 02，atlanta实际是作为proxy接收到了请求，于是针对这个请求先回应一个临时应答，这个应答里的via是在请求的基础上增加"received"这个参数，表示我是从哪个ip接收到的请求
     A  <--- A侧代理 100

----------------------------------------
 F3 INVITE atlanta.com proxy -> biloxi.com proxy 
INVITE sip:bob@biloxi.com SIP/2.0 
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1 
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8 ;received=192.0.2.1 
Max-Forwards: 69 
To: Bob <sip:bob@biloxi.com> 
From: Alice <sip:alice@atlanta.com>;tag=1928301774 
Call-ID: a84b4c76e66710 
CSeq: 314159 INVITE 
Contact: <sip:alice@pc33.atlanta.com> 
Content-Type: application/sdp 
Content-Length: 142 (Alice's SDP not shown)

3，atlanta会继续将请求转发给biloxi这个服务器/proxy,在转发之前会新建一个via，把自己的地址信息添加进来，自己的地址信息这里是一个域名，即proxy的域名：bigbox3.site3.atlanta.com
  然后把这个新via insert到报文头中
 A侧代理 ---> B侧代理  invite
------------------------------------------------------

F4 100 Trying biloxi.com proxy -> atlanta.com proxy

SIP/2.0 100 Trying
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1
 ;received=192.0.2.2
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Content-Length: 0

4，回复临时应答给atlanta，同样在topmost via中添加上"received"参数
 A侧代理 <--- B侧代理  100
----------------------------------------------------------F5 INVITE biloxi.com proxy -> Bob

INVITE sip:bob@192.0.2.4 SIP/2.0
Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4b43c2ff8.1
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1
 ;received=192.0.2.2
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
Max-Forwards: 68
To: Bob <sip:bob@biloxi.com>
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.atlanta.com>
Content-Type: application/sdp
Content-Length: 142

(Alice's SDP not shown)5，sip 服务供应商(proxy)将invite请求发给最终的uac，但是在发送前同样需要把自己的位置信息封装到一个via中insert到headers里
 B侧代理 ---> B invite
------------------------------------------------

F6 180 Ringing Bob -> biloxi.com proxy

SIP/2.0 180 Ringing
Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4b43c2ff8.1
 ;received=192.0.2.3
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1
 ;received=192.0.2.2
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
Contact: <sip:bob@192.0.2.4>
CSeq: 314159 INVITE
Content-Length: 06，bob接收到请求后，自己的手机会响零，同时回发ring报文给自己的proxy，之后由proxy最终告知A：和我之间的通路是通的，并且你要占领该通路并保持着。   如何知道是哪个proxy呢，当然是根据topmost via知道的，一看原来是biloxi这个proxy，器地址为server10.biloxi.com
   wxy:这里sip协议的"事务"的概念就出来了，首先sip的上层应用会将invite请求和branch即“事务”编码对应上，围绕这个事务创建ring报文，进而知道是针对这个invete的，所以可以从invite中的via提取出来下一步向哪里发送
    另外，所有的via在uac那里是不会被remove的，只由在proxy那里被remove
    还有就是，ring请求不会改动via，但是会重新生成contact
   注:这个响铃其实就是我们打电话的时候，所谓的通了，但是我还没接听。
    B侧代理 <--- B ring
--------------------------------------------------------------
F7 180 Ringing biloxi.com proxy -> atlanta.com proxy

SIP/2.0 180 Ringing
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1
 ;received=192.0.2.2
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
Contact: <sip:bob@192.0.2.4>
CSeq: 314159 INVITE
Content-Length: 0

7，proxy之间转发via，接收时检查topmost via，然后remove之，最后转发出去
A侧代理<--- B侧代理  ring
 
-----------------------------------------------------------
F8 180 Ringing atlanta.com proxy -> Alice

SIP/2.0 180 Ringing
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
Contact: <sip:bob@192.0.2.4>
CSeq: 314159 INVITE
Content-Length: 08，供应上/server/proxy转发ring，具体说来是：接收后检查topmost via，然后remove之，根据next via转发出去
A<--- A侧代理  ring
----------------------------------------------------------
F9 200 OK Bob -> biloxi.com proxy

SIP/2.0 200 OK
Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4b43c2ff8.1
 ;received=192.0.2.3
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1
 ;received=192.0.2.2
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Contact: <sip:bob@192.0.2.4>    ----这个contact有变化了
Content-Type: application/sdp
Content-Length: 131

(Bob's SDP not shown)9.bob回应答，即我接听了，比如按了接听键，首先给自己所属的sip供应商回，via的原理同ringwxy：这里仍然用到了“事务”的概念，上层事务模块在处理过程中用id和最原始的invite请求对应上，进而让知道transport模块知道向哪里回应
B侧代理 <--- B 200 OK
-----------------------------------------------------------
F10 200 OK biloxi.com proxy -> atlanta.com proxy

SIP/2.0 200 OK
Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1
 ;received=192.0.2.2
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Contact: <sip:bob@192.0.2.4>
Content-Type: application/sdp
Content-Length: 131

(Bob's SDP not shown)
10，proxy之间的转发，略
A侧代理 <--- B侧代理 200 OK
 
-----------------------------------------------------------
F11 200 OK atlanta.com proxy -> Alice

SIP/2.0 200 OK
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8
 ;received=192.0.2.1
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Contact: <sip:bob@192.0.2.4>
Content-Type: application/sdp
Content-Length: 131

(Bob's SDP not shown)
11，服务供应商/proxy将应答转发给最终的目的地，也是invite的源头
A <--- A侧代理 200 OK
 
-----------------------------------------------------------
F12 ACK Alice -> Bob

ACK sip:bob@192.0.2.4 SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds9
Max-Forwards: 70
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 314159 ACK
Content-Length: 0

   The media session between Alice and Bob is now established.

   Bob hangs up first.  Note that Bob's SIP phone maintains its own CSeq
   numbering space, which, in this example, begins with 231.  Since Bob
   is making the request, the To and From URIs and tags have been
   swapped.
12，alice回ack给bob，表示我知道你结听了，现在协议层面的三次握手正式建立wxy：同样的，"事务"的概念在这里就起作用了，让alice知道这个ack是为哪个invite而产生     ACK只对应invite  注：从这个事件开始，事
   A ---> B  ACK 
 
-----------------------------------------------------------
F13 BYE Bob -> Alice 
BYE sip:alice@pc33.atlanta.com SIP/2.0 
Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKnashds10 
Max-Forwards: 70 
From: Bob <sip:bob@biloxi.com>;tag=a6c85cf 
To: Alice <sip:alice@atlanta.com>;tag=1928301774 
Call-ID: a84b4c76e66710 
CSeq: 231 BYE 
Content-Length: 0 

13，bob挂电话了，即按了挂断键，于是给alice发bye报文 
    A <--- B  BYE
 
-----------------------------------------------------------
F14 200 OK Alice -> Bob

SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKnashds10
From: Bob <sip:bob@biloxi.com>;tag=a6c85cf
To: Alice <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710
CSeq: 231 BYE
Content-Length: 0
 A ---> B 200 OK  
 
```

\--------------------------------------------------------------------------- 

**总结：**

1，关于via和contact，以及first line中的Reuest URl

```
via的作用是告诉下游proxy之后向哪里回送应答，
contact是告诉对方我的联系方式是啥，
打个比方
    alice将自己的联系方式(contact=名字@住址)和住址(via=住址)写在明信片上，然后把明信片交给邮局(proxy)，
    邮局(proxy)会添加一个自己的via（via=邮局的住址）
    然后邮局直接进行中转
    最后邮局把明信片邮给bob
           
contact是身份信息，是uac专有属性，是给其他uac看的，用来联系我； 
via是位置信息，是给proxy或者uac定位看的，via不是uac专有的，每一个路过的都有
```

via在请求的创建时，生成第一个via，然后上行沿途转发的过程中逐渐insert via

  基于这个请求的所有via生成应答，然后下行沿途转发的过程中逐渐remove via

contact同样是请求创建的时候生成contact，然后一路跟随直到目的地

  基于这个请求查创建应答的时候，生成新的contact，然后再一回跟随回到发起者

  如果对端也向向我发后续的请求，则就向这个地址发

 Record-Route/Route:是在经过proxy时由proxy添加进来的，这样如果有后续的请求，则也从这些proxy走过

  via只是指导应答应该走过哪些proxy。route是告诉接收应答或者中间的那些人，如果你想针对此次通话发请求，则同样也走这条路

  比如：a--张三---李四---b，则如果b要发ring请求(针对这个会话的)，则也要走李四，张三这条路，尽管通过王二麻子也是能到a那里，但是不行/不推荐

 

 

INVITE是纯请求，创建via和contact

200 OK是纯应答，复制INVITE的所有via，然后创建自己的contact

180 Ringing既是请求也是应答，作为应答他会复制原来INVITE请求的所有via，作为请求他会创建自己的contact

 

注册过程：

REGISTER sip:bell-tel.com SIP/2.0  -----注册服务器的地址，sip uri without user

Via: SIP/2.0/UDP saturn.bell-tel.com ---地址(域名)，普通地址

From: sip:watson@bell-tel.com    ----注册报文来自哪里，aor格式地址

To: sip:watson@bell-tel.com      ---给谁注册的，同时也是写到注册服务器中的条目的样子

 

 发起过程

```
INVITE sip:bob@biloxi.com SIP/2.0   ---向谁发请求，aor类型格式地址是一个对方在注册服务器中记录的地址 
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8     ---地址(域名)，普通地址，表示经过的proxy
Max-Forwards: 70 
To: Bob <sip:bob@biloxi.com>         ----向谁发请求，aor地址
From: Alice <sip:alice@atlanta.com>;tag=1928301774 
Call-ID: a84b4c76e66710 
CSeq: 314159 INVITE 
Contact: <sip:alice@pc33.atlanta.com>   ----- 表示后续你若想向我再发请求，则发到这里来
```

 

**********************=====================================================================================**********************

**********************服务器：开源软件安装及使用的命令**********************

```
/usr/local/opensips/sbin/opensipsctl restart
/usr/local/opensips/sbin/opensipsctl stop
 /usr/local/opensips/sbin/opensipsctl start
```

 

**********************客户端：**********************

**********************安装的Yate client**********************

**********************1，关于客户端使用的端口号**********************

**********************缺省是使用的5060，一旦这个端口号被占用，则会自动使用其他端口号，所以为了达到你想要的效果可以手动启动两个client进程！**********************