shiro <= 1.2.4



bp抓包可以看到这个cookie：

![image-20250104203637698](./shiro550分析/images/image-20250104203637698.png)



太长了！而且是加密后的。



这里搜索 rememberMe关键字，能找到这里：

![image-20250104204546797](./shiro550分析/images/image-20250104204546797.png)



调试也能断下。



往上findusage能回溯到AuthenticatingFilter



当然，我们关注的是加密和序列化的过程，不用那么回溯，看这里：

![image-20250104205429626](./shiro550分析/images/image-20250104205429626.png)

![image-20250104205442660](./shiro550分析/images/image-20250104205442660.png)

这里就先序列化再加密了。

看加密：

![image-20250104205554005](./shiro550分析/images/image-20250104205554005.png)

![image-20250104205607456](./shiro550分析/images/image-20250104205607456.png)

有意思，这个常量key。。。

逐步回溯可以找到这里：

![image-20250104205658887](./shiro550分析/images/image-20250104205658887.png)

这个 DEFAULT_CIPHER_KEY_BYTES![image-20250104205720186](./shiro550分析/images/image-20250104205720186.png)



6。

然后这里的加密方法是AES。



现在的问题是，序列化的cookie在哪儿被反序列化导致漏洞的？

（待续）



2025年1月6日

继续来研究哪儿进行反序列化cookie的。

其实就是从

CookieRememberMeManager#getRememberedSerializedIdentity

find usages，找到所继承的AbstractRememberMeManager:

```java
public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
    PrincipalCollection principals = null;
    try {
        byte[] bytes = getRememberedSerializedIdentity(subjectContext);
        //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
        if (bytes != null && bytes.length > 0) {
            principals = convertBytesToPrincipals(bytes, subjectContext);
        }
    } catch (RuntimeException re) {
        principals = onRememberedPrincipalFailure(re, subjectContext);
    }

    return principals;
}
```

这里面的 `convertBytesToPrincipals`：

```java
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    if (getCipherService() != null) {
        bytes = decrypt(bytes);
    }
    return deserialize(bytes);
}
```



先decrypt，然后反序列化~







可以debug再跟一遍流程。

我们输入正确用户名密码，勾选rememberMe后，先序列化 + 加密：![image-20250106174656958](./shiro550分析/images/image-20250106174656958.png)



那我们怎么触发反序列化cookie呢？

我们把cookie的JESSONID删掉。

![image-20250106174825178](./shiro550分析/images/image-20250106174825178.png)

可以看到就进来了：

![image-20250106174842680](./shiro550分析/images/image-20250106174842680.png)



猜测是JESSONID在的时候不会反序列化rememberMe。

源码找找原因。



看下这个stack：

```
convertBytesToPrincipals:431, AbstractRememberMeManager (org.apache.shiro.mgt)getRememberedPrincipals:396, AbstractRememberMeManager (org.apache.shiro.mgt)getRememberedIdentity:604, DefaultSecurityManager (org.apache.shiro.mgt)resolvePrincipals:492, DefaultSecurityManager (org.apache.shiro.mgt)createSubject:342, DefaultSecurityManager (org.apache.shiro.mgt)buildSubject:846, Subject$Builder (org.apache.shiro.subject)buildWebSubject:148, WebSubject$Builder (org.apache.shiro.web.subject)createSubject:292, AbstractShiroFilter (org.apache.shiro.web.servlet)doFilterInternal:359, AbstractShiroFilter (org.apache.shiro.web.servlet)doFilter:125, OncePerRequestFilter (org.apache.shiro.web.servlet)internalDoFilter:168, ApplicationFilterChain (org.apache.catalina.core)doFilter:144, ApplicationFilterChain (org.apache.catalina.core)invoke:168, StandardWrapperValve (org.apache.catalina.core)invoke:90, StandardContextValve (org.apache.catalina.core)invoke:482, AuthenticatorBase (org.apache.catalina.authenticator)invoke:130, StandardHostValve (org.apache.catalina.core)invoke:93, ErrorReportValve (org.apache.catalina.valves)invoke:660, AbstractAccessLogValve (org.apache.catalina.valves)invoke:74, StandardEngineValve (org.apache.catalina.core)service:346, CoyoteAdapter (org.apache.catalina.connector)service:383, Http11Processor (org.apache.coyote.http11)process:63, AbstractProcessorLight (org.apache.coyote)process:937, AbstractProtocol$ConnectionHandler (org.apache.coyote)doRun:1791, NioEndpoint$SocketProcessor (org.apache.tomcat.util.net)run:52, SocketProcessorBase (org.apache.tomcat.util.net)runWorker:1190, ThreadPoolExecutor (org.apache.tomcat.util.threads)run:659, ThreadPoolExecutor$Worker (org.apache.tomcat.util.threads)run:63, TaskThread$WrappingRunnable (org.apache.tomcat.util.threads)run:745, Thread (java.lang)
```

emmm，没找着，嘛，无关紧要）