# 一种另类的 shiro 检测方式

原创 l1nk3r [CT Stack 安全社区](javascript:void(0);) *2020年07月30日 18:00*

## 0x01 前言

**shiro** 这玩意今年出现在大众视野里，众多师傅大喊hw没有shiro不会玩，实际上追溯这个洞最早开始时候是2016年的事情了，也就是说因为某些攻防演练，这个洞火了起来，当然我也聊一点不一样东西，因为其他东西师傅们都玩出花了。

## 0x02 过程

首先判断 **shiro** 的 **key** 这个过程，我之前采用的逻辑就是 **YSO** 的 **URLDNS** 针对 **dnslog** 进行处理，如果没有 **dnslog** 的情况下，考虑直接用CC盲打，判断延迟。这种会存在一些小问题，比如当这个 **shiro** 没有 **dnslog** ，且 **gadget** 不是CC的情况下，可能就会漏过一些漏洞。

大家判断是否是 **shiro** 的逻辑，普遍都是在 **request** 的 **cookie** 中写入 **rememberMe=1** ，然后再来看 **response** 的 **set-cookie** 是否出现的 **rememberMe=deleteMe** 。下文就针对这个 **rememberMe=deleteMe** 进行深入研究，看看为啥会这样。

网上已经有很多文章，包括我自己梳理了一遍 **shiro** 反序列化的整个过程，这里就不多赘述，核心点在 **AbstractRememberMeManager#getRememberedPrincipals** 这段代码中。

- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 

```
public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {        PrincipalCollection principals = null;
try {            byte[] bytes = this.getRememberedSerializedIdentity(subjectContext);if (bytes != null && bytes.length > 0) {                principals = this.convertBytesToPrincipals(bytes, subjectContext);            }        } catch (RuntimeException var4) {            principals = this.onRememberedPrincipalFailure(var4, subjectContext);        }
return principals;    }
```

好了，下面我们分别来看两种情况。

### 1、key不正确的情况

当key错误的时候，我们知道 **AbstractRememberMeManager#decrypt** 是处理解密的过程。

- 
- 
- 
- 
- 
- 
- 
- 
- 
- 

```
protected byte[] decrypt(byte[] encrypted) {byte[] serialized = encrypted;        CipherService cipherService = this.getCipherService();if (cipherService != null) {            ByteSource byteSource = cipherService.decrypt(encrypted, this.getDecryptionCipherKey());            serialized = byteSource.getBytes();        }
return serialized;    }
```

这里代码会进入`cipherService.decrypt(encrypted, this.getDecryptionCipherKey());`进行处理，由于key错误自然是解不出自己想要的内容，所以进入到 **JcaCipherService#crypt(Cipher cipher, byte[] bytes)** 这里会抛出异常。

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVvIctEibX1zsWxq8Sq3tFtzOMPGRHGPh7kWYPzOHxfSZyChiaiaLjq1T15A/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

这里抛出异常之后，自然会进入到我们最开始核心点 **AbstractRememberMeManager#getRememberedPrincipals** 的 **catch** 异常捕获的逻辑当中，别急，先慢慢品一下这个。

- 
- 
- 

```
catch (RuntimeException var4) {principals = this.onRememberedPrincipalFailure(var4, subjectContext);        }
```

跟进去 **onRememberedPrincipalFailure** 方法，这里代码就4行，不多赘述继续跟进 **forgetIdentity** 方法。

- 
- 
- 
- 
- 
- 
- 
- 

```
protected PrincipalCollection onRememberedPrincipalFailure(RuntimeException e, SubjectContext context) {if (log.isDebugEnabled()) {log.debug("There was a failure while trying to retrieve remembered principals.  This could be due to a configuration problem or corrupted principals.  This could also be due to a recently changed encryption key.  The remembered identity will be forgotten and not used for this request.", e);        }
this.forgetIdentity(context);throw e;    }
```

在 **forgetIdentity** 方法当中从 **subjectContext** 对象获取 **request** 和 **response** ，继续由`forgetIdentity(HttpServletRequest request, HttpServletResponse response)`这个构造方法处理。

- 
- 
- 
- 
- 
- 
- 

```
public void forgetIdentity(SubjectContext subjectContext) {if (WebUtils.isHttp(subjectContext)) {            HttpServletRequest request = WebUtils.getHttpRequest(subjectContext);            HttpServletResponse response = WebUtils.getHttpResponse(subjectContext);            forgetIdentity(request, response);        }    }
```

跟进`forgetIdentity(HttpServletRequest request, HttpServletResponse response)`，看到一个 **removeFrom** 方法。

- 
- 
- 

```
private void forgetIdentity(HttpServletRequest request, HttpServletResponse response) {        getCookie().removeFrom(request, response);    }
```

继续跟进 **removeFrom** 方法，发现了给我们的 **Cookie** 增加 **deleteMe** 字段的位置了。

- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 

```
public void removeFrom(HttpServletRequest request, HttpServletResponse response) {String name = getName();String value = DELETED_COOKIE_VALUE;                    //deleteMeString comment = null; //don't need to add extra size to the response - comments are irrelevant for deletionsString domain = getDomain();String path = calculatePath(request);        int maxAge = 0; //always zero for deletion        int version = getVersion();boolean secure = isSecure();boolean httpOnly = false; //no need to add the extra text, plus the value 'deleteMe' is not sensitive at all
        addCookieHeader(response, name, value, comment, domain, path, maxAge, version, secure, httpOnly);
```

### 2、反序列化gadget

还有一种情况，大家用反序列化 **gadget** 生成之后，拿shiro加密算法进行加密，但是最后依然在 **response** 里面携带了`rememberMe=deleteMe`。

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVv6OKbgicQ70PvBVRQs645CWk2TaGPTz3tTiaOfTNmhGF6xQTpkuZhYQcg/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)image-20200721134734696

这里再来品一下，还是回到 **AbstractRememberMeManager#convertBytesToPrincipals** 方法当中，这里的key肯定是正确的，所以经过 **decrypt** 处理之后返回 **bytes** 数组，进入了 **deserialize** 方法进行反序列化处理。

- 
- 
- 
- 
- 
- 
- 

```
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {if (this.getCipherService() != null) {            bytes = this.decrypt(bytes);        }
return this.deserialize(bytes);    }
```

跟进 **deserialize** 方法，下面重点来了。

- 
- 
- 

```
protected PrincipalCollection deserialize(byte[] serializedIdentity) {return (PrincipalCollection)this.getSerializer().deserialize(serializedIdentity);    }
```

反序列化的 **gadget** 实际上并不是继承了 **PrincipalCollection** ，所以这里进行类型转换会报错。

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVvoI4IBs1MIez1ibBicUmMicOn6neUOpPq0bFPsp1KFcEQQE6qpxPVmRqIg/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

但是在做类型转换之前，先进入了 **DefaultSerializer#deserialize** 进行反序列化处理，等处理结束返回 **deserialized** 时候，进行类型转换自然又回到了上面提到的类型转换异常，我们 **key** 不正确的情况下的 **catch** 异常捕获的逻辑里，后面的流程就和上述一样了。

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVvOWo8Dkf4ajwvHN5ohCBxS1WHc5aou5IPMFvAxmicicEqTB7HfaPbPx2w/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVvelrWexibkqWPRicdib5c9cNuOSAlLbj7ictZdKQffObOKduNlK1r81wgKA/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

## 0x03 构造

那么总结一下上面的两种情况，要想达到只依赖shiro自身进行key检测，只需要满足两点：

1.构造一个继承 **PrincipalCollection** 的序列化对象。

2.key正确情况下不返回 **deleteMe** ，key错误情况下返回 **deleteMe** 。

基于这两个条件下 **SimplePrincipalCollection** 这个类自然就出现了，这个类可被序列化，继承了 **PrincipalCollection** 。

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVv9qnD2mO5GN0GHw3F7WJ7IjUvyLbyEoDdqe7c1823toe78b8kOt7a9A/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

构造POC实际上也很简单，构造一个这个空对象也是可以达到效果的。

- 
- 
- 
- 

```
 SimplePrincipalCollection simplePrincipalCollection = new SimplePrincipalCollection();        ObjectOutputStream obj = new ObjectOutputStream(new FileOutputStream("payload"));        obj.writeObject(simplePrincipalCollection);        obj.close();
```

key正确：

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVvndXo9QHpPXuEPUbYMta6epLakZNVUfHXEh1icQMwHzIib4BMBXTQ5hSg/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

key错误：

![图片](https://mmbiz.qpic.cn/mmbiz_png/xLk5PwibzMpQIe1okzk6rcia6tYiaM4eRVvgZPLG5snVpqicbcYhglCK6Atp23YRy0ImxPrLtvQYhCzKjwGC3TSATA/640?wx_fmt=png&tp=webp&wxfrom=10005&wx_lazy=1&wx_co=1)

当然，如果您有新的姿势，欢迎和我一起探讨。互相学习才是最好的进步。