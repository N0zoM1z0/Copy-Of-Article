FROM

```
https://www.leavesongs.com/PENETRATION/client-session-security.html
```



---

在Web中，session是认证用户身份的凭证，它具备如下几个特点：

1. 用户不可以任意篡改
2. A用户的session无法被B用户获取

也就是说，session的设计目的是为了做用户身份认证。但是，很多情况下，session被用作了别的用途，将产生一些安全问题，我们今天就来谈谈“客户端session”（client session）导致的安全问题。

## [0x01 什么是客户端session](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x01-session)

在传统PHP开发中，`$_SESSION`变量的内容默认会被保存在服务端的一个文件中，通过一个叫“PHPSESSID”的Cookie来区分用户。这类session是“服务端session”，用户看到的只是session的名称（一个随机字符串），其内容保存在服务端。

然而，并不是所有语言都有默认的session存储机制，也不是任何情况下我们都可以向服务器写入文件。所以，很多Web框架都会另辟蹊径，比如Django默认将session存储在数据库中，而对于flask这里并不包含数据库操作的框架，就只能将session存储在cookie中。

因为cookie实际上是存储在客户端（浏览器）中的，所以称之为“客户端session”。

## [0x02 保护客户端session](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x02-session)

将session存储在客户端cookie中，最重要的就是解决session不能被篡改的问题。

我们看看flask是如何处理的：

```
class SecureCookieSessionInterface(SessionInterface):
    """The default session interface that stores sessions in signed cookies
    through the :mod:`itsdangerous` module.
    """
    #: the salt that should be applied on top of the secret key for the
    #: signing of cookie based sessions.
    salt = 'cookie-session'
    #: the hash function to use for the signature. The default is sha1
    digest_method = staticmethod(hashlib.sha1)
    #: the name of the itsdangerous supported key derivation. The default
    #: is hmac.
    key_derivation = 'hmac'
    #: A python serializer for the payload. The default is a compact
    #: JSON derived serializer with support for some extra Python types
    #: such as datetime objects or tuples.
    serializer = session_json_serializer
    session_class = SecureCookieSession

    def get_signing_serializer(self, app):
        if not app.secret_key:
            return None
        signer_kwargs = dict(
            key_derivation=self.key_derivation,
            digest_method=self.digest_method
        )
        return URLSafeTimedSerializer(app.secret_key, salt=self.salt,
                                      serializer=self.serializer,
                                      signer_kwargs=signer_kwargs)

    def open_session(self, app, request):
        s = self.get_signing_serializer(app)
        if s is None:
            return None
        val = request.cookies.get(app.session_cookie_name)
        if not val:
            return self.session_class()
        max_age = total_seconds(app.permanent_session_lifetime)
        try:
            data = s.loads(val, max_age=max_age)
            return self.session_class(data)
        except BadSignature:
            return self.session_class()

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        # Delete case. If there is no session we bail early.
        # If the session was modified to be empty we remove the
        # whole cookie.
        if not session:
            if session.modified:
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain, path=path)
            return
        # Modification case. There are upsides and downsides to
        # emitting a set-cookie header each request. The behavior
        # is controlled by the :meth:`should_set_cookie` method
        # which performs a quick check to figure out if the cookie
        # should be set or not. This is controlled by the
        # SESSION_REFRESH_EACH_REQUEST config flag as well as
        # the permanent flag on the session itself.
        if not self.should_set_cookie(app, session):
            return
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)
        val = self.get_signing_serializer(app).dumps(dict(session))
        response.set_cookie(app.session_cookie_name, val,
                            expires=expires, httponly=httponly,
                            domain=domain, path=path, secure=secure)
```

主要看最后两行代码，新建了`URLSafeTimedSerializer`类 ，用它的`dumps`方法将类型为字典的session对象序列化成字符串，然后用`response.set_cookie`将最后的内容保存在cookie中。

那么我们可以看一下`URLSafeTimedSerializer`是做什么的：

```
class Signer(object):
    # ...
    def sign(self, value):
        """Signs the given string."""
        return value + want_bytes(self.sep) + self.get_signature(value)

    def get_signature(self, value):
        """Returns the signature for the given value"""
        value = want_bytes(value)
        key = self.derive_key()
        sig = self.algorithm.get_signature(key, value)
        return base64_encode(sig)


class Serializer(object):
    default_serializer = json
    default_signer = Signer
    # ....
    def dumps(self, obj, salt=None):
        """Returns a signed string serialized with the internal serializer.
        The return value can be either a byte or unicode string depending
        on the format of the internal serializer.
        """
        payload = want_bytes(self.dump_payload(obj))
        rv = self.make_signer(salt).sign(payload)
        if self.is_text_serializer:
            rv = rv.decode('utf-8')
        return rv

    def dump_payload(self, obj):
        """Dumps the encoded object. The return value is always a
        bytestring. If the internal serializer is text based the value
        will automatically be encoded to utf-8.
        """
        return want_bytes(self.serializer.dumps(obj))


class URLSafeSerializerMixin(object):
    """Mixed in with a regular serializer it will attempt to zlib compress
    the string to make it shorter if necessary. It will also base64 encode
    the string so that it can safely be placed in a URL.
    """
    def load_payload(self, payload):
        decompress = False
        if payload.startswith(b'.'):
            payload = payload[1:]
            decompress = True
        try:
            json = base64_decode(payload)
        except Exception as e:
            raise BadPayload('Could not base64 decode the payload because of '
                'an exception', original_error=e)
        if decompress:
            try:
                json = zlib.decompress(json)
            except Exception as e:
                raise BadPayload('Could not zlib decompress the payload before '
                    'decoding the payload', original_error=e)
        return super(URLSafeSerializerMixin, self).load_payload(json)

    def dump_payload(self, obj):
        json = super(URLSafeSerializerMixin, self).dump_payload(obj)
        is_compressed = False
        compressed = zlib.compress(json)
        if len(compressed) < (len(json) - 1):
            json = compressed
            is_compressed = True
        base64d = base64_encode(json)
        if is_compressed:
            base64d = b'.' + base64d
        return base64d


class URLSafeTimedSerializer(URLSafeSerializerMixin, TimedSerializer):
    """Works like :class:`TimedSerializer` but dumps and loads into a URL
    safe string consisting of the upper and lowercase character of the
    alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """
    default_serializer = compact_json
```

主要关注`dump_payload`、`dumps`，这是序列化session的主要过程。

可见，序列化的操作分如下几步：

1. json.dumps 将对象转换成json字符串，作为数据
2. 如果数据压缩后长度更短，则用zlib库进行压缩
3. 将数据用base64编码
4. 通过hmac算法计算数据的签名，将签名附在数据后，用“.”分割

第4步就解决了用户篡改session的问题，因为在不知道secret_key的情况下，是无法伪造签名的。

最后，我们在cookie中就能看到设置好的session了：

[![693b25ce-0a26-43b2-b8c2-80e8786cc9b8.png](https://www.leavesongs.com/media/attachment/2018/03/26/18db98ef-c8ec-435e-a21a-f8eaa8c97631.95a9fc66c7c4.png)](https://www.leavesongs.com/media/attachment/2018/03/26/18db98ef-c8ec-435e-a21a-f8eaa8c97631.png)

注意到，在第4步中，flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的，这就可能造成一些安全问题。

## [0x03 flask客户端session导致敏感信息泄露](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x03-flasksession)

我曾遇到过一个案例，目标是flask开发的一个简历管理系统，在测试其找回密码功能的时候，我收到了服务端设置的session。

我在0x02中说过，flask是一个客户端session，所以看目标为flask的站点的时候，我习惯性地去解密其session。编写如下代码解密session：

```
#!/usr/bin/env python3
import sys
import zlib
from base64 import b64decode
from flask.sessions import session_json_serializer
from itsdangerous import base64_decode

def decryption(payload):
    payload, sig = payload.rsplit(b'.', 1)
    payload, timestamp = payload.rsplit(b'.', 1)

    decompress = False
    if payload.startswith(b'.'):
        payload = payload[1:]
        decompress = True

    try:
        payload = base64_decode(payload)
    except Exception as e:
        raise Exception('Could not base64 decode the payload because of '
                         'an exception')

    if decompress:
        try:
            payload = zlib.decompress(payload)
        except Exception as e:
            raise Exception('Could not zlib decompress the payload before '
                             'decoding the payload')

    return session_json_serializer.loads(payload)

if __name__ == '__main__':
    print(decryption(sys.argv[1].encode()))
```

例如，我解密0x02中演示的session：

[![789edad0-8216-43d3-b6eb-93557e03b63d.png](https://www.leavesongs.com/media/attachment/2018/03/26/89c47e6d-b1de-4593-9f89-c43beb64dd2a.770a934a0daa.png)](https://www.leavesongs.com/media/attachment/2018/03/26/89c47e6d-b1de-4593-9f89-c43beb64dd2a.png)

通过解密目标站点的session，我发现其设置了一个名为token、值是一串md5的键。猜测其为找回密码的认证，将其替换到找回密码链接的token中，果然能够进入修改密码页面。通过这个过程，我就能修改任意用户密码了。

这是一个比较典型的安全问题，目标网站通过session来储存随机token并认证用户是否真的在邮箱收到了这个token。但因为flask的session是存储在cookie中且仅签名而未加密，所以我们就可以直接读取这个token了。

## [0x04 flask验证码绕过漏洞](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x04-flask)

这是客户端session的另一个常见漏洞场景。

我们用一个实际例子认识这一点：https://github.com/shonenada/flask-captcha 。这是一个为flask提供验证码的项目，我们看到其中的view文件：

```
import random
try:
    from cStringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

from flask import Blueprint, make_response, current_app, session
from wheezy.captcha.image import captcha
from wheezy.captcha.image import background
from wheezy.captcha.image import curve
from wheezy.captcha.image import noise
from wheezy.captcha.image import smooth
from wheezy.captcha.image import text
from wheezy.captcha.image import offset
from wheezy.captcha.image import rotate
from wheezy.captcha.image import warp


captcha_bp = Blueprint('captcha', __name__)


def sample_chars():
    characters = current_app.config['CAPTCHA_CHARACTERS']
    char_length = current_app.config['CAPTCHA_CHARS_LENGTH']
    captcha_code = random.sample(characters, char_length)
    return captcha_code

@captcha_bp.route('/captcha', endpoint="captcha")
def captcha_view():
    out = StringIO()
    captcha_image = captcha(drawings=[
        background(),
        text(fonts=current_app.config['CAPTCHA_FONTS'],
             drawings=[warp(), rotate(), offset()]),
        curve(),
        noise(),
        smooth(),
    ])
    captcha_code = ''.join(sample_chars())
    imgfile = captcha_image(captcha_code)
    session['captcha'] = captcha_code
    imgfile.save(out, 'PNG')
    out.seek(0)
    response = make_response(out.read())
    response.content_type = 'image/png'
    return response
```

可见，其生成验证码后，就存储在session中了：`session['captcha'] = captcha_code`。

我们用浏览器访问`/captcha`，即可得到生成好的验证码图片，此时复制保存在cookie中的session值，用0x03中提供的脚本进行解码：

[![cf1b824b-9b61-4770-9224-1421e6fad65c.png](https://www.leavesongs.com/media/attachment/2018/03/26/668894a6-6f59-425b-b032-cba1370c39e9.d200fedb421d.png)](https://www.leavesongs.com/media/attachment/2018/03/26/668894a6-6f59-425b-b032-cba1370c39e9.png)

可见，我成功获取了验证码的值，进而可以绕过验证码的判断。

这也是客户端session的一种错误使用方法。

## [0x05 CodeIgniter 2.1.4 session伪造及对象注入漏洞](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x05-codeigniter-214-session)

Codeigniter 2的session也储存在session中，默认名为`ci_session`，默认值如下：

[![d2bd8335-a3e2-4f72-858f-4e93140dee6d.png](https://www.leavesongs.com/media/attachment/2018/03/26/cdd4d54b-8c8c-47f5-b364-e27d926ce1d2.1f06e03915b6.png)](https://www.leavesongs.com/media/attachment/2018/03/26/cdd4d54b-8c8c-47f5-b364-e27d926ce1d2.png)

可见，session数据被用PHP自带的serialize函数进行序列化，并签名后作为`ci_session`的值。原理上和flask如出一辙，我就不重述了。但好在codeigniter2支持对session进行加密，只需在配置文件中设置`$config['sess_encrypt_cookie'] = TRUE;`即可。

在CI2.1.4及以前的版本中，存在一个弱加密漏洞（ https://www.dionach.com/blog/codeigniter-session-decoding-vulnerability ），如果目标环境中没有安装Mcrypt扩展，则CI会使用一个相对比较弱的加密方式来处理session:

```
<?php
function _xor_encode($string, $key)
{
 $rand = '';
 while (strlen($rand) < 32)
 {
  $rand .= mt_rand(0, mt_getrandmax());
 }
 $rand = $this->hash($rand);
 $enc = '';
 for ($i = 0; $i < strlen($string); $i++)
 {
  $enc .= substr($rand, ($i % strlen($rand)), 1).(substr($rand, ($i % strlen($rand)), 1) ^ substr($string, $i, 1));
 }
 return $this->_xor_merge($enc, $key);
}

function _xor_merge($string, $key)
{
 $hash = $this->hash($key);
 $str = '';
 for ($i = 0; $i < strlen($string); $i++)
 {
  $str .= substr($string, $i, 1) ^ substr($hash, ($i % strlen($hash)), 1);
 }
 return $str;
}
```

其中用到了`mt_rand`、异或等存在大量缺陷的方法。我们通过几个简单的脚本（ https://github.com/Dionach/CodeIgniterXor ），即可在4秒到4分钟的时间，破解CI2的密钥。

获取到了密钥，我们即可篡改任意session，并自己签名及加密，最后伪造任意用户，注入任意对象，甚至通过反序列化操作造成更大的危害。

## [0x06 总结](https://www.leavesongs.com/PENETRATION/client-session-security.html#0x06)

我以三个案例来说明了客户端session的安全问题。

上述三个问题，如果session是储存在服务器文件或数据库中，则不会出现。当然，考虑到flask和ci都是非常轻量的web框架，很可能运行在无法操作文件系统或没有数据库的服务器上，所以客户端session是无法避免的。

除此之外，我还能想到其他客户端session可能存在的安全隐患：

1. 签名使用hash函数而非hmac函数，导致利用hash长度扩展攻击来伪造session
2. 任意文件读取导致密钥泄露，进一步造成身份伪造漏洞或反序列化漏洞（ [http://www.loner.fm/drops/#!/drops/227.Codeigniter%20%E5%88%A9%E7%94%A8%E5%8A%A0%E5%AF%86Key%EF%BC%88%E5%AF%86%E9%92%A5%EF%BC%89%E7%9A%84%E5%AF%B9%E8%B1%A1%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E](http://www.loner.fm/drops/#!/drops/227.Codeigniter 利用加密Key（密钥）的对象注入漏洞) ）
3. 如果客户端session仅加密未签名，利用CBC字节翻转攻击，我们可以修改加密session中某部分数据，来达到身份伪造的目的

上面说的几点，各位CTF出题人可以拿去做文章啦~嘿嘿。

相对的，作为一个开发者，如果我们使用的web框架或web语言的session是存储在客户端中，那就必须牢记下面几点：

1. 没有加密时，用户可以看到完整的session对象
2. 加密/签名不完善或密钥泄露的情况下，用户可以修改任意session
3. 使用强健的加密及签名算法，而不是自己造（反例discuz）

