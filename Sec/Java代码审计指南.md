## 一、测试工具

### 1.1 反编译java类

如果项目中未提供所有java源代码，只提供编译后的class文件，可以运行jd-gui，选择菜单File—Open File，对class文件进行反编译

选择class文件或者jar包，点击打开按钮，即可查看反汇编后的java源代码



### 1.2 Eclipse环境审计

使用Eclipse的Import功能将程序代码导入workspace，打开任一java源文件，选择Source Analyse菜单下的条目进行关键方法搜索，搜索结果在窗口下面显示，然后进行人工分析。



## 二、认证管理

### 2.1 图形验证码

- 用户登录过程是否有图形验证码保护，防止自动化程序猜测密码
- 验证码复杂度是否符合要求（干扰、变形）
- 验证码在使用过一次后是否会自动刷新
- 验证码明文是否会被传送给客户端（页面或Cookie）
- 验证码是否在被保护的操作进行前来验证（无验证或无效验证）

### 2.2 认证实现

- 用户认证过程中，用户名和密码合法性的检查方式是否符合要求

较安全的做法为先校验验证码，再检查用户名，最后比对密码的密文

- 是否具备用户注销功能

用户注销时是否清理了当前用户会话

- 是否会将密码作为重定向的一部分进行传送

在统一认证SSO模式下，有的实现并非使用Token来交换认证信息，而是通过客户端直接传递账号、密码，这种情形下有可能在URL中直接传递明文密码。

- 认证过程中对于用户名错误和密码错误提示是否相同

统一用户名和密码错误提示，可以降低账号、密码被猜解的风险

- 检查用户认证页面是否对认证失败的次数进行了限制

## 三、授权管理

### 3.1 授权实现

- 应用的用户是否具有角色的区分

明确用户的角色定义、授权访问的范围，分析哪种情况下可能会导致越权

- 应用是否具备统一的（或独立）的权限控制模块

大部分的大型应用都会采用统一的权限控制模块

- 应用的权限控制模块是否存在漏洞
- 页面/功能是否使用了权限控制（模块）

识别出需要和无需权限控制的页面/功能，逐一进行验证。验证过程中需要考虑到用户的角色划分。

- 页面的权限控制是否正确

部分应用的权限控制（模块）的使用上存在缺陷，攻击者可能通过一些隐蔽的途径绕过鉴权，访问非授权资源

### 3.2 授权管理

- 高权限用户分析

分析系统高权限用户（例如：管理员用户）的分配情况及密码复杂度等

- 默认用户分析

分析系统是否存在默认用户、密码，密码复杂度等。

## 四、输入/输出验证

### 4.1 SQL注入防护

- 是否存在全局过滤器

过滤器配置、过滤函数等

- 过滤器是否可以过滤所有查询请求

请求是否都按要求经过过滤器处理

- 过滤器的过滤是否符合要求

初期检查可以依据PHPIDS的规则库，后期根据收集的情况予以补充

- 是否使用了预查询机制

预查询是指在将数据传入SQL语句前明确指定传输数据的类型，以执行必要的转换。在Java中预查询的调用方式为prepareStatement。

- 是否存在SQL语句拼接

某些特殊的查询（特别复杂的组合查询）难免用到SQL语句拼接，遇到这种情况，就需要检查拼接是否有可能导致注入。

### 4.2 跨站攻击防护

- 是否存在全局XSS过滤器(论坛的过滤库)
- 过滤器的过滤是否符合要求
- 是否存在需过滤和不需过滤两种输出，页面是否控制恰当（*）

某些情况下可能存在两种输出，文本输出和富文本（HTML）输出，要强制文本输出，只需要调用HTMLEncode()对内容进行编码后输出即可；但是富文本本身就需要使用html来进行格式的控制，简单的编码就无法使用，这时需要在此类内容从客户端输入（用户提交）或输出给客户端（显示）时进行危险代码过滤。

- 输出的时候是否进行编码（HTML、JS）

### 4.3 CSRF攻击防护

- Web表单是否使用了Token（或验证码）
- Web表单提交（成功或不成功）后token（或验证码）是否重置
- 检查Token的生成算法是否安全

可以从测试环境来检查生成的验证码是否符合复杂性要求，如是否有干扰线/点、字符变形等。

- 检查服务器获取Web表单参数值的方式

如果在操作时不严格区分GET和POST，在没有Token（或验证码）的辅助下很容易导致CSRF的发生。

### 4.4 文件上传防护

- 是否限制了上传文件的扩展名

以白名单形式指定允许上传的扩展名；以黑名单形式指定禁止上传的文件名

- 是否对上传文件进行了重命名操作

重命名操作是否安全，防止重命名过程中产生二次风险

- 是否对上传文件的存放位置禁止了脚本执行

### 4.5 文件下载防护

- 是否存在客户端指定文件名的下载功能
- 直接指定文件名的下载是否允许客户端指定路径
- 对于不同用户的文件在下载时是否进行了权限控制

文件下载功能中是否对用户的权限进行了检查。

### 4.6 重定向与转发保护

- 是否具有客户端控制的重定向或转发
- 是否定义了重定向的信任域名或主机列表
- 是否对客户端的重定向或转发请求进行检查

## 五、会话管理

### 5.1 Session管理

- session信息是否放在url里面

通过应用服务器的配置检查

- 执行业务功能时，是否检查了当前用户session身份

从代码部分、从配置部分检查，需要根据应用实际使用的验证方式

- 成功登陆之后是否会更新SessionID

认证成功后是否强制刷新用户使用的SessionID

- session是否有超时注销功能

检查Session的超时时间设置是否符合要求，默认是20~30分钟

### 5.2 Cookie管理

- 是否会在Cookie中存储明文或简单编码/加密过的密码
- 是否会在Cookie中存储应用的特权标识
- 是否设置了Cookie的有效域和有效路径
- 是否设置了合适的Cookie有效时间

如果生存时间在20~30分钟左右，使用Session方式会更加安全

## 六、密码管理

### 6.1 加密安全

- 密码是否以不可逆的哈希形态存储
- 是否使用不带salt的哈希算法来加密密码
- 加密哈希算法中的salt是否硬编码在代码中

### 6.2 密码安全

- 认证过程中传输的密码是否进行了加密处理

可以采用哈希算法或者RSA等加密算法将密码加密后传递，或者是使用SSL来做传输层加密。

- 修改密码功能是否进行了旧密码的验证或者是安全问题的确认
- 找回密码功能是否借用第三方途径

第三方途径主要有电子邮件、手机短信等。这些途径应该是找回密码前预留的。

- 找回密码功能是否采用验证码确认并重设机制

部分应用的找回密码功能是直接将原密码发送到密码保护邮箱，这种方式存在一定的安全风险。

- 检查密码设置页面是否对密码复杂度进行检查

至少包含数字和字母，长度最少6位，避免用户输入弱口令

## 七、调试&接口

### 7.1 异常处理

- 是否捕获了应用出现的错误并阻止其输出给客户端

详细的错误输出可能会导致SQL查询泄露、程序源代码泄露、物理路径泄露等。

- 异常处理是否能够全面覆盖所有异常行为
- 异常处理是否会导致程序流程异常，引发安全问题

备注：某些异常可能是致命的，但是如果程序捕获了异常，可能会导致程序绕过一些重要的步骤而直接执行后续的操作。

### 7.2 数据接口

- 接口服务是否存在安全漏洞
- 接口服务后台登录是否存在弱密码

例如：axis2，[http://localhost:8080/axis2/axis2-admin/，默认用户名/密码：admin/axis2，密码在webapps\axis2\WEB-INF\conf\axis2.xml里配置](https://web.archive.org/web/20221208215356/http://localhost:8080/axis2/axis2-admin/，默认用户名/密码：admin/axis2，密码在webapps/axis2/WEB-INF/conf/axis2.xml里配置)

- 接口服务是否有默认的测试页面

例如：axis2，[http://localhost:8080/axis2/axis2-web/HappyAxis.jsp，会暴露物理路径](https://web.archive.org/web/20221208215356/http://localhost:8080/axis2/axis2-web/HappyAxis.jsp，会暴露物理路径)

- 接口服务应用是否包含身份认证，认证的帐号、密码（或密钥）的存储安全

例如：使用WSS4J对SOAP报文体进行身份认证

- 接口服务应用传输是否加密

例如：使用WSS4J对SOAP报文体进行加密

- 接口服务应用异常处理

例如：Webservice应用对特殊字符的处理，是否会在报错信息中泄露数据，参考[http://www.soapui.org/About-SoapUI/features.html#security-testing](https://web.archive.org/web/20221208215356/http://www.soapui.org/About-SoapUI/features.html#security-testing)

### 7.3 硬编码

- 代码中是否存在内置的敏感信息

如：调试帐号、外部接口帐号/密码、数据加/解密密钥等

## 八、日志审计

### 8.1 日志记录

- 应用是否会将用户密码记入日志
- 日志记录的内容是否合理，避免日志文件增长过快，造成磁盘空间不足

## 九、运行环境

### 9.1 应用配置

- 是否删除了不必要的网页、帐号及权限

页面包括应用服务器的默认页面、管理后台、测试页面、备份文件等；帐号指Web应用服务器的运行帐户

- 目录浏览是否被禁用
- Web容器默认帐户的密码是否更改或禁用
- 不能删除的管理后台是否启用了密码保护
- 正式发布的应用是否包含开发调试文件、代码

如SVN版本信息文件、调试工具/页面、功能模块中的调试接口等

- 重要的配置信息是否进行了加密

如数据库连接配置、其它接口连接配置等

### 9.2 自定义错误

- 是否自定义了403、404、500错误页面
- 错误页面是否会输出详细错误信息

### 9.3 日志管理

- 服务器是否开启了用户访问日志的记录
- 记录的日志是否满足问题回溯的要求

是否记录了客户端地址、请求的方法、请求的URL、提交的参数（GET、POST、COOKIE参数）、请求的状态等

## 十、第三方组件

分析应用使用的框架及引用的第三方组件，分析其是否存在各种已知漏洞，且当前环境漏洞是否可以重现

### 10.1 框架

- Struts/Struts 2
- Turbine
- Spring MVC
- Hibernate
- iBatis
- DotNetNuke

### 10.2 编辑器

- CKEditor/FCKEditor
- eWebeditor
- NicEdit
- Free Rich Text Editor

### 10.3 上传组件

- SmartUpload

### 10.4 安全功能

## 十一、安全功能

对于比较重要的业务系统，例如：支付系统，可以参考以下条目，进行检测

### 11.1 登录认证

- 重要系统是否使用了双因素登录认证，例如：数字证书，支付盾，密保卡等，防止用户密码泄露导致系统被非法登录
- 重要系统是否使用了安全控件，对用户提交的关键数据进行加密
- 重要系统的后台管理界面是否限制了访问源地址
- 系统的密码重置等短信发送等功能的使用频率是否进行了限制，例如：一个手机号一分钟只能发送一条短信，防止被恶意利用多次发送短信
- 用户登录时的用户名，状态，源地址等关键信息需要记录到应用日志中，管理员可以进行查询
- 如果用户在不常用的地址登录，系统会提示用户，并显示上一次登录的源地址
- 对于多次密码错误的登录尝试，系统能否检测，禁止源地址访问10分钟，管理员登录后可以看到，也可以进行查询

### 11.2 数据操作

- 系统中大数据量查询等影响系统负载的功能是否进行了查询范围限制，例如：只能查询最近3个月的数据
- 系统中大数据量查询等影响系统负载的功能是否进行了查询频率限制，例如：一分钟内只能查询一次
- 高可用性要求的系统中是否有用户请求频率检测，超过访问阈值时，需要用户输入页面上的图形验证码，才能进一步操作
- 对报表查询等涉及大量数据的读取和导出操作，是否严格限制了查询范围，必要时可以使用双用户认证，限制单个用户大量读取业务数据的能力
- 业务关键数据的读取页面，是否使用静态密码、手机动态密码等二次验证，防止敏感数据泄露，例如：交易详单的查询
- 业务处理过程中用户身份等关键识别信息，是否保存在服务端，禁止从客户端提交
- 业务处理过程中关键操作需要用户确认和图形验证码，手机动态验证码等保护，防止重放攻击，例如：转账操作等
- 关键业务操作需要记录到应用日志中，可以设置阈值，超过系统会告警，管理员可以进行查询。例如：转账金额大于20万的交易记录
- 涉及资金的业务用户可以设置上限，例如：用户可以设置每日最高消费限额，并在转账
- 关键业务操作可以设置短信提醒，例如：用户进行资金转账，进行详单查询等