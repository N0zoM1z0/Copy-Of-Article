# Java安全之Shiro权限绕过

## 前言

简单总结一些Shiro的权限绕过。

### Shiro权限绕过漏洞

| CVE编号        | 漏洞说明                                                     | 漏洞版本       |
| -------------- | ------------------------------------------------------------ | -------------- |
| CVE-2016-6802  | Context Path 路径标准化导致绕过                              | shrio <1.3.2   |
| CVE-2020-1957  | Spring 与 Shiro 对于 "/" 和 ";" 处理差异导致绕过             | Shiro <= 1.5.1 |
| CVE-2020-11989 | Shiro 二次解码导致的绕过以及 ContextPath 使用 ";" 的绕过     | shiro < 1.5.3  |
| CVE-2020-13933 | 由于 Shiro 与 Spring 处理路径时 URL 解码和路径标准化顺序不一致 导致的使用 "%3b" 的绕过 | shiro < 1.6.0  |
| CVE-2020-17510 | 由于 Shiro 与 Spring 处理路径时 URL 解码和路径标准化顺序不一致 导致的使用 "%2e" 的绕过 | Shiro < 1.7.0  |
| CVE-2020-17523 | Shiro 匹配鉴权路径时会对分隔的 token 进行 trim 操作 导致的使用 "%20" 的绕过 | Shiro <1.7.1   |

## Shiro使用

### 配置Bean

新建一个Shiro配置类，配置Shiro最为核心的安全管理器SecurityManager

```java
   @Bean
    public SecurityManager securityManager(UserAuthorizingRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(userRealm);
        securityManager.setRememberMeManager(null);
        return securityManager;
    }
```

配置Shiro的过滤器工厂类，将上一步配置的安全管理器注入，并配置相应的过滤规则

上面使用LinkedHashMap是为了保持顺序，Filter的配置顺序不能随便打乱，过滤器是按照我们配置的顺序来执行的。范围大的过滤器要放在后面，`/**`这条如果放在前面，那么一来就匹配上了，就不会继续再往后走了。这里的对上面用到的两个过滤器做一下简单说明，篇幅控制其他过滤器请参阅相关文档：

```java
* authc：配置的url都必须认证通过才可以访问，它是Shiro内置的一个过滤器
* 对应的实现类 @see org.apache.shiro.web.filter.authc.FormAuthenticationFilter

* anon：也是Shiro内置的，它对应的过滤器里面是空的，什么都没做，可以理解为不拦截
* 对应的实现类 @see org.apache.shiro.web.filter.authc.AnonymousFilter
```

### 实现两个方法

在配置Bean的时候方法中形参传入 了一个`UserAuthorizingRealm`对象，这个就是认证和授权相关的流程，需要我们自己实现。

继承`AuthorizingRealm`之后，我们需要实现两个抽象方法，一个是认证，一个是授权，这两个方法长得很像。

`doGetAuthenticationInfo()`：认证。相当于登录，只有通过登录了，才能进行后面授权的操作。一些只需要登录权限的操作，在登录成功后就可以访问了，比如上一步中配置的`authc`过滤器就是只需要登录权限的。

`doGetAuthorizationInfo()`：授权。认证过后，仅仅拥有登录权限，更多细粒度的权限控制，比如菜单权限，按钮权限，甚至方法调用权限等，都可以通过授权轻松实现。在这个方法里，我们可以拿到当前登录的用户，再根据实际业务赋予用户部分或全部权限，当然这里也可以赋予用户某些角色，后面也可以根据角色鉴权。下方的演示代码仅添加了权限，赋予角色可以调用`addRoles()`或者`setRoles()`方法，传入角色集合。

```java
public class UserAuthorizingRealm extends AuthorizingRealm {

    @Autowired
    private LoginService loginService;

    /**
     * 授权验证，获取授权信息
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        User user = (User) principalCollection.getPrimaryPrincipal();
        List<String> perms;
        // 系统管理员拥有最高权限
        if (User.SUPER_ADMIN == user.getId()) {
            perms = loginService.getAllPerms();
        } else {
            perms = loginService.getUserPerms(user.getId());
        }

        // 权限Set集合
        Set<String> permsSet = new HashSet<>();
        for (String perm : perms) {
            permsSet.addAll(Arrays.asList(perm.trim().split(",")));
        }

        // 返回权限
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setStringPermissions(permsSet);
        return info;
    }

    /**
     * 登录验证，获取身份信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        // 获取用户
        User user = loginService.getUserByUsername(token.getUsername());
        if (user == null) {
            throw new UnknownAccountException("账号或密码不正确");
        }
        // 判断用户是否被锁定
        if (user.getStatus() == null || user.getStatus() == 1) {
            throw new LockedAccountException("账号已被锁定,请联系管理员");
        }
        // 验证密码
        if (!user.getPassword().equals(new String(token.getPassword()))) {
            throw new UnknownAccountException("账号或密码不正确");
        }
        user.setSessionId(SecurityUtils.getSubject().getSession().getId().toString());
        // 设置最后登录时间
        user.setLastLoginTime(new Date());
        // 此处可以持久化用户的登录信息，这里仅做演示没有连接数据库
        return new SimpleAuthenticationInfo(user, user.getPassword(), getName());
    }
}
```

## Shiro解析流程

### **初始化流程**

**ShiroFilterFactoryBean**实现了FactoryBean接口，那么Spring在初始化的时候必然会调用ShiroFilterFactoryBean的getObject()获取实例，而`ShiroFilterFactoryBean`也在此时做了一系列初始化操作。

在`getObject()`中会调用`createInstance()`

```
org.apache.shiro.spring.web.ShiroFilterFactoryBean#createInstance
 protected AbstractShiroFilter createInstance() throws Exception {
        log.debug("Creating Shiro Filter instance.");
        SecurityManager securityManager = this.getSecurityManager();
        String msg;
        if (securityManager == null) {
            msg = "SecurityManager property must be set.";
            throw new BeanInitializationException(msg);
        } else if (!(securityManager instanceof WebSecurityManager)) {
            msg = "The security manager does not implement the WebSecurityManager interface.";
            throw new BeanInitializationException(msg);
        } else {
            FilterChainManager manager = this.createFilterChainManager();
            PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
            chainResolver.setFilterChainManager(manager);
            return new SpringShiroFilter((WebSecurityManager)securityManager, chainResolver);
        }
    }
```

![image-20220505201531768](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509102813137-1855711211.png)

`SecurityManager`会存储一些登录的缓存信息.

这里面首先获取了我们在ShiroConfig中注入好参数的SecurityManager，再次强调，这位是Shiro中的核心组件。然后创建了一个FilterChainManager，这个类看名字就知道是用来管理和操作过滤器执行链的，我们来看它的创建方法createFilterChainManager。

```java
protected FilterChainManager createFilterChainManager() {
        DefaultFilterChainManager manager = new DefaultFilterChainManager();
        Map<String, Filter> defaultFilters = manager.getFilters();
        for (Filter filter : defaultFilters.values()) {
            applyGlobalPropertiesIfNecessary(filter);
        }
        Map<String, Filter> filters = getFilters();
        if (!CollectionUtils.isEmpty(filters)) {
            for (Map.Entry<String, Filter> entry : filters.entrySet()) {
                String name = entry.getKey();
                Filter filter = entry.getValue();
                applyGlobalPropertiesIfNecessary(filter);
                if (filter instanceof Nameable) {
                    ((Nameable) filter).setName(name);
                }
                manager.addFilter(name, filter, false);
            }
        }
        Map<String, String> chains = getFilterChainDefinitionMap();
        if (!CollectionUtils.isEmpty(chains)) {
            for (Map.Entry<String, String> entry : chains.entrySet()) {
                String url = entry.getKey();
                String chainDefinition = entry.getValue();
                manager.createChain(url, chainDefinition);
            }
        }
        return manager;
    }
```

第一步new了一个`DefaultFilterChainManager`，在它的构造方法中将filters和filterChains两个成员变量都初始化为一个能保持插入顺序的LinkedHashMap了，之后再调用addDefaultFilters添加Shiro内置的一些过滤器。

```java
 public DefaultFilterChainManager() {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChains = new LinkedHashMap<String, NamedFilterList>();
        addDefaultFilters(false);
    }
 protected void addDefaultFilters(boolean init) {
        for (DefaultFilter defaultFilter : DefaultFilter.values()) {
            addFilter(defaultFilter.name(), defaultFilter.newInstance(), init, false);
        }
    }
```

![image-20220505202555242](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509102841756-2050902506.png)

`this.applyGlobalPropertiesIfNecessary`方法遍历了每一个默认的过滤器并调用了applyGlobalPropertiesIfNecessary设置一些必要的全局属性。

```java
 private void applyGlobalPropertiesIfNecessary(Filter filter) {
        this.applyLoginUrlIfNecessary(filter);
        this.applySuccessUrlIfNecessary(filter);
        this.applyUnauthorizedUrlIfNecessary(filter);
    }
```

在这个方法中调用了三个方法，三个方法逻辑是一样的，分别是设置loginUrl、successUrl和unauthorizedUrl，我们就看第一个applyLoginUrlIfNecessary。

```
org.apache.shiro.spring.web.ShiroFilterFactoryBean#applyLoginUrlIfNecessary
private void applyLoginUrlIfNecessary(Filter filter) {
        String loginUrl = getLoginUrl();
        if (StringUtils.hasText(loginUrl) && (filter instanceof AccessControlFilter)) {
            AccessControlFilter acFilter = (AccessControlFilter) filter;
            String existingLoginUrl = acFilter.getLoginUrl();
            if (AccessControlFilter.DEFAULT_LOGIN_URL.equals(existingLoginUrl)) {
                acFilter.setLoginUrl(loginUrl);
            }
        }
    }
```

![image-20220505202935565](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509102856154-87514911.png)

看方法名就知道是要设置loginUrl，如果我们配置了loginUrl，那么会将AccessControlFilter中默认的loginUrl替换为我们设置的值，默认的loginUrl为`/login.jsp`。后面两个方法道理一样，都是将我们设置的参数替换进去，只不过第三个认证失败跳转URL的默认值为null。

这里的`this.getLoginUrl();`是从我们shiroFilter Bean中，setLoginUrl的值。

执行回到`org.apache.shiro.spring.web.ShiroFilterFactoryBean#createFilterChainManager`代码中

`Map<String, Filter> filters = getFilters;`这里是获取我们自定义的过滤器，默认是为空的，如果我们配置了自定义的过滤器，那么会将其添加到filters中。至此filters中包含着Shiro内置的过滤器和我们配置的所有过滤器。

下一步，遍历filterChainDefinitionMap，这个filterChainDefinitionMap就是我们在ShiroConfig中注入进去的拦截规则配置。这里是根据我们配置的过滤器规则创建创建过滤器执行链。

![image-20220505203651875](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509102945491-521192946.png)

```java
public void createChain(String chainName, String chainDefinition) {
        String[] filterTokens = splitChainDefinition(chainDefinition);
        for (String token : filterTokens) {
            String[] nameConfigPair = toNameConfigPair(token);
            addToChain(chainName, nameConfigPair[0], nameConfigPair[1]);
        }
    }
```

chainName是我们配置的过滤路径，chainDefinition是该路径对应的过滤器，通常我们都是一对一的配置，比如：`filterMap.put("/login", "anon");`，但看到这个方法我们知道了一个过滤路径其实是可以通过传入`["filter1","filter2"...]`配置多个过滤器的。在这里会根据我们配置的过滤路径和过滤器映射关系一步步配置过滤器执行链。

```java
public void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) {
        Filter filter = getFilter(filterName);
        applyChainConfig(chainName, filter, chainSpecificFilterConfig);
        NamedFilterList chain = ensureChain(chainName);
        chain.add(filter);
    }
```

先从filters中根据filterName获取对应过滤器，然后ensureChain会先从filterChains根据chainName获取NamedFilterList，获取不到就创建一个并添加到filterChains然后返回。

```java
 protected NamedFilterList ensureChain(String chainName) {
        NamedFilterList chain = getChain(chainName);
        if (chain == null) {
            chain = new SimpleNamedFilterList(chainName);
            this.filterChains.put(chainName, chain);
        }
        return chain;
    }
```

因为过滤路径和过滤器是一对多的关系，所以ensureChain返回的NamedFilterList其实就是一个有着name称属性的`List<Filter>`，这个name保存的就是过滤路径，List保存着我们配置的过滤器。获取到NamedFilterList后在将过滤器加入其中，这样过滤路径和过滤器映射关系就初始化好了。

至此，createInstance中的createFilterChainManager才算执行完成，它返回了一个FilterChainManager实例。之后再将这个FilterChainManager注入PathMatchingFilterChainResolver中，它是一个过滤器执行链解析器。

![image-20220505212524765](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103002389-2081301843.png)

`org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain`中的方法不多，最为重要的是这个getChain方法。

```java
public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        FilterChainManager filterChainManager = getFilterChainManager();
        if (!filterChainManager.hasChains()) {
            return null;
        }
        String requestURI = getPathWithinApplication(request);
        for (String pathPattern : filterChainManager.getChainNames()) {
            if (pathMatches(pathPattern, requestURI)) {
                return filterChainManager.proxy(originalChain, pathPattern);
            }
        }
        return null;
    }
```

看到形参中ServletRequest和ServletResponse这两个参数，我们每次请求服务器都会调用这个方法，根据请求的URL去匹配过滤器执行链中的过滤路径，匹配上了就返回其对应的过滤器进行过滤。

这个方法中的filterChainManager.getChainNames返回的是根据我们的配置配置生成的执行链的过滤路径集合，执行链生成的顺序跟我们的配置的顺序相同。从前文中我们也提到，在DefaultFilterChainManager的构造方法中将filterChains初始化为一个LinkedHashMap。如果第一个匹配的过滤路径就是`/**`那后面的过滤器永远也匹配不上。

### 过滤实现

这个getChain是一个请求到达Tomcat时，Tomcat以责任链的形式调用了一系列Filter，`OncePerRequestFilter`就是众多Filter中的一个。它所实现的doFilter方法调用了自身的抽象方法doFilterInternal，这个方法在它的子类AbstractShiroFilter中被实现了。

```java
getChain:116, PathMatchingFilterChainResolver (org.apache.shiro.web.filter.mgt)
getExecutionChain:415, AbstractShiroFilter (org.apache.shiro.web.servlet)
executeChain:448, AbstractShiroFilter (org.apache.shiro.web.servlet)
call:365, AbstractShiroFilter$1 (org.apache.shiro.web.servlet)
doCall:90, SubjectCallable (org.apache.shiro.subject.support)
call:83, SubjectCallable (org.apache.shiro.subject.support)
execute:383, DelegatingSubject (org.apache.shiro.subject.support)
doFilterInternal:362, AbstractShiroFilter (org.apache.shiro.web.servlet)
doFilter:125, OncePerRequestFilter (org.apache.shiro.web.servlet)
internalDoFilter:193, ApplicationFilterChain (org.apache.catalina.core) [5]
```

`PathMatchingFilterChainResolver.getChain`就是被在`doFilterInternal`中被一步步调用的调用的。

```java
    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, 
                                    final FilterChain chain) throws ServletException, IOException {
            final ServletRequest request = prepareServletRequest(servletRequest, servletResponse, chain);
            final ServletResponse response = prepareServletResponse(request, servletResponse, chain);
            final Subject subject = createSubject(request, response);
            subject.execute(new Callable() {
                public Object call() throws Exception {
                    updateSessionLastAccessTime(request, response);
                    executeChain(request, response, chain);
                    return null;
                }
            });
    }
```

这里先获取过滤器，然后执行。

```java
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
            throws IOException, ServletException {
        FilterChain chain = getExecutionChain(request, response, origChain);
        chain.doFilter(request, response);
    }
```

获取过滤器方法如下。

```java
    protected FilterChain getExecutionChain(ServletRequest request, ServletResponse response, FilterChain origChain) {
        FilterChain chain = origChain;
        FilterChainResolver resolver = getFilterChainResolver();
        if (resolver == null) {
            return origChain;
        }
        FilterChain resolved = resolver.getChain(request, response, origChain);
        if (resolved != null) {
            chain = resolved;
        } else {
        }
        return chain;
    }
```

通过getFilterChainResolver就拿到了上面提到的过滤器执行链解析器PathMatchingFilterChainResolver，然后再调用它的getChain匹配获取过滤器，最终过滤器在executeChain中被执行。

这里用枚举列出了所有Shiro内置过滤器的实例。

```java
public enum DefaultFilter {
    anon(AnonymousFilter.class),
    authc(FormAuthenticationFilter.class),
    authcBasic(BasicHttpAuthenticationFilter.class),
    logout(LogoutFilter.class),
    noSessionCreation(NoSessionCreationFilter.class),
    perms(PermissionsAuthorizationFilter.class),
    port(PortFilter.class),
    rest(HttpMethodPermissionFilter.class),
    roles(RolesAuthorizationFilter.class),
    ssl(SslFilter.class),
    user(UserFilter.class);
}
```

| Filter 名称       | 对应类                                                       |
| :---------------- | :----------------------------------------------------------- |
| anon              | [org.apache.shiro.web.filter.authc.AnonymousFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/AnonymousFilter.html) |
| authc             | [org.apache.shiro.web.filter.authc.FormAuthenticationFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/FormAuthenticationFilter.html) |
| authcBasic        | [org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/BasicHttpAuthenticationFilter.html) |
| authcBearer       | [org.apache.shiro.web.filter.authc.BearerHttpAuthenticationFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/BearerHttpAuthenticationFilter.html) |
| invalidRequest    | [org.apache.shiro.web.filter.InvalidRequestFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/InvalidRequestFilter.html) |
| logout            | [org.apache.shiro.web.filter.authc.LogoutFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/LogoutFilter.html) |
| noSessionCreation | [org.apache.shiro.web.filter.session.NoSessionCreationFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/session/NoSessionCreationFilter.html) |
| perms             | [org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/PermissionsAuthorizationFilter.html) |
| port              | [org.apache.shiro.web.filter.authz.PortFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/PortFilter.html) |
| rest              | [org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/HttpMethodPermissionFilter.html) |
| roles             | [org.apache.shiro.web.filter.authz.RolesAuthorizationFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/RolesAuthorizationFilter.html) |
| ssl               | [org.apache.shiro.web.filter.authz.SslFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authz/SslFilter.html) |
| user              | [org.apache.shiro.web.filter.authc.UserFilter](https://shiro.apache.org/static/current/apidocs/org/apache/shiro/web/filter/authc/UserFilter.html) |

## CVE-2016-6802

| 漏洞信息   | 详情                                                         |
| :--------- | :----------------------------------------------------------- |
| 漏洞编号   | [CVE-2016-6802](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6802) / [CNVD-2016-07814](https://www.cnvd.org.cn/flaw/show/CNVD-2016-07814) |
| 影响版本   | shiro < 1.3.2                                                |
| 漏洞描述   | Shiro 使用非根 servlet 上下文路径中存在安全漏洞。远程攻击者通过构造的请求， 利用此漏洞可绕过目标 servlet 过滤器并获取访问权限。 |
| 漏洞关键字 | 绕过 \| Context Path \| 非根 \| /x/../                       |
| 漏洞补丁   | [Commit-b15ab92](https://github.com/apache/shiro/commit/b15ab927709ca18ea4a02538be01919a19ab65af) |
| 相关链接   | https://www.cnblogs.com/backlion/p/14055279.html             |

## CVE-2020-1957

### 漏洞复现

绕过方式：`/demo/..;/admin/index`

代码片段

ShiroConfig

```java
  @Bean(name={"shiroFilter"})
    ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager);

        bean.setLoginUrl("/login");
        bean.setUnauthorizedUrl("/unauth");
        LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
        map.put("/doLogin", "anon");
        map.put("/demo/**","anon");
        map.put("/unauth", "user");
        map.put("/admin/**","authc");
        map.put("/**", "authc");
        bean.setFilterChainDefinitionMap(map);
        return bean;
    }
```

`/demo`为未授权访问路由

![image-20220504230330293](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103014757-1764811392.png)

### 漏洞分析

```
org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain
 public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        FilterChainManager filterChainManager = this.getFilterChainManager();
        if (!filterChainManager.hasChains()) {
            return null;
        } else {
            String requestURI = this.getPathWithinApplication(request);
            if (requestURI != null && !"/".equals(requestURI) && requestURI.endsWith("/")) {
                requestURI = requestURI.substring(0, requestURI.length() - 1);
            }

            Iterator var6 = filterChainManager.getChainNames().iterator();

            String pathPattern;
            do {
                if (!var6.hasNext()) {
                    return null;
                }

                pathPattern = (String)var6.next();
                if (pathPattern != null && !"/".equals(pathPattern) && pathPattern.endsWith("/")) {
                    pathPattern = pathPattern.substring(0, pathPattern.length() - 1);
                }
            } while(!this.pathMatches(pathPattern, requestURI));

            

            return filterChainManager.proxy(originalChain, pathPattern);
        }
    }
```

调用`this.getPathWithinApplication(request);`获取uri路径

```
org.apache.shiro.web.util.WebUtils#getPathWithinApplication
 public static String getPathWithinApplication(HttpServletRequest request) {
        String contextPath = getContextPath(request);
        String requestUri = getRequestUri(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            String path = requestUri.substring(contextPath.length());
            return StringUtils.hasText(path) ? path : "/";
        } else {
            return requestUri;
        }
    }
org.apache.shiro.web.util.WebUtils#getPathWithinApplication
```

![image-20220505183752489](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103022528-247363895.png)

调用`normalize(decodeAndCleanUriString(request, uri))`

先来看看`decodeAndCleanUriString`

```java
 private static String decodeAndCleanUriString(HttpServletRequest request, String uri) {
        uri = decodeRequestString(request, uri);
        int semicolonIndex = uri.indexOf(59);
        return semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri;
    }
org.apache.shiro.web.util.WebUtils#decodeRequestString
public static String decodeRequestString(HttpServletRequest request, String source) {
    String enc = determineEncoding(request);

    try {
        return URLDecoder.decode(source, enc);
    } catch (UnsupportedEncodingException var4) {
        if (log.isWarnEnabled()) {
            log.warn("Could not decode request string [" + Encode.forHtml(source) + "] with encoding '" + Encode.forHtml(enc) + "': falling back to platform default encoding; exception message: " + var4.getMessage());
        }

        return URLDecoder.decode(source);
    }
}
decodeAndCleanUriString`中先将获取到的URI，然后截取`;`前面的值，将`;`后面值过滤掉。获取到的为`/demo/..
```

再来看看`normalize`方法

```
org.apache.shiro.web.util.WebUtils#normalize(java.lang.String, boolean)
 private static String normalize(String path, boolean replaceBackSlash) {
        if (path == null) {
            return null;
        } else {
            String normalized = path;
            if (replaceBackSlash && path.indexOf(92) >= 0) {
                normalized = path.replace('\\', '/');
            }

            if (normalized.equals("/.")) {
                return "/";
            } else {
                if (!normalized.startsWith("/")) {
                    normalized = "/" + normalized;
                }

                while(true) {
                    int index = normalized.indexOf("//");
                    if (index < 0) {
                        while(true) {
                            index = normalized.indexOf("/./");
                            if (index < 0) {
                                while(true) {
                                    index = normalized.indexOf("/../");
                                    if (index < 0) {
                                        return normalized;
                                    }

                                    if (index == 0) {
                                        return null;
                                    }

                                    int index2 = normalized.lastIndexOf(47, index - 1);
                                    normalized = normalized.substring(0, index2) + normalized.substring(index + 3);
                                }
                            }

                            normalized = normalized.substring(0, index) + normalized.substring(index + 2);
                        }
                    }

                    normalized = normalized.substring(0, index) + normalized.substring(index + 1);
                }
            }
        }
    }
```

- 替换反斜线
- 替换 `//` 为 `/`
- 替换 `/./` 为 `/`
- 替换 `/../` 为 `/`

执行完成后回到`org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain`代码中

![image-20220505221310281](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103033641-2040857346.png)

匹配成功后会调用`filterChainManager.proxy(originalChain, pathPattern);`

```java
public FilterChain proxy(FilterChain original, String chainName) {
    NamedFilterList configured = this.getChain(chainName);
    if (configured == null) {
        String msg = "There is no configured chain under the name/key [" + chainName + "].";
        throw new IllegalArgumentException(msg);
    } else {
        return configured.proxy(original);
    }
}
```

![image-20220505221710447](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103040808-185142683.png)

```
this.getChain(chainName);`会返回请求路径对应的拦截规则的Filter。比如这里是anon，则返回`AnonymousFilter
```

然后调用`configured.proxy(original);`,这里original为`AnonymousFilter`实例对象

```none
public FilterChain proxy(FilterChain orig) {
    return new ProxiedFilterChain(orig, this);
}
public FilterChain proxy(FilterChain orig) {  
    // 返回ProxiedFilterChain对象，该对象就是当一个请求到来后需要被执行的FilterChain对象  
    // 该对象只是一个代理对象，代理了两个FilterChain，一个是NamedFilterList，另一个是原始的FilterChain对象  
    // 原始的FilterChain对象包含了在web.xml中配置并应用上的Filter  
    return new ProxiedFilterChain(orig, this);  
}  
```

在`org.apache.shiro.web.servlet.AbstractShiroFilter#executeChain`,调用`chain.doFilter(request, response);`时,走到这里

```
org.apache.shiro.web.servlet.ProxiedFilterChain#doFilter
 public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        if (this.filters != null && this.filters.size() != this.index) {
            if (log.isTraceEnabled()) {
                log.trace("Invoking wrapped filter at index [" + this.index + "]");
            }

            ((Filter)this.filters.get(this.index++)).doFilter(request, response, this);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Invoking original filter chain.");
            }

            this.orig.doFilter(request, response);
        }

    }
```

![image-20220505223429293](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103048346-373469948.png)

从而执行到`AnonymousFilter`.

最终我们的原始请求 `/demo/..;/admin/index` 就会进入到 springboot中. springboot对于每一个进入的request请求也会有自己的处理方式,找到自己所对应的mapping. 具体的匹配方式是在:`org.springframework.web.util.UrlPathHelper 中的 getPathWithinServletMapping()`

```
org.springframework.web.util.UrlPathHelper#getLookupPathForRequest
 public String getLookupPathForRequest(HttpServletRequest request) {
        if (this.alwaysUseFullPath) {
            return this.getPathWithinApplication(request);
        } else {
            String rest = this.getPathWithinServletMapping(request);
            return !"".equals(rest) ? rest : this.getPathWithinApplication(request);
        }
    }
getRequestUri:326, UrlPathHelper (org.springframework.web.util)
getPathWithinApplication:244, UrlPathHelper (org.springframework.web.util)
getPathWithinServletMapping:195, UrlPathHelper (org.springframework.web.util)
getLookupPathForRequest:171, UrlPathHelper (org.springframework.web.util)
org.springframework.web.util.UrlPathHelper#getRequestUri
public String getRequestUri(HttpServletRequest request) {
        String uri = (String)request.getAttribute("javax.servlet.include.request_uri");
        if (uri == null) {
            uri = request.getRequestURI();
        }

        return this.decodeAndCleanUriString(request, uri);
    }
private String decodeAndCleanUriString(HttpServletRequest request, String uri) {
        uri = this.removeSemicolonContent(uri);
        uri = this.decodeRequestString(request, uri);
        uri = this.getSanitizedPath(uri);
        return uri;
    }
```

这里分别依次调用三个方法,分别用来过滤`;`、urldecode、过滤`//`

```java
  public String removeSemicolonContent(String requestUri) {
        return this.removeSemicolonContent ? this.removeSemicolonContentInternal(requestUri) : this.removeJsessionid(requestUri);
    }

    private String removeSemicolonContentInternal(String requestUri) {
        for(int semicolonIndex = requestUri.indexOf(59); semicolonIndex != -1; semicolonIndex = requestUri.indexOf(59, semicolonIndex)) {
            int slashIndex = requestUri.indexOf(47, semicolonIndex);
            String start = requestUri.substring(0, semicolonIndex);
            requestUri = slashIndex != -1 ? start + requestUri.substring(slashIndex) : start;
        }

        return requestUri;
    }
```

在spring中会过滤路径中的`;`,而在shiro该版本中不会，导致的权限绕过。

整体的流程就是

1. 客户端请求URL: `/demo/..;/admin/index`
2. shrio 内部处理得到校验URL为 `/xxxx/..,`校验通过
3. springboot 处理 `/demo/..;/admin/index` , 请求 `/admin/index`, 成功访问鉴权接口

## CVE-2020-11989

### 漏洞复现

环境：`https://github.com/l3yx/springboot-shiro`

该漏洞有2种绕过方式

1. ContextPath 使用 ";" 的绕过
2. 二次url编码导致的绕过

### ContextPath

ContextPath的方式利用利用条件：

应用不能部署在根目录，也就是需要 context-path ， server.servlet.context-path=/test ,如果为根目录则 context-path 为空，就会被 CVE-2020-1957 的 patch 将 URL 格式化，若 Shiro 版本小于 1.5.2 的话那么该条件就不需要。

访问`/;/test/admin/page`实现绕过

![image-20220506001346170](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103056327-49287.png)

### 双层编码

利用条件是Shiroconfig的配置，权限ant风格的配置需要是`*`而不是`**`，同时controller需要接收的request参数(@PathVariable)的类型需要是String，否则将会出错

```java
@ResponseBody
@GetMapping("/admin/{name}")
public String namePage(@PathVariable String name){
    return "Hello" + name;
}
 bean.setLoginUrl("/login");
        bean.setUnauthorizedUrl("/unauth");
        LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
        map.put("/doLogin", "anon");
        map.put("/demo/**","anon");
        map.put("/unauth", "user");
        map.put("/admin/*","authc");
```

## 漏洞分析

### ContextPath

```java
getPathWithinApplication:112, WebUtils (org.apache.shiro.web.util)
getPathWithinApplication:164, PathMatchingFilterChainResolver (org.apache.shiro.web.filter.mgt)
getChain:103, PathMatchingFilterChainResolver (org.apache.shiro.web.filter.mgt)
getExecutionChain:415, AbstractShiroFilter (org.apache.shiro.web.servlet)
executeChain:448, AbstractShiroFilter (org.apache.shiro.web.servlet)
call:365, AbstractShiroFilter$1 (org.apache.shiro.web.servlet)
doCall:90, SubjectCallable (org.apache.shiro.subject.support)
call:83, SubjectCallable (org.apache.shiro.subject.support)
execute:387, DelegatingSubject (org.apache.shiro.subject.support)
doFilterInternal:362, AbstractShiroFilter (org.apache.shiro.web.servlet)
```

与前一直，解析流程来到`org.apache.shiro.web.util.WebUtils#getPathWithinApplication`

```java
public static String getPathWithinApplication(HttpServletRequest request) {
        String contextPath = getContextPath(request);
        String requestUri = getRequestUri(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            String path = requestUri.substring(contextPath.length());
            return StringUtils.hasText(path) ? path : "/";
        } else {
            return requestUri;
        }
    }
 public static String getContextPath(HttpServletRequest request) {
        String contextPath = (String)request.getAttribute("javax.servlet.include.context_path");
        if (contextPath == null) {
            contextPath = request.getContextPath();
        }

        contextPath = normalize(decodeRequestString(request, contextPath));
        if ("/".equals(contextPath)) {
            contextPath = "";
        }

        return contextPath;
    }
```

![image-20220506231808066](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103104758-1517673343.png)

获取`getContextPath`,然后进行url解码，标准化处理进行返回。

然后调用`getRequestUri(request);`

```java
public static String getRequestUri(HttpServletRequest request) {
        String uri = (String)request.getAttribute("javax.servlet.include.request_uri");
        if (uri == null) {
            uri = valueOrEmpty(request.getContextPath()) + "/" + valueOrEmpty(request.getServletPath()) + valueOrEmpty(request.getPathInfo());
        }

        return normalize(decodeAndCleanUriString(request, uri));
    }
```

前面提到过`decodeAndCleanUriString`会将`;`后面的内容清空，只截取`;`前面的内容。

![image-20220506232316769](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103112433-861953046.png)

执行来到`org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver#getChain`,前面获取到的`/`路径进行匹配,这里会拿`/``去匹配鉴权规则。这里因为使用的是`/`，会匹配不上规则，返回null。

![image-20220506235754732](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103121215-2082624682.png)

```
org.apache.shiro.web.servlet.AbstractShiroFilter#getExecutionChain
```

![image-20220507000351817](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103129355-156917283.png)

因为前面返回null，前面匹配不上路径对应的鉴权模式，所以不会设置匹配到的鉴权对于的FIlter。跟着调用`chain.doFilter`,从而实现绕过。

request请求会进入Spring中，来到`org.springframework.web.util.UrlPathHelper#getPathWithinServletMapping`这里

在 getPathWithinApplication 处理下是能正确获取到 context-path 与路由，最终经过 getPathWithinServletMapping 函数格式化处理后，得到最终路径为 /admin/page ，所以我们可以正常访问到该页面。

![image-20220507003040541](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103136651-568011800.png)

Tomcat 判断 /;test/admin/page 为 test 应用下的 /admin/page 路由，进入到 Shiro 时被 ; 截断被认作为 / ,再进入 Spring 时又被正确处理为 test 应用下的 /admin/page 路由，最后导致 Shiro 的权限绕过。

### 双层编码

```java
@ResponseBody
@GetMapping("/admin/{name}")
public String namePage(@PathVariable String name){
    return "Hello" + name;
}
```

根据前面的解析流程其实理解这个位置的地方并不难，这里用到的`@PathVariable`

访问如下

![image-20220508144645788](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103144684-994992850.png)

![image-20220508144702026](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103151262-903121971.png)

这里利用二次url编码，中间件收到我们的 get 请求会先进行一次url解码，然后shiro会调用`decodeRequestString`进行解码从而解析为`/admin/Hello/1`字符，因为匹配规则是`*`，并不会匹配到多个目录。而在Spring处理中解析为`/admin/Hello%2f1`是能匹配到路由的。

## CVE-2020-13933

这个漏洞和CVE-2020-11989类似`Shiro权限配置必须为 /xxxx/* ，同时后端逻辑必须是 /xxx/{variable} 且 variable 的类型必须是 String`

![image-20220508153425104](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103157831-977612098.png)

在shiro1.5.3版本中可以看到`org.apache.shiro.web.util.WebUtils#getPathWithinApplication`

```java
  public static String getPathWithinApplication(HttpServletRequest request) {
        return normalize(removeSemicolon(getServletPath(request) + getPathInfo(request)));
    }
 private static String removeSemicolon(String uri) {
        int semicolonIndex = uri.indexOf(59);
        return semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri;
    }
```

这里调用的是`removeSemicolon`,

1.5.2版本代码：

```java
 public static String getPathWithinApplication(HttpServletRequest request) {
        String contextPath = getContextPath(request);
        String requestUri = getRequestUri(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            String path = requestUri.substring(contextPath.length());
            return StringUtils.hasText(path) ? path : "/";
        } else {
            return requestUri;
        }
    }

    public static String getRequestUri(HttpServletRequest request) {
        String uri = (String)request.getAttribute("javax.servlet.include.request_uri");
        if (uri == null) {
            uri = valueOrEmpty(request.getContextPath()) + "/" + valueOrEmpty(request.getServletPath()) + valueOrEmpty(request.getPathInfo());
        }

        return normalize(decodeAndCleanUriString(request, uri));
    }
```

1.5.3版本后不再调用`decodeAndCleanUriString`进行url解码。

使用`removeSemicolon`进行处理，`removeSemicolon`是用来截取`;`前面的字符。假设请求为`/admin/;123`

![image-20220508155013855](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103205229-440492070.png)

看看他是怎么处理的

![image-20220508155144608](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103212646-1095359651.png)

截取到前面的`/admin/`，因为前面的匹配规则是`*`，这里不会匹配到对应的规则，从而绕过权限。

## CVE-2020-17523

```
/admin/%20
```

![image-20220508165104760](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103225284-901543551.png)

最后会调用到`org.apache.shiro.util.AntPathMatcher#doMatch`进行匹配

![image-20220508165229578](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103233296-953125363.png)

调用`StringUtils.tokenizeToStringArray`进行处理。

```java
 public static String[] tokenizeToStringArray(String str, String delimiters, boolean trimTokens, boolean ignoreEmptyTokens) {
        if (str == null) {
            return null;
        } else {
            StringTokenizer st = new StringTokenizer(str, delimiters);
            List tokens = new ArrayList();

            while(true) {
                String token;
                do {
                    if (!st.hasMoreTokens()) {
                        return toStringArray(tokens);
                    }

                    token = st.nextToken();
                    if (trimTokens) {
                        token = token.trim();
                    }
                } while(ignoreEmptyTokens && token.length() <= 0);

                tokens.add(token);
            }
        }
    }
/admin%20`会被调用`trim`方法去除空格，解析为`/admin/
```

![image-20220508165642085](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103249872-1710351743.png)

![image-20220508165330212](https://img2022.cnblogs.com/blog/1993669/202205/1993669-20220509103257005-1905026397.png)

`trimTokens`参数默认为true，空格会经过`trim()`处理，因此导致空格被清除。1.7.1版本后在新版本中`trimTokens`参数为false，不会调用`trim()`方法进行处理。

### 小Tips

`/admin/./`，也能进行利用，在`normalize`方法中会进行把`./`替换为空

`/admin/.`，可以进行利用，是因为SpringBoot开启全路径匹配的话，会匹配整个url，因此Spring返回200。如果没有开启全路径匹配的话，在Spring中`.`和`/`是作为路径分隔符的，不参与路径匹配。因此会匹配不到mapping，返回404

## 参考文章

https://www.guitu18.com/post/2019/08/01/45.html#more

https://su18.org/post/shiro-5/

http://rui0.cn/archives/1643

http://wjlshare.com/archives/1591

https://github.com/jweny/shiro-cve-2020-17523

https://blog.spoock.com/2020/05/09/cve-2020-1957/

## 结尾

Shiro中各种权限绕过的方式问题都有由于Shiro与Spring等一些框架解析差异导致的问题。