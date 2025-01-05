# Android反编译及调试利器(jadx+apktool+android studio)

### 为什么要反编译别人的代码

- 人家比咱写的好，学习？
- 了解别人某个功能实现，参考？
- 看中了人家的本地数据库或者其他资源想要，但是人家的本地数据库加密了，要读源码才能解密？
- 分析竞品使用了哪些广告，或者什么策略？
- 破解vip限制？
  ······

# jadx的高级技巧

### 介绍

jadx是史上最好用的反编译软件，有以下优点：

- 图形化的界面
- 拖拽式的操作
- 反编译输出 Java 代码
- 导出 Gradle 工程
- 支持.dex, **.apk**, .jar or .class
- 反混淆
- 支持代码跳转
- 支持搜索文本，类

这些优点都让 jadx 成为我反编译的第一选择，它可以处理大部分反编译的需求，基本上是我反编译工具的首选。

### 安装 [官网](https://github.com/skylot/jadx)

jadx 本身就是一个开源项目，源代码已经在 Github 上开源了。有兴趣可以直接 clone 源代码，然后本地自己编译。但是多数情况下，我们是需要一个编译好的版本。编译好的版本，在github是也可以直接下载到，下载[最新版本](https://github.com/skylot/jadx/releases/latest)，现在的最新版是 jadx-0.8.0 。下载好解压之后，你会获得这样的目录结构：

![img](https://upload-images.jianshu.io/upload_images/2404560-2c75a343ae332d9f.png?imageMogr2/auto-orient/strip|imageView2/2/w/507/format/webp)

jadx-img.png


对于 Mac 或者 Linux，使用 jadx-gui ，Windows 下就需要使用 jadx-gui.bat 了，双击可以直接运行，如果有安全警告，忽略它就可以了。（后文主要以 Windows 环境为讲解， 其他平台下的大部分操作都是类似的）



### 使用

直接双击前面解压出来的jadx-gui.bat就可以直接运行。运行之后会打开一个界面，有一个文件选择弹窗，你可以选择一个 apk、dex、jar、zip、class、aar 文件，可以看到 jadx 支持的格式还是挺多的，基本上编译成 Java 虚拟机能识别的字节码，它都可以进行反编译。除了选择一个文件，还可以直接将 apk 文件，拖拽进去，这一点非常好用。下面给大家感受一下jadx的强大：



![img](https://upload-images.jianshu.io/upload_images/2404560-dc4987edf429fe2c.png?imageMogr2/auto-orient/strip|imageView2/2/w/960/format/webp)

jadx_java.png



![img](https://upload-images.jianshu.io/upload_images/2404560-baaac7852669eb0a.png?imageMogr2/auto-orient/strip|imageView2/2/w/1140/format/webp)

jadx_androidmanifest.png

![img](https://upload-images.jianshu.io/upload_images/2404560-7712f80364bbb579.png?imageMogr2/auto-orient/strip|imageView2/2/w/1139/format/webp)

jadx_drawable.png

![img](https://upload-images.jianshu.io/upload_images/2404560-540b616486d893c3.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)

jadx_layout.png

![img](https://upload-images.jianshu.io/upload_images/2404560-016b1b0709c1fade.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)

jadx_string.png

- **搜索功能**
  jadx 提供的搜索功能，非常强大，而且搜索速度也不慢。点击 Navigation -> Text Search 或者 Navigation -> Class Search 激活它，并且 jadx 的搜索支持四种维度，Class、Method、Field、Code，我们可以根据我们搜索的内容进行勾选，范围最大的就是 Code ，基本上就是文本匹配搜索。
- **查找引用**
  比如想要找到我们想要的类和代码，那么可以直接使用 jadx 的搜索代码功能，找到我们需要查看的类或者代码，选中点击右键，选择Find　Usage
- **反混淆（Deobfuscation）**
  一般 apk 在发布出去之前，都是会被混淆的，这基本上是国内 App 的标配，但其实非常不利于我们阅读。我们很难看到一个 a.java 的文件之后，就确定它是哪一个，还需要根据包名来区分。而 Deobfusation 功能，可以为它们起一个特殊的名字，这样它在这个项目中，名字就是唯一的，方便我们识别和搜索。这个功能可以在 Tools -> deobfusation 中激活
- **导出Gradle工程**
  jadx-gui 可以直接阅读代码，还是很方便的。但是毕竟没有我们常见的编辑器来的方便。jadx支持将反编译后的项目，直接导出成一个 Gradle 编译的工程。可以通过 File -> Save as gradle project 来激活这个功能。最终输出的项目，可以直接通过 Android Studio 打开。

### 可能出现的问题

- 资源文件可能有缺失，资源文件还是通过apktool来获取
- inconsistent code
  有时候有代码，反编译的不完整，你会看到 JADX WARNING : inconsistent code 标志的错误。jadx 为了应对这样的情况，可以尝试开启 Show inconsistent code 开关。你可以在 File -> Preferences 中找到它。这样处理的代码，大部分为伪代码，可能会有错误的地方。
- 在反编译较大的apk时，如果遇到jadx-jui卡顿和假死的情况，可适当优化jvm相关参数
  - 减少处理的线程数
    jadx 为了加快编译的效率，所以是使用多线程处理的，而多个线程会耗费跟多的内存。所以减小反编译时候的线程数，是一个有效的方法。如果使用命令行的话，可以使用 -j 1 参数，配置线程数为 1，不配置的话，默认线程数为 4。而使用 jadx-gui 的话，可以在 Preferences 中，通过配置 Processing threads count 来配置线程数
  - 修改 jadx 脚本
    直接编辑 ./bin 目录下的 jadx.bat脚本，配置找到 DEFAULT_JVM_OPTS ，将它设置为 DEFAULT_JVM_OPTS="-Xmx2500M" ，就可以配置当前使用的内存大小。
  - 使用命令行命令
    如果以上方式都不好用，在没有更好的办法的情况下，你可以直接使用命令行，通过 jadx 的命令进行放编译。并将线程数配置为 1 ，这样虽然慢一些，但是多数情况下，是可以正常输出反编译后的代码的。
    举个例子：
    `jadx -d out -j 1 classes.dex`
    更过命令，可以通过 jadx -h 命令进行查看。
    仔细看看 jadx 命令配置的参数，基本上都可以在 Preferences 中，找到对应的配置项，相互对照理解一下，应该不难发现它的使用方式。

# apktool查看资源文件

利用apktool查看apk的xml文件、AndroidManifest.xml和图片等，也可以查看src目录下的smali文件。

### 安装 [官网](https://ibotpeaches.github.io/Apktool/install/)

- 下载apktool.bat，把鼠标移至wrapper script上，然后右击，链接另存为…,把下载来的文件放到如E:\Android\apktools，记得名字要改成apktool.bat；
- 下载apktool.jar文件，点击find newest here，跳到下载页，我们能尽量下载最新版本，旧版本可能不能用，我这里下载最新版本apktool_2.3.4.jar，也把该文件刚到apktool文件夹下。
- 把你下载来的jar文件重新命名为：apktool.jar。
- 官网建议你把apktool.bat、apktool.jar放到C盘的Windows下，也可以不用，但是需要把存放的路径配置到环境变量的PATH中

### 使用

1. win+R，输入cmd调出命令行窗口，切换到apktool文件夹目录下。接下来把apk拷贝到E:\Android\apktools下面，然后在cmd窗口输入命令，回车，如下图：
   `apktool d yourapp.apk`

   ![img](https://upload-images.jianshu.io/upload_images/2404560-2eada643c34267f3.png?imageMogr2/auto-orient/strip|imageView2/2/w/708/format/webp)

   apktools_d.png

   这样就表示成功了，我们就可以在E:\Android\apktools发现一个新的文件夹yourapp(这个文件夹的文字跟你的apk名字一样)，里面我们就可以看到xml文件、AndroidManifest.xml和图片等资源文件了。

   经过上面的步骤，我们可以在文件夹yourapp中发现一个文件夹smali，这里面其实就java代码，只不过不是jar形式的，关于如何查看java源码，可以通过dex2jar工具，这里不是我们关注的重点，不在这里赘述。

   

2. 反编译后想验证自己的某些想法，或者代码有些地方没有看明白想添加log，可以通过修改图片等资源文件或者smali源码后再重新打包的方式。命令如下：
   `apktool b test`
   重新打包后新的未签名apk生成的路径在yourapp/dist/yourapp.apk。
   修改图片,或者strings.xml等资源文件，可以直接执行重新打包命令即可。如果需要修改smali源码，要对smali语法有一定的了解，再进行修改。

3. 对打包后的apk签名，未签名的apk无法安装到Android手机里。使用你自己的签名文件进行签名，签名命令参考如下：
   `apksigner.bat sign --ks yourapp\keystore.jks --ks-key-alias keystore yourapp\dist\yourapp.apk`
   也可以使用其他三方的apk签名工具进行签名。

4. 优化apk包，这一步是可选的。用来将apk包进行整理，以适应设备的读取等
   `zipalign.exe -f -v 4 yourapp.apk yourapp_zip.apk`
   -f 强制覆盖已有的文件
   -v 输出详细内容
   4 指定档案整理的字节数，一般为4，即32位
   yourapp.apk 是未整理的apk文件名 yourapp_zip.apk 是整理后的apk文件名
   检查apk有没有zipalign对齐:
   `zipalign -c -v 4 被检查的apk文件`
   对齐安装时会可能会遇到[错误](http://blog.bihe0832.com/android-v2-issue.html)
   **先签名再对齐,否则先对齐再签名会破坏对齐**

5. 正常安装签名后的apk即可体验。

# android studio无源码动态调试apk

主要过程就是AndroidStudio动态调试Smali，是非常有效的逆向分析方法。把apk反编译成Smali然后倒入AndroidStudio中，然后通过[jdwp](https://www.ibm.com/developerworks/cn/java/j-lo-jpda3/index.html)调试相关进程。

### 基本技能

- 会使用AndroidStudio的debug的功能，不会的看[这里](https://www.jianshu.com/p/30aa9f25fa52)
- 能够理解简单的Smali语法[看这里](http://febsky.me/2016/07/26/2016-07-26-Android中反编译Smali文件解读/)，还有[这里](http://blog.csdn.net/lpohvbe/article/details/7981386)
- 能够使用[apktool](https://ibotpeaches.github.io/Apktool)反编译apk，并且重新打包，不会的看[这里](https://www.jianshu.com/p/cf6323588a30)

### 工具

- Android Studio最新版本
- [smaliidea-x.x.x.zip](https://bitbucket.org/JesusFreke/smali/downloads/)这个是AndroidStudio的插件，从这个链接的列表中下载那个,最新版本的zip文件[插件的官网](https://github.com/JesusFreke/smali)
- apktool 反编译apk->Smali 并且重新打包修改后的Smali到apk
- jadx 用了查看Smali对应的java代码，增加可读性

### 动态调试Smali文件

- **调试的前提条件 使app可调试**
  要想调试一个apk的前提是这个apk是可调式，一般我们发版的时候，会发release版。以前，我们开发Android是没有gradle的，那时候发release版不像现在在gradle配置好就行了，是直接操作AndroidManifest.xml文件中标签的属性 android:debuggable="true"，因为在一般的手机上，release版本的应用是不可以被调试的，相对来说起到了保护app的作用。
  从上面来看，可以在AndroidManifest文件中设置debuggable开关，那么这个开关是被谁来验证的呢？答案是系统，Android系统会通过debuggable 验证一个app是不是可以调试。可以不可以关掉系统的验证？答案是可以的。不过很麻烦，据说有两种方式可以修改，一种是重新刷入boot.img [修改方法](https://bbs.pediy.com/thread-188870.htm),另一种是通过xpost修改。
  而我们平常用的最多的就是，修改AndroidManifest.xml 中的android:debuggable="true"，然后重新打包apk。
  举例前段时间看的一个闹钟应用alarmy.apk:

  - 通过apktool d alarmy.apk来反编译
  - 在生成的目录中找到AndroidManifest.xml,用AS或者文本编辑器打开修改里面的标签，如果有debuggable属性，修改为true，如果没有，给标签添加android:debuggable="true"
  - apktool b alarmy这时候会在./alarmy/dist目录下生成重新打包好的apk。
  - 然后要给这个apk签名，参考签名说的签名部分。
  - 然后我们把这个自签名后的apk安装到手机就可以了

- **导入Smail源码到AndroidStudio中**
  打开as后，通过File-->Open ...选择我们刚才反编译处理的那个目录，alarmy，然后等待as建立完索引。
  注意左侧选择Project视图，如下所示：

  ![img](https://upload-images.jianshu.io/upload_images/2404560-ea1a27835cd75a17.png?imageMogr2/auto-orient/strip|imageView2/2/w/610/format/webp)

  android_studio_project.png

  

然后右键工程主目录：Mark Directory as -> Sources Root



![img](https://upload-images.jianshu.io/upload_images/2404560-9cf819a6f443f032.png?imageMogr2/auto-orient/strip|imageView2/2/w/619/format/webp)

source_root.png

然后设置sdk，最好和测试手机的系统版本一致：项目目录-->右键-->Open Module Settings：



![img](https://upload-images.jianshu.io/upload_images/2404560-36c70c0c08463928.png?imageMogr2/auto-orient/strip|imageView2/2/w/862/format/webp)

sdk_settings.png

- Android Studio 的配置

  接下来配置：Run/Debug Configurations里面的配置文件：

  ![img](https://upload-images.jianshu.io/upload_images/2404560-b0c52e1e158e5327.png?imageMogr2/auto-orient/strip|imageView2/2/w/385/format/webp)

  edit_confi.png

打开后我们点击上面的+符合，然后选择Remote，添加一个远程调试如下图：



![img](https://upload-images.jianshu.io/upload_images/2404560-b7448bf101139539.png?imageMogr2/auto-orient/strip|imageView2/2/w/773/format/webp)

remote.png

然后配置远程调试的端口和一些其他信息，如下图：



![img](https://upload-images.jianshu.io/upload_images/2404560-7b83e34ed3502424.png?imageMogr2/auto-orient/strip|imageView2/2/w/1091/format/webp)

remote_confi.png

注意，上面的Name可以随便写，因为每一个Remote配置都对应手机app上的一个进程，每一个手机app可能有多个进程，所有名字上我们做下区分。另一个需要配置的地方是Port，这个port也可以随便写，只要当前电脑上没有是用这个端口就好，如果要同时调试手机上的某个app的多个进程，这个每次配置Remote的时候，port不能一样。我们这里是用默认的5005。

- 打通AndroidStudio和可调试apk之间的通道

  手机上已经安装了我们前面重新打包的可调试的alarmy的apk，启动它

  - 查看alarmy的所有的进程信息
    先找到当前的包名，可以通过查看当前的activity来获取：
    `adb shell dumpsys activity activities`

    ![img](https://upload-images.jianshu.io/upload_images/2404560-2a7ce7d751e43c7f.png?imageMogr2/auto-orient/strip|imageView2/2/w/906/format/webp)

    activity.png

    然后命令行运行:

    ```
    adb shell ps | findstr droom.sleepIfUCan
    ```

    ![img](https://upload-images.jianshu.io/upload_images/2404560-817bb2f85fed2682.png?imageMogr2/auto-orient/strip|imageView2/2/w/687/format/webp)

    ps.png

    

  - 判断你要debug的那个页面（Activity）在哪个进程里面
    首先打开这个页面，然后命令行运行：
    `adb shell dumpsys activity | findstr mFocusedActivity`
    或者
    ···adb shell dumpsys activity | findstr mResumedActivity```
    这会得到当前显示的Activity的名字，然后去AndroidManifest.xml中去查看这个Activity的信息，里面会有进程信息。

  - 端口映射
    `adb forward tcp:5005 jdwp:5972`
    设置端口转发，这条命令的含义可以认为是在本地5005端口与手机5972进程之间建立一条通道，当开始调试时，AS连接本地的5005端口，通过这条通道控制程序的运行。这个5005是前面（图3.2）中配置的端口，这个5972是alarmy在手机上运行的一个进程的进程id,在前面执行ps时获取的。

  - 加断点
    和平常一样，只要加到你想要程序暂停的地方就好，我们把断点下到alarmy的首页，通过adb shell dumpsys activity | findstr mResumedActivity这个命令可知道首页叫droom.sleepIfUCan/.view.activity.MainActivity。

    ![img](https://upload-images.jianshu.io/upload_images/2404560-63db3b74f22c25fe.png?imageMogr2/auto-orient/strip|imageView2/2/w/1006/format/webp)

    onresume.png

    注：这里把断点下到了首页的onResume方法中是为了测试用，因为onResume方法会被调用很多次，当我们按home键，然后在打开alarmy的时候这个方法就会被调用。

  - 启动debug

    ![img](https://upload-images.jianshu.io/upload_images/2404560-7406da9c0ee8a21b.png?imageMogr2/auto-orient/strip|imageView2/2/w/314/format/webp)

    debug.png

    首先选择要调试的配置，然后点击那个调试按钮。如果左下角出现下图说明启动成功：

    ![img](https://upload-images.jianshu.io/upload_images/2404560-64660f9dc7a726fc.png?imageMogr2/auto-orient/strip|imageView2/2/w/603/format/webp)

    connected.png

    试试打开个别的应用，然后再切回alarmy，这时候程序会停在断点处。

    ![img](https://upload-images.jianshu.io/upload_images/2404560-fb73664e0bc9ca4f.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)

    pause.png

  - **链接失败处理**
    使用过程中很容易出现如下错误：

    ![img](https://upload-images.jianshu.io/upload_images/2404560-439b6cfbcb3e32ae.png?imageMogr2/auto-orient/strip|imageView2/2/w/780/format/webp)

    error.png

    尝试了修改端口号，重启等一系列方法都没有效果。 最后找到了一种简单有效的办法，直接用attach的方式找到进程再attach上去，但是没有找到打开Choose Process窗口的入口，只能通过快捷键的方式来打开：

    先绑定快捷键

    ![img](https://upload-images.jianshu.io/upload_images/2404560-cfd5b4585fc38bd8.png?imageMogr2/auto-orient/strip|imageView2/2/w/750/format/webp)

    keymap.png

    这里我设置了ctrl+alt+R,也可以设置其他不冲突的。然后再直接用快捷键打开：

    ![img](https://upload-images.jianshu.io/upload_images/2404560-a3df7f7bd357d8e4.png?imageMogr2/auto-orient/strip|imageView2/2/w/460/format/webp)

    attach.png

    找到需要的进程即可

    

### 代码注入

先通过jadx阅读目标app的代码，方便阅读，降低难度，然后再通过Android Studio来编辑smali代码。简单的可以直接修改某个值，复杂的可以先写好代码，然后将该段反编译出smali代码，再复制黏贴到需要注入的目标smali代码。这里需要注意smali的一些语法。
这里举个简单的例子，想获知alarmy监听了哪些广播，添加Log打印。

- 先写好要添加的java代码：

  ![img](https://upload-images.jianshu.io/upload_images/2404560-07858aa2ac9e193d.png?imageMogr2/auto-orient/strip|imageView2/2/w/555/format/webp)

  log_java.png

- 通过jadx查看需要添加的代码：

  ![img](https://upload-images.jianshu.io/upload_images/2404560-8efa3ff80c1083f2.png?imageMogr2/auto-orient/strip|imageView2/2/w/410/format/webp)

  log_jadx.png

- 通过apktool反编译准备注入的代码：

  ![img](https://upload-images.jianshu.io/upload_images/2404560-f91357514676d3b5.png?imageMogr2/auto-orient/strip|imageView2/2/w/794/format/webp)

  log_smali.png

- 把上述smali代码复制黏贴到目标smali的方法处，如下：

  ![img](https://upload-images.jianshu.io/upload_images/2404560-822e0039919f098b.png?imageMogr2/auto-orient/strip|imageView2/2/w/857/format/webp)

  inject_source.png

  修改Smali时有一件很重要的事情就是要注意寄存器。

  如果乱用寄存器的话可能会导致程序崩溃。每个方法开头声明了registers的数量，这个数量是参数和本地变量总和。参数统一用P表示。如果是非静态方法p0代表this，p1-pN代表各个参数。如果是静态方法的话，p0-pN代表各个参数。本地变量统一用v表示。如果想要增加的新的本地变量，需要在方法开头的registers数量上增加相应的数值。