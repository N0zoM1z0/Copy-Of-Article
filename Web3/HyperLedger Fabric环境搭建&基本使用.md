**一、说明**

[Hyperledger Fabric](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=Hyperledger+Fabric&zhida_source=entity) 是一个是开源的，企业级的，带权限的分布式账本解决方案的平台。Hyperledger Fabric 由模块化架构支撑，并具备极佳的保密性、可伸缩性、灵活性和可扩展性。Hyperledger Fabric 被设计成支持不同的模块组件直接拔插启用，并能适应在经济生态系统中错综复杂的各种场景。

本文分享在 [Centos7](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=Centos7&zhida_source=entity) 下搭建 Hyperledger Fabric 2.5 环境并进行简单的网络测试。

**二、环境准备**

2.1. 环境依赖

- [Git](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=Git&zhida_source=entity) 1.8.3.1
- [Golang](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=Golang&zhida_source=entity) 1.21.0
- [Docker](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=Docker&zhida_source=entity) 24.0。5
- [docker compose](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=docker+compose&zhida_source=entity) 2.20.2
- [Node](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=Node&zhida_source=entity) 16.18.1

2.2 环境安装

1）git安装：yum install git

查看版本： git version

![img](https://pic1.zhimg.com/v2-2141f73dc50d56ce9219d77da04e9064_1440w.jpg)

2）go安装

下载文件:

```text
wget -P /usr/local https://dl.google.com/go/go1.16.linux-amd64.tar.gz
```

解压文件到 /usr/local（可以自行选择路径）

```text
cd /usr/local
tar -zxvf go1.16.linux-amd64.tar.gz
```

配置环境

```text
vim /etc/profile
```

写入

```text
export PATH=$PATH:/usr/local/go/bin
export GOROOT=/usr/local/go
export GOPATH=/root/go/
```

\#根据自己的路径进行修改

使环境配置生效：source /etc/profile

查看版本：go version

![img](https://pica.zhimg.com/v2-d40a5703de1a5b255d891d21cf981940_1440w.jpg)



3）docker 安装

安装docker依赖库：

```text
yum install -y yum-utils device-mapper-persistent-data lvm2
```

添加Docker CE的软件源信息：

```text
yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

dnf makecache
```

安装最新版docker：

```text
yum -y install docker-ce
systemctl start docker
```

查看是否安装成功：docker version

![img](https://pic1.zhimg.com/v2-4d5c248f98adb30e4338fe1758ceb5ba_1440w.jpg)

4） 安装docker compose

```text
curl -L 503 Service Temporarily Unavailable -s`-`uname -m` > /usr/local/bin/docker-compose
```

赋权：chmod +x /usr/local/bin/docker-compose

查看版本：docker-compose version

![img](https://pica.zhimg.com/v2-e722e7e17c694a3ffd035eefeef33a06_1440w.jpg)

5） 安装Node

```text
yum -y install nodejs
```

查看版本: npm -v node -v

![img](https://pica.zhimg.com/v2-f2920f00466ecd2da07a245015b2d292_1440w.jpg)



三、Fabric 源码安装

1、下载源码

```text
git clone https://github.com/hyperledger/fabric.git
cd fabric/scripts
```

\#下载镜像和二进制文件：

```text
./bootstrap.sh
```

过程会比较慢，有可能出现卡顿的情况，解决办法如下：

使用国内的[码云](https://link.zhihu.com/?target=https%3A//so.csdn.net/so/search%3Fq%3D%E7%A0%81%E4%BA%91%26spm%3D1001.2101.3001.7020)的镜像仓库

```text
git clone https://gitee.com/hyperledger/fabric.git
```

手动下载`fabric` 和 `fabric-ca` 编译后的压缩包，存放在 `fabric/scripts/` 目录下：

```text
https://github.com/hyperledger/fabric/releases/download/v2.5.4/hyperledger-fabric-linux-amd64-2.5.4.tar.gz

https://github.com/hyperledger/fabric-ca/releases/download/v1.5.6/hyperledger-fabric-ca-linux-amd64-1.5.6.tar.g
```

压缩压缩包，得到 bin 与 config 两个文件夹：

```text
tar -zxvf hyperledger-fabric-linux-amd64-2.5.4.tar.gz
 
tar -zxvf hyperledger-fabric-ca-linux-amd64-1.5.6.tar.gz
```

执行以下命令复制到fabric-samples 目录中

```text
cp -r bin fabric-samples/
cp -r config fabric-samples/
```

2）修改安装脚本

编辑 `bootstrap.sh` 文件

把 [https://github.com/hyperledger/fabric-samples.git](https://link.zhihu.com/?target=https%3A//github.com/hyperledger/fabric-samples.git) 修改为 [Hyperledger/fabric-samples](https://link.zhihu.com/?target=https%3A//gitee.com/hyperledger/fabric-samples.git)

![img](https://pica.zhimg.com/v2-eb8520efe92d3365e7966070caf455d4_1440w.jpg)

注释 pullBinaries

![img](https://pic2.zhimg.com/v2-85a25e6ea583436a71947a24348770e9_1440w.jpg)

\3. 执行安装脚本

./bootstrap.sh

如下图所示，脚本执行成功之后会下载一个 `fabric-samples` 工程和一堆 fabric 的 docker 镜像：

![img](https://picx.zhimg.com/v2-64ed93016cde5488f0b95f12e021a267_1440w.jpg)



**四、启动 [test-network](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=test-network&zhida_source=entity) 测试网络**

进入 test-network 目录

执行以下命令：

```text
./network.sh up
```

如下图所示，已成功启动一个 `orderer节点` 和两个 `peer节点`：

![img](https://pic3.zhimg.com/v2-85a4c9f7bf911da1dd756b0ae9bf983c_1440w.jpg)

到此一个基于 `Hyperledger Fabric` 的测试网络就搭建完成了

**五、测试网络使用**

可以执行以下命令打印脚本的帮助文本：

```text
./network.sh -h
```

5.1. 创建 Channel

现在我们的机器上正在运行对等节点和排序节点， 我们可以使用脚本创建用于在 Org1 和 Org2 之间进行交易的 Fabric 通道。

Fabric channel 是特定网络成员之间的专用通信层，通道只能由被邀请加入通道的组织使用，并且对网络的其他成员不可见。 每个通道都有一个单独的区块链账本，被邀请的组织 “加入” 他们的对等节点来存储其通道账本并验证交易，建立一个通道相当于建立了一个子链。

使用 [network.sh](https://link.zhihu.com/?target=http%3A//network.sh) 脚本在 Org1 和 Org2 之间创建通道并加入他们的对等节点，执行以下命令创建一个通道：

```text
./network.sh createChannel
```

如下图所示创建成功后默认名称为 mychannel

![img](https://picx.zhimg.com/v2-4489a835ab824f9370522ffcebeb342f_1440w.jpg)

可使用 `-c` 来指定通道名称，以下命令将创建一个名为 `channel1` 的通道：

```text
./network.sh createChannel -c channel1
```

![img](https://pic4.zhimg.com/v2-8fa8a4c84d5b90b24143cb042906cef1_1440w.jpg)

5.2. 在通道启动一个链码

创建通道后，可以开始使用智能合约与通道账本交互。智能合约包含管理区块链账本上资产的业务逻辑，由成员运行的应用程序网络可以在账本上调用智能合约创建，更改和转让这些资产，应用程序还通过智能合约查询，以在分类账上读取数据。

在 Fabric 中，智能合约作为链码以软件包的形式部署在网络上。链码安装在组织的对等节点上，然后部署到某个通道，然后可以在该通道中用于认可交易和区块链账本交互。在将链码部署到通道前，该频道的成员需要就链码定义达成共识，建立链码治理。何时达到要求数量的组织同意后，链码定义可以提交给通道，并且可以使用链码了。

创建频道后，可以使用 [network.sh](https://link.zhihu.com/?target=http%3A//network.sh) 脚本在通道上启动链码：

```text
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-java -ccl java
-ccn：为指定链码名称
-ccl：为指定链码语言
```

提示找不到tools.jar的解决方法

1）查找当前服务器是否有这个文件，

```text
find / -name tools.jar
```

![img](https://pic3.zhimg.com/v2-9f4704f93da13f0747f3b5020707fde4_1440w.jpg)

如果有，复制到/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.382.b05-1.el7_9.x86_64/jre/lib/目录下



出现如下图这个提示，安装jq即可。下载：[官网地址](https://link.zhihu.com/?target=https%3A//jqlang.github.io/jq/)

![img](https://picx.zhimg.com/v2-bf543a77368ed8631acabcc7f37bf1ad_1440w.jpg)

进入官网

![img](https://pic2.zhimg.com/v2-57de251d421848a6a29acf30baef58bd_1440w.jpg)

将下载的jq-linux64上传至/usr/local/jq目录下，没有jq目录就创建一个，如下图

![img](https://pic4.zhimg.com/v2-77bab6b1b826665bef998867242943e9_1440w.jpg)

安装成功

再次运行上面的命令，出现下图，说明启动成功

![img](https://picx.zhimg.com/v2-3ae47e227e58cad46d4383e993d82fd9_1440w.jpg)

备注：deployCC 子命令将在 [peer0.org1.example.com](https://link.zhihu.com/?target=http%3A//peer0.org1.example.com) 和 [peer0.org2.example.com](https://link.zhihu.com/?target=http%3A//peer0.org2.example.com) 上安装 asset-transfer-basic 链码，如果第一次部署链码，脚本将安装链码的依赖项。默认情况下，脚本安装 Go 版本的 asset-transfer-basic 链码，可以通过参数 -ccl 来安装 Java 或 javascript 版本的链码。

5.3. 与网络交互

在启用测试网络后，可以使用 peer cli 客户端与网络进行交互，通过 peer cli 客户端可以调用已部署的智能合约，更新通道，或安装和部署新的智能合约。

首先确保操作目录为 test-network 目录，比如我的目录是：

以下操作需确保在 test-network 目录中进行操作：

![img](https://pic4.zhimg.com/v2-ce4c3c7d9e7c0d8c08f0e7a62da3222f_1440w.jpg)

执行以下命令将 cli 客户端添加到环境变量中：

```text
export PATH=${PWD}/../bin:$PATH
```

还需要将 fabric-samples 代码库中的 FABRIC_CFG_PATH 设置为指向其中的 core.yaml 文件：

```text
export FABRIC_CFG_PATH=$PWD/../config/
```

设置允许 org1 操作 peer cli 的环境变量：

```text
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
```

CORE_PEER_TLS_ROOTCERT_FILE 和 CORE_PEER_MSPCONFIGPATH 环境变量指向 Org1 的 organizations 文件夹中的的加密材料。

执行以下命令用一些资产来初始化账本：

```text
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n basic --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"InitLedger","Args":[]}'
```

执行成功会返回 Chaincode invoke successful. result: status:200 如下图所示：

![img](https://pic2.zhimg.com/v2-a2a0c1c03edbeb4d70d506db8464610b_1440w.jpg)

执行以下指令来查询通道账本中的资产列表：

```text
peer chaincode query -C mychannel -n basic -c '{"Args":["GetAllAssets"]}'
```

返回如下图,说明测试网络操作成功

![img](https://picx.zhimg.com/v2-3629ba70b83873748e93118537a00ecf_1440w.jpg)

**六、关闭网络**

使用完测试网络后，可执行以下命令关闭网络：

```text
./network.sh down
```

该命令将停止并删除节点和链码容器，删除组织加密材料，并从 Docker Registry 移除链码镜像，另外还会删除之前运行的通道项目：

![img](https://pic2.zhimg.com/v2-57cb3622e7dd4ebe06319ff6ad5e16cd_1440w.jpg)



**七、使用认证机构创建网络**

Hyperledger Fabric 使用公钥基础设施 (PKI) 来验证所有网络参与者的行为。 每个节点，网络管理员和用户提交的交易需要具有公共证书和私钥以验证其身份。

默认情况下，脚本使用 [cryptogen](https://zhida.zhihu.com/search?content_id=233562971&content_type=Article&match_order=1&q=cryptogen&zhida_source=entity) 工具创建证书和密钥，该工具用于开发和测试，并且可以快速为具有有效根信任的 Fabric 组织创建所需的加密材料。

测试网络脚本还提供了使用证书颁发机构（CA）的网络的启动选项。在网络中每个组织操作一个 CA（或多个中间 CA）来创建属于他们的组织身份，所有由该组织运行的 CA 创建的身份享有相同的组织信任根源。

首先运行以下命令关停所有正在运行的网络：

```text
./network.sh down
```

使用 CA 参数启动网络：

```text
./network.sh up -ca
```

执行命令成功后，通过打印的 docker 容器可以看到启动了三个 CA，每个网络中的组织一个：

![img](https://pic2.zhimg.com/v2-115213ee90fe67382b6d744c9f15e927_1440w.jpg)

以通过 `tree` 命令来查看 Org1 管理员用户的 MSP 文件夹结构和文件：

```text
tree organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/
```

![img](https://picx.zhimg.com/v2-bf698a8b54c5354a9fafc1d345ae9ef7_1440w.jpg)