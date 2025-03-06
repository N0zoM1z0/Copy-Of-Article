# Solidity 字节码和操作码基础知识



- [Zhumaomao.eth](https://learnblockchain.cn/people/1877)
-  

- 发布于 2022-09-22 19:52
-  

- 阅读 6684

在本文中，简单地解释一些 EVM 基础知识。

随着我们深入编写智能合约，我们会遇到诸如“PUSH1”、“SSTORE”、“CALLVALUE”等术语。 它们是什么，我们甚至应该关心它们吗？

要了解这些命令，我们必须深入了解以太坊虚拟机（EVM）。 当我四处搜索时，我很惊讶关于这个主题的资源很少。 也许他们太技术化了？ 在本文中，我将尽可能简单地解释一些 EVM 基础知识。

像许多其他流行的编程语言一样，[Solidity](https://learnblockchain.cn/article/567) 是一种[高级编程语言](https://en.wikipedia.org/wiki/High-level_programming_language)。 我们理解它，但机器不理解。 当我们安装像[geth](https://github.com/ethereum/go-ethereum/wiki/geth)这样的以太坊客户端时，它还附带了以太坊[虚拟机](https://en.wikipedia.org/wiki/Virtual_machine)，这是一个专门为运行智能合约而创建的轻量级[操作系统](https://en.wikipedia.org/wiki/Operating_system)。

## 当我们使用 solc 编译器编译 solidity 代码时，它会将我们的代码翻译成字节码，只有 EVM 才能理解。

让我们以一个非常简单的合约为例：

```js
pragma solidity ^0.4.11;
contract MyContract {
    uint i = (10 + 2) * 2;
}
```

如果我们在[Remix](http://remix.ethereum.org/)中运行此代码并单击合约详细信息，我们会看到很多信息。

![image.png](https://img.learnblockchain.cn/attachments/2022/09/AcNUkhhc632c437b9d4f4.png)
![image.png](https://img.learnblockchain.cn/attachments/2022/09/MZrxwb5a632c4348258ee.png)

在这种情况下，编译后的代码是：

```js
606060405260186000553415601057fe5b5b603380601e6000396000f30060606040525bfe00a165627a7a72305820e8d51d91f3af019d36e0e5d9d96443cdedaffd6764df9527ba3d510872b554f50029
```

(BYTECODE中的object属性)

这些长值是最终合约的[十六进制](https://en.wikipedia.org/wiki/Hexadecimal)表示，也称为[字节码](https://en.wikipedia.org/wiki/Bytecode)。 在Remix的“Web3 Deploy”部分下，我们看到：

```js
var mycontractContract = new web3.eth.Contract([]);
var mycontract = mycontractContract.deploy({
     data: '0x606060405260186000553415601057fe5b5b603380601e6000396000f30060606040525bfe00a165627a7a72305820e8d51d91f3af019d36e0e5d9d96443cdedaffd6764df9527ba3d510872b554f50029', 
     arguments: [
     ]
}).send({
     from: web3.eth.accounts[0], 
     gas: '4700000'
   }, function (e, contract){
    console.log(e, contract);
    if (typeof contract.address !== 'undefined') {
         console.log('Contract mined! address: ' + contract.address + ' transactionHash: ' + contract.transactionHash);
    }
 })
```

简单来说就是我们在部署合约的时候，简单的部署data字段下的16进制，推荐gas为4300000。

如果我们想与 EVM 对话，我们必须开始考虑十六进制。 有没有想过为什么你的钱包或交易地址前面有一个“0x”？ 没错，任何以“0x”开头的都只是表示该值是十六进制格式。 在十六进制前面有“0x”不是强制性的，因为 EVM 将任何值视为十六进制而不管。

我们还看到了操作码（又名[操作码](https://en.wikipedia.org/wiki/Opcode)）：

```js
"opcodes": 
    "PUSH1 0x60 PUSH1 0x40 MSTORE PUSH1 0x18 PUSH1 0x0 SSTORE CALLVALUE ISZERO PUSH1 0x10 JUMPI INVALID JUMPDEST JUMPDEST PUSH1 0x33 DUP1 PUSH1 0x1E PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN STOP PUSH1 0x60 PUSH1 0x40 MSTORE JUMPDEST INVALID STOP LOG1 PUSH6 0x627A7A723058 SHA3 0xe8 0xd5 0x1d SWAP2 RETURN 0xaf ADD SWAP14 CALLDATASIZE 0xe0 0xe5 0xd9 0xd9 PUSH5 0x43CDEDAFFD PUSH8 0x64DF9527BA3D5108 PUSH19 0xB554F500290000000000000000000000000000"
```

操作码是程序的低级人类可读指令。 所有操作码都有对应的十六进制，例如“MSTORE”是“0x52”，SSTORE 是“0x55”……等等。[以太坊黄皮书](http://gavwood.com/paper.pdf)对所有的solidity 操作码及其十六进制值都有很好的参考。

EVM 也是一个[堆栈机](https://en.wikipedia.org/wiki/Stack_machine)。 简单地解释一下，想象一下在微波炉中堆叠面包片，您放入的最后一片面包是您取出的第一片。 在计算机科学术语中，我们称之为 [LIFO](https://techterms.com/definition/filo)。

在普通算术中，我们这样写方程

```js
//答案是 14。我们在加法之前做乘法。
10 + 2 * 2
```

在堆栈机中，它以 LIFO 原理工作

```js
2 2 * 10 + 
```

这意味着，首先将“2”放入堆栈，然后是另一个“2”，然后是乘法操作。 结果是“4”位于堆栈顶部。 现在在“4”之上添加一个数字“10”，最终将两个数字相加。 堆栈的最终值变为 14。这种类型的算术称为Postfix Notation(后缀表示法)或[Reverse Polish Notation](https://en.wikipedia.org/wiki/Reverse_Polish_notation)(反向波兰表示法)。

将数据放入堆栈的动作称为“PUSH”指令，而从堆栈中删除数据的动作称为“POP”指令。 很明显，我们在上面的示例中看到的最常见的操作码是“PUSH1”，这意味着将 1 个字节的数据放入堆栈。

所以，这个指令：

```js
PUSH1 0x60
```

表示将 1 字节值“0x60”放入堆栈。 巧合的是，“PUSH1”的十六进制值也恰好是“0x60”。 去掉非强制的“0x”，我们可以用字节码把这个逻辑写成“6060”。

让我们更进一步。

```js
PUSH1 0x60 PUSH1 0x40 MSTORE 
```

再次查看我们最喜欢的 pyethereum 操作码图表，我们看到 MSTORE (0x52) 接受 2 个输入并且不产生输出。 上面的操作码意味着：

1. PUSH1 (0x60)：将 0x60 放入堆栈。
2. PUSH1 (0x40)：将 0x40 放入堆栈。
3. MSTORE (0x52)：分配0x60的内存空间并移动到0x40的位置。

生成的字节码是：

```js
6060604052
```

事实上，我们总是在任何 Solidity 字节码的开头看到这个神奇的数字“6060604052”，因为它是智能合约引导的方式。

更复杂的是，0x40 或 0x60 不能解释为实数 40 或 60。由于它们是十六进制的，因此 40 实际上等于 64 (16 x 4)，而 60 等于十进制的 96 (16 x 6)。

简而言之，“*PUSH1 0x60 PUSH1 0x40 MSTORE*”所做的就是分配 96 字节的内存并将指针移动到第 64 字节的开头。 我们现在有 64 字节用于暂存空间和 32 字节用于临时内存存储。

> 在 EVM 中，有 3 个地方存储数据。 首先，在堆栈中。 根据上面的示例，我们刚刚使用“PUSH”操作码在那里存储数据。 其次，在我们使用“MSTORE”操作码的内存（RAM）中，最后，在我们使用“SSTORE”存储数据的磁盘存储中。 将数据存储到存储所需的气体Gas是最昂贵的，而将数据存储到堆栈是最便宜的。

## 汇编语言

也可以使用操作码编写整个智能合约。 这就是 [Solidity 汇编语言](https://docs.soliditylang.org/en/develop/assembly.html)的用武之地。它可能更难理解，但如果你想节省 gas 并做一些 Solidity 无法完成的事情，它可能会很有用。

## 概括

我们只介绍了字节码的基础知识和一些操作码。 有很多操作码尚未讨论，但你明白了。 回到最初的问题，即我们是否应该费心学习 Solidity 操作码——可能是也可能不是。

我们不需要知道操作码就可以开始编写智能合约，这增加了学习曲线。 另一方面，在撰写本文时，EVM 错误处理仍然非常原始，并且在出现问题时可以方便地查看操作码。 归根结底，学习更多并没有什么坏处。