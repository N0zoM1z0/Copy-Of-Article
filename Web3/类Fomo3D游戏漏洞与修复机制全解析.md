#### ***摘要：\***

*无论是 Fomo3D 山寨版还是正宗原版都摆脱不了“一轮就凉凉”的宿命，这与其智能合约的设计漏洞不无关系。本文从合约安全开发的角度出发，详细分析了类 Fomo3D 游戏的两个问题，并提出若干个可能的解决方案。*

### 黑客攻击之下，类 Fomo3D 游戏一蹶不振

Fomo3D 游戏已正式进入第三轮。截止北京时间 9 月 29 日上午 11 点整，本轮奖池仅累积了 97.8988 Ether，外加上一轮滚入的 680 Ether，奖池总金额不足 800 Ether，相较前两轮的盛况，可谓惨不忍睹。

安比（SECBIT）实验室曾经撰文分析了类 Fomo3D 游戏的衰败现状，先来简单回顾一下 。

![img](https://i-blog.csdnimg.cn/blog_migrate/35506706ecd8317f1f04820e39bfc472.png)

​                           *图一：Fomo3D 玩家参与度与入场资金状况*

上图展示了「Fomo3D 玩家参与度与入场资金状况」。红色代表调用合约参与游戏的人次，蓝色则代表进入游戏合约的资金量。图左侧出现数据曲线最高峰，对应时间分别是 7 月 20 日和 7 月 21 日。这两天恰好大量媒体疯狂报道 Fomo3D 这一现象级游戏。当时众多玩家跟风入场，游戏合约的参与次数和入场资金均达到了最高峰，入场资金量超过 40,000 Ether，而参与次数最高超过 18,000 次。高峰过后，Fomo3D 游戏热度骤降，于 8 月 22 日前后结束第一轮，并随即进入第二轮，但游戏热度已然无法恢复。

尽管如此，黑客却没有停止攻击

![img](https://i-blog.csdnimg.cn/blog_migrate/c215d28722c8a3ddac8b45015bafa0a5.png)

​                          *图二：Fomo3D 游戏合约被攻击状况*

上图是「Fomo3D 游戏合约被攻击状况」，第一轮游戏高峰前后以及第二轮开始后，有黑客疯狂地利用“空投漏洞”进行攻击，攫取高额收益 。而在第一轮临近结束，以及第二轮倒计时快结束之际，则有黑客疯狂尝试“阻塞交易”攻击，企图夺取最终大奖 。

不仅仅是 Fomo3D 原版游戏，其他众多的类 Fomo3D 山寨游戏，也成为黑客的攻击目标。

![img](https://i-blog.csdnimg.cn/blog_migrate/3b737811d95d311495fd2211b45d8196.png)

Fomo3D 类游戏参与形式是用 Ether 购买游戏道具，最后一位购买者获得“最终大奖”，平时参与者有一定概率获得“空投奖励”，分别从主奖池和副奖池中获取。这两类奖励是游戏设计层面对参与者的重要激励。这一设计，目的在于利用“随机”和“竞争”提升游戏趣味度，吸引更多人投入资金参与，从而延长游戏时间。

然而事与愿违，由于合约代码存在漏洞，掌握攻击技巧的黑客能够以很高的概率持续获得“空投奖励”，而“最终大奖”也会被黑客利用特殊技巧夺走。普通参与者在这类游戏中几乎无法获得这两种重要奖励。因此，他们仅能幻想在每轮游戏开始后第一时间入场，然后靠后续他人的资金回本。但是，游戏最重要的两个激励机制已然失效，无法持续吸引新资金，最终形成恶性循环。

黑客是如何利用这两个漏洞的？项目方难道就无计可施吗？

### 空投漏洞分析

先看看“空投奖励”。

所有投入游戏的 Ether，会有 1% 数量进到副奖池。空投的概率从 0% 开始，每增加一笔不小于 0.1 ETH 销售订单，空投概率会增加 0.1%。同时空投奖励金额与购买金额也挂钩，如果购买 0.1 ~ 1 ETH，就有概率赢得 25% 副奖池奖金，购买越多则比例越大。游戏界面会鲜明显示当前中奖概率和奖池金额。

Fomo3D 空投奖励实现存在两处问题：

> \1. 合约中的“随机数”可被预测
> \2. 判断调用者是否是合约地址的方法有漏洞

空投奖励依靠[智能合约](https://so.csdn.net/so/search?q=智能合约&spm=1001.2101.3001.7020)内生成的“随机数”，在 Fomo3D 源码中由 airdrop() 函数控制。

```solidity
/**
* @dev generates a random number between 0-99 and checks to see if thats
* resulted in an airdrop win
* @return do we have a winner?
*/
function airdrop()
private
view
returns(bool)
{
uint256 seed = uint256(keccak256(abi.encodePacked(
(block.timestamp).add
(block.difficulty).add
((uint256(keccak256(abi.encodePacked(block.coinbase)))) / (now)).add
(block.gaslimit).add
((uint256(keccak256(abi.encodePacked(msg.sender)))) / (now)).add
(block.number)
 
)));
if((seed - ((seed / 1000) * 1000)) < airDropTracker_)
return(true);
else
return(false);
}
```

airdrop() 函数中的“随机数” seed 由各种区块信息和交易发起者地址计算得来。这显然十分容易预测 。

为了防止合约自动化攻击，Fomo3D 开发者还使用 isHuman() 来防止合约账户参与 Fomo3D 游戏，试图以此方法来禁止玩家在合约内预测中奖随机数。

```solidity
/**
* @dev prevents contracts from interacting with fomo3d
*/
modifier isHuman() {
address _addr = msg.sender;
uint256 _codeLength;
assembly {_codeLength := extcodesize(_addr)}
require(_codeLength == 0, "sorry humans only");
_;
}
```

这里犯了另一个常见错误。extcodesize 操作符用来获取目标地址上的代码大小。对于已部署成功的合约，由于其地址对应着特定代码，extcodesize 的返回值始终大于 0。因此不少人用此方法来判断目标地址是否是合约，Fomo3D 甚至以此为依据来阻止合约调用特定函数。但该判断方法存在明显漏洞，在构造新合约的过程中（即合约构造方法里）调用游戏参与函数即可绕过该限制。这是因为合约在构造过程中，其地址并未对应任何代码，extcodesize 的返回值为 0 [5]。

上述的两个安全问题综合作用，最终导致黑客可以构造攻击合约，通过合约参与游戏，随意预测随机数，进而极大提高自己的胜率 。

### 如何修复空投漏洞

那么究竟如何解决 Fomo3D 的“空投漏洞”？

黑客能够成功攻击，是利用了上文列出的两个漏洞，构造攻击合约来预测游戏合约中的“随机数”。因此，我们只需完成以下两件事之一，使攻击所需的必要条件不满足即可：

> \1. 防止智能合约中的“随机数”预测
> \2. 采取更安全的方式判断调用者是否是合约

**方案一：防范智能合约中的“随机数”预测**

让我们先解决“随机数”预测的问题。

智能合约环境内“随机数”容易被预测的原因在于，“随机数”产生所依赖的“随机源”可以被任何人轻易获得。攻击者可以构造一个攻击合约，在相同环境内执行“随机数”计算公式，即可得到需要的“随机数”，并以之作为下一步行动的判断依据。

智能合约内几乎一切可用变量都是公开的，并且“随机数”计算公式需要确保所有节点执行结果都一致。因此，很难找到十分简洁的方法来产生无法被预测的“随机数”。

但仍有一些稍复杂但可行的解决方案。如开发者可通过先提交再披露（commit/reveal）、或延迟若干个区块开奖。此外，还有一些引入外部预言机（Oracle）的方案，如 Oraclize 和 BTCRelay [6]。

安比（SECBIT）实验室结合 Fomo3D 游戏机制，介绍一种利用“当前/未来”区块的哈希值来防止“随机数”被预测的方案 [7]。

以太坊智能合约中可以通过 block.blockhash() 来获取特定区块的哈希值。该函数接受参数为区块高度，可取范围为除当前区块外的最近 256 个区块。当传入其他值时，该函数均返回 0。

![img](https://i-blog.csdnimg.cn/blog_migrate/54f024dcecddb49162326323c13e9b52.png)

常见不安全的“随机数”计算方法，会读取当前块的前一个块的哈希 block.blockhash(block.number-1) 作为随机源。而在合约内执行 block.blockhash(block.number) 返回值为 0。我们无法在合约内获得当前区块的哈希，这是因为矿工打包并执行交易时，当前区块哈希尚未被算出。因此，我们可以认为“当前区块”哈希是“未来”的，无法预测。

我们可以在用户首次购买道具参与游戏时，记录其地址、当前区块高度 N 至一个数组中，最终拿到一个唯一的 id（如下面 _purchase() 函数所示）。

```solidity
function _purchase(address user) internal {
Purchase memory p = Purchase({
user: user,
commit: uint64(block.number),
randomness: 0
});
uint id = purchases.push(p) - 1;
 
emit KeysPurchased(id, user, packCount);
}
```

在接下来的 255 个区块内，用户可以用该 id 再次参与游戏，此时高度为 N 的区块哈希可正常获得，以此来生成“随机数”，判断用户是否中奖（如下面 _airdrop() 函数所示）。

```solidity
function _airdrop(uint id) internal returns(bool) {
Purchase storage p = purchases[id];
require(p.randomness == 0);
require(block.number - 256 < p.commit);
require(uint64(block.number) != p.commit);
require(p.user == msg.sender);
 
bytes32 bhash = blockhash(p.commit);
uint seed = uint(keccak256(abi.encodePacked(bhash, p.user, id)));
p.randomness = seed;
 
if((seed - ((seed / 1000) * 1000)) < airDropTracker_)
return(true);
else
return(false);
}
```

255 个区块之后，用户参与游戏时的区块哈希在合约内无法正常获得。因此，务必要限制用户在一定时间范围内查询是否中奖，并及时参与游戏领取奖励。当然，为了游戏体验，如果用户错失领奖，也可以参照上面的原理再给他一次机会重新抽奖。结合游戏规则，这里仍有一些技术细节需注意，欢迎添加小安同学微信（secbit_xiaoanbi），加入到「SECBIT 智能合约安全技术群」参与讨论。

这种方法也用在知名的区块链卡牌游戏 Gods Unchained 中，用来控制用户所购卡牌稀有程度。当然我们也可以用当前高度后指定数量（如五个）的区块哈希来作为随机源，原理是一样的 [8]。

**方案二：防止合约自动化攻击**

另一个问题，我们如何判断调用者是否是合约地址？
有一个简便但是有效的方法。

```solidity
modifier isHuman() {
require(tx.origin == msg.sender, "sorry humans only");
_;
}
```

以太坊安全开发最佳实践中推荐尽量不要使用 tx.origin，因为很多人将 tx.orign 和 msg.sender 混淆。tx.orign 代表的是一笔交易的发起者，而 msg.sender 代表每一次合约调用（call）的发起者。

```
A -> B -> C
```

如普通账户 A 调用合约 B，合约 B 再调用合约 C。在合约 C 内，msg.sender 是合约 B，而 tx.origin 是账户 A。msg.sender 可以是合约地址，但 tx.origin 永远不会是合约。因此，上面的方法可以有效防止合约调用合约。

### “阻塞交易”攻击分析

再看看“最终大奖”。

Fomo3D 类游戏存在倒计时，在每轮游戏结束前最后一个购买道具的参与者获胜，可以拿走主奖池中近半的资金。因此众多参与者会在临近结束时，发起购买交易参与游戏，如果能幸运地在最后一刻被矿工打包入块，即可获胜。

普通人在游戏快结束时都是类似的策略：紧盯着时间，调高 Gas 费用，发起参与游戏的交易，然后闭上眼睛祈祷，希望自己能是最后一个参与者。然而，采用这种方法几乎不可能中奖。

据安比（SECBIT）实验室分析，Fomo3D 前两轮获奖者使用手法如出一辙，均在游戏快结束时，发起攻击交易。

获奖者（黑客）通过提前部署好的攻击合约，在合约内调用 getCurrentRoundInfo() 接口查询游戏信息，重点关注剩余时间和最后一位购买者地址。当游戏剩余时间达到一个阈值，并且最后一个购买者是自己时，则通过 assert() 让整个交易失败，并耗光所有 Gas；当剩余时间很长或最后一个购买者不是自己时，则不做任何操作，仅消耗很少的 Gas。

![img](https://i-blog.csdnimg.cn/blog_migrate/bc87fb273004a25f61cb6ed74de8b2e9.png)

获奖者（黑客）就是利用这种方法，发起大量类似的可变神秘交易：在自己极有可能成为中奖者时，利用这些高额手续费的神秘交易，吸引矿池优先打包，占满后续区块，从而使得其他玩家购买 key 的交易无法被正常打包，最终加速游戏结束，并极大地提高自己的中奖概率。

普通玩家只能在游戏快结束时手动调高 Gas 费用参与游戏，也有人试图使用自动脚本在临近游戏结束时调高 Gas Price 发起参与游戏交易。与这些盲目的方法相比，黑客的攻击手法显然高明许多。

### 如何防范“阻塞交易”攻击

其实，这一问题不止会威胁类 Fomo3D 游戏。所有采用类似机制，即需要玩家抢在某个时间范围内完成某种竞争操作的智能合约，都会受此威胁。只要游戏奖励足够丰厚，攻击回报远大于投入，就会有人利用前文提到的方法来破坏游戏公平性。

**方案一：提高攻击所需成本**

要杜绝这一问题，安比（SECBIT）实验室建议游戏开发者，从游戏机制入手，切断游戏最终胜利（获得某个巨额大奖）和倒计时结束（最后一个交易被打包）之间的必然联系，从而使黑客的攻击获利概率和攻击意愿都降到最低。*（wx添加小安同学：secbit_xiaoan-bi,加入“SECBIT智能合约安全技术讨论”社群）。*

例如，我们可以修改游戏规则为：每轮游戏结束前最后一个购买道具的参与者有概率获得最终大奖，并将此概率调整为一个较低的值，如 5 %。在倒计时结束但大奖因概率原因没有正常开出的情况下，合约自动给游戏续一定时间。这样一来，前面提到的堵塞区块、阻止别人参与游戏的技巧，无法确保攻击者一定能获得最终大奖。而黑客持续进行“阻塞交易”攻击需耗费大量 Gas 费用，成本会很高，最终会选择放弃攻击。

```solidity
function buyCore(...)
private
{
...
// check to see if end round needs to be ran
if (_now > round_[_rID].end && round_[_rID].ended == false)
{
// check to see whether or not this round should end
if shouldRndEnd(lastCommitId) (
// end the round (distributes pot) & start new round
round_[_rID].ended = true;
_eventData_ = endRound(_eventData_);
...
) else {
...
updateTimer(_keys, _rID);
...
}
}
...
}
```

上面为示例代码，其中 shouldRndEnd() 函数用来在倒计时结束后控制中奖概率，决定这一轮游戏是否真的结束。这里的概率同样依赖“随机数”不能被预测，具体实现原理与前文提到的空投概率控制代码类似。

**方案二：禁止合约调用游戏信息查询接口**

Fomo3D 最终获胜者可以轻易攻击成功的另一个原因是，游戏合约开放了一个完整的游戏进度信息查询接口，并且普通账户和合约账户都可以任意调用查询。这方便了黑客在攻击合约内实时查询游戏状态，进而执行不同策略来降低攻击成本和提高命中率。

```solidity
modifier isHuman() {
require(tx.origin == msg.sender, "sorry humans only");
_;
}
function getCurrentRoundInfo()
isHuman()
public
view
returns(...)
{
...
}
```

因此，针对 Fomo3D 游戏，还有另一个简易的防范方法。对 getCurrentRoundInfo() 函数使用前文提到的安全版的 isHuman() 校验来保护，就可以有效避免合约自动化攻击。

### 总结

有安全和公平性问题的 Fomo3D 原版以及山寨版，仅是“黑客”掘金的对象，注定无法吸引更多普通玩家参加。随着一轮一轮的进行，玩家会逐渐流失，这些游戏会进一步没落。

安比（SECBIT）实验室呼吁后来者吸取教训，不要再原封不动地复制代码，不要试图仅靠“运营”来吸引新人入场。作出一些小小的改变，智能合约的安全性会得到很大的提升，去中心化游戏才能走得更远。

### 参考文献

• [1] Fomo3D二轮大奖开出，黑客获奖，机制漏洞成游戏没落主因, https://zhuanlan.zhihu.com/p/45330743, 2018/09/25

• [2] 智能合约史上最大规模攻击手法曝光，盘点黑客团伙作案细节, https://zhuanlan.zhihu.com/p/42318584, 2018/08/17

• [3] Fomo3D 千万大奖获得者“特殊攻击技巧”最全揭露, https://zhuanlan.zhihu.com/p/42742004, 2018/08/23

• [4] How to PWN FoMo3D, a beginners guide, [https://www.reddit.com/r/ethereum/comments/916xni/how](https://link.zhihu.com/?target=https%3A//www.reddit.com/r/ethereum/comments/916xni/how)*to*pwn*fomo3d*a*beginners*guide, 2018/07/23

• [5] Using EVM assembly to get the address' code size, [https://ethereum.stackexchange.com/questions/14015/using-evm-assembly-to-get-the-address-code-size](https://link.zhihu.com/?target=https%3A//ethereum.stackexchange.com/questions/14015/using-evm-assembly-to-get-the-address-code-size), 2017/04/07

• [6] Predicting Random Numbers in Ethereum Smart Contracts, [https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620](https://link.zhihu.com/?target=https%3A//blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620), 2018/02/01

• [7] Random Number Generation on [http://Winsome.io](https://link.zhihu.com/?target=http%3A//Winsome.io) — Future Blockhashes, [https://blog.winsome.io/random-number-generation-on-winsome-io-future-blockhashes-fe44b1c61d35](https://link.zhihu.com/?target=https%3A//blog.winsome.io/random-number-generation-on-winsome-io-future-blockhashes-fe44b1c61d35), 2017/05/07

• [8] Gods Unchained, [https://etherscan.io/address/0x482cf6a9d6b23452c81d4d0f0f139c1414963f89#code](https://link.zhihu.com/?target=https%3A//etherscan.io/address/0x482cf6a9d6b23452c81d4d0f0f139c1414963f89%23code), 2018/07/16

本文由安比（SECBIT）实验室提供，安比（SECBIT）实验室致力于参与共建共识、可信、有序的区块链经济体。