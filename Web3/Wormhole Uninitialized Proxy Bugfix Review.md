# **Summary**

On February 24th, a whitehat who goes by the pseudonym [satya0x](https://twitter.com/satya0x), responsibly disclosed a critical bug in the Wormhole core bridge contract on Ethereum. This bug was an upgradeable proxy implementation self-destruct bug that could have led to a potential lockup of user funds. This responsible disclosure is yet another example of the immense strategic value that running a multi-million dollar bug bounty program can have for Web3 security programs.

Wormhole was amazingly fast in its response to the bug report, verifying and fixing the issue on the same day it was reported. No user funds were lost, thanks largely to the fact that this issue was responsibly disclosed via Wormhole’s bug bounty program, hosted by Immunefi.

Wormhole paid satya0x a record bug bounty of $10 million dollars for the find. It’s one thing to create a program with a really high top payout, but Wormhole has proven that they are very serious about paying top-dollar to help mitigate security issues in partnership with the white-hat community.

Security bugs in software are a fact of life and Web3 is no exception. They exist in every program and every protocol. What’s important, however, is how seriously a protocol takes security. That can be the difference between success and failure. Clearly, the Wormhole team takes the security of their platform very seriously and demonstrated their commitment by both having the world’s largest bug bounty program and paying out this record breaking bounty.

Wormhole is sending a clear message with this payout to the best, most talented whitehats on the planet that if they responsibly disclose security vulnerabilities to Wormhole, they’ll be well taken care of. Everyone wins in this arrangement, especially Wormhole’s users.

Immunefi is pleased to have facilitated this responsible disclosure using our platform. Our goal is to make Web3 safer by incentivizing hackers to responsibly disclose bugs and receive clean money and reputation in exchange.

To better understand the bug, let’s first dive into an explanation on what proxies are and how they work. Then, we’ll discuss the specific proxy issue at play here, the uninitialized proxy.

# Intro to Proxies

It is logical that all code, even immutable smart contracts, may eventually need to be upgraded. This is especially true as a safeguard against newly-discovered vulnerabilities and for adding new features to the protocol. But there is some disagreement from developers on which specific pattern of upgrade mechanism is best.

Introducing the ability to upgrade contracts adds a lot of complexity to the process, and for some, defeats the purpose of blockchain’s immutability and decentralization.

A smart contract upgrade can be simply summarized as: a change in the code at a specific address while preserving the storage state of previous code and the relationship of that address to other contracts.

Preserving storage state is necessary, as we want to have access to all of the state changes that happened before (i.e. history of interactions), but we want to change the code that is governing the logic of its interactions. Another way of saying this is that we are only swapping the implementation, not the state of the contract.

We can achieve this by using a proxy contract and delegate calls.

# Proxy and DELEGATECALL

In Ethereum, there are three major types of contract calls: regular `CALL`, `STATICCALL`, and `DELEGATECALL`.

When contract A makes a `CALL` to contract B by calling `foo()`, the function execution relies on contract B’s storage, and the `msg.sender` is set to contract A.

This is because contract A called the function `foo()`, so that the `msg.sender` would be contract A’s address and `msg.value` would be the ETH sent along with that function call. Changes made to state during that function call can only affect contract B.

![img](https://miro.medium.com/v2/resize:fit:875/0*-sRlZ4FNIR3IMKQe)

![img](https://miro.medium.com/v2/resize:fit:875/0*V7h8gmEyPps-6quS)

However, when the same call is made using `DELEGATECALL`, the function `foo()` would be called on contract B but in the context of contract A. This means that the logic of contract B would be used, but any state changes made by the function `foo()` would affect the storage of contract A. And also, `msg.sender` would point to the EOA who made the call in the first place. (See example 2)

![img](https://miro.medium.com/v2/resize:fit:875/0*8fdsXZKUkP_WqZu-)

A `delegatecall` makes it possible to create upgradeable contracts using a proxy pattern. The proxy contract (Contract A) redirects all the calls it receives to an implementation contract, whose address is stored in its (Contract A’s) storage. From a user perspective, the proxy contract runs the implementation contract’s code as its own, modifying the storage and balance of Contract A, the proxy contract. (See example 3)

![img](https://miro.medium.com/v2/resize:fit:875/0*jv2nl6V0cwqqTcr3)

Making an upgrade in this case is quite simple, as we only need to change the stored implementation contract address in order to change its smart contract logic. All incoming calls will be redirected to the new address, and nothing changes from the user’s perspective.

Another thing we need to take into account is: how can we handle the constructor logic? The contract’s constructor is automatically called during contract deployment. Most developers would put the initialization logic there, in order to make the smart contract functions correctly.

But this is no longer possible when proxies are in play, as the constructor would change only the implementation contract’s storage (Contract B), not the storage of the proxy contract (Contract A), which is the one that matters.

Therefore, an additional step is required. We need to change the constructor to a regular function. This function is conventionally called `initialize` or `init`. These are regular Solidity functions that are added to the implementation contract and, when called from the proxy, change the proxy contract’s storage. They also need special logic to ensure they can only be called once, similar to a constructor.

There are two major ways to implement this proxy and delegate call pattern. We illustrate using specifics and terminology for version 4.4.0 of OpenZeppelin’s contracts, although the details in the case of the Wormhole code were differently implemented, but worked in practice very similarly.

# Transparent Proxy Pattern (TPP) and Universal Upgradeable Proxy Standard (UUPS)

For the proxy method described above, there are some major issues. For example, when a proxy admin wants to call a proxy contract function `transferOwnership()` which shares a name with a function in the implementation contract, which one would be called? This sort of conflict can lead to unintended behaviors or even malicious exploitation.

There are a few solutions to avoid this issue. The first one is called the [Transparent Proxy Pattern](https://blog.openzeppelin.com/the-transparent-proxy-pattern/) (TPP). This method makes it so that all calls by a user always execute using the implementation contract’s logic. Calls by the proxy admin always execute using the proxy contract’s logic.

In a scenario where a user would call a function `transferOwnership()` which shares a name in both contracts, they can be sure that the logic from the implementation will be executed and not the proxy’s.

But what about the proxy’s admin? We would still want to be able to call the tproxy’s `transferOwnership()` function when needed. The solution to the whole issue is to assign one address as the admin to deploy and manage the proxy. This also ensures that, when a call isn’t made from the admin, the implementation contract is called instead. The following diagram shows an example of scenarios that could happen:

![img](https://miro.medium.com/v2/resize:fit:823/0*3TjsAv7nLKtD8yxp)

(source:https://i2.wp.com/blog.openzeppelin.com/wp-content/uploads/2018/11/Proxy_scenarios.png?resize=659%2C93&ssl=1)

However, this solution is not without its drawbacks. The transparent proxy needs additional logic in the proxy contract to manage all the upgradability functions, as well as the ability to identify whether the caller is the admin address. This involves reading the storage state, as well as executing additional logic which increases the execution cost of the contract. Therefore, TPP is not as gas efficient as UUPS.

Although TPP is still widely used, attention is starting to shift towards an alternative called UUPS.

The main difference between the two is which contract contains the upgrade logic. As we know, with TPP, the upgrade logic is located in the proxy contract itself. But with UUPS, the upgrade logic is in the *implementation* contract. Calling `upgradeToAndCall()` on the proxy delegates to the same function on the implementation. When `upgradeToAndCall()` executes on the implementation (in the context of the proxy), it changes the stored implementation address *in the proxy*. This works because UUPS implementations have access to all the storage of the proxy; they can overwrite the storage slot of the proxy contract where the proxy stores the address of the implementation.

This simple change alone makes proxy calls cheaper, because we only check that the caller is the admin *when an upgrade is requested*. We also don’t need to have logic for the case where there are two functions with the same name. The code generated automatically by Solidity in the implementation contract takes care of this for us. All authorization logic for upgradability is located within the implementation contract to guard against any unintended calls from happening.

Another distinction is how upgrade logic behaves. The following logic only applies to versions of UUPS prior to 4.4.2 version. More recent versions of the UUPS pattern in the OpenZeppelin library use a different safety mechanism. In order to ensure the new upgraded contract is also able to be upgraded in future, the `upgradeTo()` and `upgradeToAndCall()` functions also perform a “rollback” check to ensure that we don’t accidentally upgrade to a contract that can’t be upgraded further.

For a more in-depth analysis of differences between TPP and UUPS, we recommend you read OpenZeppelin’s [explanation](https://docs.openzeppelin.com/contracts/4.x/api/proxy#transparent-vs-uups).

If you want to read the newest changes to how UUPS upgrade logic works now, please read the PR for the issue [here](https://github.com/OpenZeppelin/openzeppelin-contracts/pull/3021#issuecomment-1088108044).

# OpenZeppelin UUPS Uninitialized Proxies Vulnerability

Before we look at the Wormhole vulnerability, we discuss the OpenZeppelin UUPS vulnerability, which is very closely related but affected many more deployed contracts. Although the code is different, the Wormhole vulnerability was detected by generalizing the pattern of the OpenZeppelin UUPS vulnerability.

As mentioned previously, when UUPS proxy contracts are deployed, the “constructor” is instead a regular Solidity function that exists in the implementation. The implementation provides the `initialize()` function. In many cases, developers also use upgradeable versions of the standard OpenZeppelin contracts which implement their own `initialize()` functions.

The below example is taken from OpenZeppelin’s [security advisory post](https://forum.openzeppelin.com/t/security-advisory-initialize-uups-implementation-contracts/15301).

![img](https://miro.medium.com/v2/resize:fit:875/0*xwRl5r3ycEikxV0x)

We can see the `initialize()` function calls `__Ownable_init`, which sets the owner of the implementation contract to the first person to call it. This is a key point.

Being an owner of the UUPS implementation contract means you can control the upgrade functions. In particular, the owner of the implementation can call `upgradeToAndCall()` directly on the implementation contract, instead of going through the proxy.

The vulnerability lies in how `upgradeToAndCall()` works internally. Apart from changing the implementation address to a new one, it atomically executes any migration/initialization function using `DELEGATECALL` and the data passed along it. If the initialization function of the new implementation executes the `SELFDESTRUCT` opcode, the `DELEGATECALL` caller will be destroyed. Normally, this would cause the proxy to be destroyed, but we don’t worry about this because only the admin of the proxy can call `upgradeToAndCall()`. However, what would happen if somehow we managed to get the implementation contract to do an `upgradeToAndCall()` *in its own context*?

This would cause the proxy contract to become useless, as it would forward all the calls to an empty address. Upgrading would no longer be possible, nor could anyone switch the upgrade mechanism to fix this, as the upgrade logic is hosted on the implementation contract by design of the UUPS pattern.

Here is a step-by-step guide of how a hypothetical attack could be performed:

1. The attacker calls `initialize()` on the implementation contract to become the owner. Remember the point above where `initialize()` makes the first person to call it the owner. Since nobody has called this function yet *in the context of the implementation*, the call works and makes the attacker the owner
2. Attacker deploys a malicious contract with a `selfdestruct()` function
3. The attacker calls `upgradeToAndCall()` on the *implementation contract* as an owner, and points it to the malicious selfdestruct contract
4. During the `upgradeToAndCall()` execution, `DELEGATECALL` is called from the implementation contract to the malicious selfdestruct contract using the context of the implementation contract (not the proxy)
5. `SELFDESTRUCT` is called, destroying the implementation contract
6. The proxy contract is now rendered useless

# Wormhole Vulnerability

Wormhole is also using a UUPS style proxy, where the upgrade logic resides in the implementation contract. The main difference is that the upgrade is guarded by Guardians that need to produce a multi-sig message stating the upgrade to the new implementation address is authorized.

The implementation contract found at [0x736d2a394f7810c17b3c6fed017d5bc7d60c077d](https://etherscan.io/address/0x736d2a394f7810c17b3c6fed017d5bc7d60c077d) was uninitialized after a previous bugfix had reverted the original initialization. That means an attacker would be able to pass their own Guardian set and proceed with the upgrade as a Guardian they controlled.

Once in control of the Guardian address, the attacker can use `submitContractUpgrade()` to force an upgrade attempt, causing a `DELEGATECALL` to an attacker-submitted address. If this address is a contract that executes a `SELFDESTRUCT` opcode, the implementation contract will be destroyed.

Let’s look at the code:

![img](https://miro.medium.com/v2/resize:fit:875/0*5n4T9bm77EImNXHZ)

The `submitContractUpgrade()` takes `bytes _vm` as an argument, which is a multi-sig message prepared by the Guardian which instructs the system to upgrade to the contract encoded in the message. After all safety checks have been completed, which the attacker passes because they are a valid Guardian, the function makes a call to `upgradeImplementation()`. This function makes the `delegatecall` to `initialize()` function.

The malicious implementation contract needs to contain a `SELFDESTRUCT` instruction in the `initialize()` function to destroy the current implementation contract.

The step-by-step guide to exploit is similar to the UUPS issue:

1. The attacker calls `initialize()` on the implementation contract to set the attacker controllable Guardian set
2. Attacker deploys a malicious contract with a `selfdestruct()` function
3. The attacker calls `submitContractUpgrade()` on the implementation contract and passes a signature signed by the malicious Guardian, which encodes the address of the malicious implementation contract for an upgrade
4. During the `submitContractUpgrade()` execution, `DELEGATECALL` is called from the regular implementation contract to the malicious implementation contract
5. `SELFDESTRUCT` is called, destroying the regular implementation contract
6. The proxy contract is now rendered useless

The Immunefi triaging team has also prepared a runnable Proof of Concept of the bug for educational purposes, which is available [here](https://github.com/immunefi-team/wormhole-uninitialized).

# Vulnerability Fix

Wormhole team fixed the issue in the [following transaction](https://etherscan.io/tx/0x9acb2b580aba4f5be75366255800df5f62ede576619cb5ce638cedc61273a50f).

The transaction called `initialize()` on the implementation contract and set the Guardians.

# A Word From Satya0x

“I am proud to have played a role in mitigating a serious vulnerability and a systemic threat to the ecosystem. I have great respect for the way the Wormhole team handled both the security response and the entire bug bounty process. The decision to award this bounty, and the existence of such a bounty in the first place, speaks volumes to the team’s commitment to users, the security of user funds, and the stability of the networks on which they operate.

I am also endlessly grateful for the work done by the Immunefi team. The importance of a knowledgeable, visible, and credibly neutral third party in blockchain security cannot be overstated. I hope and believe that Immunefi will continue to play a critical role in the industry.

The challenges of blockchain security represent an existential threat to the vision of the future we are building. If we fail to recognize and aggressively reduce systemic risk; if we fail to provide the transparency and tooling needed for users to make informed decisions; if we continue to condemn simple mistakes while praising Total Value Lost as the sole measure of success — we risk enabling the reemergence of the very power structures we seek to destroy.

The commitment to security shown by Immunefi and Wormhole is exactly what is needed if we are to build the decentralized future on firmer foundations than the present. It is imperative that we — as users, developers, and community members — demand more of the same.”

# Acknowledgments

We would like to thank satya0x for doing an amazing job and responsibly disclosing such an important bug. Big props also to the Wormhole team who responded quickly to the report and patched it.

If you’d like to start bug hunting, we got you. Check out the [Web3 Security Library](https://github.com/immunefi-team/Web3-Security-Library?utm_source=immunefi), and start earning rewards on Immunefi — the leading bug bounty platform for web3 with the world’s biggest payouts.

And if you’re feeling good about your skillset and want to see if you will find bugs in the code, check out the [bug bounty program from Wormhole.](https://immunefi.com/bounty/wormhole/)