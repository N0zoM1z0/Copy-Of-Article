# **Introduction**

The Platypus Finance protocol was hacked on February 16, 2023, resulting in a loss of about $8.5m in stablecoin collateral to a logic error exploit. A flaw in the USP–Platypus’ stablecoin–-solvency check mechanism in the collateral holding contract allowed the attacker to borrow against flash loaned collateral and then withdraw it without paying the debt.

The attacker went on to swap the borrowed USP for existing liquidity in other stables inside Platypus pools. You can see the attack transaction [here](https://phalcon.xyz/tx/avax/0x1266a937c2ccd970e5d7929021eed3ec593a95c68a99b4920c2efa226679b430).

In this article, we will be analyzing the exploited vulnerability in the Platypus Finance contract, and then we’ll create our own version of the logic error exploit, testing it against a local fork. You can check the full PoC [here](https://github.com/immunefi-team/hack-analysis-pocs/tree/main/src/platypus-february-2023).

*This article was written by* [*gmhacker.eth*](https://twitter.com/realgmhacker)*, an Immunefi Smart Contract Triager*.

# **Background**

Platypus Finance is an AMM protocol on the Avalanche blockchain, and it’s specifically designed for exchanging stablecoins. They introduce the concept of asset liability management, where, upon withdrawal, liquidity providers can claim the exact amount of the same tokens they provided plus token emissions.

In the beginning of February 2023, the Platypus team [announced](https://medium.com/platypus-finance/platypus-recap-the-2022-2023-transition-503ca5483076) the introduction of USP, Platypus Finance’s new native over-collateralized stablecoin. Users can deposit LP tokens from Platypus pools to mint USP tokens, bringing more capital efficiency to the protocol.

**Root Cause**

Having a rough understanding of what the Platypus Finance protocol is and how USP works, we can dive into the actual smart contract code to explore the root cause vulnerability leveraged in the February 2023 hack. To do that, we need to dive into the code of the `MasterPlatypusV4` contract, Platypus’ Masterchef-like orchestrator. We’re particularly interested in the `emergencyWithdraw` function.

<iframe src="https://medium.com/media/01db511ca01f66c713c8bb62a55da5ee" allowfullscreen="" frameborder="0" height="777" width="680" title="Platypus Finance Hack Analysis 1.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 777px; position: absolute; left: 0px;"></iframe>

Snippet 1: *emergencyWithdraw* function in [*MasterPlatypusV4.sol*](https://snowtrace.deth.net/address/0xc007f27b757a782c833c568f5851ae1dfe0e6ec7)

The `emergencyWithdraw` function in the `MasterPlatypus` contract allows a user to withdraw their LP tokens from a given pool without caring about rewards. A function meant for “EMERGENCY ONLY” — a classic place for a hacker to lurk in.

The only check done by this function is whether the user is solvent or not, using `PlatypusTreasure.isSolvent`. That function uses an internal function called `_isSolvent`. Let’s peek into it.

<iframe src="https://medium.com/media/5f90bf27883e126439456a1e94f7428f" allowfullscreen="" frameborder="0" height="432" width="680" title="Platypus Finance Hack Analysis 2.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 432px; position: absolute; left: 0px;"></iframe>

Snippet 2: *_isSolvent* function in [*PlatypusTreasure.sol*](https://snowtrace.deth.net/address/0xbcd6796177ab8071f6a9ba2c3e2e0301ee91bef5)

Importantly, we know that `emergencyWithdraw` only cares about the boolean `solvent` parameter of the return data. This variable is true if the user’s debt is less than or equal to its USP borrow limit. In other words, a user is considered solvent if it has enough collateral to pay for its debt.

Going back to the `MasterPlatypus` contract, we see that only having this check is quite the problem. A user being solvent means that its collateral can pay for its debt. However, withdrawing the collateral should not leave unpaid debt! Using the `emergencyWithdraw` function, any user with debt can withdraw all its collateral LP tokens without paying for USP previously borrowed with that same collateral, leaving the protocol in debt.

# **Proof of Concept**

Now that we understand the vulnerability that compromised the Platypus Finance protocol, we can formulate our own proof of concept (PoC) of the exploit transaction. We will follow the hacker’s example and flash loan funds from AAVE so that we can borrow a good amount of USP.

We’ll start by selecting an RPC provider with archive access. For this demonstration, we will be using [the free public RPC aggregator](https://www.ankr.com/rpc/avalanche) provided by Ankr. We select the block number 26343613 as our fork block, 1 block before the hack transaction.

Our PoC needs to run through a number of steps to be successful. Here is a high-level overview of what we will be implementing in our attack PoC:

1. Flash loan 44M USDC from AAVE.
2. Deposit the borrowed USDC into a Platypus pool to get LP tokens
3. Deposit the LP tokens to the `MasterPlatypus` contract as collateral.
4. Borrow as much USP as possible against the LP collateral.
5. Execute `emergencyWithdraw` to get the LP collateral back without paying the debt.
6. Use the LP tokens to withdraw the USDC initially borrowed from AAVE. These funds will be used to pay back the flash loan at the end of the transaction.
7. Swap as much USP as possible for Platypus pool liquidity in the form of other stablecoins.

Let’s code one step at a time, and eventually look at how the entire PoC looks. We will be using [Foundry](https://book.getfoundry.sh/).

# **The Attack**

<iframe src="https://medium.com/media/681dba882ae1e3564cea34d37ed7cff1" allowfullscreen="" frameborder="0" height="1510" width="680" title="Platypus Finance Hack Analysis 3.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 1510px; position: absolute; left: 0px;"></iframe>

Snippet 3: *interfaces.sol*, with the interfaces we need

Let’s begin by creating our `interfaces.sol` file, where we will define the various functions we’re going to use on the protocol’s contracts and AAVE. We’re dealing with 4 different key contract ABIs: `AaveLendingPool`, `PlatypusPool`, `MasterPlatypusV4` and `PlatypusTreasure`.

The `AaveLendingPool` contract is the flash loan provider for our PoC. The `PlatypusPool` contract is responsible for the issuance of LP tokens upon supplying liquidity, as well as swapping different tokens present in the protocol pools. The `MasterPlatypusV4` contract allows the depositing of LP tokens to accrue rewards, and also implements the vulnerable `emergencyWithdraw` function. Finally, `PlatypusTreasure` allows the borrowing of USP against the supplied collateral.

Besides these interfaces, we will be using the standard ERC20 interface, which is provided in the `forge-std` library, and OpenZeppelin’s [EnumerableMap](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/EnumerableMap.sol), to simplify our PoC logic, given our lack of gas constraints.

<iframe src="https://medium.com/media/4eac31237e1e5cce139ab2c67112949f" allowfullscreen="" frameborder="0" height="1180" width="680" title="Platypus Finance Hack Analysis 4.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 1180px; position: absolute; left: 0px;"></iframe>

Snippet 4: Our *Attacker* contract without the attacking functions

As we can see from the above snippet, we define various different addresses on the Avalanche blockchain as constants in our contract. Specifically, we’re defining all the ERC20 tokens we’re going to use, AAVE’s pool and relevant Platypus contracts. We’re also going to create an `AddressToUintMap` variable–`tokenToAmount`–which will be used in the constructor to set tokens to amounts for swap. This is just a struct to help with the final swapping of USP for other stablecoin liquidity in the Platypus pools.

<iframe src="https://medium.com/media/3775f2843f6d03fa56183b75916c152c" allowfullscreen="" frameborder="0" height="234" width="680" title="Platypus Finance Hack Analysis 5.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 234px; position: absolute; left: 0px;"></iframe>

Snippet 5: the *attack* function

The entrypoint for our attack is the `attack` function. It just does one simple job–asking AAVE for a flash loan. We pass on the token we want to get, USDC, and the amount of funds, 44m. The AAVE lending pool will transfer those funds to us and then execute a callback function on our contract. This means AAVE expects us to implement a specific interface function called `executeOperation`.

<iframe src="https://medium.com/media/7306d1babe0e8a3cea5007959f33e00f" allowfullscreen="" frameborder="0" height="1642" width="680" title="Platypus Finance Hack Analysis 6.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 1642px; position: absolute; left: 0px;"></iframe>

Snippet 6: the *executeOperation* function

Once AAVE calls our callback function, we’re ready to use our newly received tokens to perform the attack logic. The functions we call will always do the transfer of tokens for us using `ERC20.transferFrom`, hence why we need to call `ERC20.approve` a bunch of times throughout our function. Let’s fit our logic into the steps we originally planned:

1. Flash loan 44m USDC. Well, we are now inside the callback executed by the AAVE lending pool, so we’re already done with that.
2. Deposit USDC into the Platypus pool to get LP tokens. We call `PlatypusPool.deposit` for this to happen. We specify the token address and the amount we want to deposit. We know these are USDC and 44m, but we also know AAVE will pass those values in the function inputs `asset` and `amount`, so we abstract that. You will see `block.timestamp + 1 minutes` being used a few times here for `deadline` inputs. This is a common input in such transactions, in essence to avoid the situation where validators or searchers hold signed transactions and execute them once certain market conditions are met. After the deadline is reached, the transaction will no longer work. Since we’re just building a PoC, the value is irrelevant, but we could potentially pass a delta of 1 minute.
3. Deposit the LP tokens to the `MasterPlatypus` contract. For this, we need to call `MasterPlatypusV4.deposit`. We need both the `poolId` and the amount of LP tokens we have, but we also need to approve the spending of those tokens, so naturally we need the address of the LP token. The amount of tokens is returned in the deposit from the previous step. We can find the LP token address by calling `PlatypusPool.assetOf(USDC)`, and we get the id of the pool by calling `MasterPlatypusV4.getPoolId(LPtoken)`. We have all the necessary information to call `deposit` on the `MasterPlatypus` contract.
4. Borrow USP. We will call *PlatypusTreasure.borrow*. Because we want to borrow as much USP tokens as our collateral allows, we need to check our borrowing limit. We query this value through the function *positionView* in the *PlatypusTreasure* contract. It will return a struct–*PositionView* which will have the information we want, so we just need to pass it to the *borrow* function.
5. Execute *emergencyWithdraw*–the most important part of our exploit, yet also the simplest one. All we need to do is to call` MasterPlatypusV4.emergencyWithdraw`.
6. Withdraw the original USDC. Since we have the LP tokens again in our possession, we can go to the `PlatypusPool` contract and redeem the underlying token–USDC–using the `withdraw` function.
7. Swap USP for other stablecoins–to make our PoC code more succinct, we loop over the `AddressToUintMap` data we originally stored. For each of those records, we call `PlatypusPool.swap` to try to swap specific quantities of USP for a hopefully good amount of other stablecoins. Noteworthy, both the specific amounts for each token and the *swap* function inputs are the same as the values used by the original hacker.

Ending our logic, we call `ERC20.approve` on the quantity of USDC that AAVE needs to transfer from us to pay back the flashloan. We are also required to return `true` in our callback function so that the flash loan doesn’t revert, as per the rules of the lending pool contract.

This completes the entire exploit. If we add Foundry logs, our PoC amounts to only 136 lines of code. If we run this PoC against the forked block number, we will get the following assets:

- USDC: 2,403,762
- USDCe: 1,946,900
- USDT: 1,552,550
- USDTe: 1,217,581
- BUSD: 687,369
- DAIe: 691,984
- USP leftovers: 33,044,533

# **Conclusion**

The Platypus Finance exploit was among the hacks that kicked off the year 2023. The attack stresses the importance of proper validation, most importantly when it comes to special functions that break the normal flow.

In this particular case, we’ve learned how crucial it is for such functions, originally meant for emergency situations, to have all the necessary checks implemented and well tested. The vulnerability broke the assumption that collateral cannot be fully withdrawn while one has debt in the market. Extensive testing against such a critical assumption should be done, with the help of sketching all possible state transitions in user flows.

In a surprising turn of events, less than 24 hours after the exploit, the Platypus team, with the help of [BlockSec](https://blocksec.com/), managed to accomplish a [reverse hack](https://phalcon.xyz/tx/avax/0x5e3eb070c772631d599367521b886793e13cf0bc150bd588357c589395d2d5c3) against the attacker, recovering about $2.5m of stolen funds. Yet another crazy tale only the DeFi world could ever have thought of.

This is what our entire PoC looks like.

<iframe src="https://medium.com/media/3855afef1026f3128dd05eb102e56d6a" allowfullscreen="" frameborder="0" height="3402" width="680" title="Platypus Finance Hack Analysis 7.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 3402px; position: absolute; left: 0px;"></iframe>

[All code.](https://github.com/immunefi-team/hack-analysis-pocs/blob/main/src/platypus-february-2023/Attacker.sol)