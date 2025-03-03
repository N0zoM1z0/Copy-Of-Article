# Summary

On Nov 15th, an anonymous whitehat submitted a critical logic error vulnerability to the Beanstalk protocol via Immunefi, demonstrating a direct theft of assets from the accounts that were approved for the Beanstalk contract. The [Beanstalk Immunefi Committee](https://docs.bean.money/almanac/governance/beanstalk/bic-process) estimated that the vulnerability could have resulted in a loss of up to $3.1 million in funds, as $537k worth of BEAN tokens and $2.5 million non-BEAN assets were at risk.

Fortunately, thanks to the whitehat’s swift discovery and report via Immunefi, the [Beanstalk Community Multisig](https://docs.bean.money/almanac/governance/beanstalk/bcm-process) was able to quickly remediate the issue, and no user funds were lost.

The whitehat was awarded 181,850 BEAN tokens ($181,850 USD) through Beanstalk’s bug bounty program on Immunefi.

# What is Beanstalk?

Beanstalk is a [permissionless stablecoin protocol](https://docs.bean.money/almanac) built on Ethereum. It aims to create a monetary basis for a rent-free economy on the Ethereum network through its native fiat currency, the stablecoin called Bean.

Beanstalk’s primary objective is to incentivize independent market participants to sustainably cross the price of 1 Bean over its dollar peg. To achieve this, Beanstalk focuses on providing a stablecoin that does not compromise on decentralization, does not require collateral, has competitive carrying costs, and trends towards increased stability and liquidity.

# Vulnerability Analysis

The whitehat reported the vulnerability in one of the facet libraries which the Beanstalk diamond proxy contract was using. The library is available [here](https://etherscan.io/address/0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5#code).

A diamond proxy is a modular smart contract system that can be upgraded or extended after deployment without any significant size constraints. This system operates by using external functions provided by contracts, which are known as facets. The facets are independent contracts that can access shared internal functions, libraries, and state variables.

More information on how diamond proxy works can be found [here](https://eips.ethereum.org/EIPS/eip-2535).

In this instance, the Beanstalk diamond proxy was utilizing the Token Facet, which is responsible for handling the logic of farming, such as querying the internal balances of accounts, approving tokens, and transferring tokens. The vulnerability was discovered in the `transferTokenFrom()` function of the Token Facet, which transfers tokens from the sender to the recipient.

This Token Facet contract can be viewed at the following [address](https://etherscan.io/address/0x8D00eF08775872374a327355FE0FdbDece1106cF#code).

The facets used by the Beanstalk Diamond Proxy can be explored on[ Louper](https://louper.dev/diamond/0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5?network=mainnet), an interface for inspecting Ethereum diamond proxy facets. Using this interface, we can easily find the TokenFacet contract.

<iframe src="https://medium.com/media/c572322cc7fbf989a0605b81dea3205e" allowfullscreen="" frameborder="0" height="652" width="680" title="Beanstalk Logic Error Bugfix Review 1.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 652px; position: absolute; left: 0px;"></iframe>

Snippet 1: [TokenFacet : transferTokenFrom()](https://etherscan.io/address/0x8d00ef08775872374a327355fe0fdbdece1106cf#code)

The Token Facet has a function called `transferTokenFrom()`, which transfers tokens from a sender to a recipient. This function has an additional argument for transfer modes (`fromMode`, `toMode`), which can be either EXTERNAL or INTERNAL.

1. The INTERNAL mode updates the internal token balance of the account in the LibBalance facet, which contains all of the accounting logic of the contract.
2. The EXTERNAL mode transfers the amount of tokens directly from the sender to the recipient using the `token.safeTransferFrom` call.

The vulnerability arises due to the fact that the `transferTokenFrom()` function only checks the allowance for the internal balance for the `msg.sender`, but not for external transfers.

However, if `msg.sender` calls the function with the EXTERNAL transfer type, the allowance is not checked and the `LibTransfer.transferToken(…)` is involved, which calls the `token.safeTransferFrom(victim,attacker,amount)` and the attacker would receive the funds from the victim’s account who has already granted approval to the Beanstalk contract for the transfer of the given token.

It should be noted that this vulnerability only affected externally owned accounts (EOA) or contracts that had authorized the Beanstalk contract to handle their tokens using ERC20 `approve()`.

<iframe src="https://medium.com/media/40fa7eff104dda67dbe8a6c126a5eef3" allowfullscreen="" frameborder="0" height="410" width="680" title="Beanstalk Logic Error Bugfix Review 2.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 410px; position: absolute; left: 0px;"></iframe>

Snippet 2: [LibTransfer: transferToken()](https://etherscan.io/address/0x8d00ef08775872374a327355fe0fdbdece1106cf#code)

# Proof of Concept (PoC):

The Immunefi team prepared the following PoC to demonstrate the vulnerability.

<iframe src="https://medium.com/media/d3b801ac9f5d8e2acbd8f77c8aa0bcfb" allowfullscreen="" frameborder="0" height="3395" width="680" title="Beanstalk Logic Error Bugfix Review 3.sol" class="fs n gi dw bh" scrolling="no" style="box-sizing: inherit; top: 0px; width: 680px; height: 3395px; position: absolute; left: 0px;"></iframe>

Snippet 3: Full PoC

![img](https://miro.medium.com/v2/resize:fit:875/0*19-rfi9UTjznP1CC)

Output of running Foundry PoC

# Funds at Risk

The total funds at risk due to this vulnerability was about $3,087,655. The following table is the composition of multiple assets and the value in dollars at risk.

![img](https://miro.medium.com/v2/resize:fit:875/1*5vfe8utpTPizJoO_RH8-sg.png)

[Source](https://github.com/BeanstalkFarms/Beanstalk-Governance-Proposals/blob/master/bip/ebip/ebip-5-remove-transfertokenfrom-function.md)

# Vulnerability Fix

The Beanstalk team took prompt action after the whitehat reported the vulnerability in the Beanstalk Market contract. An [EBIP](https://github.com/BeanstalkFarms/Beanstalk-Governance-Proposals/blob/master/bip/ebip/ebip-5-remove-transfertokenfrom-function.md) (Emergency Beanstalk Improvement Proposal) was submitted to remove the vulnerable function `transferTokenFrom(…)` until a suitable fix could be implemented.

To address the issue, the Beanstalk Community Multisig removed the `transferTokenFrom(…)` functionality and introduced a new function, `transferInternalTokenFrom(…)`, which will always transfer with INTERNAL `fromMode`.

The changes were made in accordance with the BIP. They were implemented in EBIP-6 and the Facet contract upgrade, as outlined in the [fixed GitHub pull request](https://github.com/BeanstalkFarms/Beanstalk/pull/146/files).

# Acknowledgements

We would like to thank the anonymous whitehat for doing an amazing job and responsibly disclosing such an important bug. Big props also to the Beanstalk Immunefi Committee who responded quickly to the report and patched it.

If you’d like to start bug hunting, we got you. Check out the [Web3 Security Library](https://github.com/immunefi-team/Web3-Security-Library?utm_source=immunefi), and start earning rewards on Immunefi — the leading bug bounty platform for web3 with the world’s biggest payouts.

And if you’re feeling good about your skillset and want to see if you will find bugs in the code, check out the bug bounty program from [Beanstalk](https://immunefi.com/bounty/beanstalk/).