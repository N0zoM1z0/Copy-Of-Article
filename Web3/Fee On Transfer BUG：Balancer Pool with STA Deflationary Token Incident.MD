At least two Balancer multi-token pools were drained for more than $500k today by using a vulnerability in context of AMM and token with deflationary model.

> Balancer Pools are multi-dimensional Uniswap-like automatic market makers (AMM). They contain multiple assets and keep them balanced in certain proportions by creating arbitrage opportunity for swapping any assets by forming prices by special formula.

The hacker sent a [complex transaction](https://etherscan.io/tx/0x013be97768b702fe8eccef1a40544d5ecb3c1961ad5f87fee4d16fdc08c78106) to Ethereum Mainnet which caused an attack on [one of the Balancer Pools](https://pools.balancer.exchange/#/pool/0x0e511Aa1a137AaD267dfe3a6bFCa0b856C1a3682). A several minutes later [second transaction](https://etherscan.io/tx/0xeb008786a7d230180dbd890c76d6a7735430e836d55729a3ff6e22e254121192) happened and also drained another Balancer Pool. We analysed what happened and created the following report.

The attacker used a smart contract to automate multiple actions in a single transaction. At first step, the attacker **got a FlashLoan of 104k WETH** **from dYdX**. These funds were used to **swap WETH to STA token back and forth 24 times** which drained STA balance from the pool and it became 1 weiSTA (0.000000000000000001 STA). It was possible because Balancer Pool contract keeps track of token balances in the contract and STA token had a deflationary model with transfer fee of 1% charged from a recipient, thus resulted in `transfer()` and `transferFrom()` misbehaviour. So every time the attacker swapped WETH to STA, the Balancer Pool received 1% less STA than was expected.

As the next step, the attacker **swapped 1 weiSTA to WETH multiple times**. Due to STA token transfer fee implementation, the pool never received STA but released WETH regardless. The same step was repeated to drain WBTC, SNX and LINK token balances from the pool.

As the final step, the attacker **repaid FlashLoan of 104k WETH to dYdX**. The hacker rapidly increased his share in Balancer Pool by depositing a few weiSTAs. Then he swapped collected Balancer Pool token to 136k STA via Uniswap V2, and then he swapped 136k STA to 109 WETH again. All the stolen funds were transferred to the following address [0xbf675c80540111a310b06e1482f9127ef4e7469a](https://etherscan.io/address/0xbf675c80540111a310b06e1482f9127ef4e7469a).

In the result of the attack Balancer Pool lost nearly to $500k, while the hacker got almost $425k worth of tokens:

- 455 WETH *($100k worth)*
- 2.4m STA *($100k worth)* and converted it to 109 WETH *($25k worth)*
- 11.36 WBTC *($100k worth)*
- 60.9k SNX *($100k worth)*
- 22.6k LINK *($100k worth)*

The person behind this attack was very sophisticated smart contract engineer with extensive knowledge and understanding of the leading DeFi protocols. The attack was organized and well prepared in advance. Additionally he used [Tornado Cash](https://medium.com/u/f5afbb39f1c0?source=post_page---user_mention--a8f7131c980e---------------------------------------) to get initial funds, which were spent for deploying smart contracts and performing the attack, hence hiding his source of Ether.