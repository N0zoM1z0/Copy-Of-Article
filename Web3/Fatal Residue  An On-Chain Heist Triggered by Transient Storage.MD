# Background

On March 30, 2025, the SlowMist MistEye security monitoring system detected an attack on the Ethereum-based leveraged trading project **SIR.trading** (@leveragesir), resulting in a loss of over **$300,000** in assets. The SlowMist security team conducted an in-depth analysis of the incident, and the findings are as follows:

![img](https://miro.medium.com/v2/resize:fit:875/0*l5vYUDeZNqlTBpYB)

https://x.com/SlowMist_Team/status/1906245980770746449

# Relevant Information

- **Attacker’s Address:**
  https://etherscan.io/address/0x27defcfa6498f957918f407ed8a58eba2884768c
- **Vulnerable Contract Address:**
  https://etherscan.io/address/0xb91ae2c8365fd45030aba84a4666c4db074e53e7#code
- **Attack Transaction:**
  https://etherscan.io/tx/0xa05f047ddfdad9126624c4496b5d4a59f961ee7c091e7b4e38cee86f1335736f

# Prerequisite Knowledge

Version 0.8.24 of Solidity, released in January 2024, introduced transient storage based on EIP-1153. This is a new data storage location designed to provide developers with a low-cost, temporary storage mechanism that remains valid only during a transaction.

Transient storage is a new storage type alongside storage, memory, and calldata. Its core characteristic is that data persists only during the current transaction execution and is automatically cleared after the transaction completes. Accessing and modifying transient storage is done using two new EVM instructions:

- TSTORE(key, value): Stores a 256-bit value at the specified key in transient storage.
- TLOAD(key): Retrieves a 256-bit value from transient storage using the specified key.

## Key Features

- Low Gas Cost: The gas cost for TSTORE and TLOAD is fixed at 100, which is equivalent to warm storage access. In comparison, standard storage operations (SSTORE) can cost up to 20,000 gas when writing from zero to a nonzero value and at least 5,000 gas for updates.
- Persistence Within a Transaction: Data stored in transient storage remains valid throughout the entire transaction, including all function calls and subcalls, making it suitable for scenarios requiring temporary state sharing across calls.
- Automatic Clearance: At the end of the transaction, transient storage is automatically reset to zero, eliminating the need for manual cleanup and reducing development overhead.

# Root Cause

The root cause of this exploit is that the value stored using `TSTORE` in a function was not cleared after the function call ended. As a result, the attacker was able to exploit this characteristic by crafting a specific malicious address to bypass permission checks and transfer tokens.

# Attack Steps

Step 1: The attacker first creates two malicious tokens, A and B, and then creates a pool for these two tokens on UniswapV3 and adds liquidity, where token A is the attack contract.

![img](https://miro.medium.com/v2/resize:fit:875/0*HdnTJ4LLJ0ry8mu7)

Step 2: The attacker then calls the initialize function of the Vault contract, using A as the collateral token and B as the debt token to create a leveraged trading market called APE-21.

![img](https://miro.medium.com/v2/resize:fit:875/0*EhQVdD10ffTMNWkb)

Step 3: Next, the attacker calls the mint function of the Vault contract, deposits the debt token B, and mints leveraged token APE.

![img](https://miro.medium.com/v2/resize:fit:875/0*JwjTYIbPHTG-rCc7)

In the mint function, we observe that when depositing the debt token B to mint the leveraged token, the parameter collateralToDepositMin must not be equal to 0. After that, it will use UniswapV3 to exchange token B into collateral token A and transfer it to the Vault, during which the address of the UniswapV3 pool created earlier by the attacker will be stored in transient storage for the first time.

![img](https://miro.medium.com/v2/resize:fit:875/0*3Wyn1fCzcMG7I-Rw)

When the UniswapV3 pool executes the swap, it will trigger a callback to the uniswapV3SwapCallback function of the Vault contract. It can be seen that this function first uses TLOAD to retrieve the value stored at the specified key 1 in the transient storage to verify if the caller is the UniswapV3 pool. Then, the debt token B is transferred from the minter address and the leveraged token APE is minted. Finally, the minted amount is stored for the second time in transient storage, at the specified key 1, to be used as the return value of the mint function. The amount to be minted is pre-calculated and controlled by the attacker, and its value is 95759995883742311247042417521410689.

![img](https://miro.medium.com/v2/resize:fit:875/0*uEY0Wd2a9970g17D)

![img](https://miro.medium.com/v2/resize:fit:875/0*XAazEFz9nABRmST8)

Step 4: The attacker then calls the safeCreate2 function of the Keyless CREATE2 Factory contract to deploy a malicious contract, which has the contract address 0x00000000001271551295307acc16ba1e7e0d4281, the same as the value stored in the second transient storage.

![img](https://miro.medium.com/v2/resize:fit:875/0*eTZfSVQ45lPLznuF)

Step 5: The attacker then uses this malicious contract to directly call the uniswapV3SwapCallback function of the Vault contract to transfer tokens.

![img](https://miro.medium.com/v2/resize:fit:875/0*0D0IV8ZdpS21bc8N)

Since the uniswapV3SwapCallback function verifies if the caller is the UniswapV3 pool by using TLOAD(1), and in the previous mint operation, the value at the specified key 1 in the transient storage was set to the minted amount 95759995883742311247042417521410689, which was not cleared after the mint function call, the UniswapV3 pool address is mistakenly retrieved as 0x00000000001271551295307acc16ba1e7e0d4281, which causes the caller verification to pass incorrectly.

![img](https://miro.medium.com/v2/resize:fit:875/0*MHqJjiFuVs4Ki09j)

Additionally, the attacker pre-calculates the amount of tokens to be transferred and sets the final minted amount to a specified value: 1337821702718000008706643092967756684847623606640. Similarly, at the end of this uniswapV3SwapCallback function call, the third transient storage will be used to store this value at the specified key 1, which must match the value of the attack contract’s (token A’s) address, 0xea55fffae1937e47eba2d854ab7bd29a9cc29170, in order for the caller check to pass.

![img](https://miro.medium.com/v2/resize:fit:875/0*TpxtCaduS_75H-4q)

Step 6: Finally, the attacker can directly use the attack contract (token A) to call the uniswapV3SwapCallback function of the Vault contract, transferring other tokens (WBTC, WETH) from the Vault contract to profit.

![img](https://miro.medium.com/v2/resize:fit:875/0*z9G-aL-A8afSf_CR)

# MistTrack Analysis

According to the analysis from [MistTrack](https://misttrack.io/), the blockchain anti-money laundering and tracking tool, the attacker (0x27defcfa6498f957918f407ed8a58eba2884768c) stole approximately $300,000 worth of assets, including 17,814.8626 USDC, 1.4085 WBTC, and 119.871 WETH.

![img](https://miro.medium.com/v2/resize:fit:875/0*rhdtP8PfVXhlod4X)

Among the stolen assets, WBTC was exchanged for 63.5596 WETH, and USDC was exchanged for 9.7122 WETH.

![img](https://miro.medium.com/v2/resize:fit:875/0*N6KHDH792PFWFOc6)

A total of 193.1428 WETH was transferred into Railgun.

![img](https://miro.medium.com/v2/resize:fit:875/0*IpkUKLJNflBN8P2O)

In addition, the attacker’s initial funds originated from 0.3 ETH transferred from Railgun.

![img](https://miro.medium.com/v2/resize:fit:723/0*ZC1oUPB0GlTXGdcJ)

# Summary

The core of this attack lies in the fact that the attacker exploited the transient storage feature in the project, where the stored values are not immediately cleared after a function call but persist throughout the entire transaction. This allowed the attacker to bypass the callback function’s permission checks and profit. The SlowMist Security Team recommends that project teams immediately clear the values in transient storage after the function call by using TSTORE(key, 0) according to the business logic. Additionally, the project’s contract code should undergo enhanced audits and security testing to prevent similar incidents from occurring in the future.

# About SlowMist

SlowMist is a blockchain security firm established in January 2018. The firm was started by a team with over ten years of network security experience to become a global force. Our goal is to make the blockchain ecosystem as secure as possible for everyone. We are now a renowned international blockchain security firm that has worked on various well-known projects such as HashKey Exchange, OSL, MEEX, BGE, BTCBOX, Bitget, BHEX.SG, OKX, Binance, HTX, Amber Group, Crypto.com, etc.

SlowMist offers a variety of services that include but are not limited to security audits, threat information, defense deployment, security consultants, and other security-related services. We also offer AML (Anti-money laundering) software, MistEye (Security Monitoring) , SlowMist Hacked (Crypto hack archives), FireWall.x (Smart contract firewall) and other SaaS products. We have partnerships with domestic and international firms such as Akamai, BitDefender, RC², TianJi Partners, IPIP, etc. Our extensive work in cryptocurrency crime investigations has been cited by international organizations and government bodies, including the United Nations Security Council and the United Nations Office on Drugs and Crime.

By delivering a comprehensive security solution customized to individual projects, we can identify risks and prevent them from occurring. Our team was able to find and publish several high-risk blockchain security flaws. By doing so, we could spread awareness and raise the security standards in the blockchain ecosystem.