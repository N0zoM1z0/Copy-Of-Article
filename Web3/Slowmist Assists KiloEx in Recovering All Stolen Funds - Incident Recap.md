On April 15, 2025, decentralized perpetual contract trading platform KiloEx suffered an attack, resulting in a loss of approximately $8.44 million. Following the incident, SlowMist immediately stepped in to analyze the attack and issued a security alert. Fortunately, with the proactive efforts of the project team and coordination from multiple parties including SlowMist, all stolen funds were successfully recovered after 3.5 days, bringing the incident to a satisfactory resolution.

![img](https://miro.medium.com/v2/resize:fit:744/1*EDd5ML1l24hATf-eaSbBKw.png)

https://x.com/SlowMist_Team/status/1911991384254402737

# Incident Overview

## **Vulnerability Analysis**

According to KiloEx’s analysis report, the attack stemmed from a flaw in the contract’s permission verification mechanism. The `TrustedForwarder` contract inherited OpenZeppelin’s `MinimalForwarderUpgradeable` contract. However, the `execute` method was not overridden in `TrustedForwarder`, making it accessible without authorization.

![img](https://miro.medium.com/v2/resize:fit:875/1*HIEuQ__Ouly0AgBTY_zbVw.jpeg)

![img](https://miro.medium.com/v2/resize:fit:875/1*vXz44iTHW88Z7vCjGkokQw.jpeg)

The attacker exploited this vulnerability by directly calling the original `execute` method in OpenZeppelin’s `MinimalForwarderUpgradeable`. The request executed by `execute` invoked the `delegateExecutePositions` function, which only verified whether `msg.sender == trustedForwarder` and did not check whether the actual initiator was a keeper. This allowed the attacker to bypass the permission checks. In a single transaction, the attacker opened a position at an extremely low price and then closed it at a much higher price, completing the exploit.

![img](https://miro.medium.com/v2/resize:fit:875/1*Po2U4ZBvtpUkViTzgzbNng.jpeg)

## Attack Timeline

The on-chain traces of the attack were clear, and the key timestamps were as follows:

**Apr-13–2025 23:31:59 UTC**
Hacker address `0x00faC92881556A90FdB19eAe9F23640B95B4bcBd` withdrew 1 ETH from Tornado Cash as initial funding.

![img](https://miro.medium.com/v2/resize:fit:875/1*2cHYVE43HP6PIn0A5H2Mog.jpeg)

https://etherscan.io/tx/0xa0fa4ab8ded0c07085d244e1981919b440f78b609e1cf8d7f8ee32d358dfdf46

**Apr-13–2025 23:39:11 ~ Apr-14–2025 01:21:36 UTC**
The hacker used multiple DeFi protocols and bridges to split and transfer the ETH from Tornado Cash to opBNB, Base, BSC, Taiko, B2, and Manta chains for gas fees needed to deploy attack contracts.

![img](https://miro.medium.com/v2/resize:fit:875/1*q1PBtAUigog1KFONfT7hyQ.jpeg)

https://dashboard.misttrack.io/address/ETH/0x00faC92881556A90FdB19eAe9F23640B95B4bcBd

**Apr-14–2025 18:27:43 ~ 19:36:49 UTC**
The hacker deployed attack contracts on opBNB, Base, BSC, Taiko, B2, and Manta chains.

![img](https://miro.medium.com/v2/resize:fit:875/1*dUfTZSYqzYURfV35yS2Ymw.jpeg)

https://opbnbscan.com/tx/0x657ab20a838043e36ab372a122804e07dbeca522b989899e27dee54b4c3f2971

**Apr-14–2025 18:52:27 ~ 19:40:49 UTC**
The hacker executed the attacks using the deployed contracts on the above chains.

![img](https://miro.medium.com/v2/resize:fit:875/1*V0RPV_cWSs-Hdq23EmvKZw.jpeg)

https://opbnbscan.com/tx/0x79eb28ae21698733048e2dae9f9fe3d913396dc9d93a0e30d659df6065127964

## Emergency Response

After the incident occurred, SlowMist immediately activated its Security Emergency Response service. A dedicated emergency team was assembled to work with KiloEx in mapping out the attack path and fund flow. Relying on its proprietary blockchain anti-money laundering and tracing platform [MistTrack](https://misttrack.io/) and its InMist threat intelligence network, SlowMist extracted attacker characteristics.

At the same time, SlowMist led the on-chain behavioral analysis of the incident, clarified the root cause of the vulnerability, and assisted KiloEx in multiple rounds of negotiation with the attacker to push for a fund return agreement.

![img](https://miro.medium.com/v2/resize:fit:875/1*rg7cZ6v1Bv7PyYc_Xt7kKA.jpeg)

https://etherscan.io/idm?addresses=0x00fac92881556a90fdb19eae9f23640b95b4bcbd%2C0x1D568fc08a1d3978985bc3e896A22abD1222ABcF%2C&type=1

With the collaboration of SlowMist and other stakeholders, KiloEx ultimately reached a 10% white hat bounty agreement with the attacker. The attacker subsequently returned all stolen assets to KiloEx’s official Safe multisig wallets at the following addresses:

- **opBNB:** `0xb1a95732ed3c75f7b1dc594a357f7a957e9baad2`
- **BNB, Base, ETH, Arbitrum:**`0xd38a22f5330f45162f13086d6ccbde0335c1ae9e`
- **Manta:** `0x0f9c71f888c1d263eab34d6d9360a3a45855365d`

The returned assets included not only USDT and USDC but also ETH, BNB, WBTC, DAI, and other tokens that had been exchanged by the hacker during the attack.

![img](https://miro.medium.com/v2/resize:fit:875/0*d9SyV-nI6rTTrboT)

https://t.me/misttrack_alert

The KiloEx team expressed its special thanks to SlowMist for its support during the incident.

![img](https://miro.medium.com/v2/resize:fit:875/0*eykq1lfpyMbDAU1H)

https://x.com/KiloEx_perp/status/1913168299292328115

Binance founder CZ also retweeted the relevant post, commenting: Glad to see the industry and the @BNBChain ecosystem working closely.

![img](https://miro.medium.com/v2/resize:fit:875/1*QvvfaSlWr57vScdrWIyKrQ.jpeg)

https://x.com/cz_binance/status/1913234751319859231

## Security Reinforcement

After the incident, KiloEx engaged SlowMist to conduct a security audit. SlowMist proposed two audit plans: the first involved conducting a comprehensive security audit lasting approximately 45 days before the platform resumes operation, ensuring the security of all components; the second focused on prioritizing a thorough review of protocol permissions to prevent similar attacks from recurring. Based on the results of this initial permissions audit, KiloEx would determine whether to relaunch the platform. Once the permission issues are resolved, SlowMist would then proceed with an in-depth audit of KiloEx’s overall logic and economic model, expected to take less than 45 days. Ultimately, taking into account community feedback and timeline considerations, KiloEx opted for the second plan — prioritizing the permissions audit followed by the comprehensive audit.

![img](https://miro.medium.com/v2/resize:fit:875/0*33q-aM9GZ7IAvSAU)

https://x.com/KiloEx_perp/status/1913542713825480863

# Conclusion

From swift response to full fund recovery, and from thorough audits to security upgrades, the joint emergency effort between KiloEx and SlowMist showcased the critical importance of collaboration between project teams and security firms. This incident serves as a reminder to all Web3 projects that security should not end with a pre-launch audit — real-time monitoring and post-incident response are equally essential.

Security is not a patch applied after launch; it is a core element throughout the full lifecycle of any Web3 project. SlowMist will continue to partner with more projects to build a full-circle security framework — prevention, detection, and response — to safeguard user assets and promote the healthy development of the industry.

For a more detailed analysis of the KiloEx security incident, please refer to the official KiloEx post-mortem report: https://medium.com/@KiloEx/kiloex-security-incident-root-cause-analysis-post-mortem-3d899caac08c.

## About SlowMist

SlowMist is a blockchain security firm established in January 2018. The firm was started by a team with over ten years of network security experience to become a global force. Our goal is to make the blockchain ecosystem as secure as possible for everyone. We are now a renowned international blockchain security firm that has worked on various well-known projects such as HashKey Exchange, OSL, MEEX, BGE, BTCBOX, Bitget, BHEX.SG, OKX, Binance, HTX, Amber Group, Crypto.com, etc.

SlowMist offers a variety of services that include but are not limited to security audits, threat information, defense deployment, security consultants, and other security-related services. We also offer AML (Anti-money laundering) software, MistEye (Security Monitoring) , SlowMist Hacked (Crypto hack archives), FireWall.x (Smart contract firewall) and other SaaS products. We have partnerships with domestic and international firms such as Akamai, BitDefender, RC², TianJi Partners, IPIP, etc. Our extensive work in cryptocurrency crime investigations has been cited by international organizations and government bodies, including the United Nations Security Council and the United Nations Office on Drugs and Crime.

By delivering a comprehensive security solution customized to individual projects, we can identify risks and prevent them from occurring. Our team was able to find and publish several high-risk blockchain security flaws. By doing so, we could spread awareness and raise the security standards in the blockchain ecosystem.