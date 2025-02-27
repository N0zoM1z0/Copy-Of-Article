# Part 1: On DEXs

### dromos.eth

15 min read·August 17, 2024

[1 Collected](https://paragraph.xyz/@dromos/collectors/CND0rxcFuF6NNmpwi4eo)

[Collect](https://paragraph.xyz/@dromos/nft/CND0rxcFuF6NNmpwi4eo)

# AMM DEXs: the foundations of DeFi

## How DEXs work

Decentralized exchanges (DEXs) are a wholly new implementation of liquid markets and a fundamental primitive of entire Decentralized Finance (DeFi) ecosystems. Unlike traditional centralized exchanges, which use a single entity to facilitate transactions and hold user funds, DEXs leverage automated market-makers (AMMs). AMMs allow trustless and permissionless token swapping.

DEXs can play a pivotal role in growing the onchain ecosystem around them by offering several key advantages when compared to traditional exchanges: they allow users to create and transact on markets permissionlessly, they provide essential always-on liquidity for other DeFi protocols to leverage programmatically, and they provide a real-time source of truth on token prices.

## What DEXs do

### Permissionless market creation

Users can permissionlessly create markets for a wide variety of tokens on a DEX. Users can then deposit tokens into these markets, facilitating token swaps without gatekeepers.

On a basic AMM, a token swap looks like this: to swap USDC for WETH, a trader sends USDC to a smart contract wallet (pool) containing both USDC and WETH, getting back WETH. There’s now a little more USDC and a little less WETH in the pool, and because the pool is designed to always have equal values of both assets, WETH is now a little more expensive relative to USDC. More assets in the pools means traders can swap larger amounts without incurring major price changes (slippage)—the ratio of USDC to WETH changes less for the same-sized trade in a larger pool.

![post image](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2F50c8d45127aee93e81b45edd7a73ff48.webp&w=3840&q=75)

### DeFi centrality

DEXs are central to DeFi because they enable frictionless, programmatic swaps. This type of swap is often needed by other DeFi functions. For example, when lending protocols need to programmatically sell undercollateralized borrowed positions, DEXes provide an always-on buyer allowing them to sell painlessly and on demand.

### Price discovery

Users need token price history to do almost anything in DeFi. When DEXs are adequately liquid and active with swaps and arbitrage activity, they provide accurate pricing information on tokens, allowing oracles, automated trading, and other functions that rely on these data to operate correctly.

## What DEXs need

**Every DEX has the same goal as a marketplace: offer the best trade execution with the most liquidity, so traders use that DEX and not other modes of swapping.** It’s not quite a zero-sum, winner-take-all game, but competition is real and has to be acknowledged.

For this marketplace to work, traders need LPs to put up enough assets to allow low-slippage trades (buying or selling more without moving the price too much). And LPs need compensation for the high risk of providing liquidity in an AMM. *To understand why, articles on Impermanent Loss are instructive. Providing liquidity (“or LPing”) is risky, and LPs need compensation for their risk.*

DEXs’ primary challenge is to solve this bootstrap problem. This is a difficult problem as an LP; it’s not easy to make it worth your while as an LP, and so DEXs need to attract large capital providers to put up the capital to enable trades.

### DEX monetization, tokens, and economics

Although DEXs don’t *need* any way to monetize or fund their operations, building and operating a DEX are often done with some payoff in mind, especially given the risk of doing so in a hypercompetitive environment with enormous potential for value generation. Because traders benefit from the service, trading fees are often charged, usually at some percentage of trading volume.

Often these DEXs will launch their own tokens. DEX tokens have several potential uses that can benefit builders and participants. The utility of these tokens can make a significant difference in a DEX’s economic structure.

A helpful framework for understanding a DEX is to view it as an economy. Generally speaking, **a DEX economy relates to how its varied counterparties—traders, LPs, tokenholders, and contributors—interact.** Ideally, these counterparties organically help the DEX operate sustainably and competitively toward the goals of deep liquidity and high trading volume. How a DEX’s generated value is distributed between these counterparties, for example, tends to determine how the DEX is organized and how resistant it is to competition.

**As a token marketplace, a DEX is one of the only onchain products so far with an undeniable product-market fit**. People will pay to trade, and organizations will pay to attract liquidity to certain pools or to ecosystems. This means that there’s a lot of generated value to distribute between stakeholders. Our view is that in a decentralized system such as this one, distributing this value correctly is essential to sustaining a DEX’s market position.

# How major DEXs solve the bootstrapping problem

## Uniswap: the first superstar DEX

### Innovations: new AMMs and a foolproof compensation structure

The undisputed leader in AMM development, Uniswap developed and popularized two key AMM structures still overwhelmingly used today.

#### **vAMM**

This is typically known as Uniswap V2, which allows for price discovery at infinite price ranges. LPs provide liquidity at all potential prices, which are calculated using the amount of tokens available on each side of a pool.

#### **Concentrated liquidity**

Also known as V3, this AMM allows users to define price ranges for which they are willing to provide liquidity. This more flexible structure allows LPs to provide very deep liquidity around a specific price, set buy-sell orders at specific prices, or scale in and out of their positions. It is typically regarded as a much more capital-efficient structure than a vAMM because more of LPs’ capital can be allocated to price ranges where it will actually be used.

![Source thread: https://tinyurl.com/veloclamm](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2Fd25916f5d391520135ace3094803cbc3.png&w=3840&q=75)

There is also more risk and overhead associated with this structure; if the price moves outside of LPs’ defined ranges, their liquidity ceases to be used, and the risk of losses increases, so LPs frequently have to update their positions. This challenge has often left V3 LPing to be dominated by professional market makers and various third parties that will, for a fee, manage individuals’ LP positions for them.

### Uniswap’s approach to bootstrapping and its challenges

To incentivize LPs, Uniswap charges trading fees and directs 100% of them to LPs. In effect, LPs have to produce their own returns; they earn their share of whatever is generated by the protocol as they participate.

To many, this is an economically sound model, one that doesn’t require any outside incentivization or incentive token; indeed, initially Uniswap didn’t have any native tokens.

There are a few limitations to this model, however, detailed below.

**Value generated by LPs is capped by volume and isn’t robust to liquidity mining**

Compensating LPs with 100% of protocol fees means that under this model, LPs’ available earnings are capped: the most LPs can earn at any given point are fees from volumes occurring in that moment.

So if LPs’ returns are capped, how do you compete with Uniswap? Give LPs the opportunity to earn more than just their share of fees. Sushiswap was created to do just this, exploiting a concept called *liquidity mining*. With liquidity mining, LPs get *not just* volume fees but also a bonus token—a little extra. So when Sushiswap said “come to us and we’ll give you this bonus”, LPs swarmed there, to the tune of almost $1B in capital. [Within a week of this program, Sushi had taken over half of Uniswap’s capital.](https://www.gemini.com/cryptopedia/sushiswap-uniswap-vampire-attack)

**Uniswap’s fee structure means that LPs are** ***highly*** **sensitive to Uniswap’s ability to win trades and generate volume.** Attracting capital away from Uniswap puts it at great risk: as LPs leave, Uniswap’s pools generate less volume than previously, which lowers the potential for generated fees, which means remaining LPs earn less, which causes them to leave, kicking off a downward spiral.

This doesn’t mean that liquidity mining is itself a durable play. A protocol using liquidity mining on top of the LP fee compensation model is itself susceptible to other protocols running comparable incentive programs. This has resulted in a rotation of capital across various protocols and ecosystems giving away value to temporarily attract capital, which inevitably leaves for the newest thing.

**Value is disproportionately given to LPs**

It’s no surprise that Uniswap’s success as a marketplace has generated enormous value in fees, [to the tune of $1B annually since 2021](https://defillama.com/fees/uniswap). The collective efforts behind this success were provided by a wide range of stakeholders—traders, LPs, the protocol developers, projects with listed tokens, and layer ecosystems. What may be surprising, though, is that *all of this value goes right to the LPs*, not to any of the other participants. As a business, this could make some sense; the LPs, after all, are providing the capital that allows all of the other parties to benefit from it.

However, there is evidence to suggest that this type of distribution isn’t the best way to keep all parties bought into this system. In any case, this fee distribution might change: other interests are beginning to demand more of the value generated, which puts LP returns under pressure and leaves the protocol vulnerable to competition.

For example: to build Uniswap, the development company, [Uniswap Labs, raised investor money](https://techcrunch.com/2022/10/13/uniswap-labs-raises-165-million-in-new-funding/), offering the promise of future monetization. However, because LPs receive all of the volume fees generated by the protocol, Uniswap Labs’ equity investors do not receive any returns from core protocol activities, as of yet.

As a result, Uniswap has sought new ways to generate revenue, most notably the [introduction of front-end fees](https://support.uniswap.org/hc/en-us/articles/20131678274957-What-are-Uniswap-Labs-fees). Here, users making swaps on Uniswap’s own site will pay volume fees directly to Uniswap Labs.

What this means, however, is that a group of users now face two layers of fees: the base trading fees to LPs, and now even more fees going to Uniswap Labs. Much of the imagined value added in the future may be reaped in this manner by Uniswap Labs, the primary entity developing on top of Uniswap.

**There’s nobody at the wheel**

Uniswap as a protocol was designed to be effectively headless: it is deployed on a blockchain, and LPs determine how it is going to be used by choosing where to provide liquidity. It’s a perfectly fine model in a competitive vacuum or in an ungoverned ecosystem such as Ethereum Mainnet.

But because LPs are the only party to gain from its use, that’s a lot of value left on the table that isn’t being picked up by the other stakeholders. These parties could have other priorities as to how to manage such a fundamentally central, essential piece of DeFi infrastructure, and their contribution could be beneficial to Uniswap’s success.

The inability to steer Uniswap can be frustrating in many ways. For example, projects seeking to get liquidity on their native token have no way to efficiently convince LPs to help. Ecosystem teams need a forcing function to migrate from one stablecoin to another. For liquidity, projects need VC firms to put up capital, or they have to apply for some liquidity mining grants.

Autonomous market-based systems can represent a a major step forward from permissioned ones, but their functional lifespan increases when all of the participating stakeholders can push these systems toward a durable equilibrium. Governance tokens are ostensibly a way for these different parties to do so, but their application across DeFi, including Uniswap, has often been suboptimal.

**The UNI token is near useless—and that’s the best-case scenario**

[Uniswap introduced UNI](https://blog.uniswap.org/uni) for two reasons: to enable the compensation of Uniswap Labs and its investors, and to provide *additional* incentivization to LPs to fend off Sushiswap (yes, people forget that it was originally used for liquidity mining—confirmation of the weaknesses of the model identified above).

For several years, UNI has acted as a governance token with two major functions. The first is to distribute the large UNI allocation granted to the Uniswap Foundation (UNI’s DAO). The second is eventually to activate the [exhaustively discussed](https://www.gauntlet.xyz/resources/uniswap-protocol-fee-report) fee switch.

The thing is, no UNI holders currently get any value out of holding UNI. As a result, it is prohibitively expensive and risky to accumulate the token for control of the DAO treasury, which could theoretically be used to direct LPs in a way that best meets the market. The makup of Uniswap’s governance exhibits little of this.

So what has UNI in fact been good for? For Uniswap Labs to fund its operations by selling it, and for the Uniswap Foundation to administer a grants program while operating its own budget of millions. The Uniswap Foundation alone has [sold](https://gov.uniswap.org/t/uniswap-foundation-summary-q1-2024-financials/24008/2) [approximately $60mm](https://gov.uniswap.org/t/governance-proposal-complete-initial-funding-of-the-uniswap-foundation/22020/1) worth of UNI through brokers to fund its operations and grants.

![The passed governance budget creating the Uniswap Foundation. Source: Messari](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2F5842d031676c0bf0d4fc01447419bdcf.webp&w=3840&q=75)

Activating the fee switch would certainly do more to get stakeholders involved and maintain the fundamental value of the UNI token. Although there have been a range of theories proposed as to why this hasn’t occurred, less discussed is the fact that fee distribution is a zero-sum question: if the UNI token gets more fee revenue, that means LPs get less. And as discussed above, LPs can’t tolerate less and will seek better opportunities.

So Uniswap is in a bit of a limbo. No fee switch, UNI remains limited in value, and the DEX economy remains rudderless. And should the Uniswap Foundation activate the fee switch, the entire system’s liquidity is at risk of being sapped by a competitor.

## Curve: a decentralized, autonomous business

### Innovations: real governance, real value accrual

Curve first emerged as an alternative AMM focused on stablecoin swaps, which are difficult to maintain on Uniswap’s v2 pool. The contributing team have since iterated on their AMM models and provided genuine, technological advancements.

More relevant to our topic here—how to bootstrap and sustain a DEX—are Curve’s economic innovations, which expanded the utility of a DEX’s native token.

**CRV - a token you can run a DCF on**

One change by Curve handled both the problem of capped LP earnings and the inability to get revenue share without compromising the DEX economy. In addition to giving the LPs fees, give them your native token—but also give some of the fees back to native tokenholders. This structure allows LPs to potentially get more than just whatever they generate in fees—and CRV holders could get some piece of fees generated.

**veCRV - a token you can run a business on**

Designing a new stakeholdership, the tokenholders—is tricky. A DEX has only so much value to generate, and if you’re going to reward some party other than LPs with fees, they should be people who have a real stake in the protocol’s success.

How do you enforce this? Get tokenholders to commit to holding their tokens for some amount of time. In return, give them a cut of fees. Once you have locked your tokens, you are *in it.*

Curve launched in 2020. The fact that there are still many, many die-hard Curve fanatics today is no accident; they are people who have committed themselves to the ecosystem.

**Voting and incentivization**

LPs up to this point always faced a chicken-and-egg problem: how do you attract LPs and TVL to the kinds of pools that will best meet the market’s demand for tokens? Without any direction, LPs will choose to work with certain pools for any number of reasons—but what’s good for LPs might not be best for meeting market demand over time, and it might not be best for the growth of other participants in the surrounding ecosystem.

Because LPs on Curve receive some portion of fees and CRV emissions, it becomes necessary to determine how much CRV each pool is going to get to reward LPs, and it would be very hard to do so programmatically.

Curve turned this challenge into an opportunity, handing this responsibility to veCRV holders. The idea was that veCRV holders, being committed to the ecosystem, are going to reward pools they assume will be popular to trade on because they stand to get more fee distributions over time. This was a big step forward in allowing market forces to optimize the DEX.

**Discovering a whole new revenue stream**

Arguably the most pivotal innovation made by the Curve ecosystem came from the insight that getting veCRV holders to vote on a pool has value. These votes are something that token issuers will pay a lot for.

This insight, which led to the implementation of voting incentives, created an entirely new marketplace, a liquidity marketplace, which can bootstrap itself almost from scratch.

![Vote incentive marketplace, an enduring revenue source. Source: Llama Airforce](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2Fef83eb52c0d59551c6e90ff653861d7b.webp&w=3840&q=75)

It was a massive hit. New stablecoin issuers such as [Abracadabra](https://x.com/danielesesta/status/1445138184443252752) and [Terra](https://x.com/ReliableNarr/status/1464012072904060941) deposited enormous capital into the Curve ecosystem, hoping to get more LPs to service their pools. LPs and veCRV holders benefited tremendously from these deposits. The hyped “Curve Wars” resulted from a number of protocols competing to acquire veCRV and the rewards it offered.

This was a huge shot in the arm for DEXs and for DeFi. If rewards to AMM LPs now carry the option of a cut of new revenue streams, other DEXs will have a harder time drawing them away. But more generally, this development expanded the definition of a DEX away from just being an AMM. Specifically, if a DEX and its tokenholders are able to get access to new revenue streams, imagine what else is possible. Curve’s introduction of crvUSD, clearly thinking along these lines, is just the start.

What’s possible is something we’ll leave to the next installment of this series.

### Issues

**A business with many interests**

It’s indisputable that Curve forever changed the shape of both DEXs and DeFi through its radical approaches. However, holding it back have been challenges that are ancient in nature: stakeholder issues.

**Hostile takeovers**

Curve’s structure has left it fragile to behavior from participants rationally acting in their self-interest, ultimately stressing sustainability.

We can trace this back to the Curve Wars, which, despite a large amount of hype, ended almost immediately. Why? Because a handful of entities already scooped up the vast majority of CRV, particularly Convex. Most of the protocol’s value had been accounted for, making it much more difficult to bootstrap, except at great cost, a sizeable position in a hot liquidity engine.

![Top holders of veCRV. Source: https://www.defiwars.xyz/wars/curve](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2F323379ed5118df287269dc017d5c4c78.webp&w=3840&q=75)

Three protocols own 75% of veCRV. Each of these protocols charges a “performance fee” of between 15-20%, which goes to various other parties, team treasuries, or incentivization of particular pools. Regardless of what these protocols did, users seeking to participate in Curve’s ecosystem thus are likely to have to interact with it through these other protocols, which may have interests that are not in line with the success of the protocol’s health.

#### Overuse of unaligned contractors limiting an organization’s value generation

Convex Finance was digital alchemy, answering the question: what if you could make this supposedly locked veCRV position liquid and economically useful? It was a revelation that spawned several new features and an enormous amount of speculative interest, and Curve’s structure gave Convex participants a good deal; get the kind of real yield generated through the two revenue streams, but with greater capital efficiency because you’re not locking up capital to do so.

This development arguably undermined Curve in three ways:

1. It broke the incentive alignment that you get with veCRV holders being locked into the system; although early lockers could (and did) remain involved, late entrants were free to enter and exit through the use of Convex’s liquid tokens.
2. It centralized agency and various kinds of risk to an entirely new protocol, which effectively ceded control. The introduction of Convex fragmented the community into different classes of stakeholders, some not wholly aligned with veCRV holders.
3. It atomized user experience: some functions were now outsourced to new UIs, splitting protocol participants across several different sites.

More broadly, this set a precedent of several new follow-on protocols piggybacking on Convex—each with their own fee cut, each with new centralization and security risks.

This has been done in the name of “composability”: the idea that new builders can easily add new features to an existing system and generate new value for the overall system. But what are veCRV holders getting out of this? An increasingly eaten-into pie.

![Curve's derivative yield products, many charging fees. Source: https://x.com/TokenBrice/status/1814228571495240052](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2F07c2e0a3d9471235e06b01e5561d8422.webp&w=3840&q=75)

Just like Uniswap’s LPs face a cap in their potential earnings, and could potentially see them cut into by UNI token holders, veCRV holders risk seeing these outside teams capture an outsized portion of the value generated. This leaves an opportunity for a new entrant to promise all of the value generated by the protocol to tokenholders, offering a strictly better deal and taking away the native protocol LPs. There is a lot of fundamental strength holding up Curve in a highly competitive landscape, but just as with Uniswap, its moat isn’t insurmountable..

#### Principal-agent issues

And finally, what happens when your core contributors become massively wealthy early into the life of the protocols? Often in DeFi, a token has a huge run in price, massively enriching the team and insiders, who then begin to sell their large liquid allocations into this speculative demand. Unfortunately, this often happens very early in the product’s life, or even before launch.

When these parties’ token allocations are a large amount of the overall supply in circulation, this puts a major damper on the token’s market price. Over time the team becomes less incentivized to continue working as hard on their project. They are rich, the token is distributed, and unless there is a dominant market position or clear product-market fit, it becomes difficult to sustain the interest of either protocol participants or the team. They may fail to attend to emergent alternatives to their core value proposition or miss out on major market opportunities.

We are deep admirers of the Curve team. They are dedicated builders, they care about the proliferation of DeFi within the Ethereum ecosystem, and they have not entirely followed this model. The core contributors do continue to work hard and develop new product extensions, and instead of selling his tokens, Curve’s Michael Egorov famously lent them out as collateral and borrowed stablecoins against them.

Egorov and the Curve team are extraordinary. Unfortunately, the incentive structure posed by this type of borrowing is not. Both selling and borrowing against one’s position are liquidity events that distort a team’s incentives with respect to the protocol’s success. What’s more, Egorov’s CRV collateral became a major target for speculators and a talking point for people unsure of the protocol’s longevity.

But perhaps most consistent with the overall pattern of contributors getting early liquidity into hype is contributors’ failure to attend to emergent alternatives to their core value proposition. The below posts are, respectively, a contributor’s admission of lack of knowledge and another contributor’s mistaken interpretation of a new entrant’s mechanics.

![post image](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2Ffd0e978bed31e0e498402c47f0b41953.webp&w=3840&q=75)

The contracts may be immutable, but the market isn’t. DEXs need contributors paying special attention to what’s around the corner.

# Where are we now?

Uniswap and Curve have for years sat atop the DEX league tables. Despite being majorly different operations with unique innovations and challenges, they are both trying to answer the same bootstrapping question: how do you get everyone to continue participating on our platform for the long term?

There appear to be a few unaddressed gaps in their ability to sustain themselves:

### The value that can be distributed to users is capped.

On Uniswap, LPs can only earn what they generate in fees. UNI tokenholders receive nothing. A privately held company, Uniswap Labs, seems set to receive all undefined upside unlocked by the protocol’s function, including additional revenue streams such as front-end fees.

Although Curve has two revenue streams and does distribute value to both LPs and tokenholders, the value that these parties can earn is capped, too, due in part to the large fee capture introduced by third-party protocols such as Convex.

A threat to these business models is thus that a DEX could enter the marketplace and offer more value across the user base on the same value propositions. Such a value distribution could attract and keep LPs and users.

### Community activity is limited.

Uniswap’s economic activity is determined primarily by raw market forces directing LPs. The Uniswap Foundation has limited scope in how to allocate its resources. UNI tokenholders don’t have a market mechanism enforcing their stewardship because they are unable to receive any of the value generated by Uniswap.

Similar in limitation is Curve’s community. While this community is a die-hard one, It is split across several derivative protocols, each with its own incentive structure. The teams behind the varied derivative protocols often take on the major business development functions a DEX needs to stimulate demand for liquidity. Again, those are efforts that may lack coordination or alignment. The token distribution is frequently stacked towards major holders and may stunt the protocol’s growth in favor of supporting large interests.

There’s an opportunity for a DEX to enter the marketplace with a focused community orientation, aligned business development efforts to shape and grow the DEX economy, and a diverse stakeholder base. This approach could offer a compelling alternative to these other networks. Resiliency and outperformance are superior in the long run to simplistic efficiency (or captive interests).

### Protocol teams’ alignment is uncertain.

It’s important to repeat that Uniswap is not singularly Uniswap Labs, and the former’s own UNI token allocation is close to the end of vesting. Without revamping fee structures, Uniswap’s core protocol has little to offer Uniswap Labs in terms of revenue generation except to the extent that Uniswap can find new ways to charge users. Or, of course, they and their investors can continue to sell their own sizable UNI allocations. It is possible that the work Uniswap Labs is embarking on might by design be the kind of work that doesn’t benefit UNI holders, LPs, or other users of Uniswap.

Like Uniswap, Curve’s core contributing team has likely generated the vast majority of its liquidity through token sales and other market operations on their CRV allocations. A large portion of locked veCRV allocations are set to vest, as well. To the extent that contributing team members have continued to lock allocated CRV, they will have participated in the long-term health of the protocol’s value generation—but this is only a partial measure. Curve has operated for four years without core contributors tracking its success in the market, as shown below:

![post image](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2F419d241ce8f6909f25ad82b29e2b27cc.webp&w=3840&q=75)

Because of this, a DEX could enter the marketplace with a wholly aligned set of contributing users. These contributors may benefit only when the protocol’s long-term sustainability is proven out—and will fight to make that happen.

Success wouldn’t come from contributors who could or would sell project tokens as a primary objective. Rather, these contributors must correctly apprehend the long-term view of a DEX as an enormous value machine, one that is valuable to users, ecosystem projects, and ecosystems themselves. The Base team has adopted such a view of its own ecosystem:

![post image](https://paragraph.xyz/_next/image?url=https%3A%2F%2Fstorage.googleapis.com%2Fpapyrus_images%2Ff0a5e79231a1fddc8dabdf5d5bc31adc.webp&w=3840&q=75)

This is difficult work, but building a DEX in this manner achieves a globally aligned incentive framework that defines an arguably new class of DeFi infrastructure.

The next installment will discuss the result of such an effort: the MetaDEX.