# SlowMist: Analysis of Web3 Phishing Techniques

[![SlowMist](https://miro.medium.com/v2/resize:fill:55:55/1*4XGrkBr5c54rFezOTk4SBw.png)](https://slowmist.medium.com/?source=post_page---byline--ceb1a41d1bd5---------------------------------------)

[SlowMist](https://slowmist.medium.com/?source=post_page---byline--ceb1a41d1bd5---------------------------------------)·[Follow](https://medium.com/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fsubscribe%2Fuser%2F4ceeedda40e8&operation=register&redirect=https%3A%2F%2Fslowmist.medium.com%2Fslowmist-analysis-of-web3-phishing-techniques-ceb1a41d1bd5&user=SlowMist&userId=4ceeedda40e8&source=post_page-4ceeedda40e8--byline--ceb1a41d1bd5---------------------post_header------------------)

9 min read·Jan 24, 2025



20









![img](https://miro.medium.com/v2/resize:fit:875/1*gsl8g_41BPyfN7UtdP-2Dg.png)

# Background

Recently, SlowMist was invited to participate in the Ethereum Web3 Security BootCamp organized by DeFiHackLabs. As a guest speaker, Thinking, the head of SlowMist’s security audit team, led participants through eight key sections — “Camouflage, Bait, Lure, Attack, Concealment, Techniques, Identification, and Defense.” Drawing on real-world cases, Thinking provided an in-depth analysis of phishing hackers’ malicious tactics and stealth techniques, along with practical countermeasures.

Phishing attacks remain one of the most critical threats in the industry. Understanding these threats is essential for building effective defenses. This article highlights key insights from the session to help users recognize the current state of phishing attacks and adopt measures to mitigate such risks effectively.

# **Why Do People Fall for Phishing?**

![img](https://miro.medium.com/v2/resize:fit:875/1*p7q7xmOwoYuAtM0ArHVMmA.png)

Phishing has become one of the major security threats in the Web3 world. Let’s first explore why users fall victim to phishing. Even users with strong security awareness sometimes lament, “You can’t walk by the shore without getting your feet wet.” After all, maintaining constant vigilance is challenging. Attackers analyze recent trends, community activity, and user demographics to select high-profile targets. They meticulously disguise their attacks, using airdrops, high returns, and other lures to entice users. These techniques often incorporate social engineering, exploiting user psychology to achieve their fraudulent goals:

- **Enticement**: Airdrop whitelist eligibility, early mining opportunities, keys to wealth, etc.
- **Curiosity/Desire**: Escape-top strategies to avoid missing out on potential 100x gains; enticing event links like *https://us04-zoom[.]us* (malicious) or *https://vote-pengu[.]com* (malicious).
- **Fear**: “Urgent alert: Project XX has been hacked. Use *revake[.]cash* (malicious) to revoke permissions and prevent asset loss.”
- **Convenience**: Tools like airdrop bots, AI-based quantitative trading tools, or one-click mining for yields.

By creating and deploying these lures, attackers profit by extracting sensitive information or permissions from users, leading to asset theft:

- **Mnemonic Phrase/Private Key Theft**: Trick users into inputting their mnemonic phrases or private keys.
- **Wallet Signature Fraud**: Exploit users via authorization or transfer signatures.
- **Account Credential Theft**: Target Telegram, Gmail, X (formerly Twitter), Discord, etc.
- **Social Media Permissions**: Compromise X and Discord accounts.
- **Malicious App Installs**: Disseminate fake wallet apps, social apps, or meeting apps.

# **Common Phishing Techniques**

![img](https://miro.medium.com/v2/resize:fit:875/1*j2D3XayCmRK6EohsiMaD5g.png)

## **Account Hijacking/Impersonation**

Recently, the X accounts of Web3 project teams and KOLs have frequently been hijacked. Attackers use these accounts to promote fake tokens or post deceptive “good news” containing phishing links. In some cases, attackers even take over legitimate domains of the targeted project. Clicking such links and signing or downloading malicious software often results in theft.

Attackers also impersonate accounts in comment sections to lure users. SlowMist’s analysis revealed that phishing accounts occupy the first comment on tweets from major projects about 80% of the time. Automated bots follow accounts for major projects and post phishing comments immediately after tweets are published, ensuring high visibility. These bots often mimic the project’s name and branding, making it difficult for users to distinguish real from fake.

![img](https://miro.medium.com/v2/resize:fit:875/1*lKYCh0JOiVib76LFxVE_5Q.png)

Additionally, attackers use Discord to impersonate administrators. By copying profile pictures and nicknames, they post phishing messages or DM users. Without thoroughly checking the profile, users may fall for these traps, especially as attackers create usernames nearly identical to legitimate admins (e.g., adding an underscore or period).

![img](https://miro.medium.com/v2/resize:fit:875/0*zZp4By3Nfd3-2oWi)

## **Invitation Phishing**

Attackers build relationships with victims on social platforms and recommend “high-quality” projects or invite them to meetings, directing them to malicious sites or fake apps. For instance, users have fallen victim to phishing by downloading fake Zoom apps disguised under domains like *app[.]us4zoom[.]us*. These malicious apps collect sensitive data like KeyChain information or plugin wallet data, allowing attackers to steal mnemonic phrases, private keys, and other credentials.

![img](https://miro.medium.com/v2/resize:fit:875/0*V79tiEtgNafbw60L)

## **Exploiting S**earch Engine Rankings

Phishing sites sometimes appear higher than legitimate ones in search engine rankings due to ad promotion. When users are unaware of the official website’s URL, it becomes difficult to determine whether a site is genuine solely based on its appearance. Additionally, phishing sites can exploit Google Ads’ customization feature to display deceptive URLs in their ads. The URL shown in the “Sponsored” section might appear identical to the official URL, but clicking on it redirects users to a phishing site crafted by attackers. Since these phishing sites often look almost identical to the official ones, users can easily be misled. For this reason, it’s not recommended to rely on search engines to find the official website, as it significantly increases the risk of landing on a phishing site.

![img](https://miro.medium.com/v2/resize:fit:875/1*WWJ9K96-yVI-NnznLYnn3g.png)

## **Telegram Advertisements**

Recently, many users have been deceived by fake Telegram bots. Attackers use targeted ads to display fake bots in official channels, prompting users to bind wallets by entering their private keys, resulting in theft.

![img](https://miro.medium.com/v2/resize:fit:875/0*jKRuaqXoyZ699jCj)

Additionally, we recently uncovered a new phishing tactic — the “[Telegram Fake Safeguard Scam](https://slowmist.medium.com/new-scam-technique-fake-safeguard-scam-on-telegram-bb4803bad521).” Many users fell victim after following the attackers’ instructions and executing malicious code, resulting in asset theft.

![img](https://miro.medium.com/v2/resize:fit:875/0*Skp8O5UEbifAyadg)

## **App Stores**

Not all software available on app stores such as Google Play, Chrome Store, App Store, or APKCombo is legitimate. Often, app stores cannot fully vet every application. Some attackers exploit keyword ranking and traffic-buying strategies to lure users into downloading fraudulent apps. We advise users to exercise caution and verify the developer’s information before downloading. Ensure it matches the official developer credentials. Additionally, consider app ratings, download counts, and reviews as part of your evaluation process.

![img](https://miro.medium.com/v2/resize:fit:875/0*6pJM8xeYrRQeS5OU)

## **Phishing Emails**

Email phishing is one of the most classic and straightforward schemes. Attackers use phishing templates combined with reverse proxy tools like Evilginx to create deceptive emails resembling the example below. When users click “VIEW THE DOCUMENT,” they are redirected to a fake DocuSign interface (now inaccessible). If the user attempts to log in via Google on this interface, they are redirected to a reverse-proxied Google login page. By entering their account credentials, password, and 2FA code, the account is immediately compromised by the attacker.

![img](https://miro.medium.com/v2/resize:fit:875/0*srhQ0E0SPV1PVTQS)

![img](https://miro.medium.com/v2/resize:fit:875/0*fY18tniAILPpi6ty)

The phishing email shown above is evidently not meticulously crafted, as the sender’s email address was not properly spoofed. Let’s examine how attackers can disguise their email addresses more effectively: the attacker’s email address in the example below differs from the official one by just a small dot. By using tools like DNSTwist, attackers can identify special characters supported by Gmail. At first glance, it might seem like a smudge on the computer screen rather than a malicious discrepancy.

![img](https://miro.medium.com/v2/resize:fit:875/0*Tk83x7LBms_zR5om)

## Exploiting Browser Features

For more details, refer to SlowMist’s article: [How Scammer Used Malicious Bookmark to Gain Access to Discords of NFT projects](https://slowmist.medium.com/how-scammer-used-malicious-bookmark-to-gain-access-to-discords-of-nft-projects-7c3b325ff2e9).

# **Defense Challenges**

![img](https://miro.medium.com/v2/resize:fit:875/1*MURddrIYqgUf7yRdnbV2KA.png)

Attackers’ tactics are constantly evolving, becoming more refined and template-driven. Previously, we discovered that attackers not only create websites that closely resemble official sites of well-known projects and hijack project domains, but they’ve also fabricated entire projects. These fake projects not only have many followers on social media (purchased), but also boast GitHub repositories, making it even harder for users to identify phishing threats. Moreover, attackers’ adept use of anonymous tools further complicates tracking their activities. To conceal their identity, attackers often use VPNs, Tor, or even control compromised hosts to carry out malicious actions.

![img](https://miro.medium.com/v2/resize:fit:875/0*-OVBvtEWOhOHK2Z2)

Once attackers have established anonymous identities, they also need to purchase foundational services like Namecheap, which supports cryptocurrency payments. Some services only require an email to register, with no KYC verification, allowing attackers to avoid being traced.

![img](https://miro.medium.com/v2/resize:fit:875/0*LedAQ7-YQQuBbqtx)

After preparing these basic elements, attackers can launch phishing attacks. Once they’ve profited, they use services like Wasabi and Tornado to obfuscate the flow of funds. To further enhance anonymity, they may even convert the funds into highly anonymous cryptocurrencies like Monero.

![img](https://miro.medium.com/v2/resize:fit:875/0*qH-l_N53ToZC8Yc4)

To avoid leaving traces and evidence, attackers will erase relevant domain resolutions, malicious programs, GitHub repositories, platform accounts, etc. This often results in security teams encountering situations where phishing websites are no longer accessible, and malicious programs can no longer be downloaded, thus complicating analysis and tracking efforts.

# **Defense Strategies**

![img](https://miro.medium.com/v2/resize:fit:875/1*GPktczpLYhmyDGwjD0T5YQ.png)

![img](https://miro.medium.com/v2/resize:fit:875/1*gxyuJRszGuO6LzsE67-J_Q.png)

Users can recognize phishing threats based on the features shown in the above image and grasp the basic methods for verifying the authenticity of information. Additionally, they can use some defense tools to enhance their anti-phishing capabilities:

- **Phishing Risk Blocking Plugins**: Tools like **Scam Sniffer** can detect risks from multiple dimensions. When users open a suspicious phishing page, the tool will promptly display a risk warning.
- **Wallets with High Interaction Security**: For example, **Rabby’s** Watch Mode (no private key required), phishing website detection, “what you see is what you sign,” high-risk signature identification, and historical scam detection features.
- **Internationally Recognized Antivirus Software**: Such as **AVG, Bitdefender, Kaspersky**, etc.
- **Hardware Wallets**: Hardware wallets offer an offline method for storing private keys. When interacting with DApps using a hardware wallet, the private key is not exposed online, significantly reducing the risk of asset theft.

# **Conclusion**

In the blockchain dark forest, phishing attacks are everywhere. When navigating through this dark forest, it is essential to cultivate the habit of maintaining zero trust and continuous verification. We recommend that everyone read and gradually master the *Blockchain Dark Forest Selfguard Handbook*: https://github.com/slowmist/Blockchain-dark-forest-selfguard-handbook/.

Due to space constraints, this article only introduces the main content of the sharing session. The nearly seventy-page PPT is now publicly available (https://github.com/slowmist/Knowledge-Base/blob/master/security-research/Analysis-of-Web3-Phishing-Techniques.pdf). Feel free to check it out.

# About SlowMist

SlowMist is a blockchain security firm established in January 2018. The firm was started by a team with over ten years of network security experience to become a global force. Our goal is to make the blockchain ecosystem as secure as possible for everyone. We are now a renowned international blockchain security firm that has worked on various well-known projects such as HashKey Exchange, OSL, MEEX, BGE, BTCBOX, Bitget, BHEX.SG, OKX, Binance, HTX, Amber Group, Crypto.com, etc.

SlowMist offers a variety of services that include but are not limited to security audits, threat information, defense deployment, security consultants, and other security-related services. We also offer AML (Anti-money laundering) software, MistEye (Security Monitoring) , SlowMist Hacked (Crypto hack archives), FireWall.x (Smart contract firewall) and other SaaS products. We have partnerships with domestic and international firms such as Akamai, BitDefender, RC², TianJi Partners, IPIP, etc. Our extensive work in cryptocurrency crime investigations has been cited by international organizations and government bodies, including the United Nations Security Council and the United Nations Office on Drugs and Crime.

By delivering a comprehensive security solution customized to individual projects, we can identify risks and prevent them from occurring. Our team was able to find and publish several high-risk blockchain security flaws. By doing so, we could spread awareness and raise the security standards in the blockchain ecosystem.