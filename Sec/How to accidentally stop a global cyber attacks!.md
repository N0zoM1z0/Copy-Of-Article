！！！respect！！！

---

# How to Accidentally Stop a Global Cyber Attacks

[May 13, 2017](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/2017/05) [MalwareTech](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/author/malwaretech) [ms17-010](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/?tag=ms17-010), [ransowmare](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/?tag=ransowmare), [worm](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/?tag=worm) [415](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html)

So finally I’ve found enough time between emails and Skype calls to write up on the crazy events which occurred over Friday, which was supposed to be part of my week off (I made it a total of 4 days without working, so there’s that). You’ve probably read about the WannaCrypt fiasco on several news sites, but I figured I’d tell my story.

I woke up at around 10 AM and checked onto the UK cyber threat sharing platform where i had been following the spread of the Emotet banking malware, something which seemed incredibly significant until today. There were a few of your usual posts about various organisations being hit with ransomware, but nothing significant…yet. I ended up going out to lunch with a friend, meanwhile the WannaCrypt ransomware campaign had entered full swing.

When I returned home at about 2:30, the threat sharing platform was flooded with posts about various NHS systems all across the country being hit, which was what tipped me of to the fact this was something big. Although ransomware on a public sector system isn’t even newsworthy, systems being hit simultaneously across the country is (contrary to popular belief, most NHS employees don’t open phishing emails which suggested that something to be this widespread it would have to be propagated using another method). I was quickly able to get a sample of the malware with the help of Kafeine, a good friend and fellow researcher. Upon running the sample in my analysis environment I instantly noticed it queried an unregistered domain, which i promptly registered.

Using Cisco Umbrella, we can actually see query volume to the domain prior to my registration of it which shows the campaign started at around 8 AM UTC.

[![img](https://web.archive.org/web/20170521230840im_/https://www.malwaretech.com/wp-content/uploads/2017/05/opendns.png)](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/wp-content/uploads/2017/05/opendns.png)

While the domain was propagating, I ran the sample again in my virtual environment to be met with WannaCrypt ransom page; but more interestingly was that after encrypting the fake files I left there as a test, it started connecting out to random IP addresses on port 445 (used by SMB). The mass connection attempts immediately made me think exploit scanner, and the fact it was scanning on the SMB port caused me to look back to the recent ShadowBroker leak of NSA exploits containing….an SMB exploit. Obvious I had no evidence yet that it was definitely scanning SMB hosts or using the leaked NSA exploit, so I tweeted out my finding and went to tend to the now propagated domain.



Now one thing that’s important to note is the actual registration of the domain was not on a whim. My job is to look for ways we can track and potentially stop botnets (and other kinds of malware), so I’m always on the lookout to pick up unregistered malware control server (C2) domains. In fact I registered several thousand of such domains in the past year.

Our standard model goes something like this.

1. Look for unregistered or expired C2 domains belonging to active botnets and point it to our sinkhole (a sinkhole is a server designed to capture malicious traffic and prevent control of infected computers by the criminals who infected them).
2. Gather data on the geographical distribution and scale of the infections, including IP addresses, which can be used to notify victims that they’re infected and assist law enforcement.
3. Reverse engineer the malware and see if there are any vulnerabilities in the code which would allow us to take-over the malware/botnet and prevent the spread or malicious use, via the domain we registered.

In the case of WannaCrypt, step 1, 2 and 3 were all one and the same, I just didn’t know it yet.

A few seconds after the domain had gone live I received a DM from a Talos analyst asking for the sample I had which was scanning SMB host, which i provided. Humorously at this point we had unknowingly killed the malware so there was much confusion as to why he could not run the exact same sample I just ran and get any results at all. As curious as this was, I was pressed for time and wasn’t able to investigate, because now the sinkhole servers were coming dangerously close to their maximum load.

I set about making sure our sinkhole server were stable and getting the expected data from the domain we had registered (at this point we still didn’t know much about what the domain I registered was for, just that anyone infected with this malware would connect to the domain we now own, allowing us to track the spread of the infection). Sorting out the sinkholes took longer than expected due to a very large botnet we had sinkholed the previous week eating up all the bandwidth, but soon enough I was able to set up a live tracking map and push it out via twitter (you can still see it [here](https://web.archive.org/web/20170521230840/https://intel.malwaretech.com/WannaCrypt.html)).



Around 6:23 PM (BST) I asked an employee to look into the worm code and verify the domain we registered would not change (some malware will periodically change the domain using an algorithm, so we needed to know if there would be new domains so we could register those too), meanwhile I performed some updated to the live map to deal with the rapid influx of new visitors.

After about 5 minutes the employee came back with the news that the registration of the domain had triggered the ransomware meaning we’d encrypted everyone’s files (don’t worry, this was later proven to not be the case), but it still caused quite a bit of panic. I contacted Kafeine about this and he  linked me to the following freshly posted tweet made by ProofPoint researcher Darien Huss, who stated the opposite (that our registration of the domain had actually stopped the ransomware and prevent the spread).



Having heard to conflicting answers, I anxiously loaded back up my analysis environment and ran the sample….nothing. I then modified my host file so that the domain connection would be unsuccessful and ran it again…..RANSOMWARED.

Now you probably can’t picture a grown man jumping around with the excitement of having just been ransomwared, but this was me. The failure of the ransomware to run the first time and then the subsequent success on the second mean that we had in fact prevented the spread of the ransomware and prevented it ransoming any new computer since the registration of the domain (I initially kept quiet about this while i reverse engineered the code myself to triple check this was the case, but by now Darien’s tweet had gotten a lot of traction).

So why did our sinkhole cause an international ransomware epidemic to stop?

Talos wrote a great writeup explaining the code side [here](https://web.archive.org/web/20170521230840/http://blog.talosintelligence.com/2017/05/wannacry.html), which I’ll elaborate on using Darien’s screenshot.

[![img](https://web.archive.org/web/20170521230840im_/https://www.malwaretech.com/wp-content/uploads/2017/05/IDA.jpg)](https://web.archive.org/web/20170521230840/https://www.malwaretech.com/wp-content/uploads/2017/05/IDA.jpg)

All this code is doing is attempting to connect to the domain we registered and if the connection is not successful it ransoms the system, if it is successful the malware exits (this was not clear to me at first from the screenshot as I lacked the context of what the parent function may be doing with the results).

The reason which was suggested is that the domain is a “kill switch” in case something goes wrong, but I now believe it to be a badly thought out anti-analysis.

In certain sandbox environments traffic is intercepted by replying to all URL lookups with an IP address belonging to the sandbox rather than the real IP address the URL points to, a side effect of this is if an unregistered domain is queried it will respond as it it were registered (which should never happen).

I believe they were trying to query an intentionally unregistered domain which would appear registered in certain sandbox environments, then once they see the domain responding, they know they’re in a sandbox the malware exits to prevent further analysis. This technique isn’t unprecedented and is actually used by the Necurs trojan (they will query 5 totally random domains and if they all return the same IP, it will exit); however, because WannaCrypt used a single hardcoded domain, my registartion of it caused all infections globally to believe they were inside a sandbox and exit…thus we initially unintentionally prevented the spread and and further ransoming of computers infected with this malware. Of course now that we are aware of this, we will continue to host the domain to prevent any further infections from this sample.

One thing that is very important to note is our sinkholing only stops this sample and there is nothing stopping them removing the domain check and trying again, so it’s incredibly importiant that any unpatched systems are patched as quickly as possible.

As well as the names & companies mentioned in this blog I’d like to give a shout out to:

**NCSC UK** – Their threat intelligence sharing program provided us with valuable information needed to first identify the malware family behind the attack. They also helped ensure our sinkholes were not mistaken for criminal controlled infrastructure so that we could feed them the information required to notify UK victims.

**FBI & ShadowServer** – They were a great help in getting non-UK victims notified of the infections in a very short span of time, even if it did mean me staying up all night to link in with them.

**2sec4u** – For reducing my workload today and providing free panic attacks.

**Microsoft** – By realeasing an out of bounds patch for unsupported operating systems such as Windows XP and Server 2003, people now are able to patch rather than having to attempt upgrades to newer system in order to be secured against this worm.

If you have anything to patch, patch it. If you need a guide, this one is being reguarly updated: https://www.ncsc.gov.uk/guidance/protecting-your-organisation-ransomware

Now I should probably sleep.

