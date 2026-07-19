# Phishing Email Report 2 — "Microsoft Account Unusual Sign-in" Email

**Final Answer: This is a Phishing Email**

## 1. Email Header Check

| What we checked | What we found | What it means |
|---|---|---|
| SPF | none | The website nuhstrfpolviin[.]co.uk has no SPF record at all. Double-checked with a tool called EasyDMARC, and it also said "No Record." So we can't trust that this email really came from them. |
| DKIM | none (not signed) | This email has no DKIM signature at all. |
| DMARC | none, and compauth=fail | This domain has no DMARC rulebook (none) and compauth came back fail. |
| X-MS-Exchange-Organization-SCL | 5 (high) | SCL (Spam Confidence Level) Microsoft's own score (5 is high). |

**Important Point to Note:** This email uses three different domains that don't match each other:
1. From header domain: 3i04bit0zm.com
2. Reply-To domain: gmail.com
3. Return-Path domain: nuhstrfpolviin[.]co.uk

A real Microsoft email should use Microsoft's own domain everywhere. Having three unrelated domains is a big red flag.

## 2. Sender / Domain Check

The From field says "Microsoft account team," but the real email address is hsypm@3i04bit0zm.com, which is strange, nowhere close to Microsoft at all.

The Reply-To address is assistant.supp0rt.acc0unt@gmail.com a free Gmail address, not a Microsoft address. Look closely at the spelling: supp0rt and acc0unt use the number zero (0) instead of the letter "o." This is typosquatting / character substitution scammers do this on purpose to prevent detection from spam filters that search for the real words "support" or "account."

The Return-Path domain, nuhstrfpolviin[.]co.uk, is also another unrelated domain. A trusted brand like Microsoft would never have this kind of setup all their addresses should resemble Microsoft-owned domains, not some random unrelated ones.

## 3. Email Body Check

The email tries to create panic by saying someone signed in to "your Microsoft account" from Russia/Moscow, using IP address 103.225.77.255, on Windows 10 with Firefox.

This is a social engineering trick, using fear and urgency ("was this you? report it now!") to make people click or reply without thinking.

## 4. Links and Attachment Analysis

All three "links" in this email "Report The User," "click here," and the account name itself are not normal web links. They are mailto: links, and clicking them opens a new email addressed to assistant.supp0rt.acc0unt@gmail.com. The scammer is trying to get you to reply, which is used to confirm whether the email address is real or not.

## 5. Hidden Artifacts

* There's a tracking pixel a completely invisible 1x1 pixel image hidden in the email: hxxp://thebandalisty[.]com/track/o45364qpUEM22448528ERZO49413XpA67854DIHB176. This secretly tells the scammer when you open the email.
* We checked thebandalisty[.]com on VirusTotal, and 11 out of 91 security companies flagged it as malicious. Someone in the VirusTotal community left a comment that basically describes this exact email: "Serves a 1x1px image with CSS visibility=hidden and tracking token in a phishing-site spam-link email pretending to be a Microsoft warning about someone signing in to your Microsoft account." That's about as close to a confirmed match as you can get.


## 6. IOC (Indicators of Compromise) Table

| Type | Value |
|---|---|
| From domain | 3i04bit0zm.com |
| Reply-To | assistant.supp0rt.acc0unt@gmail[.]com |
| Return-Path / HELO domain | nuhstrfpolviin[.]co.uk |
| Sending IP | 188.93.118.59 |
| Tracking pixel domain | thebandalisty[.]com (flagged by 11/91 VirusTotal vendors) |

## 7. MITRE ATT&CK Mapping

| Technique | ID | Tactic | Why it applies |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | A tracking beacon and reply-bait links were delivered through the email |
| User Execution: Malicious Link | T1204.001 | Execution | The scam only works if the victim clicks or replies |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Defense Evasion | Display name "Microsoft account team" used with an unrelated domain |
| Acquire Infrastructure: Domains | T1583.001 | Resource Development | Disposable domains used (3i04bit0zm.com, nuhstrfpolviin.co.uk, thebandalisty.com) |

**Final Verdict:** This email pretends to be a Microsoft security alert, but everything is fake. SPF, DKIM, and DMARC all failed or were missing, the sender domain has nothing to do with Microsoft, the "links" are actually secret reply-traps, and VirusTotal confirms the hidden tracking image comes from a known phishing campaign. So the conclusion is it's a Phishing email.
