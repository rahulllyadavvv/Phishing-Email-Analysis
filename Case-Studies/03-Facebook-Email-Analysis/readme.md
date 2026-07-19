
# Phishing Email Report — "Facebook Login Attempt" Email

**What this email is trying to do:** It poses as a Facebook security alert claiming someone logged into the recipient's account from a new device, pushing them to click "Report the user" or "Yes, me" to respond.

**Final Answer: This is a Phishing Email**

## 1. Email Header Check

| What we checked | What we found | What it means |
|---|---|---|
| SPF | none | The website dalimnthefoob.co has no SPF record at all. Double-checked with EasyDMARC, and it also said "No Record." So we can't trust that this email really came from them. |
| DKIM | none (not signed) | This email has no DKIM signature at all. |
| DMARC | none, and compauth=fail | This domain has no DMARC rulebook (none) and compauth came back fail. |
| X-MS-Exchange-Organization-SCL | 5 (high) | SCL (Spam Confidence Level) — Microsoft's own score (5 is high). |

**Important Point to Note:** This email uses three different domains that don't match each other:
1. From header domain: 5cv1avaeyq.com
2. Reply-To domain: gmail.com
3. Return-Path domain: dalimnthefoob.co

A real Facebook email should use Facebook's own domain everywhere. Having three unrelated domains is a big red flag.

There's also a trick hiding in the subject line itself: "Someone tried to Iog in To Your Account, User lD : phishing@pot." Look closely at "Iog" and "lD" the scammer used a capital "I" where "log" should have a lowercase "l," and a lowercase "l" where "ID" should have a capital "I." This is called a homoglyph substitution, done on purpose so spam filters searching for the real words "log in" and "ID" don't catch it.

## 2. Sender / Domain Check

The From field says "Facebook," but the real email address is e8lf9@5cv1avaeyq.com a strange, random, made-up-looking domain, nowhere close to Facebook at all. The Reply-To address is ssecnewssotrecognizd@gmail.com a free Gmail address, not a Facebook address. The Return-Path domain, dalimnthefoob.co, is also another unrelated domain. A trusted brand like Facebook would never have this kind of setup all their addresses should resemble back to Facebook-owned domains, not some random unrelated ones.

## 3. Email Body Check

The email tries to create panic by saying a user just logged into "your Facebook account from a new device Samsung S21," and asks you to confirm "it's really you," using fear and urgency to make people click or reply without thinking. The footer also lists a fake headquarters address: "1 Facebook Way, Menlo Park, CA 94025." Facebook's real address is 1 Hacker Way a near-miss that gives away a copy-pasted template.

## 4. Links and Attachment Analysis

This email has some links (the Facebook logo, and "Learn more") that really do point to real facebook.com web addresses. But the two main buttons "Report the user" and "Yes, me" are not normal web links at all. They are mailto: links, meaning clicking them opens a new email addressed to ssecnewssotrecognizd@gmail.com. The scammer is trying to get you to reply, which is used to confirm whether the email address is real or not. Mixing real Facebook links with fake reply-trap buttons makes this harder to catch than a template where every link is obviously fake.

## 5. Hidden Artifacts

There's a tracking pixel — a completely invisible 1x1 pixel image — hidden in the email: hxxp://thema214[.]com/track/o47840Nmjxo27537896zAMm1371191pit68285sBhG176. This secretly tells the scammer when you open the email.

There's also a giant hidden block of made-up HTML tags (`<HWYhT>`) stuffed with hundreds of random junk words in different languages, repeated six separate times through the email. This is used for filter-evasion the random words confuse spam-detection systems into thinking the email is boring, normal text.

## 6. IOC (Indicators of Compromise) Table

| Type | Value |
|---|---|
| From domain | 5cv1avaeyq.com |
| Reply-To | ssecnewssotrecognizd@gmail.com |
| Return-Path / HELO domain | dalimnthefoob.co |
| Sending IP | 89.144.44.17 |
| Tracking pixel domain | thema214.com |
| Shared tracking ID (matches PayPal case) | 27537896 / 1371191 |

## 7. MITRE ATT&CK Mapping

| Technique | ID | Tactic | Why it applies |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | A tracking beacon and reply-bait links were delivered through the email |
| User Execution: Malicious Link | T1204.001 | Execution | The scam only works if the victim clicks or replies |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Defense Evasion | Display name "Facebook" used with an unrelated domain, mixed with real facebook.com links |
| Acquire Infrastructure: Domains | T1583.001 | Resource Development | Disposable domains used (5cv1avaeyq.com, dalimnthefoob.co, thema214.com) |
| Establish Accounts: Email Accounts | T1585.002 | Resource Development | Free Gmail account set up to receive reply-bait responses |

**Final Verdict:** This email pretends to be a Facebook security alert, but everything is fake. SPF, DKIM, and DMARC all failed or were missing, the sender domain has nothing to do with Facebook, the main buttons are actually secret reply-traps, and also the presence of hidden tracking pixel. So the conclusion is it's a Phishing email.
