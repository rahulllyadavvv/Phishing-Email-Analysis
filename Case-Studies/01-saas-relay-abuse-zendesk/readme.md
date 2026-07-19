
Phishing Email Report  — "Trust Wallet Verification(zenDesk)" Email

**What this email is trying to do:** It poses as a Trust Wallet "urgent account verification" notice, sent through a real Zendesk account, pressuring the reader to click a "Verification Link" before their account is suspended.

**Final Answer: This is a Phishing Email**

## 1. Email Header Check

| What we checked | What we found | What it means |
|---|---|---|
| SPF | pass | The sending IP (188.172.137.8) is authorized to send for gaksbdad.zendesk.com. This is a real, technically true pass. |
| DKIM | pass, signed by zendesk.com | A genuine Zendesk signature — not forged. |
| DMARC | pass | The From domain (gaksbdad.zendesk.com) aligns with the authenticated domain — true alignment. |

**Important Point to Note:** All three checks passing does not mean this email is safe. The sending domain, gaksbdad.zendesk.com, is a free Zendesk trial subdomain anyone can register one in minutes. The attacker didn't spoof Zendesk,they signed up for a real Zendesk account and used it as a mail relay. Every authentication check downstream sees genuine Zendesk infrastructure and passes it correctly because the infrastructure really is genuine. It's the sender behind that infrastructure that isn't.

## 2. Sender / Domain Check

The From field reads "Notification trust account" at help@gaksbdad.zendesk.com. The Reply-To, help+id1545639@gaksbdad.zendesk.com, follows Zendesk's own standard ticket-reply format so there's no classic Reply-To mismatch here. The giveaway is the subdomain itself: gaksbdad has no relationship to Trust Wallet, the brand being impersonated. The email also opens with "Dear Customer" despite the recipient's name being available elsewhere in the message a generic greeting a real personalized notification wouldn't use.

## 3. Email Body Check

The email creates urgency: "Immediate action is needed. Verify your account now to avoid any service interruption." This is designed to trigger a reflex click before the reader stops to check anything.

## 4. Links and Attachment Analysis

The "Verification Link" button doesn't go anywhere near Trust Wallet. It resolves to hxxps://scnv[.]io/i5iT — a URL shortener, not an official domain. This link was confirmed malicious/phishing on VirusTotal. The anchor text says "Verification Link"; the actual destination says otherwise.

The Trust Wallet logo shown in the email is also not hosted by Trust Wallet it's hotlinked from images.g2crowd[.]com, an unrelated third-party product-review CDN. The attacker never controlled a real Trust Wallet asset; they just linked to a public image of the logo hosted somewhere else. The footer even links to a privacy policy at zalando[.]fr a French fashion retailer with zero connection to Trust Wallet or Zendesk, a strong sign this is a reused, templated phishing kit where the attacker swapped in a new brand but never updated the boilerplate underneath.

## 5. Hidden Artifacts

There's a string of white-on-white text, [L6LGWW-GWY9J], embedded in the email's HTML completely invisible to a normal reader, but present in the source. This kind of hidden marker is common in mass-phishing kits, likely used to tag which batch or campaign a specific message belongs to.

## 6. IOC (Indicators of Compromise) Table

| Type | Value |
|---|---|
| Sending domain | gaksbdad.zendesk.com |
| Sending IP | 188.172.137.8 |
| Malicious redirector | hxxps://scnv[.]io/i5iT |
| Hotlinked brand asset host | images.g2crowd[.]com |
| Mismatched footer domain | zalando[.]fr |

## 7. MITRE ATT&CK Mapping

| Technique | ID | Tactic | Why it applies |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | Malicious redirect delivered via a "Verification Link" |
| User Execution: Malicious Link | T1204.001 | Execution | Requires the victim to click through to the phishing page |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Defense Evasion | Trust Wallet brand impersonation using a hotlinked, unowned logo |
| Acquire Infrastructure: Web Services | T1583.006 | Resource Development | Free Zendesk trial account registered and abused as a legitimate-looking mail relay |


**Final Verdict:** This email pretends to be a Trust Wallet security notice sent through Zendesk, and it passes SPF, DKIM, and DMARC cleanly but that's only because the attacker rented a free, real Zendesk account rather than spoofing anything. The "Verification Link" leads to a confirmed phishing redirect, the brand logo is hotlinked from an unrelated site, and the footer links to a completely unrelated company. So the conclusion is it's a Phishing email and a clear demonstration that a clean authentication result only proves who controls the sending domain, not whether that sender is trustworthy.
