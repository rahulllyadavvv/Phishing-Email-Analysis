
# Phishing Email Report — "Life Line Screening" Email

**What this email is trying to do:** It poses as a Life Line Screening health-package promotion offering a discounted "Stroke & Cardiovascular Disease Risk Package," pushing the reader to click "Book Your Appointment" to claim the deal.

**Final Answer: This is a Phishing Email**

## 1. Email Header Check

| What we checked | What we found | What it means |
|---|---|---|
| SPF | none | The sending domain has no SPF record at all. So we can't trust that this email really came from where it claims. |
| DKIM | none (not signed) | This email has no DKIM signature at all. |
| DMARC | none, and compauth=fail | This domain has no DMARC rulebook (none) and compauth came back fail. |
| X-MS-Exchange-Organization-SCL | 9 (very high) | SCL (Spam Confidence Level) — 9 very high confidence, meaning it was flagged as spam before it even reached an inbox. |

**Important Point to Note:** This email uses three different domains that don't match each other:
1. From header domain: 5e2bsalbdm.com
2. Return-Path domain: cxxldt.net
3. HELO (sending) domain: tunatyfrrlen.net

A real Life Line Screening email should use its own domain everywhere. Having three unrelated domains, all failing authentication, is a big red flag.

There's also a mail-merge trick in the subject line: "phishing@pot, Please verify" the recipient's own email address is stuffed directly into the subject to fake personalization.

## 2. Sender / Domain Check

The From field says "Life Line Screening," but the real sending domain is 5e2bsalbdm.com  which is random, made-up-looking domain, nowhere close to Life Line Screening at all. The Return-Path domain, cxxldt.net, and the HELO domain, tunatyfrrlen.net, are both separate, unrelated domains too. A trusted health-screening company would never have this kind of setup all its addresses should resemble its own brand domain, not three random unrelated ones.

## 3. Email Body Check

The email tries to tempt the reader with a struck-through discount: "Get Our Comprehensive Stroke & Cardiovascular Disease Risk Package for $330 $149," using a fake limited-time deal to push a click on "Book Your Appointment" without thinking it through.

## 4. Links and Attachment Analysis

The main call-to-action links are routed through Twitter/X's t.co shortener. The unsubscribe link goes to:

hxxp://dtherhproblem[.]us/su47375FcgyR22448528yCWm49413gAc67777twVX3375


## 5. Hidden Artifacts

The footer address on this email — "110 N Interstate 35, Round Rock, TX 78681" is character-for-character identical to the fake footer. Life Line Screening has no real connection to that address.

## 6. IOC (Indicators of Compromise) Table

| Type | Value |
|---|---|
| From domain | 5e2bsalbdm.com |
| Return-Path domain | cxxldt.net |
| HELO domain | tunatyfrrlen.net |
| Phishing domain | dtherhproblem.us (also seen in the PayPal case, Part 3) |
| Shared tracking ID | 22448528 / 49413 (also seen in the Microsoft case, Part 2) |
| Shared fake footer address | 110 N Interstate 35, Round Rock, TX 78681 (also seen in the PayPal case, Part 3) |

## 7. MITRE ATT&CK Mapping

| Technique | ID | Tactic | Why it applies |
|---|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access | Malicious link delivered via the "Book Your Appointment" button |
| User Execution: Malicious Link | T1204.001 | Execution | Requires the victim to click through to the phishing page |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Defense Evasion | "Life Line Screening" display name paired with unrelated domains |
| Acquire Infrastructure: Domains | T1583.001 | Resource Development | Disposable domains used (5e2bsalbdm.com, cxxldt.net, tunatyfrrlen.net, dtherhproblem.us) |
| Acquire Infrastructure: Web Services | T1583.006 | Resource Development | Twitter's t.co shortener abused as a redirect layer |

**Final Verdict:** This email pretends to be a discounted health-screening offer, but everything about it is fake SPF, DKIM, and DMARC all failed or were missing, and Microsoft's own spam filter gave it the highest-risk score (9).Hence.it's a phishing email.
