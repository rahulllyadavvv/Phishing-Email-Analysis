# Phishing Email Report — "Banco do Brasil" Gmail PDF Email

**What this email is trying to do:** It poses as a Banco do Brasil consumer-service notice claiming there are unclaimed funds tied to the recipient's CPF (Brazilian Tax ID), pushing them to open an attached PDF within a 48-hour deadline.

**Final Answer: This is a Phishing Email**

## 1. Email Header Check

| What we checked | What we found | What it means |
|---|---|---|
| SPF | pass (sender IP 209.85.222.175) | The sending server is genuinely Gmail's own infrastructure. This is a real, technically true pass. |
| DKIM | pass, signed by gmail.com | A real Google DKIM signature — not forged. |
| DMARC | pass | The From address domain (gmail.com) matches the domain that passed SPF/DKIM, so alignment genuinely checks out. |
| X-MS-Exchange-Organization-SCL | 1 (low) | SCL (Spam Confidence Level) — because the mail is truly from Gmail, Microsoft's filter doesn't flag it as risky. |

**Important Point to Note:** All three checks passing does not mean this email is safe. DMARC only checks that the domain in the From address (gmail.com) matches the domain that sent the mail it says nothing about the display name. And the display name here is doing all the lying: "Banco do Brasil (no-reply@bb.com.br) | SVR Consulta de valores a receber | Atendimento: 691076456020794" a fake bank name, a fake email address, and a fake reference number, all stuffed into the display name field, while the real address underneath is a random Gmail account. Anyone can make a free Gmail account and pass real authentication Google is confirming "this came from Gmail," not "this came from Banco do Brasil."

## 2. Sender / Domain Check

The From field says "Banco do Brasil," but the real email address is qazwes332@gmail.com — a personal Gmail account, nowhere close to Banco do Brasil at all. The Return-Path is also qazwes332@gmail.com matching the From address exactly, consistent with this being sent from a genuine, ordinary Gmail account rather than a spoofed one. A real bank would never send official notices from a personal Gmail address it must have its own domain (bb.com.br), not some random unrelated one.

## 3. Email Body Check

The email tries to tempt the reader by saying there are "amounts to be received" tied to their CPF, using fear of missing out on money to make people act fast. It also creates urgency with a "48-hour deadline to request the amount," pushing the reader to act without thinking it through.

## 4. Links and Attachment Analysis

This email has no clickable web links instead, it delivers a PDF attachment named Informativo-Online_nMFMPPVC4Ye7Eek4CDBCy1uJFqpHeoaCgwN.pdf. The random alphanumeric text in the filename is suspicious no legitimate organization sends attachments named like that.

VirusTotal and Hybrid Analysis both marked the file as "clean" but this does not mean it's safe. The PDF is password-protected/encrypted, and VirusTotal itself notes: "This file is password-protected, security vendors may not have been able to look into it." In other words, the scanners couldn't see inside the file at all "clean" here means "unscannable," not "safe." The password ("1010") is handed to the victim directly in the email body, meaning only a human who reads the email can unlock it automated security tools cannot.

## 5. Hidden Artifacts

The PDF's internal structure contains a hidden clickable link covering the entire page (a Link annotation with a URI action, sized to the full page). Because the file is encrypted, the actual destination of that link is also encrypted and can't be read without the password meaning opening the PDF and clicking anywhere on the page could trigger a hidden link that no scanner has ever inspected.


## 6. IOC (Indicators of Compromise) Table

| Type | Value |
|---|---|
| From / Return-Path address | qazwes332@gmail.com |
| Sending IP | 209.85.222.175 (legitimate Gmail infrastructure) |
| Attachment filename | Informativo-Online_nMFMPPVC4Ye7Eek4CDBCy1uJFqpHeoaCgwN.pdf |
| Attachment SHA-256 | 8ba841c3ff2860c0028ac3b5288729bd9262658b733975f73599874c00b58383 |
| Document open password | 1010 (given in the email body) |
| Tracking token | xxlAdImgD1bPvrF (shared between subject and body) |

## 7. MITRE ATT&CK Mapping

| Technique | ID | Tactic | Why it applies |
|---|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access | Malicious PDF delivered as an email attachment |
| User Execution: Malicious File | T1204.002 | Execution | Victim must open the PDF and manually enter the password to unlock it |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Defense Evasion | "Banco do Brasil" display-name stuffed onto a personal Gmail address |
| Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | Defense Evasion | PDF encrypted specifically to block AV/sandbox inspection |
| Establish Accounts: Email Accounts | T1585.002 | Resource Development | Free Gmail account used as the sending identity |

**Final Verdict:** This email pretends to be an official Banco do Brasil notice, but everything about it is fake. SPF, DKIM, and DMARC all pass not because the email is legitimate, but because it was genuinely sent through a personal Gmail account and Gmail is honestly authenticating itself, not the bank. The attachment is a deliberately encrypted PDF designed to block security scanners from seeing what's inside, and it hides a full-page clickable link that only unlocks with a password supplied by the scammer. So the conclusion is it's a Phishing email.
