

# Email Analysis

Almost every individual over the internet uses a mail service, making it a common target for attackers. Analyzing mail and being able to classify it as malicious or not is a very important and helpful skill to learn.

Let's dig deep and learn the procedure of analyzing an email.

The steps are:

## 1. Header Analysis

In this section we will focus on SPF, DKIM, and DMARC checks.

**SPF (Sender Policy Framework):** It ensures the SMTP server IP is authorised to send email on behalf of the (envelope from) domain. The SMTP server IP must be present in the DNS records of the domain (the domain of the envelope-from address, generally noted as the return-path address).

**DKIM (DomainKeys Identified Mail):** It is used to maintain the integrity of the mail during its transfer from sender to receiver using a cryptographic signature. The sending server attaches a hidden digital signature to the email header using a private key; the receiving server then fetches the sender's public key from the DNS records and decrypts the signature. If it is not tampered with or altered, it means the email is unaltered and maintains integrity.

**DMARC (Domain-based Message Authentication, Reporting and Conformance):** DMARC passes if at least one of SPF or DKIM passes and is aligned with the From domain; it fails only when both fail. DMARC's real job is alignment: it checks that the domain validated by SPF (the return-path/envelope-from) and/or the domain in the DKIM signature matches the visible From: header domain. It also acts as a policy enforcer and reporting tool.

**Three DMARC Policies:**
1. **p=none (Monitoring Only):** The email will be delivered normally even if it fails the authentication check.
2. **p=quarantine (Spam Folder):** Emails that fail authentication are sent to the SPAM or JUNK folder.
3. **p=reject (Block Completely):** Emails that fail authentication are blocked entirely by the receiving server and never reach the user.

## 2. Sender / Domain Checks

In this we will analyse the domain in the From, Return-Path, and Reply-To headers. We will ensure there is no typosquatting / character substitution tricks, check domain age, and check the consistency in the domain names. Suppose the From is @microsoft.com and the Return-Path is @zetatech — there is no consistency, they are totally different domains, so it's a red flag.

## 3. Body Language / Tone Analysis of the Email Body

We will check if the mail is trying to create a panic situation / urgency or trying to tempt the user with greed via offers and discounts.

## 4. URL / Attachment Analysis

Making sure the URLs and attachments inside the mail are not malicious by using platforms like VirusTotal and sandboxes.

## 5. Identifying Hidden Artifacts

This includes tracking pixels, malformed headers, and filter evasion content blocks.

## 6. IOC Extraction

Every case study ends with a consolidated Indicators of Compromise table: sending domains, IPs, tracking domains, malicious URLs, and file hashes.

## 7. MITRE ATT&CK Mapping

Each case is tagged with the relevant ATT&CK techniques, giving the analysis a standardized vocabulary that maps to how security teams categorize and share threat intelligence.

