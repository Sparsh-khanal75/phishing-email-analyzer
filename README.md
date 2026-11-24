# Phishing Email Analyzer

A command-line tool that triages suspicious `.eml` files the way a SOC analyst does. It checks the sender's authentication, the headers, the links, the attachments and the wording, then gives an **explainable verdict** and a **defanged IOC list** ready for blocking. Every finding is tagged with MITRE ATT&CK where one applies.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen) ![Tests](https://img.shields.io/badge/tests-6%20passing-success) ![MITRE](https://img.shields.io/badge/MITRE-T1566-red)

## Why

Phishing is the most common way into an organisation, and "user reported a suspicious email" is one of the most frequent tickets a Tier-1 SOC analyst handles. Each report needs the same checks: does SPF/DKIM/DMARC pass, is Reply-To redirected, does the link go where the text says, and is the attachment what it claims to be. This tool runs all of them in under a second, and every point it adds to the score comes with a stated reason.

## What it checks

| Area | Checks | ATT&CK |
|---|---|---|
| Authentication | SPF, DKIM, DMARC results from `Authentication-Results` | — |
| Headers | Reply-To / Return-Path mismatch, display-name spoofing (brand in name, address in name), Message-ID domain, full `Received` route with origin IP | T1566, T1656 |
| Look-alike domains | Typosquats (Damerau-Levenshtein = 1), homoglyphs (`rn`→`m`, `0`→`o`, Cyrillic letters), **IDN/punycode homographs**, brand-as-subdomain (`login.microsoftonline.com.evil.xyz`), brand + words, wrong TLD | T1583.001 |
| Links | Text-vs-target mismatch, raw-IP URLs, shorteners, high-abuse TLDs, `@` in URL, `data:`/`javascript:` links, HTML forms in the body | T1566.002 |
| Attachments | Double extensions, executable/script/ISO/LNK/OneNote types, macro-capable Office files, archives, **magic-byte check** (declared PDF that is really an `MZ` executable), MD5/SHA-256 | T1566.001, T1036.007, T1036.008 |
| Content | Urgency and credential-lure language | — |

Scoring: critical 40, high 25, medium 12, low 5 (capped at 100). **≥ 60 = MALICIOUS, ≥ 25 = SUSPICIOUS**, otherwise LIKELY CLEAN.

## Demo

**1. Credential phishing:** a fake "Microsoft 365" sign-in alert

```
 From    : Microsoft 365 Security <no-reply@micros0ft-security.com>
 Verdict : MALICIOUS   (risk score 100/100)
 Auth    : SPF=fail  DKIM=none  DMARC=fail
 Route   : mail.micros0ft-security.com [203.0.113.88]  ->  mx.corp-mail.example [10.0.0.25]
 CRITICAL lookalike  From domain micros0ft-security.com impersonates microsoft.com (homoglyph substitution + extra words)
 CRITICAL lookalike  Reply-To domain outlook-support.xyz impersonates outlook.com (brand name combined with other words)
 HIGH     header     Reply-To (it-helpdesk@outlook-support.xyz) differs from From domain - replies go to the attacker
 HIGH     url        hxxps://login[.]microsoftonline[.]com[.]verify-session[.]xyz/... - link text shows
                     login.microsoftonline.com but points to login.microsoftonline.com.verify-session.xyz
 ...
 IOCs to block / hunt (defanged):
   domains  login[.]microsoftonline[.]com[.]verify-session[.]xyz
   domains  micros0ft-security[.]com
   domains  outlook-support[.]xyz
```

**2. Compromised vendor:** SPF, DKIM and DMARC all **pass**, and the email is still malicious

```
 From    : Northwind Accounts Payable <ap@northwind-traders.example>
 Verdict : MALICIOUS   (risk score 100/100)
 Auth    : SPF=pass  DKIM=pass  DMARC=pass
 CRITICAL attachment  Double extension 'Invoice_88213.pdf.exe' disguises a .exe file            [T1036.007]
 CRITICAL attachment  Invoice_88213.pdf.exe is declared as application/pdf but is a Windows
                      executable (MZ header)                                                     [T1036.008]
 MEDIUM   content     Pressure / credential-lure language: immediately, invoice attached, payment failed, wire transfer
```

This is the most important lesson in the project. **Email authentication only proves which server sent a message, not that the message is safe.** When a real supplier's mailbox is compromised (vendor email compromise / BEC), every authentication check passes. Only content and attachment analysis catches it.

**3. Legitimate GitHub notification:** `LIKELY CLEAN (0/100)`, with zero findings.

## Usage

```bash
python analyze.py samples/credential_phish.eml
python analyze.py reported/*.eml --json triage.json        # batch + JSON for a SIEM/SOAR
python analyze.py mail.eml --protect yourcompany.com       # also catch look-alikes of your own domain
python -m unittest discover -s tests
```

No third-party packages are needed; it uses only the Python standard library. The exit code is `2` if any email is MALICIOUS, so it can drive automation. To get an `.eml` file: in Gmail, use *Show original → Download original*; in Outlook on the web, use *Download* on the message.

## Project structure

```
analyze.py                  CLI and report
phishalyzer/analyzer.py     header, URL, attachment and content checks; scoring; IOC extraction
phishalyzer/domains.py      look-alike detection (edit distance, homoglyphs, IDN, subdomain abuse)
samples/                    three synthetic emails + the script that generates them
tests/                      unit tests and sample-based regression tests
```

## Limitations and next steps

- It does not open attachments or visit links. That is deliberate (it's safe to run on a workstation), and sandbox detonation is out of scope.
- Look-alike detection compares against a built-in list of commonly impersonated brands. Use `--protect` to add your organisation's own domains.
- Planned: enrich IOCs with VirusTotal / URLhaus reputation, check domain age through WHOIS, and parse `.msg` (Outlook) files.

> All sample emails are synthetic. They use reserved `.example` domains and RFC 5737 IP addresses.

## Author

**Sparsh Khanal** · [GitHub](https://github.com/Sparsh-khanal75) · [LinkedIn](https://www.linkedin.com/in/Sparsh-khanal75)
