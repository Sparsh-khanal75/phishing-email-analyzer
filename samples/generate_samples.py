#!/usr/bin/env python3
"""Generate the three sample .eml files used in the README and tests (synthetic data only)."""
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).parent


def save(msg, name):
    (OUT / name).write_bytes(bytes(msg))
    print("wrote", name)


# 1) Credential phishing: Microsoft 365 look-alike, failed auth, deceptive link
m = EmailMessage()
m["Received"] = ("from mx.corp-mail.example (mx.corp-mail.example [10.0.0.25]) by mailstore.corp.example; "
                 "Tue, 18 Nov 2026 14:02:13 +0000")
m["Received"] = ("from mail.micros0ft-security.com (unknown [203.0.113.88]) by mx.corp-mail.example; "
                 "Tue, 18 Nov 2026 14:02:11 +0000")
m["Authentication-Results"] = ("mx.corp-mail.example; spf=fail smtp.mailfrom=micros0ft-security.com; "
                               "dkim=none; dmarc=fail header.from=micros0ft-security.com")
m["Return-Path"] = "<bounce@mailer-secure-mx.top>"
m["From"] = '"Microsoft 365 Security" <no-reply@micros0ft-security.com>'
m["Reply-To"] = "it-helpdesk@outlook-support.xyz"
m["To"] = "a.sharma@corp.example"
m["Subject"] = "Action required: unusual sign-in activity on your account"
m["Message-ID"] = "<20261118140211.4471@mailer-secure-mx.top>"
m["Date"] = "Tue, 18 Nov 2026 14:02:09 +0000"
m.set_content("We detected unusual sign-in activity. Verify your account within 24 hours or it will be "
              "suspended. Visit https://bit.ly/3xMsVerify")
m.add_alternative("""<html><body>
<p>We detected <b>unusual sign-in activity</b> on your Microsoft 365 account.</p>
<p>Verify your account <b>within 24 hours</b> or your mailbox will be suspended.</p>
<p><a href="https://login.microsoftonline.com.verify-session.xyz/auth?u=a.sharma">https://login.microsoftonline.com</a></p>
<p>Or <a href="https://bit.ly/3xMsVerify">click here</a>.</p>
<p>Microsoft 365 Security Team</p></body></html>""", subtype="html")
save(m, "credential_phish.eml")

# 2) Compromised-vendor invoice: authentication PASSES, payload is the attachment
m = EmailMessage()
m["Received"] = ("from mail.northwind-traders.example (mail.northwind-traders.example [198.51.100.40]) "
                 "by mx.corp-mail.example; Wed, 19 Nov 2026 09:15:40 +0000")
m["Authentication-Results"] = ("mx.corp-mail.example; spf=pass smtp.mailfrom=northwind-traders.example; "
                               "dkim=pass header.d=northwind-traders.example; dmarc=pass")
m["Return-Path"] = "<ap@northwind-traders.example>"
m["From"] = '"Northwind Accounts Payable" <ap@northwind-traders.example>'
m["To"] = "finance@corp.example"
m["Subject"] = "RE: Invoice 88213 - payment failed, wire transfer details updated"
m["Message-ID"] = "<a91f2c@northwind-traders.example>"
m["Date"] = "Wed, 19 Nov 2026 09:15:38 +0000"
m.set_content("Hi,\n\nPayment failed on our last invoice. Please process the wire transfer immediately "
              "using the updated details in the invoice attached.\n\nRegards,\nAccounts Payable")
fake_exe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56 + b"This program cannot be run in DOS mode." + b"\x00" * 200
m.add_attachment(fake_exe, maintype="application", subtype="pdf", filename="Invoice_88213.pdf.exe")
m.add_attachment(b"PK\x03\x04" + b"\x00" * 120, maintype="application", subtype="zip",
                 filename="Remittance_Advice.zip")
save(m, "malware_invoice.eml")

# 3) Legitimate notification
m = EmailMessage()
m["Received"] = ("from out-21.smtp.github.com (out-21.smtp.github.com [192.30.252.204]) by "
                 "mx.corp-mail.example; Thu, 20 Nov 2026 08:01:02 +0000")
m["Authentication-Results"] = "mx.corp-mail.example; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass"
m["Return-Path"] = "<noreply@github.com>"
m["From"] = "GitHub <noreply@github.com>"
m["To"] = "sparsh@corp.example"
m["Subject"] = "[GitHub] A new SSH key was added to your account"
m["Message-ID"] = "<6f0c1e2d@github.com>"
m["Date"] = "Thu, 20 Nov 2026 08:01:00 +0000"
m.set_content("A new public key was added to your account. If you did not add it, review your keys at "
              "https://github.com/settings/keys")
save(m, "legit_notification.eml")
