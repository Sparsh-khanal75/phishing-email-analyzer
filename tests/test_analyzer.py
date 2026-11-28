import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishalyzer.analyzer import analyze, defang  # noqa: E402
from phishalyzer.domains import check_lookalike, damerau_levenshtein, registered_domain  # noqa: E402

SAMPLES = ROOT / "samples"


class DomainTests(unittest.TestCase):
    def test_techniques(self):
        cases = {
            "paypa1.com": "homoglyph",
            "rnicrosoft.com": "homoglyph",          # rn looks like m
            "xn--pypal-4ve.com": "IDN homograph",   # Cyrillic 'а' in paypal
            "paypal.co": "different TLD",
            "dropbox-share.com": "combined",
            "login.microsoftonline.com.verify-session.xyz": "subdomain",
            "amazom.com": "typosquat",
        }
        for domain, technique in cases.items():
            hit = check_lookalike(domain)
            self.assertIsNotNone(hit, domain)
            self.assertIn(technique, hit.technique, domain)

    def test_legitimate_domains_not_flagged(self):
        for d in ["www.paypal.com", "login.microsoftonline.com", "github.com", "mail.google.com", "bbc.co.uk"]:
            self.assertIsNone(check_lookalike(d), d)

    def test_helpers(self):
        self.assertEqual(registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(damerau_levenshtein("paypal", "papyal"), 1)  # transposition
        self.assertEqual(defang("http://evil.com"), "hxxp://evil[.]com")


class SampleTests(unittest.TestCase):
    def test_credential_phish(self):
        r = analyze(SAMPLES / "credential_phish.eml")
        self.assertEqual(r.verdict, "MALICIOUS")
        msgs = " ".join(f.message for f in r.findings)
        self.assertIn("link text shows login.microsoftonline.com", msgs)
        self.assertEqual(r.auth, {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        self.assertNotIn("bit.ly", r.iocs["domains"])  # never block a whole shortener

    def test_authenticated_but_malicious_attachment(self):
        r = analyze(SAMPLES / "malware_invoice.eml")
        self.assertEqual(r.auth["dmarc"], "pass")
        self.assertEqual(r.verdict, "MALICIOUS")
        self.assertEqual(r.attachments[0]["magic"], "Windows executable")

    def test_legitimate_mail_is_clean(self):
        r = analyze(SAMPLES / "legit_notification.eml")
        self.assertEqual(r.verdict, "LIKELY CLEAN")
        self.assertEqual(r.findings, [])



class DashboardTests(unittest.TestCase):
    def test_html_dashboard_covers_all_emails(self):
        import tempfile

        from phishalyzer.dashboard import write_dashboard

        reports = [analyze(p) for p in sorted(SAMPLES.glob("*.eml"))]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            write_dashboard(reports, str(out))
            page = out.read_text(encoding="utf-8")
        self.assertIn("Phishing triage report", page)
        self.assertIn("credential_phish.eml", page)
        self.assertIn("MALICIOUS", page)
        self.assertNotIn("<script src", page)


if __name__ == "__main__":
    unittest.main()
