#!/usr/bin/env python3
"""
Phishing Email Analyzer - triage a suspicious .eml the way a SOC analyst would.

Usage:
  python analyze.py samples/credential_phish.eml
  python analyze.py suspicious/*.eml --json report.json
  python analyze.py mail.eml --protect corp.example        # add your own domain to look-alike checks
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from phishalyzer.analyzer import analyze, defang
from phishalyzer.domains import PROTECTED

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m",
          "MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "LIKELY CLEAN": "\033[92m"}


def c(key, text, on):
    return f"{COLORS.get(key, '')}{text}\033[0m" if on else text


def print_report(r, color):
    print("=" * 92)
    print(f" File    : {r.path}")
    print(f" Subject : {r.subject}")
    print(f" From    : {r.sender}")
    print(f" Verdict : {c(r.verdict, r.verdict, color)}   (risk score {r.score}/100)")
    print(f" Auth    : SPF={r.auth.get('spf')}  DKIM={r.auth.get('dkim')}  DMARC={r.auth.get('dmarc')}")
    if r.hops:
        print(" Route   : " + "  ->  ".join(f"{h['from']} [{h['ip']}]" for h in r.hops))
    print("-" * 92)
    for f in sorted(r.findings, key=lambda f: SEV_ORDER[f.severity]):
        tag = f" [{f.mitre}]" if f.mitre else ""
        print(f" {c(f.severity, f'{f.severity.upper():<8}', color)} {f.category:<14} {f.message}{tag}")
    if r.attachments:
        print("-" * 92)
        for a in r.attachments:
            print(f" Attachment: {a['filename']}  ({a['size']} bytes, declared {a['content_type']}, "
                  f"actual {a['magic']})")
            print(f"   SHA256 {a['sha256']}")
    if any(r.iocs.values()) and r.verdict != "LIKELY CLEAN":
        print("-" * 92)
        print(" IOCs to block / hunt (defanged):")
        for kind, vals in r.iocs.items():
            for v in vals:
                print(f"   {kind:<8} {defang(v) if kind != 'sha256' else v}")
    print("=" * 92)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Analyse .eml files for phishing indicators")
    ap.add_argument("emails", nargs="+")
    ap.add_argument("--json", help="write full reports as JSON")
    ap.add_argument("--protect", action="append", default=[], help="extra domain to protect from look-alikes")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()

    reports = [analyze(p, PROTECTED + args.protect) for p in args.emails]
    for r in reports:
        print_report(r, color)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{**asdict(r), "score": r.score, "verdict": r.verdict} for r in reports], fh, indent=2)
        print(f"JSON written to {args.json}")
    return 2 if any(r.verdict == "MALICIOUS" for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
