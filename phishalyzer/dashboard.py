"""HTML dashboard for one or more analysed emails."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .analyzer import Report as EmailReport
from .html_report import Report, render


def build(reports: list[EmailReport]) -> Report:
    verdicts = Counter(r.verdict for r in reports)
    iocs = sum(len(v) for r in reports for v in r.iocs.values()) if reports else 0
    rows = []
    for r in sorted(reports, key=lambda r: -r.score):
        for f in r.findings:
            rows.append(
                {
                    "severity": f.severity,
                    "email": f"{Path(r.path).name} · {r.verdict} {r.score}",
                    "category": f.category,
                    "finding": f.message,
                    "mitre": f.mitre or "-",
                }
            )
    return Report(
        tool="phishalyzer",
        title="Phishing triage report",
        subtitle="Header authentication, look-alike domains, deceptive links, attachments and lure language",
        meta={"emails": len(reports)},
        kpis=[
            ("emails analysed", len(reports), "acc"),
            ("malicious", verdicts["MALICIOUS"], "bad" if verdicts["MALICIOUS"] else "good"),
            ("suspicious", verdicts["SUSPICIOUS"], "warn"),
            ("likely clean", verdicts["LIKELY CLEAN"], "good"),
            ("IOCs extracted", iocs, "acc"),
        ],
        charts=[
            ("Risk score by email (0-100)", [(f"{Path(r.path).name}", r.score) for r in sorted(reports, key=lambda r: -r.score)]),
            ("Findings by category", Counter(f.category for r in reports for f in r.findings).most_common(8)),
        ],
        columns=["email", "category", "finding", "mitre"],
        rows=rows,
        empty_message="No phishing indicators found.",
    )


def write_dashboard(reports: list[EmailReport], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(build(reports)))
