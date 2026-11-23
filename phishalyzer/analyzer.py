"""Parse an .eml file and collect phishing indicators with explainable scoring."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .domains import PROTECTED, all_lookalikes, registered_domain

URL_RE = re.compile(r"""(?:https?|hxxps?)://[^\s"'<>)\]]+""", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
              "support", "rest", "cam", "icu", "monster", "sbs", "cfd"}
DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "lnk",
                 "iso", "img", "vhd", "msi", "jar", "one", "html", "htm", "svg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xls", "doc"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "ace", "cab"}
MAGIC = {b"MZ": "Windows executable", b"PK\x03\x04": "ZIP/Office Open XML", b"%PDF": "PDF",
         b"\xd0\xcf\x11\xe0": "OLE2 (legacy Office)", b"Rar!": "RAR", b"7z\xbc\xaf": "7-Zip"}
URGENCY = ["urgent", "immediately", "within 24 hours", "account will be", "suspended", "verify your",
           "confirm your", "unusual sign-in", "unusual activity", "password expires", "action required",
           "final notice", "invoice attached", "payment failed", "wire transfer", "gift card",
           "click here", "login to", "update your payment", "your mailbox is full"]
WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5}


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    mitre: str = ""


@dataclass
class Report:
    path: str
    subject: str = ""
    sender: str = ""
    findings: List[Finding] = field(default_factory=list)
    urls: List[Dict] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)
    hops: List[Dict] = field(default_factory=list)
    auth: Dict[str, str] = field(default_factory=dict)
    iocs: Dict[str, List[str]] = field(default_factory=dict)

    def add(self, severity, category, message, mitre=""):
        self.findings.append(Finding(severity, category, message, mitre))

    @property
    def score(self) -> int:
        return min(100, sum(WEIGHTS[f.severity] for f in self.findings))

    @property
    def verdict(self) -> str:
        return "MALICIOUS" if self.score >= 60 else "SUSPICIOUS" if self.score >= 25 else "LIKELY CLEAN"


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self._href: Optional[str] = None
        self._text: List[str] = []
        self.forms: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        if tag == "form":
            self.forms.append(a.get("action", ""))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _bodies(msg: EmailMessage) -> Tuple[str, str]:
    text, html = "", ""
    for part in msg.walk():
        if part.is_attachment() or part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = part.get_payload(decode=True).decode("latin-1", "replace")
        if ctype == "text/plain":
            text += content
        elif ctype == "text/html":
            html += content
    return text, html


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_headers(msg: EmailMessage, r: Report):
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain_of(from_addr)
    r.sender = f"{from_name} <{from_addr}>" if from_name else from_addr

    reply = [a for _, a in getaddresses([str(v) for v in msg.get_all("Reply-To", [])])]
    for a in reply:
        if _domain_of(a) and registered_domain(_domain_of(a)) != registered_domain(from_dom):
            r.add("high", "header", f"Reply-To ({a}) differs from From domain ({from_dom}) - replies go to the attacker",
                  "T1566")
    rp = parseaddr(str(msg.get("Return-Path", "")))[1]
    if rp and from_dom and registered_domain(_domain_of(rp)) != registered_domain(from_dom):
        r.add("medium", "header", f"Return-Path domain ({_domain_of(rp)}) differs from From ({from_dom})")

    # Display-name spoofing: the name claims a brand or contains an e-mail address
    if from_name:
        embedded = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", from_name)
        if embedded and _domain_of(embedded.group()) != from_dom:
            r.add("high", "header", f"Display name contains a different address: '{from_name}'", "T1656")
        for brand in PROTECTED:
            b = brand.split(".")[0]
            if len(b) >= 5 and b in from_name.lower() and registered_domain(from_dom) != brand:
                r.add("medium", "header", f"Display name mentions '{b}' but sender domain is {from_dom}", "T1656")
                break

    # Authentication-Results (SPF / DKIM / DMARC) as stamped by the receiving server
    ar = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", ar, re.I)
        r.auth[mech] = m.group(1).lower() if m else "none"
    sev = {"fail": "high", "softfail": "medium", "permerror": "medium", "none": "low", "temperror": "low"}
    for mech, res in r.auth.items():
        if res in sev and not (res == "none" and not ar):
            r.add(sev[res], "authentication", f"{mech.upper()} result: {res}")
    if not ar:
        r.add("low", "authentication", "No Authentication-Results header (cannot confirm SPF/DKIM/DMARC)")

    msgid = str(msg.get("Message-ID", ""))
    mid_dom = msgid.strip("<>").rsplit("@", 1)[-1].lower() if "@" in msgid else ""
    if mid_dom and from_dom and registered_domain(mid_dom) != registered_domain(from_dom) \
            and not mid_dom.endswith(("outlook.com", "google.com", "gmail.com", "amazonses.com", "mail.gmail.com")):
        r.add("low", "header", f"Message-ID domain ({mid_dom}) does not match sender ({from_dom})")

    # Received chain (bottom = origin)
    for hop in reversed(msg.get_all("Received", []) or []):
        hop = " ".join(str(hop).split())
        ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", hop)
        frm = re.search(r"from\s+(\S+)", hop)
        when = hop.rsplit(";", 1)[-1].strip() if ";" in hop else ""
        try:
            when = parsedate_to_datetime(when).isoformat()
        except (TypeError, ValueError):
            pass
        r.hops.append({"from": frm.group(1) if frm else "?", "ip": ip.group(1) if ip else "", "time": when})


def _url_host(u: str) -> str:
    try:
        return (urlparse(u.replace("hxxp", "http")).hostname or "").lower()
    except ValueError:
        return ""


def check_urls(text: str, html: str, r: Report):
    parser = _LinkParser()
    if html:
        parser.feed(html)
    urls = {u.rstrip(".,;") for u in URL_RE.findall(text + " " + html)}
    anchors = {href: label for href, label in parser.links}
    urls |= {h for h in anchors if h.lower().startswith(("http", "data:", "javascript:"))}

    for u in sorted(urls):
        host = _url_host(u)
        reasons = []
        if u.lower().startswith(("data:", "javascript:")):
            reasons.append(("high", "script/data URI in link"))
        if host:
            try:
                ipaddress.ip_address(host)
                reasons.append(("high", "raw IP address instead of a domain"))
            except ValueError:
                pass
            if registered_domain(host) in SHORTENERS:
                reasons.append(("medium", "URL shortener hides the destination"))
            if host.rsplit(".", 1)[-1] in RISKY_TLDS:
                reasons.append(("medium", f"high-abuse TLD .{host.rsplit('.', 1)[-1]}"))
            if host.count(".") >= 4:
                reasons.append(("low", "many subdomain levels"))
            if "xn--" in host:
                reasons.append(("high", "punycode (IDN) domain - possible homograph"))
        if "@" in urlparse(u).netloc:
            reasons.append(("high", "'@' in URL - the real host comes after it"))
        if u.lower().startswith("http://"):
            reasons.append(("low", "unencrypted http"))
        label = anchors.get(u, "")
        shown = _url_host(label) if URL_RE.match(label or "") else ""
        if shown and host and registered_domain(shown) != registered_domain(host):
            reasons.append(("high", f"link text shows {shown} but points to {host}"))
        for sev, why in reasons:
            r.add(sev, "url", f"{defang(u)[:90]} - {why}", "T1566.002")
        r.urls.append({"url": u, "host": host, "text": label, "flags": [w for _, w in reasons]})

    for action in parser.forms:
        r.add("high", "url", f"HTML form in e-mail body posts to {defang(action) or '(same page)'} - credential harvesting",
              "T1566.002")
    return {u["host"] for u in r.urls if u["host"]}


def check_attachments(msg: EmailMessage, r: Report):
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        data = part.get_payload(decode=True) or b""
        exts = name.lower().split(".")[1:]
        ext = exts[-1] if exts else ""
        magic = next((desc for sig, desc in MAGIC.items() if data.startswith(sig)), "unknown")
        info = {"filename": name, "size": len(data), "content_type": part.get_content_type(),
                "md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
                "magic": magic}
        r.attachments.append(info)
        if len(exts) >= 2 and ext in DANGEROUS_EXT | MACRO_EXT:
            r.add("critical", "attachment", f"Double extension '{name}' disguises a .{ext} file", "T1036.007")
        elif ext in DANGEROUS_EXT:
            r.add("high", "attachment", f"Executable/script attachment type .{ext}: {name}", "T1566.001")
        if ext in MACRO_EXT:
            r.add("high", "attachment", f"Macro-capable Office document: {name}", "T1566.001")
        if ext in ARCHIVE_EXT:
            r.add("medium", "attachment", f"Archive attachment (often used to bypass filters): {name}", "T1566.001")
        declared = part.get_content_type()
        if magic == "Windows executable" and (ext not in {"exe", "scr", "dll"} or
                                              declared not in {"application/octet-stream",
                                                               "application/x-msdownload",
                                                               "application/x-dosexec"}):
            r.add("critical", "attachment", f"{name} is declared as {declared} but is a Windows executable "
                  "(MZ header)", "T1036.008")


def check_language(subject: str, text: str, html: str, r: Report):
    body = re.sub(r"<[^>]+>", " ", html) if html and not text else text
    blob = f"{subject} {body}".lower()
    hits = sorted({k for k in URGENCY if k in blob})
    if len(hits) >= 3:
        r.add("medium", "content", f"Pressure / credential-lure language: {', '.join(hits[:6])}")
    elif hits:
        r.add("low", "content", f"Urgency language: {', '.join(hits)}")


def analyze(path: str | Path, protected: List[str] = PROTECTED) -> Report:
    raw = Path(path).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    r = Report(path=str(path), subject=str(msg.get("Subject", "")))
    check_headers(msg, r)
    text, html = _bodies(msg)
    hosts = check_urls(text, html, r)
    check_attachments(msg, r)
    check_language(r.subject, text, html, r)

    from_dom = _domain_of(parseaddr(str(msg.get("From", "")))[1])
    reply_doms = {_domain_of(a) for _, a in getaddresses([str(v) for v in msg.get_all("Reply-To", [])])}
    ordered = [from_dom] + sorted(reply_doms) + sorted(hosts)
    for la in all_lookalikes([d for d in ordered if d], protected):
        where = "From" if la.domain == from_dom else "Reply-To" if la.domain in reply_doms else "link"
        r.add("critical" if where != "link" else "high", "lookalike",
              f"{where} domain {la.domain} impersonates {la.impersonates} ({la.technique})", "T1583.001")

    origin_ips = [h["ip"] for h in r.hops if h["ip"] and not ipaddress.ip_address(h["ip"]).is_private]
    r.iocs = {
        "sender": [from_dom] if from_dom else [],
        "domains": sorted({u["host"] for u in r.urls if u["flags"] and registered_domain(u["host"]) not in SHORTENERS}
                          | {la.domain for la in all_lookalikes(
            [d for d in {from_dom, *reply_doms} if d], protected)}),
        "urls": sorted(u["url"] for u in r.urls if u["flags"]),
        "ips": sorted(set(origin_ips[:1])),
        "sha256": [a["sha256"] for a in r.attachments],
    }
    return r
