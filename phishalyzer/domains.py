"""Look-alike (typosquat / homoglyph / IDN) domain detection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

# Brands commonly impersonated in credential phishing. Extend with your own org's domains.
PROTECTED = [
    "microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com", "office365.com", "sharepoint.com",
    "google.com", "gmail.com", "apple.com", "icloud.com", "paypal.com", "amazon.com",
    "netflix.com", "dhl.com", "fedex.com", "ups.com", "docusign.net", "dropbox.com",
    "linkedin.com", "facebook.com", "instagram.com", "adobe.com", "wellsfargo.com",
    "rbc.com", "td.com", "scotiabank.com", "bmo.com", "cibc.com", "canadapost-postescanada.ca",
]

# Visual confusables an attacker can swap in. Multi-char sequences first.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"),
              ("5", "s"), ("@", "a"), ("$", "s"), ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"),
              ("с", "c"), ("х", "x"), ("і", "i"), ("ӏ", "l"), ("ԁ", "d")]

# Multi-part public suffixes we need to handle without a dependency on the full PSL
MULTI_SUFFIX = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "org.uk", "gov.uk", "ac.uk"}


def registered_domain(host: str) -> str:
    """'login.secure.paypal.com' -> 'paypal.com' (approximation of eTLD+1)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def decode_idn(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def damerau_levenshtein(a: str, b: str) -> int:
    d = {(i, -1): i + 1 for i in range(-1, len(a))}
    d.update({(-1, j): j + 1 for j in range(-1, len(b))})
    for i, ca in enumerate(a):
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            d[(i, j)] = min(d[(i - 1, j)] + 1, d[(i, j - 1)] + 1, d[(i - 1, j - 1)] + cost)
            if i and j and ca == b[j - 1] and a[i - 1] == cb:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)
    return d[(len(a) - 1, len(b) - 1)]


def unconfuse(label: str) -> str:
    for fake, real in HOMOGLYPHS:
        label = label.replace(fake, real)
    return label


@dataclass
class Lookalike:
    domain: str
    impersonates: str
    technique: str


def check_lookalike(host: str, protected: Iterable[str] = PROTECTED) -> Optional[Lookalike]:
    hit = _check(decode_idn(host.lower()), protected)
    if hit and "xn--" in host.lower():
        return Lookalike(host.lower(), hit.impersonates, f"IDN homograph - displays as '{hit.domain}'")
    return hit


def _check(host: str, protected: Iterable[str]) -> Optional[Lookalike]:
    reg = registered_domain(host)
    protected = list(protected)
    if reg in protected:
        return None
    name, _, tld = reg.partition(".")
    sub_labels = host[: -len(reg)].strip(".").split(".") if host != reg else []
    for brand in protected:
        bname, _, btld = brand.partition(".")
        if bname in sub_labels:
            return Lookalike(host, brand, "brand used as subdomain")
        if name == bname and tld != btld:
            return Lookalike(host, brand, f"same name, different TLD (.{tld})")
        if unconfuse(name) == bname and name != bname:
            return Lookalike(host, brand, "homoglyph substitution")
        if len(bname) >= 5 and damerau_levenshtein(name, bname) == 1:
            return Lookalike(host, brand, "typosquat (1 edit away)")
        if bname in name and name != bname and len(bname) >= 5:
            return Lookalike(host, brand, "brand name combined with other words")
        if bname in unconfuse(name) and len(bname) >= 5:
            return Lookalike(host, brand, "homoglyph substitution + extra words")
    return None


def all_lookalikes(hosts: Iterable[str], protected: List[str] = PROTECTED) -> List[Lookalike]:
    seen, out = set(), []
    for h in hosts:
        if h in seen:
            continue
        seen.add(h)
        hit = check_lookalike(h, protected)
        if hit:
            out.append(hit)
    return out
