"""Is my version affected? Compares a version against NVD's affected ranges.

The portal has a JavaScript copy of these rules (site/app.js, `affected`); keep them in step.

Answers are "yes", "no" or "unknown". "unknown" is the honest answer whenever the data is
missing or incomplete, and callers treat it like "yes".
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[a-z]+")
_PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1, "pre": -1}


def parse(version: str) -> list:
    """'19.5.4' -> [19, 5, 4]; '0.83.0-rc.1' -> [0, 83, 0, -1, 1]; pre-release tags sort before the release."""
    out = []
    for tok in _TOKEN.findall(str(version or "").lower().lstrip("v")):
        out.append(int(tok) if tok.isdigit() else _PRE.get(tok, 0))
    return out


def compare(a: str, b: str) -> int:
    pa, pb = parse(a), parse(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _in_range(version: str, r: dict) -> bool:
    exact = r.get("v", "*")
    if exact not in ("*", "-", "") and not any(k in r for k in ("si", "se", "ei", "ee")):
        return compare(version, exact) == 0
    if "si" in r and compare(version, r["si"]) < 0:
        return False
    if "se" in r and compare(version, r["se"]) <= 0:
        return False
    if "ei" in r and compare(version, r["ei"]) > 0:
        return False
    if "ee" in r and compare(version, r["ee"]) >= 0:
        return False
    return True


def affected(version: str | None, ranges: list[dict] | None, partial: bool = False) -> str:
    if not version or not parse(version):
        return "unknown"
    if not ranges:
        return "unknown"
    if any(_in_range(version, r) for r in ranges):
        return "yes"
    # A truncated list may have dropped the matching entry.
    return "unknown" if partial else "no"


def fixed_in(version: str, ranges: list[dict]) -> str | None:
    """The lowest 'fixed in' version above the given one, when NVD names it."""
    cands = [r["ee"] for r in ranges or [] if "ee" in r and _in_range(version, r)]
    return min(cands, key=parse) if cands else None


_SPLIT = re.compile(r"^(.*?)\s+v?(\d+(?:[.\-]\w+)*)$")


def split_name_version(entry: str) -> tuple[str, str | None]:
    """'GitLab 19.5.1' -> ('GitLab', '19.5.1'); 'Acme Vault' -> ('Acme Vault', None)."""
    m = _SPLIT.match(str(entry or "").strip())
    return (m.group(1).strip(), m.group(2)) if m else (str(entry or "").strip(), None)
