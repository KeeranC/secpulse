"""Shared helpers: HTTP, time, text and JSON files."""
from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

log = logging.getLogger("secpulse")

UA = "SecPulse/1.0 (feed reader)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def get(url, *, params=None, headers=None, timeout=25, retries=2):
    """GET with a generic User-Agent and a couple of retries on transient errors."""
    hdrs = {"User-Agent": UA}
    hdrs.update(headers or {})
    last = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, params=params, headers=hdrs, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(3 * (attempt + 1))
                continue
            return r
        except requests.RequestException as e:  # network trouble: retry, then give up
            last = e
            time.sleep(2 * (attempt + 1))
    raise last


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_dt(s) -> datetime | None:
    """Parse the ISO-ish timestamps used by NVD, CVE.org, KEV and our own files."""
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    if len(s) == 10:
        s += "T00:00:00+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def age_days(s, now: datetime) -> float:
    dt = parse_dt(s)
    return 1e9 if dt is None else (now - dt).total_seconds() / 86400


def strip_html(text) -> str:
    return _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", text or ""))).strip()


def find_cves(text) -> list[str]:
    return sorted({m.upper() for m in CVE_RE.findall(text or "")})


def sid(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


def load_json(path: Path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path: Path, obj, *, compact=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":") if compact else None,
                      indent=None if compact else 1)
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
