"""Vulnerability data: NVD, CVE.org (cvelistV5), CISA KEV, FIRST EPSS, GitHub advisories, public PoCs.

Every fetcher returns plain dicts. A CVE record looks like:
  {id, published, updated, title, desc, vendors[], products[], cvss, severity, refs[]}
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from ..util import get, log

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVELIST_DELTA = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
CVELIST_PREFIX = "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"
POC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"


def _severity(score):
    if score is None:
        return None
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


# ---------------------------------------------------------------- CISA KEV

def fetch_kev() -> dict:
    """{cve id: {date_added, vendor, product, name, desc, ransomware}}"""
    for url in KEV_URLS:
        try:
            r = get(url)
            if r.status_code != 200:
                continue
            out = {}
            for v in r.json().get("vulnerabilities", []):
                out[v["cveID"].upper()] = {
                    "date_added": v.get("dateAdded"),
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "desc": v.get("shortDescription", ""),
                    "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    "due": v.get("dueDate"),
                    "action": v.get("requiredAction", ""),
                }
            if out:
                return out
        except Exception as e:
            log.warning("KEV fetch failed from %s: %s", url.split("/")[2], e)
    return {}


# ---------------------------------------------------------------- NVD

def _nvd_cvss(metrics: dict):
    """(score, vector) from the best available CVSS entry."""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            pick = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            data = pick.get("cvssData") or {}
            if data.get("baseScore") is not None:
                return float(data["baseScore"]), data.get("vectorString") or ""
    return None, ""


_RANGE_KEYS = {"versionStartIncluding": "si", "versionStartExcluding": "se",
               "versionEndIncluding": "ei", "versionEndExcluding": "ee"}


def parse_nvd(cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    vendors, products = set(), set()
    ranges = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4 and m.get("vulnerable", True):
                    vendors.add(parts[3])
                    products.add(parts[4])
                    # Affected versions, for "is my version affected?". `v` is an exact version,
                    # "*" means any; the bounds narrow it down.
                    r = {"cpe": f"{parts[3]}:{parts[4]}", "v": parts[5] if len(parts) > 5 else "*"}
                    r.update({short: m[key] for key, short in _RANGE_KEYS.items() if m.get(key)})
                    if r not in ranges:          # the same range is often listed per edition
                        ranges.append(r)
    score, vector = _nvd_cvss(cve.get("metrics") or {})
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) or [] for d in w.get("description", [])
                   if str(d.get("value", "")).startswith("CWE-")})
    refs = [r for r in cve.get("references", []) if r.get("url", "").startswith("http")]
    fix = next((r["url"] for r in refs if "Patch" in (r.get("tags") or [])), None) \
        or next((r["url"] for r in refs if "Vendor Advisory" in (r.get("tags") or [])), None)
    return {
        "id": cve["id"].upper(),
        "published": cve.get("published"),
        "updated": cve.get("lastModified"),
        "title": "",
        "desc": desc,
        "vendors": sorted(vendors),
        "products": sorted(products),
        "cvss": score,
        "severity": _severity(score),
        "vector": vector,
        "cwe": cwes,
        "fix": fix,
        "ranges": ranges[:200],
        "ranges_partial": len(ranges) > 200,
        "refs": [r["url"] for r in refs[:5]],
        "rejected": cve.get("vulnStatus") == "Rejected",
    }


def _nvd_headers():
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _nvd_pause():
    # Public rate limit: 5 requests / 30 s without a key, 50 with one.
    time.sleep(0.7 if os.environ.get("NVD_API_KEY") else 6.5)


def fetch_nvd_window(start: datetime, end: datetime, *, modified=False) -> tuple[list[dict], bool]:
    """(records, complete). complete is False when NVD failed part-way, so the caller can retry the window."""
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    a, b = ("lastModStartDate", "lastModEndDate") if modified else ("pubStartDate", "pubEndDate")
    out, index = [], 0
    while True:
        r = get(NVD_URL, headers=_nvd_headers(), timeout=60,
                params={a: start.strftime(fmt), b: end.strftime(fmt), "startIndex": index, "resultsPerPage": 2000})
        if r.status_code != 200:
            log.warning("NVD returned HTTP %s", r.status_code)
            return out, False
        data = r.json()
        out.extend(parse_nvd(v["cve"]) for v in data.get("vulnerabilities", []))
        index += data.get("resultsPerPage", 0)
        if index >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
            break
        _nvd_pause()
    return out, True


def fetch_nvd_ids(ids: list[str]) -> list[dict]:
    out = []
    for i, cid in enumerate(ids):
        if i:
            _nvd_pause()
        try:
            r = get(NVD_URL, headers=_nvd_headers(), params={"cveId": cid}, timeout=40)
            if r.status_code == 200:
                out.extend(parse_nvd(v["cve"]) for v in r.json().get("vulnerabilities", []))
        except Exception as e:
            log.warning("NVD lookup failed for %s: %s", cid, e)
    return out


# ---------------------------------------------------------------- CVE.org (freshest data)

def _cna_ranges(affected: list) -> list[dict]:
    """Affected versions as the CVE record's author (often the vendor) gives them, in the same
    shape as NVD's ranges. New CVEs carry these days before NVD adds its own."""
    out = []
    for a in affected or []:
        cpe = next((c for c in a.get("cpes") or [] if str(c).count(":") > 4), "")
        if cpe:
            parts = cpe.split(":")
            key = f"{parts[3]}:{parts[4]}"
        else:
            vendor, product = str(a.get("vendor") or "").strip(), str(a.get("product") or "").strip()
            if not vendor or not product or "n/a" in (vendor.lower(), product.lower()):
                continue
            key = f"{vendor.lower().replace(' ', '_')}:{product.lower().replace(' ', '_')}"
        for v in a.get("versions") or []:
            if v.get("status") != "affected" or str(v.get("versionType", "")).lower() == "git":
                continue
            start = str(v.get("version") or "").strip()
            r = {"cpe": key, "v": "*"}
            if start and start not in ("0", "*", "n/a", "unspecified") and (v.get("lessThan") or v.get("lessThanOrEqual")):
                r["si"] = start
            if v.get("lessThan") and v["lessThan"] != "*":
                r["ee"] = str(v["lessThan"])
            elif v.get("lessThanOrEqual") and v["lessThanOrEqual"] != "*":
                r["ei"] = str(v["lessThanOrEqual"])
            elif start and start not in ("*", "n/a", "unspecified"):
                r["v"] = start                     # one exact version
            else:
                continue
            if r not in out:
                out.append(r)
    return out[:200]


def parse_cvelist(rec: dict) -> dict | None:
    meta = rec.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return None
    cna = (rec.get("containers") or {}).get("cna") or {}
    adp = (rec.get("containers") or {}).get("adp") or []
    desc = next((d.get("value", "") for d in cna.get("descriptions", []) if str(d.get("lang", "")).startswith("en")), "")
    vendors, products = set(), set()
    for a in cna.get("affected", []) or []:
        for field, bucket in (("vendor", vendors), ("product", products)):
            val = str(a.get(field) or "").strip()
            if val and val.lower() not in ("n/a", "unknown"):
                bucket.add(val)
    score, vector = None, ""
    for container in [cna, *adp]:
        for m in container.get("metrics", []) or []:
            for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0"):
                s = (m.get(key) or {}).get("baseScore")
                if s is not None and score is None:
                    score, vector = float(s), (m.get(key) or {}).get("vectorString") or ""
    cwes = sorted({d["cweId"] for pt in cna.get("problemTypes", []) or [] for d in pt.get("descriptions", []) or []
                   if str(d.get("cweId", "")).startswith("CWE-")})
    refs = [r for r in cna.get("references") or [] if str(r.get("url", "")).startswith("http")]
    tags = lambda r: {str(t).lower() for t in r.get("tags") or []}
    # The fix or vendor advisory: tagged as such, or a project's GitHub security advisory.
    fix = next((r["url"] for r in refs if "patch" in tags(r)), None) \
        or next((r["url"] for r in refs if "vendor-advisory" in tags(r)), None) \
        or next((r["url"] for r in refs if "/security/advisories/GHSA-" in r["url"]), None)
    ranges = _cna_ranges(cna.get("affected"))
    return {
        "vector": vector,
        "cwe": cwes,
        "id": str(meta.get("cveId", "")).upper(),
        "published": meta.get("datePublished"),
        "updated": meta.get("dateUpdated"),
        "title": str(cna.get("title") or "")[:200],
        "desc": desc,
        "vendors": sorted(vendors),
        "products": sorted(products),
        "cvss": score,
        "severity": _severity(score),
        "refs": [r["url"] for r in refs[:5]],
        "fix": fix,
        "ranges": ranges,
        "ranges_src": "cna" if ranges else None,
        "src": "cna",
    }


def fetch_cvelist_ids(ids: list[str]) -> list[dict]:
    """Specific CVE records from the CVE.org list, e.g. to pick up affected versions."""
    def url(cid):
        _, year, num = cid.split("-")
        return f"{CVELIST_PREFIX}main/cves/{year}/{int(num) // 1000}xxx/{cid}.json"

    def one(cid):
        try:
            resp = get(url(cid), retries=1)
            return parse_cvelist(resp.json()) if resp.status_code == 200 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [rec for rec in pool.map(one, ids) if rec and rec["id"]]


def fetch_cvelist_new(limit=150) -> list[dict]:
    """CVEs published in the most recent CVE.org delta (roughly the last hour)."""
    r = get(CVELIST_DELTA)
    if r.status_code != 200:
        return []
    links = [n.get("githubLink", "") for n in r.json().get("new", [])]
    links = [u for u in links if u.startswith(CVELIST_PREFIX)][:limit]

    def one(url):
        try:
            resp = get(url, retries=1)
            return parse_cvelist(resp.json()) if resp.status_code == 200 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [rec for rec in pool.map(one, links) if rec and rec["id"]]


# ---------------------------------------------------------------- EPSS

def fetch_epss(ids: list[str]) -> dict:
    """{cve id: exploitation probability 0..1}"""
    out = {}
    for i in range(0, len(ids), 80):
        try:
            r = get(EPSS_URL, params={"cve": ",".join(ids[i:i + 80])})
            if r.status_code == 200:
                for row in r.json().get("data", []):
                    out[row["cve"].upper()] = float(row["epss"])
        except Exception as e:
            log.warning("EPSS batch failed: %s", e)
    return out


# ---------------------------------------------------------------- GitHub advisories (open-source packages)

def fetch_ghsa() -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    out = []
    for sev in ("critical", "high"):
        try:
            r = get(GHSA_URL, headers=headers,
                    params={"type": "reviewed", "severity": sev, "per_page": 60, "sort": "published"})
            if r.status_code != 200:
                continue
            for a in r.json():
                if not a.get("cve_id"):
                    continue
                pkgs = {(v.get("package") or {}).get("name", "") for v in a.get("vulnerabilities", []) or []}
                ecos = {(v.get("package") or {}).get("ecosystem", "") for v in a.get("vulnerabilities", []) or []}
                score = (a.get("cvss") or {}).get("score")
                out.append({
                    "id": a["cve_id"].upper(),
                    "published": a.get("published_at"),
                    "updated": a.get("updated_at"),
                    "title": str(a.get("summary") or "")[:200],
                    "desc": str(a.get("description") or "")[:1500],
                    "vendors": [],
                    "products": sorted(p for p in pkgs if p),
                    "ecosystems": sorted(e for e in ecos if e),
                    "cvss": float(score) if score else None,
                    "severity": _severity(float(score)) if score else sev.upper(),
                    "refs": [a["html_url"]] if a.get("html_url") else [],
                })
        except Exception as e:
            log.warning("GitHub advisories fetch failed: %s", e)
    return out


# ---------------------------------------------------------------- Public PoC

def public_poc(cve_id: str) -> tuple[bool | None, str | None]:
    """(found, date of the oldest PoC repository). found is None when the lookup itself failed."""
    try:
        r = get(POC_URL.format(year=cve_id.split("-")[1], cve=cve_id), retries=0, timeout=15)
        if r.status_code == 404:
            return False, None
        if r.status_code == 200:
            repos = r.json() or []
            dates = sorted(str(x.get("created_at") or "") for x in repos if isinstance(x, dict) and x.get("created_at"))
            return bool(repos), (dates[0] if dates else None)
    except Exception:
        pass
    return None, None
