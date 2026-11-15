"""Write the static portal: copy site/ and emit the JSON it reads.

Only public information is written here. Nothing derived from the watchlist may be added.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from .util import age_days, iso, parse_dt, save_json


def _clip(text: str, n: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "…"


def _public_ranges(ranges) -> list[dict]:
    """Ranges without the CPE name; editions often repeat the same bounds, so drop repeats."""
    out = []
    for r in ranges or []:
        r = {k: v for k, v in r.items() if k != "cpe"}
        if r not in out:
            out.append(r)
    return out


def public_cves(cves: dict, now: datetime, retention: int, always: set) -> list[dict]:
    out = []
    for c in cves.values():
        kev_recent = c.get("kev") and age_days(c.get("kev_date"), now) <= retention
        notable = ((c.get("cvss") or 0) >= 7 or (c.get("epss") or 0) >= 0.1 or c.get("poc")
                   or (c.get("news") or 0) >= 2)
        # Every CVE of a catalogue product in the window, so the browser can check *your* products
        # without the published data depending on (and revealing) the watchlist.
        catalogue = c.get("prod") and age_days(c.get("published"), now) <= retention
        if not (c["id"] in always or kev_recent or catalogue or (age_days(c.get("published"), now) <= 14 and notable)):
            continue
        out.append({
            "prod": c.get("prod", ""), "area": c.get("area", ""), "kind": c.get("kind", ""),
            "path": c.get("path", ""), "fix": c.get("fix"), "due": c.get("kev_due"), "news": c.get("news", 0),
            "fix_date": c.get("fix_date"), "poc_date": c.get("poc_date"),
            # Affected versions of the catalogue product, for the browser's version check.
            "ranges": _public_ranges(c.get("ranges"))[:60] or None,
            "ranges_partial": bool(c.get("ranges_partial")) or len(c.get("ranges") or []) > 60 or None,
            "id": c["id"], "published": c.get("published"), "title": _clip(c.get("title"), 160),
            "desc": _clip(c.get("desc"), 320), "vendors": (c.get("vendors") or [])[:4],
            "products": (c.get("products") or [])[:6], "cvss": c.get("cvss"), "epss": c.get("epss"),
            "kev": bool(c.get("kev")), "kev_date": c.get("kev_date"), "ransomware": bool(c.get("kev_ransomware")),
            "poc": bool(c.get("poc")), "score": c.get("score", 0), "why": c.get("why", ""),
            "label": c.get("kev_product", ""), "refs": (c.get("refs") or [])[:3],
        })
    out.sort(key=lambda c: (c["id"] not in always, -c["score"], c["id"]))
    out = out[:4000]
    out.sort(key=lambda c: (-c["score"], c["id"]))
    return out


def trends(cves: dict, kev: dict, now: datetime) -> dict:
    days = [(now - timedelta(days=d)).strftime("%Y-%m-%d") for d in range(13, -1, -1)]
    crit, kev_adds = Counter(), Counter()
    vendors = Counter()
    for c in cves.values():
        day = (c.get("published") or "")[:10]
        if (c.get("cvss") or 0) >= 9:
            crit[day] += 1
        if (c.get("cvss") or 0) >= 7 and age_days(c.get("published"), now) <= 7:
            for v in (c.get("vendors") or [])[:1]:
                vendors[v.replace("_", " ")] += 1
    for k in kev.values():
        kev_adds[(k.get("date_added") or "")[:10]] += 1
    return {
        "days": days,
        "critical": [crit[d] for d in days],
        "kev": [kev_adds[d] for d in days],
        "top_vendors": vendors.most_common(6),
    }


def copy_site(site_dir: Path, out_dir: Path) -> None:
    """Copy the portal and stamp its stylesheet and script with a content hash.

    Without the stamp a browser can pair a fresh index.html with a cached style.css or app.js
    from an older version, which shows a broken page until the cache expires.
    """
    shutil.copytree(site_dir, out_dir, dirs_exist_ok=True)
    index = out_dir / "index.html"
    if not index.exists():
        return
    html = index.read_text(encoding="utf-8")

    def stamp(m):
        f = out_dir / m.group(2)
        if not f.exists():
            return m.group(0)
        return f'{m.group(1)}{m.group(2)}?v={hashlib.sha256(f.read_bytes()).hexdigest()[:10]}"'
    html = re.sub(r'((?:href|src)=")(style\.css|app\.js)(?:\?v=\w+)?"', stamp, html)
    index.write_bytes(html.encode("utf-8"))


def publish(out_dir: Path, site_dir: Path, *, stories, cves, kev, brief, feed_status, ai_on, now, retention,
            majors=(), catalog=None):
    out_dir = Path(out_dir)
    if site_dir.exists():
        copy_site(site_dir, out_dir)
    data = out_dir / "data"

    pub_stories = []
    for s in sorted(stories, key=lambda s: s["updated"], reverse=True):
        if age_days(s["updated"], now) > retention:
            continue
        pub_stories.append({**{k: s[k] for k in ("id", "title", "url", "kind", "category", "published", "updated",
                                                  "sources", "n_sources", "cves", "importance", "prods", "area",
                                                  "facts")},
                            "vkind": (s.get("facts") or {}).get("kind") or s.get("kind_hint", ""),
                            "summary": s.get("summary") or _clip(s.get("teaser"), 260),
                            "ai": bool(s.get("summary"))})
    always = {cid for m in majors for cid in m["cves"]} | {s["facts"]["cve"] for s in stories if s.get("facts")}
    pub_cves = public_cves(cves, now, retention, always)

    save_json(data / "stories.json", pub_stories)
    save_json(data / "cves.json", pub_cves)
    save_json(data / "majors.json", list(majors))
    save_json(data / "products.json", [{"name": p["name"], "area": p["area"], "what": p["what"]}
                                       for p in (catalog.products if catalog else [])])
    save_json(data / "brief.json", brief or {})
    save_json(data / "meta.json", {
        "generated": iso(now),
        "counts": {"stories": len(pub_stories), "cves": len(pub_cves),
                   "kev_total": len(kev), "sources": len(feed_status)},
        "trends": trends(cves, kev, now),
        "feeds": feed_status,
        "ai": ai_on,
    })
    return len(pub_stories), len(pub_cves)


if __name__ == "__main__":   # refresh only the portal files of a local build: python -m collector.build
    root = Path(__file__).resolve().parent.parent
    copy_site(root / "site", root / "public")
    print("site copied to public/")
