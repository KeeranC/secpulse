"""The "Major vulnerabilities" block: the vulnerability events of the last weeks that the
industry is dealing with, whether or not they were published today.

One event groups the CVEs of one product. Events can also come from press coverage alone,
when several outlets report a flaw in a widely deployed product before a CVE id is attached.
Nothing here depends on the watchlist, so the result may be published.
"""
from __future__ import annotations

import re
from datetime import datetime

from .catalog import is_catchall, norm
from .score import event_age, impact_score
from .util import age_days

_HOT = re.compile(r"zero[- ]day|0-day|exploited|under attack|in the wild|actively", re.I)


def _key(c: dict) -> tuple[str, bool]:
    """(group label, is it a specific catalogue product)."""
    prod = c.get("prod") or ""
    if prod and not is_catchall(prod):
        return prod, True
    if c.get("kev_product"):
        return c["kev_product"], False
    label = " ".join(x for x in ((c.get("vendors") or [""])[0], (c.get("products") or [""])[0]) if x)
    vendor = prod.replace(" (other)", "").replace(" (enterprise software)", "")
    return (label.replace("_", " ").title() or vendor or c["id"]), False


def _clip(text, n=220):
    text = (text or "").strip()
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "…"


def build_majors(cves: dict, stories: list[dict], sources_by_cve: dict, catalog, now: datetime,
                 *, days=30, limit=20) -> list[dict]:
    groups: dict[str, dict] = {}
    for c in cves.values():
        if event_age(c, now) > days:
            continue
        news = len(sources_by_cve.get(c["id"], ()))
        if not (c.get("kev") or news >= 2 or (c.get("prod") and (c.get("cvss") or 0) >= 9)
                or (c.get("epss") or 0) >= 0.5):
            continue
        label, specific = _key(c)
        g = groups.setdefault(norm(label), {"product": label, "specific": specific, "members": [], "stories": []})
        g["members"].append((impact_score(c, news, now), c))

    by_cve = {c["id"]: k for k, g in groups.items() for _, c in g["members"]}
    for s in stories:
        if age_days(s["updated"], now) > days or s["kind"] in ("advisory", "vendor"):
            continue
        keys = {by_cve[c] for c in s["cves"] if c in by_cve}
        if not keys and s["category"] == "vulnerabilities" and s["n_sources"] >= 2 and s.get("prods"):
            # Covered by several outlets, in a catalogue product, but no CVE we track yet.
            k = norm(s["prods"][0])
            groups.setdefault(k, {"product": s["prods"][0], "specific": True, "members": [], "stories": []})
            keys = {k}
        for k in keys:
            groups[k]["stories"].append(s)

    out = []
    for g in groups.values():
        members = sorted(g["members"], key=lambda m: -m[0])
        g["stories"].sort(key=lambda s: -s["importance"])
        cat = catalog.find(g["product"]) if g["specific"] else None
        lead = members[0][1] if members else None
        press = set()
        for _, c in members:
            press |= set(sources_by_cve.get(c["id"], ()))
        for s in g["stories"]:
            press |= {x["source"] for x in s["sources"]}
        if lead:
            impact = members[0][0] + min(2 * (len(members) - 1), 6)
            dates = [d for d in (lead.get("published"), lead.get("kev_date"), lead.get("news_date")) if d]
        else:
            top = g["stories"][0]
            impact = 15 + 5 * min(len(press), 5) + (10 if _HOT.search(top["title"]) else 0) \
                - 0.7 * age_days(top["updated"], now)
            dates = [s["updated"] for s in g["stories"]]
        cs = [c for _, c in members]
        out.append({
            "product": g["product"],
            "what": (cat or {}).get("what", ""),
            "area": (cat or {}).get("area") or (lead or {}).get("area", ""),
            "broad": bool(cat) or bool(lead and lead.get("prod")),
            "cves": [c["id"] for c in cs[:6]],
            "n_cves": len(cs),
            "cvss": max((c.get("cvss") or 0 for c in cs), default=None) or None,
            "epss": max((c.get("epss") or 0 for c in cs), default=None) or None,
            "kev": any(c.get("kev") for c in cs),
            "ransomware": any(c.get("kev_ransomware") for c in cs),
            "poc": any(c.get("poc") for c in cs),
            "due": min((c["kev_due"] for c in cs if c.get("kev_due")), default=None),
            "kind": (lead or {}).get("kind") or (g["stories"][0].get("kind_hint", "") if g["stories"] else ""),
            "path": (lead or {}).get("path", ""),
            "fix": (lead or {}).get("fix"),
            "text": _clip((lead or {}).get("why") or (lead or {}).get("title") or (lead or {}).get("desc")
                          or (g["stories"][0]["title"] if g["stories"] else "")),
            "date": max(str(d)[:10] for d in dates) if dates else None,
            # Real dates, not "last mentioned": first publication and the latest KEV listing.
            "published": min((str(c["published"])[:10] for c in cs if c.get("published")), default=None),
            "kev_date": max((str(c["kev_date"])[:10] for c in cs if c.get("kev_date")), default=None),
            "news": len(press),
            "stories": [{"title": s["title"], "url": s["url"], "source": s["sources"][0]["source"]}
                        for s in g["stories"][:2]],
            "impact": round(impact, 1),
        })
    for e in out:
        # Fit for the front page: a widely deployed product the industry is actually talking
        # about. Exploited needs two outlets; unexploited needs three (patch days, big disclosures).
        e["front"] = e["broad"] and (e["news"] >= 2 if e["kev"] else e["news"] >= 3)
        # One plain sentence: what the product is, so an unfamiliar name is not a riddle.
        e["headline"] = e["what"] or _clip(e["text"], 120)
    # Two lists in one: what is being exploited, and what is critical but not exploited yet.
    out.sort(key=lambda e: -e["impact"])
    return [e for e in out if e["kev"]][:limit] + [e for e in out if not e["kev"]][:limit]
