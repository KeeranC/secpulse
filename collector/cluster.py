"""Group articles about the same event into one story, and give each story a category."""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import timedelta

from .catalog import is_catchall, weakness_kind
from .util import find_cves, parse_dt

STOP = set("""a an and are as at be been by for from has have how in into is it its new of on or over says
that the their this to via was were what when who why will with after amid about more than you your can
could may now not out up all one two using used use security cyber cybersecurity attack attacks attackers
hackers hacker update updates week weekly report reports""".split())

_WORD = re.compile(r"[a-z0-9][a-z0-9\.\-]*[a-z0-9]|[a-z0-9]")


def tokens(title: str) -> frozenset:
    return frozenset(w for w in _WORD.findall(title.lower()) if len(w) > 2 and w not in STOP)


def cluster(items: list[dict], *, window_hours=48, threshold=0.3) -> list[list[dict]]:
    """Greedy single pass, oldest first. Two items join when their titles overlap strongly,
    or when they name the same CVE and overlap a little. Overlap is weighted by how rare a
    word is, so "PHP" or "Maersk" counts for much more than "critical" or "flaw". Vendor
    advisories use a stricter threshold because their titles are formulaic."""
    window = timedelta(hours=window_hours)
    ordered = sorted(items, key=lambda i: i["published"])
    all_toks = {it["id"]: tokens(it["title"]) for it in ordered}
    df = Counter(t for toks in all_toks.values() for t in toks)
    n = max(len(ordered), 1)
    weight = {t: math.log(1 + n / c) for t, c in df.items()}

    def _jaccard(a, b) -> float:
        if not a or not b:
            return 0.0
        return sum(weight[t] for t in a & b) / sum(weight[t] for t in a | b)

    clusters: list[dict] = []
    by_token: dict[str, set] = defaultdict(set)
    by_cve: dict[str, set] = defaultdict(set)

    for it in ordered:
        toks, when, cves = all_toks[it["id"]], parse_dt(it["published"]), set(it.get("cves") or [])
        candidates = Counter()
        for t in toks:
            for ci in by_token[t]:
                candidates[ci] += 1
        shared_cve = set()
        if 0 < len(cves) <= 4:
            for c in cves:
                shared_cve |= by_cve[c]
        best, best_sim = None, 0.0
        for ci in set(candidates) | shared_cve:
            c = clusters[ci]
            if when - c["last"] > window:
                continue
            # Different outlets describing one event word it differently, so a loose match is
            # enough. The same feed repeating itself ("... new victim: X") must match closely.
            other = [t for t, src in zip(c["toks"], c["srcs"]) if src != it["source"]][:6]
            same = [t for t, src in zip(c["toks"], c["srcs"]) if src == it["source"]][:6]
            need = 0.75 if it["kind"] == "advisory" or c["kind"] == "advisory" else threshold
            if ci in shared_cve and len(c["cves"]) <= 6:
                need = 0.15
            sim_other = max((_jaccard(toks, m) for m in other), default=0.0)
            sim_same = max((_jaccard(toks, m) for m in same), default=0.0)
            sim = max(sim_other if sim_other >= need else 0.0, sim_same if sim_same >= 0.8 else 0.0)
            if sim > best_sim:
                best, best_sim = ci, sim
        if best is None:
            best = len(clusters)
            clusters.append({"items": [], "toks": [], "srcs": [], "cves": set(), "last": when, "kind": it["kind"]})
        c = clusters[best]
        c["items"].append(it)
        c["srcs"].append(it["source"])
        c["toks"].append(toks)
        c["cves"] |= cves
        c["last"] = max(c["last"], when)
        for t in toks:
            by_token[t].add(best)
        for cve in cves:
            by_cve[cve].add(best)
    return [c["items"] for c in clusters]


# ---------------------------------------------------------------- categories

CATEGORIES = ["vulnerabilities", "breaches", "ransomware", "threat-actors", "research", "policy", "tools"]

_RULES = [
    ("ransomware", r"ransomware|extortion|lockbit|ransom\b|akira|qilin|black ?basta|clop"),
    ("breaches", r"breach|data leak|leaked|stolen data|data theft|exposed (data|records|database)|"
                 r"million (users|customers|records)|hacked|compromised accounts"),
    ("threat-actors", r"\bapt\d*\b|state[- ]sponsored|nation[- ]state|espionage|campaign|botnet|malware|"
                      r"phishing|backdoor|trojan|stealer|north korea|lazarus|threat actor|spyware"),
    ("policy", r"regulat|legislation|\bbill\b|sanction|\bnis2\b|gdpr|arrest|sentenced|indict|court|\bfine[ds]?\b|"
               r"lawsuit|\bsec\b|executive order|compliance|extradit|pleads?"),
    ("vulnerabilities", r"cve-\d|vulnerabilit|zero[- ]day|0-day|\bflaw|patch|exploit|\brce\b|"
                        r"remote code execution|privilege escalation|auth(entication)? bypass|schwachstelle|"
                        r"sicherheitsl"),
    ("tools", r"open[- ]source tool|released? (a |an )?(new )?(tool|framework|scanner)|\bv?\d+\.\d+ released"),
]
_RULES = [(cat, re.compile(rx, re.I)) for cat, rx in _RULES]
_KIND_DEFAULT = {"research": "research", "advisory": "vulnerabilities", "breach": "breaches"}


def categorize(story_items: list[dict]) -> str:
    lead = story_items[0]
    text = " ".join(i["title"] for i in story_items) + " " + lead.get("teaser", "")
    has_cve = any(i.get("cves") for i in story_items)
    for cat, rx in _RULES:
        if cat == "ransomware" and rx.search(text):
            return cat
    if has_cve:
        return "vulnerabilities"
    for cat, rx in _RULES:
        if rx.search(text):
            return cat
    for it in story_items:
        if it.get("cat_hint"):
            return it["cat_hint"]
    return _KIND_DEFAULT.get(lead["kind"], "research" if lead["kind"] == "community" else "threat-actors")


def _story_facts(cve_ids: list[str], cves: dict) -> dict | None:
    """Triage facts of the most serious CVE a story is about."""
    known = [cves[c] for c in cve_ids if c in cves]
    if not known:
        return None
    c = max(known, key=lambda c: c.get("score") or 0)
    return {"cve": c["id"], "cvss": c.get("cvss"), "epss": c.get("epss"), "kev": bool(c.get("kev")),
            "ransomware": bool(c.get("kev_ransomware")), "poc": bool(c.get("poc")),
            "kind": c.get("kind", ""), "path": c.get("path", ""), "fix": c.get("fix"), "due": c.get("kev_due")}


def build_stories(items: list[dict], kev_ids: set, catalog=None, cves: dict | None = None) -> list[dict]:
    cves = cves or {}
    stories = []
    # Vendor feeds (security releases of a named product) stand on their own: never merged
    # with press coverage, always tagged with their product.
    vendor = [i for i in items if i["kind"] == "vendor"]
    for it in vendor:
        cat = catalog.find(it.get("product", "")) if catalog else None
        stories.append({
            "prods": [cat["name"] if cat else it.get("product", "")], "area": (cat or {}).get("area", ""),
            "facts": _story_facts(it.get("cves") or [], cves), "kind_hint": "",
            "id": it["id"], "title": it["title"], "url": it["url"], "kind": "vendor",
            "category": "vulnerabilities", "published": it["published"], "updated": it["published"],
            "sources": [{"source": it["source"], "title": it["title"], "url": it["url"]}], "n_sources": 1,
            "cves": (it.get("cves") or [])[:10], "teaser": it.get("teaser", ""), "summary": "",
            "importance": 0, "security": bool(it.get("security")),
        })
    for group in cluster([i for i in items if i["kind"] != "vendor"]):
        lead = max(group, key=lambda i: (i["weight"], -len(i["title"])))
        first = min(group, key=lambda i: i["published"])
        sources = []
        for it in sorted(group, key=lambda i: -i["weight"]):
            if it["source"] not in [s["source"] for s in sources]:
                sources.append({"source": it["source"], "title": it["title"], "url": it["url"]})
        story_cves = sorted({c for it in group for c in it.get("cves") or []})
        teaser =max((it.get("teaser", "") for it in group if it["source"] == lead["source"]), key=len, default="")
        titles = " . ".join(i["title"] for i in group)
        # Products: named in a headline first, then those of the CVEs the story cites.
        prods = [p["name"] for p in catalog.match_text(titles)] if catalog else []
        cve_ids = story_cves
        if len(cve_ids) <= 3:
            prods += [cves[c]["prod"] for c in cve_ids if c in cves and cves[c].get("prod")]
        specific = [p for p in dict.fromkeys(prods) if not is_catchall(p)]
        prods = (specific or list(dict.fromkeys(prods)))[:3]
        area = next((p["area"] for p in (catalog.products if catalog else []) if prods and p["name"] == prods[0]), "")
        # An exploited CVE only lifts a story that is about it, not one that mentions it in passing.
        headline_cves = set(find_cves(titles))
        about = headline_cves | (set(cve_ids) if len(cve_ids) <= 2 else set())
        importance = (lead["weight"] + 2 * (len(sources) - 1) + (4 if kev_ids & about else 0)
                      + (1 if prods else 0))
        stories.append({
            "prods": prods,
            "area": area,
            "facts": _story_facts(sorted(headline_cves) or (cve_ids if len(cve_ids) <= 3 else []), cves),
            "kind_hint": weakness_kind([], titles),
            "id": first["id"],
            "title": lead["title"],
            "url": lead["url"],
            "kind": lead["kind"],
            "category": categorize(group),
            "published": first["published"],
            "updated": max(i["published"] for i in group),
            "sources": sources[:8],
            "n_sources": len(sources),
            "cves": story_cves[:10],
            "teaser": teaser,
            "summary": "",
            "importance": importance,
        })
    return stories
