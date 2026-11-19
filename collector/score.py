"""Your stack (watchlist), risk and impact scoring, and the alert decision."""
from __future__ import annotations

from datetime import datetime

from .catalog import Catalog, clean, is_catchall, kw_re, norm
from .versions import split_name_version
from .util import age_days


class Watchlist:
    """The owner's stack, in two tiers.

    core:  products they run. A catalogue name resolves to that product's exact identifiers;
           other strings match as vendor, product or keyword; mappings may give `vendor`,
           `products` and `keywords`.
    areas: catalogue areas (for example "network-edge"). Broad on purpose, so they only
           raise a phone alert when something in the area is actively exploited.

    A core entry with `mode: info` is a product that updates itself (a browser, Windows):
    you want to know, but only an exploited flaw needs you to do something.
    """

    def __init__(self, raw, catalog: Catalog | None = None):
        if isinstance(raw, dict):
            core = raw.get("core") or raw.get("watchlist") or []
            areas = raw.get("areas") or []
        else:
            core, areas = raw or [], []
        self.areas = {norm(a) for a in areas if a}
        self.entries = []
        for e in core:
            info = False
            if isinstance(e, dict) and not ({"vendor", "products", "keywords"} & e.keys()):
                # {name: Google Chrome, mode: info}: the name works like a plain line.
                info = str(e.get("mode") or "").strip().lower() == "info"
                e = " ".join(str(x) for x in (e.get("name"), e.get("version")) if x)
            if isinstance(e, str):
                if not e.strip():
                    continue
                e, version = split_name_version(e)       # "GitLab 19.5.1"
                hit = catalog.find(e) if catalog else None
                if hit and not is_catchall(hit["name"]):
                    self.entries.append({"name": hit["name"], "cat": {hit["name"]}, "version": version, "info": info})
                    continue
                # "Google Chrome" names the catalogue's "Google Chrome / Chromium": catalogue
                # products whose name contains the words count too (the portal does the same).
                rx = kw_re(e)
                cats = {p["name"] for p in (catalog.products if catalog else []) if rx.search(norm(p["name"]))}
                if hit:
                    cats.add(hit["name"])          # "Microsoft": the catch-all row and every Microsoft product
                self.entries.append({"name": e, "any": norm(e), "keywords": [rx], "version": version,
                                     "info": info, "cat": cats})
            elif isinstance(e, dict):
                kws = list(e.get("keywords") or [])
                vendor = norm(e.get("vendor")) or None
                name = str(e.get("name") or e.get("vendor") or (kws[0] if kws else "")).strip()
                if not name:
                    continue
                if not vendor and not kws:
                    kws = [name]
                self.entries.append({"name": name, "vendor": vendor, "version": str(e.get("version") or "") or None,
                                     "info": str(e.get("mode") or "").strip().lower() == "info",
                                     "products": [norm(p) for p in e.get("products") or []],
                                     "keywords": [kw_re(k) for k in kws]})

    def is_info(self, name: str) -> bool:
        return any(e.get("info") for e in self.entries if e["name"] == name)

    def version_of(self, name: str) -> str | None:
        return next((e.get("version") for e in self.entries if e["name"] == name), None)

    def __len__(self):
        return len(self.entries) + len(self.areas)

    def match(self, cve: dict) -> tuple[str, str] | None:
        """(entry name, "core" | "area") for the strongest match, or None."""
        vendors = {norm(v) for v in cve.get("vendors") or []}
        products = {norm(p) for p in cve.get("products") or []}
        # Descriptions mention other products in passing; only lean on them when the CVE
        # carries no structured vendor data yet.
        text = clean(f"{cve.get('kev_product', '')} {cve.get('title', '')}")
        if not vendors:
            text += " " + clean(cve.get("desc", ""))
        for e in self.entries:
            if e.get("cat") and cve.get("prod") in e["cat"]:
                return e["name"], "core"
            if e.get("any") and (e["any"] in vendors or e["any"] in products):
                return e["name"], "core"
            if e.get("vendor") and e["vendor"] in vendors:
                if not e["products"] or any(p in products for p in e["products"]):
                    return e["name"], "core"
            if any(rx.search(text) for rx in e.get("keywords") or []):
                return e["name"], "core"
        if cve.get("area") and norm(cve["area"]) in self.areas:
            return cve.get("prod") or cve["area"], "area"
        return None


def risk_score(cve: dict) -> int:
    """0..100 for the radar. Exploitation evidence outweighs theoretical severity."""
    score = 0.0
    if cve.get("kev"):
        score += 40
    score += 25 * float(cve.get("epss") or 0)
    score += 2.5 * float(cve.get("cvss") or 0)
    if cve.get("poc"):
        score += 10
    return round(min(score, 100))


def event_age(cve: dict, now: datetime) -> float:
    """Days since this CVE last became news: published, added to KEV, or written about."""
    return min(age_days(cve.get("published"), now), age_days(cve.get("kev_date"), now),
               age_days(cve.get("news_date"), now))


def impact_score(cve: dict, news: int, now: datetime) -> float:
    """How much this CVE matters to the industry right now: exploitation, press coverage,
    how widely the product is deployed, severity, with a mild penalty for age.
    Independent of the watchlist, so it may be published."""
    age = event_age(cve, now)
    # NVD often scores days after CISA lists a CVE as exploited; unscored is not harmless.
    cvss = float(cve.get("cvss") or (8.0 if cve.get("kev") else 0))
    # Reachable over the network with no login and no victim action: the drop-everything class.
    preauth = cve.get("path") == "remote, no login, no user action" and float(cve.get("cvss") or 0) >= 9.5
    # Internet-facing perimeter devices (firewalls, VPN gateways) are the favourite way in.
    return (35 * bool(cve.get("kev")) + 5 * min(news, 5) + 15 * bool(cve.get("prod"))
            + 8 * (cve.get("area") == "network-edge") + 12 * bool(preauth and cve.get("prod"))
            + 1.5 * cvss + 10 * float(cve.get("epss") or 0)
            + 5 * bool(cve.get("poc")) - 0.7 * min(age, 60))


# Alert levels, highest first. A CVE re-alerts only when it climbs to a higher level.
#        reason shown in the notification          ntfy priority   tags
LEVELS = {
    5: ("Exploited and in your stack", 5, ["rotating_light"]),
    4: ("In your stack", 4, ["warning"]),
    2: ("Big exploited flaw in the news", 3, ["fire"]),
    1: ("High exploitation risk", 3, ["chart_with_upwards_trend"]),
}


def alert_level(cve: dict, match: tuple[str, str] | None, cfg: dict, now: datetime) -> int:
    """0 = no alert, otherwise a key of LEVELS."""
    tier = match[1] if match else None
    cvss = float(cve.get("cvss") or 0)
    epss = float(cve.get("epss") or 0)
    poc = bool(cve.get("poc"))
    fresh = age_days(cve.get("published"), now) <= cfg["fresh_days"]
    kev_fresh = bool(cve.get("kev")) and age_days(cve.get("kev_date"), now) <= cfg["kev_fresh_days"]

    if tier in ("core", "info") and cve.get("kev") and (kev_fresh or fresh):
        return 5
    if tier == "core" and fresh and (cvss >= cfg["watch_cvss"] or epss >= cfg["watch_epss"] or poc):
        return 4
    # Outside your products only the big cases, the same rule as the portal's emergency block:
    # a widely deployed product (catalogue), covered by several outlets, critical and exploited.
    # Areas only shape the portal, never the phone.
    if not cve.get("prod") or int(cve.get("news") or 0) < cfg.get("any_min_sources", 2):
        return 0
    # Without a CVSS score yet, only a clear signal counts: ransomware use or a high EPSS.
    if cve.get("cvss") is None:
        critical = bool(cve.get("ransomware")) or epss >= cfg["any_epss"]
    else:
        critical = cvss >= cfg.get("emergency_cvss", 9.0)   # unscored: NVD lags KEV
    if kev_fresh and critical:
        return 2
    if fresh and (epss >= cfg["any_epss"] or (cvss >= cfg["any_cvss_with_poc"] and poc)):
        return 1
    return 0
