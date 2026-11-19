"""SecPulse collector. One run: fetch, score, alert, summarise, publish.

    python -m collector.main              normal run
    python -m collector.main --dry-run    send nothing, print what would alert (local use only)
    python -m collector.main --test-notify  send one test push and exit

Runs in public CI: log counts only, never anything derived from the watchlist.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

import re

from . import build, notify
from .catalog import Catalog, attack_condition, attack_path, weakness_kind
from .cluster import build_stories
from .majors import build_majors
from .versions import affected
from .score import LEVELS, Watchlist, alert_level, risk_score
from .sources import rss, vulns
from .summarize import Summarizer
from .util import age_days, iso, load_json, log, parse_dt, save_json, utcnow

ROOT = Path(__file__).resolve().parent.parent
VULN_TITLE = re.compile(r"vulnerab|zero[- ]day|0-day|\bflaws?\b|\bbugs?\b|exploit|patch|\brce\b|bypass|"
                        r"code execution|privilege escalation", re.I)

DEFAULTS = {
    "timezone": "Europe/Berlin", "brief_hour": 7, "portal_url": "", "ntfy_server": "https://ntfy.sh",
    "retention_days": 30, "backfill_days": 30, "majors_days": 30,
    "alerts": {"watch_cvss": 7.0, "watch_epss": 0.10, "any_epss": 0.50, "any_cvss_with_poc": 9.8,
               "fresh_days": 7, "kev_fresh_days": 5, "bundle_over": 5},
    "ai": {"enabled": True, "language": "English", "summary_model": "", "brief_model": "", "fallback": False,
           "max_story_summaries_per_run": 25, "max_cve_notes_per_run": 15},
}


def load_settings() -> dict:
    user = yaml.safe_load((ROOT / "config" / "settings.yaml").read_text(encoding="utf-8")) or {}
    cfg = {**DEFAULTS, **{k: v for k, v in user.items() if not isinstance(v, dict)}}
    for section in ("alerts", "ai"):
        cfg[section] = {**DEFAULTS[section], **(user.get(section) or {})}
    cfg["portal_url"] = os.environ.get("PORTAL_URL") or cfg["portal_url"] or ""
    # Model ids are configured outside the repository (secrets or local environment).
    cfg["ai"]["summary_model"] = os.environ.get("AI_SUMMARY_MODEL") or cfg["ai"]["summary_model"]
    cfg["ai"]["brief_model"] = os.environ.get("AI_BRIEF_MODEL") or cfg["ai"]["brief_model"]
    cfg["ai"]["fallback"] = os.environ.get("AI_FALLBACK") == "1" or bool(cfg["ai"]["fallback"])
    return cfg


def load_watchlist():
    """The raw stack definition: a mapping with `core` and `areas`, or a plain list."""
    raw = os.environ.get("WATCHLIST_YAML")
    path = ROOT / "config" / "watchlist.yaml"
    if not raw and path.exists():
        raw = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw) if raw else None
    except yaml.YAMLError:
        # Never print the parser's message: it quotes the offending lines of the (secret) list.
        log.error("the watchlist is not valid YAML; running without it")
        data = None
    return data if isinstance(data, (dict, list)) else []


def load_vendor_feeds(raw) -> list[dict]:
    """Vendor feeds live in the private watchlist (`feeds:`), since they name your products."""
    out = []
    for f in (raw.get("feeds") if isinstance(raw, dict) else None) or []:
        if isinstance(f, dict) and str(f.get("url", "")).startswith("https://") and f.get("product"):
            out.append({"weight": 1, "max": 10, **f, "kind": "vendor", "name": str(f.get("name") or f["product"])})
    return out


def merge_cve(store: dict, rec: dict, now):
    cid = rec.get("id")
    if not cid:
        return
    if rec.pop("rejected", False):
        store.pop(cid, None)
        return
    old = store.get(cid)
    if old is None:
        rec["first_seen"] = iso(now)
        store[cid] = rec
        return
    for key in ("title", "desc", "published"):
        if rec.get(key) and not old.get(key):
            old[key] = rec[key]
    for key in ("vendors", "products"):
        old[key] = sorted(set(old.get(key) or []) | set(rec.get(key) or []))
    if rec.get("cvss") is not None:
        old["cvss"], old["severity"] = rec["cvss"], rec.get("severity")
    cna = rec.get("src") == "cna"
    for key in ("vector", "cwe", "fix"):
        # NVD tags patch links; the record author's link only fills a gap.
        if rec.get(key) and not (cna and key == "fix" and old.get("fix")):
            old[key] = rec[key]
    # NVD's analysed ranges win over the record author's; the author's fill the days before.
    if rec.get("ranges") and not (cna and old.get("ranges") and not old.get("ranges_src")):
        old["ranges"], old["ranges_partial"] = rec["ranges"], rec.get("ranges_partial", False)
        old["ranges_src"] = rec.get("ranges_src")
    old["refs"] = list(dict.fromkeys((old.get("refs") or []) + (rec.get("refs") or [])))[:6]
    old["updated"] = max(str(old.get("updated") or ""), str(rec.get("updated") or "")) or None


def collect_cves(cves, items, kev, state, cfg, now, first_run):
    retention = cfg["retention_days"]
    # NVD has its own watermark: it only moves on when the whole window arrived, so an outage
    # (NVD often answers 503) is caught up on the next run instead of leaving a gap.
    since = parse_dt(state.get("nvd_since"))
    backfill = since is None or (now - since).days >= cfg["backfill_days"]
    if backfill:
        recs, complete = vulns.fetch_nvd_window(now - timedelta(days=cfg["backfill_days"]), now)
    else:
        recs, complete = vulns.fetch_nvd_window(since - timedelta(hours=1), now, modified=True)
    if complete:
        state["nvd_since"] = iso(now)
    log.info("NVD: %d records%s", len(recs), "" if complete else " (incomplete, retried next run)")
    fresh = vulns.fetch_cvelist_new()
    log.info("CVE.org delta: %d new", len(fresh))
    ghsa = vulns.fetch_ghsa()
    log.info("GitHub advisories: %d", len(ghsa))
    for rec in [*recs, *fresh, *ghsa]:
        if rec["id"] in cves or rec.get("rejected") or age_days(rec.get("published"), now) <= retention:
            merge_cve(cves, rec, now)

    # Young, serious CVEs without version data yet: read the CVE record itself once, which
    # often lists affected and fixed versions days before NVD does.
    todo = [cid for cid, c in cves.items() if not c.get("ranges") and not c.get("cna_checked")
            and age_days(c.get("published"), now) <= 14 and ((c.get("cvss") or 0) >= 7 or c.get("kev"))]
    # Widely deployed products first, then the newest: those are the ones you look at.
    todo.sort(key=lambda cid: str(cves[cid].get("published") or ""), reverse=True)
    todo = sorted(todo, key=lambda cid: not cves[cid].get("prod"))[:300]
    if todo:
        got = vulns.fetch_cvelist_ids(todo)
        for rec in got:
            merge_cve(cves, rec, now)
        for cid in todo:
            cves[cid]["cna_checked"] = True
        log.info("CVE records checked for versions: %d (%d with versions)", len(todo), sum(1 for r in got if r.get("ranges")))

    # KEV entries added recently: make sure they exist even when the CVE itself is old.
    for cid, k in kev.items():
        if cid not in cves and age_days(k["date_added"], now) <= retention:
            cves[cid] = {"id": cid, "published": None, "updated": None, "title": k["name"], "desc": k["desc"],
                         "vendors": [k["vendor"].lower()], "products": [k["product"].lower()],
                         "cvss": None, "severity": None, "refs": [], "first_seen": iso(now)}

    # Look up details for KEV entries and for CVEs the news is talking about.
    mentions = Counter(c for it in items.values() for c in it.get("cves") or [])
    tried = state.setdefault("nvd_tried", {})
    # CVEs named in a headline first, then exploited ones we only know from KEV, then the rest.
    from .util import find_cves
    headline = [c for it in items.values() for c in find_cves(it["title"])]
    want = [c for c in headline if c not in cves]
    want += [c for c in cves if cves[c].get("published") is None]
    want += [c for c, _ in mentions.most_common() if c not in cves]
    want = [c for c in dict.fromkeys(want) if age_days(tried.get(c), now) > 1]
    cap = 40 if os.environ.get("NVD_API_KEY") else 15
    for rec in vulns.fetch_nvd_ids(want[:cap]):
        merge_cve(cves, rec, now)
    for c in want[:cap]:
        tried[c] = iso(now)
    for c in [c for c, ts in tried.items() if age_days(ts, now) > 7]:
        del tried[c]
    return set(mentions)


def enrich(cves, kev, state, catalog, cfg, now):
    for cid, c in cves.items():
        k = kev.get(cid)
        if k:
            c.update(kev=True, kev_date=k["date_added"], kev_ransomware=k["ransomware"],
                     kev_product=f"{k['vendor']} {k['product']}".strip(), kev_due=k.get("due"))
            c["title"] = c.get("title") or k["name"]
        # Plain-language triage facts, all from public data.
        hit = catalog.match_cve(c)
        c["prod"], c["area"] = (hit["name"], hit["area"]) if hit else ("", "")
        # Version ranges only matter for catalogue products, and only those of that product
        # (CPE data also lists unrelated products that bundle the vulnerable one).
        if c.get("ranges"):
            c["ranges"] = catalog.ranges_for(hit, c["ranges"]) if hit else []
        # When a fix was first listed. Only dated when we actually know:
        #  - we saw this CVE without a fix on an earlier run, and now it has one: today;
        #  - it had a fix from the start and was published within two days: shipped with it.
        # Anything else (a fix already present on an older CVE) stays undated.
        if not c.get("fix"):
            c["nofix_seen"] = True
        elif not c.get("fix_date"):
            if c.get("nofix_seen"):
                c["fix_date"] = iso(now)
            elif age_days(c.get("published"), now) <= 2:
                c["fix_date"] = c.get("published")
        c["kind"] = weakness_kind(c.get("cwe"), f"{c.get('title', '')} {c.get('desc', '')}")
        c["path"] = attack_path(c.get("vector"))
        c["cond"] = attack_condition(c.get("vector"))

    stale = age_days(state.get("epss_ts"), now) > 0.25
    # EPSS only where it can change a decision; low-severity CVEs in unknown products are skipped.
    ids = [cid for cid, c in cves.items() if (stale or c.get("epss") is None) and (
        c.get("kev") or c.get("prod") or (c.get("cvss") or 0) >= 7
        or (c.get("cvss") is None and age_days(c.get("published"), now) <= 5))]
    if ids:
        for cid, val in vulns.fetch_epss(ids).items():
            cves[cid]["epss"] = val
        if stale:
            state["epss_ts"] = iso(now)

    # Which CVEs get a PoC lookup must not depend on the watchlist: the stored result sits on a
    # public branch, and a lookup on an otherwise unremarkable CVE would give the watchlist away.
    checked = state.setdefault("poc_checked", {})
    cand = [c for c in cves.values()
            if (not c.get("poc") or not c.get("poc_date")) and age_days(checked.get(c["id"]), now) > 0.5
            and (age_days(c.get("published"), now) <= 14 or age_days(c.get("kev_date"), now) <= 14)
            and (c.get("kev") or (c.get("cvss") or 0) >= 7 or (c.get("epss") or 0) >= 0.1)]
    cand.sort(key=lambda c: (not c.get("kev"), -(c.get("cvss") or 0), c["id"]))
    cand = cand[:150]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for c, (found, since) in zip(cand, pool.map(lambda c: vulns.public_poc(c["id"]), cand)):
            if found is not None:
                c["poc"] = found
                if found:
                    c["poc_date"] = since or iso(now)
                checked[c["id"]] = iso(now)
    for cid in [c for c in checked if c not in cves]:
        del checked[cid]
    for c in cves.values():
        c["score"] = risk_score(c)


def fallback_brief(stories):
    top = sorted((s for s in stories if s["kind"] != "advisory"), key=lambda s: -s["importance"])[:6]
    if not top:
        return None
    return {"headline": "", "ai": False, "deep_dive": "",
            "bullets": [{"text": s["title"], "ref": s["id"]} for s in top]}


def run(args) -> int:
    cfg = load_settings()
    sources = yaml.safe_load((ROOT / "config" / "sources.yaml").read_text(encoding="utf-8"))
    feeds, exclude = sources["feeds"], rss.compile_exclude(sources.get("exclude"))
    catalog = Catalog.load(ROOT / "config" / "products.yaml")
    raw_wl = load_watchlist()
    wl = Watchlist(raw_wl, catalog)
    vendor_feeds = load_vendor_feeds(raw_wl)
    # On the public site, nothing may hint at your stack: vendor releases stay out of the
    # published JSON, the saved state and the (public) CI log.
    public = os.environ.get("PUBLIC_SITE") == "1"
    topic = os.environ.get("NTFY_TOPIC", "").strip()
    server = os.environ.get("NTFY_SERVER") or cfg["ntfy_server"]
    now = utcnow()

    if args.test_notify:
        if not topic:
            print("NTFY_TOPIC is not set.")
            return 1
        ok = notify.send(server, topic, title="SecPulse test", tags=["white_check_mark"],
                         message="Notifications work. Real alerts will look like this.",
                         click=cfg["portal_url"] or None)
        print("sent" if ok else "failed")
        return 0 if ok else 1

    data = Path(args.data)
    state = load_json(data / "state.json", {})
    items = load_json(data / "items.json", {})
    cves = load_json(data / "cves.json", {})
    first_run = "last_run" not in state
    retention = cfg["retention_days"]
    log.info("watchlist entries: %d | notifications: %s | first run: %s",
             len(wl), "on" if topic else "off", first_run)

    # ---- news
    fetched, feed_status = rss.fetch_all(feeds + vendor_feeds, exclude)
    vendor_status = {f["name"]: feed_status.pop(f["name"], None) for f in vendor_feeds}
    vendor_items = [it for it in fetched if it["kind"] == "vendor" and age_days(it["published"], now) <= retention]
    fetched = [it for it in fetched if it["kind"] != "vendor"]
    if vendor_feeds:
        log.info("vendor feeds: %d ok, %d failed",
                 sum(isinstance(v, int) for v in vendor_status.values()),
                 sum(not isinstance(v, int) for v in vendor_status.values()))
    fresh_items = [it for it in fetched if it["id"] not in items and age_days(it["published"], now) <= retention]
    # Headlines about a flaw often leave the CVE id to the article body: read it from the page.
    scan = [it for it in fresh_items if not it["cves"] and it["kind"] in ("news", "research")
            and VULN_TITLE.search(it["title"])][:20]
    with ThreadPoolExecutor(max_workers=6) as pool:
        for it, found in zip(scan, pool.map(lambda it: rss.page_cves(it["url"]), scan)):
            it["cves"] = found
    log.info("article pages read for CVE ids: %d, ids found in %d", len(scan), sum(1 for it in scan if it["cves"]))
    for it in fresh_items:
        items[it["id"]] = it
    bad = {k: v for k, v in feed_status.items() if not isinstance(v, int)}
    log.info("feeds: %d ok, %d failed, %d items stored", len(feed_status) - len(bad), len(bad), len(items))
    for name, err in bad.items():
        log.warning("feed failed: %s (%s)", name, err)
    for iid in [i for i, it in items.items() if age_days(it["published"], now) > retention]:
        del items[iid]

    # ---- vulnerabilities
    kev = vulns.fetch_kev()
    log.info("KEV catalogue: %d entries", len(kev))
    mentioned = collect_cves(cves, items, kev, state, cfg, now, first_run)
    enrich(cves, kev, state, catalog, cfg, now)
    def keep(cid, c):
        if cid in mentioned or age_days(c.get("kev_date"), now) <= retention:
            return True
        age = age_days(c.get("published"), now)
        # Low-signal CVEs can no longer alert after two weeks; dropping them keeps the store small.
        notable = (c.get("cvss") or 0) >= 7 or (c.get("epss") or 0) >= 0.1 or c.get("poc") or c.get("prod")
        return age <= 14 or (age <= retention and notable)

    for cid in [cid for cid, c in cves.items() if not keep(cid, c)]:
        del cves[cid]
    log.info("CVEs tracked: %d", len(cves))

    # ---- stories and summaries
    stories = build_stories(list(items.values()) + vendor_items, {cid for cid, c in cves.items() if c.get("kev")}, catalog, cves)
    sources_by_cve: dict[str, set] = {}
    last_mention: dict[str, str] = {}
    for it in items.values():
        for cid in it.get("cves") or []:
            sources_by_cve.setdefault(cid, set()).add(it["source"])
            last_mention[cid] = max(last_mention.get(cid, ""), it["published"])
    for cid, c in cves.items():
        c["news"] = len(sources_by_cve.get(cid, ()))
        c["news_date"] = last_mention.get(cid)

    # ---- alert decisions (after press coverage is known: it gates the any-vendor levels)
    secret = os.environ.get("STATE_KEY", "").strip() or topic or "local"
    alog = state.setdefault("alerted", {})
    alerts = []
    for c in cves.values():
        match = wl.match(c)
        if match and match[1] == "core":
            # All your versions are outside the affected ranges: not your problem. "unknown" still alerts.
            mine = wl.versions_of(match[0])
            if mine and all(affected(v, c.get("ranges"), c.get("ranges_partial", False)) == "no" for v in mine):
                match = None
            elif wl.is_info(match[0]):
                match = (match[0], "info")    # updates itself: only an exploited flaw alerts
        level = alert_level(c, match, cfg["alerts"], now)
        if level and alog.get(notify.alert_key(secret, c["id"]), 0) < level:
            alerts.append((c, level, match))

    majors =build_majors(cves, stories, sources_by_cve, catalog, now, days=cfg["majors_days"])
    ai = Summarizer({**cfg["ai"], "enabled": cfg["ai"]["enabled"] and not args.no_ai})
    cache = state.setdefault("sum", {})
    todo = []
    for s in stories:
        if s["kind"] == "vendor":
            continue
        hit = cache.get(s["id"])
        if hit:
            s["summary"], s["category"] = hit["summary"], hit["category"]
        grown = hit and s["n_sources"] >= 2 * hit["n"] and s["n_sources"] >= 3
        if (not hit or grown) and age_days(s["updated"], now) <= 3 and not (s["kind"] == "advisory" and s["n_sources"] == 1):
            todo.append(s)
    todo.sort(key=lambda s: (-s["importance"], s["updated"]))
    todo = todo[: cfg["ai"]["max_story_summaries_per_run"]]
    for sid_, res in ai.stories(todo).items():
        s = next(s for s in todo if s["id"] == sid_)
        s["summary"], s["category"] = res["summary"], res["category"]
        cache[sid_] = {**res, "n": s["n_sources"]}
    live = {s["id"] for s in stories}
    for sid_ in [k for k in cache if k not in live]:
        del cache[sid_]

    # Notes are stored publicly, so the queue is chosen by risk score alone, never by watchlist.
    queue = sorted((c for c in cves.values() if not c.get("why") and c["score"] >= 45
                    and (age_days(c.get("published"), now) <= 14 or age_days(c.get("kev_date"), now) <= 14)),
                   key=lambda c: (-c["score"], c["id"]))
    for cid, why in ai.cves(queue[: cfg["ai"]["max_cve_notes_per_run"]]).items():
        cves[cid]["why"] = why

    # ---- send alerts
    if args.dry_run:
        print(f"\n{len(alerts)} alert(s) would be sent:")
        for c, level, match in sorted(alerts, key=lambda a: (-a[1], -a[0]["score"])):
            msg = notify.format_alert(c, level, match)
            print(f"  [{LEVELS[level][0]}] {msg['title']}  ({notify.facts(c)})")
    elif alerts:
        if first_run:
            ok = True  # do not flood the phone with the backfill
            if topic:
                notify.send(server, topic, title="SecPulse is live", tags=["satellite"],
                            message=f"Tracking {len(cves)} recent CVEs and {len(feed_status)} sources. "
                                    "You will be alerted from now on.", click=cfg["portal_url"] or None)
        elif topic:
            ok = notify.send_alerts(alerts, server=server, topic=topic, portal_url=cfg["portal_url"],
                                    bundle_over=cfg["alerts"]["bundle_over"])
        else:
            ok = True
        log.info("alerts: %d new, %s", len(alerts),
                 "recorded silently (first run)" if first_run else "sent" if topic and ok else
                 "not sent (NTFY_TOPIC missing)" if not topic else "send failed, will retry")
        if ok:
            for c, level, _ in alerts:
                alog[notify.alert_key(secret, c["id"])] = level

    # ---- security releases of your products (from the private vendor feeds)
    mine = {n for e in wl.entries for n in (e.get("cat") or {e["name"]})}
    releases = [s for s in stories if s["kind"] == "vendor" and s.get("security")
                and set(s["prods"]) & mine and age_days(s["updated"], now) <= 2
                and notify.alert_key(secret, "rel:" + s["id"]) not in alog]
    if args.dry_run:
        print(f"{len(releases)} vendor release alert(s) would be sent")
    elif releases:
        ok = True
        if topic and not first_run:
            for s in releases[:5]:
                ok = notify.send(server, topic, title=f"{s['prods'][0]}: security release",
                                 message=s["title"][:200], tags=["package"], priority=3,
                                 click=s["url"] if s["url"].startswith("https://") else None) and ok
        log.info("vendor release alerts: %d", len(releases))
        if ok:
            for s in releases:
                alog[notify.alert_key(secret, "rel:" + s["id"])] = 1

    # ---- daily brief
    local = now.astimezone(ZoneInfo(cfg["timezone"]))
    brief = load_json(data / "brief.json", {})
    if (local.hour >= cfg["brief_hour"] or not brief) and state.get("brief_date") != local.strftime("%Y-%m-%d"):
        press = [s for s in stories if s["kind"] != "vendor"]
        recent = [s for s in press if age_days(s["updated"], now) <= 1]
        if len(recent) < 6:
            recent = [s for s in press if age_days(s["updated"], now) <= 3]
        recent = sorted(recent, key=lambda s: -s["importance"])[:30]
        hot = sorted((c for c in cves.values()
                      if age_days(c.get("published"), now) <= 3 or age_days(c.get("kev_date"), now) <= 3),
                     key=lambda c: -c["score"])[:12]
        new_brief = ai.brief(recent, hot) or fallback_brief(recent)
        if new_brief:
            brief = {**new_brief, "date": local.strftime("%Y-%m-%d"), "generated": iso(now)}
            if not args.dry_run:
                state["brief_date"] = brief["date"]
                if topic and not first_run:
                    lines = [("• " + b["text"])[:160] for b in brief["bullets"][:3]]
                    notify.send(server, topic, title="Your security brief is ready", tags=["newspaper"],
                                message="\n".join(lines), priority=2, click=cfg["portal_url"] or None)
            log.info("daily brief built (%s)", "AI" if brief.get("ai") else "rule-based")

    # ---- publish and save
    pub = [s for s in stories if s["kind"] != "vendor"] if public else stories
    n_stories, n_cves = build.publish(Path(args.out), ROOT / "site", stories=pub, cves=cves, kev=kev,
                                      brief=brief, feed_status=feed_status, ai_on=ai.on, now=now,
                                      retention=retention, majors=majors, catalog=catalog)
    log.info("published %d stories and %d CVEs; AI cost this run about $%.4f", n_stories, n_cves, ai.cost)
    save_json(data / "items.json", items)
    save_json(data / "cves.json", cves)
    save_json(data / "brief.json", brief)
    if not args.dry_run:
        state["last_run"] = iso(now)
    save_json(data / "state.json", state)
    return 0


def main():
    p = argparse.ArgumentParser(description="SecPulse collector")
    p.add_argument("--data", default=str(ROOT / "data"), help="state directory")
    p.add_argument("--out", default=str(ROOT / "public"), help="portal output directory")
    p.add_argument("--dry-run", action="store_true", help="send nothing; print would-be alerts")
    p.add_argument("--no-ai", action="store_true", help="skip AI summaries")
    p.add_argument("--test-notify", action="store_true", help="send a test notification and exit")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
