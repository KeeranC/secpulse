"""News, research and advisory feeds (RSS/Atom)."""
from __future__ import annotations

import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import feedparser

from ..util import CVE_RE, find_cves, get, iso, sid, strip_html, utcnow


def compile_exclude(patterns) -> re.Pattern | None:
    patterns = [p for p in patterns or [] if p]
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.I) if patterns else None


def page_cves(url: str) -> list[str]:
    """CVE ids an article is actually about, read from its page. Nothing else is kept.
    Ids named only once are usually sidebar links to other stories, and a page naming many
    is a roundup, so both are ignored."""
    try:
        r = get(url, timeout=15, retries=0)
        if r.status_code != 200 or "html" not in r.headers.get("content-type", ""):
            return []
        counts = Counter(m.upper() for m in CVE_RE.findall(r.text[:600_000]))
    except Exception:
        return []
    if len(counts) > 10:
        return []
    return sorted(c for c, n in counts.items() if n >= 2)[:4]


def fetch_feed(feed: dict, exclude: re.Pattern | None = None) -> list[dict]:
    r = get(feed["url"], timeout=20, retries=1,
            headers={"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
    r.raise_for_status()
    parsed = feedparser.parse(r.content)
    now = utcnow()
    own = compile_exclude(feed.get("exclude"))
    include = compile_exclude(feed.get("include"))      # e.g. only security entries of a changelog
    security = compile_exclude(feed.get("security") or [r"security|vulnerab|\bcve-\d|critical patch"])
    vendor = feed.get("kind") == "vendor"
    out = []
    for e in parsed.entries[: int(feed.get("max", 50))]:
        link = (e.get("link") or "").strip()
        title = strip_html(e.get("title", ""))
        if not title or not link.startswith(("http://", "https://")):
            continue
        # Newsletters, podcasts and weekly roundups are not news: match title, tags and URL.
        labels = " ".join(t.get("term", "") for t in e.get("tags", []) or [])
        probe = f"{title} | {labels} | {link}"
        if (exclude and not vendor and exclude.search(probe)) or (own and own.search(probe)):
            continue
        ts = e.get("published_parsed") or e.get("updated_parsed")
        try:
            published = datetime(*ts[:6], tzinfo=timezone.utc) if ts else now
        except (TypeError, ValueError):
            published = now
        published = min(published, now)  # some feeds post-date entries
        body = " ".join(c.get("value", "") for c in e.get("content", []) or [])
        teaser = strip_html(e.get("summary", ""))
        full = f"{title} {teaser} {strip_html(body)}"
        if include and not include.search(full):
            continue
        if re.match(r"\s*submitted\s+by\s+/u/", teaser):   # Reddit link posts carry no text
            teaser = ""
        item = {
            # A vendor thread that gets a new advisory keeps its link; the date makes it a new entry.
            "id": sid(link + iso(published)[:10]) if vendor else sid(link),
            "title": title[:300],
            "url": link,
            "source": feed["name"],
            "kind": feed.get("kind", "news"),
            "weight": int(feed.get("weight", 3)),
            "cat_hint": feed.get("category"),
            "published": iso(published),
            "teaser": teaser[:500],
            "cves": find_cves(full)[:12],
        }
        if vendor:
            item["product"] = feed.get("product", "")
            item["security"] = bool(security.search(full))
        out.append(item)
    return out


def fetch_all(feeds: list[dict], exclude: re.Pattern | None = None) -> tuple[list[dict], dict]:
    """Fetch every feed in parallel. Returns (items, {feed name: count or error text})."""
    def one(feed):
        try:
            return feed["name"], fetch_feed(feed, exclude), None
        except Exception as e:  # one bad feed must never stop the run
            return feed["name"], [], f"{type(e).__name__}: {e}"[:160]

    items, status = [], {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for name, got, err in pool.map(one, feeds):
            items.extend(got)
            status[name] = err or len(got)
    return items, status
