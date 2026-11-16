"""Phone push notifications through ntfy."""
from __future__ import annotations

import hashlib
import hmac
import os
from functools import lru_cache

import requests

from .score import LEVELS
from .util import log


def alert_key(secret: str, cve_id: str) -> str:
    """Opaque key for the alert log.

    The state file lives on a public branch. Storing plain CVE ids there would reveal which
    CVEs matched the private watchlist, so they are keyed with a secret (STATE_KEY, or the
    ntfy topic). The key is stretched with scrypt first: a plain HMAC would let anyone test
    guesses for the secret offline, millions per second, against the public file.
    """
    return hmac.new(_log_key(secret or "local"), cve_id.encode(), hashlib.sha256).hexdigest()[:20]


@lru_cache(maxsize=4)
def _log_key(secret: str) -> bytes:
    return hashlib.scrypt(secret.encode(), salt=b"secpulse/alert-log/v2", n=2 ** 14, r=8, p=1, dklen=32)


def send(server: str, topic: str, *, title: str, message: str, priority=3, tags=None, click=None) -> bool:
    payload = {"topic": topic, "title": title[:200], "message": message[:3500], "priority": priority}
    if tags:
        payload["tags"] = tags
    if click:
        payload["click"] = click
    # Optional access token, for a reserved topic on ntfy.sh or a self-hosted server.
    token = os.environ.get("NTFY_TOKEN", "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else None
    try:
        r = requests.post(server.rstrip("/") + "/", json=payload, headers=headers, timeout=20)
        if r.status_code >= 300:
            log.warning("ntfy returned HTTP %s", r.status_code)
        return r.status_code < 300
    except requests.RequestException as e:
        log.warning("ntfy send failed: %s", type(e).__name__)
        return False


def cve_link(cve_id: str, portal_url: str) -> str:
    if portal_url:
        return portal_url.rstrip("/") + "/#" + cve_id
    return "https://www.cve.org/CVERecord?id=" + cve_id


def facts(cve: dict) -> str:
    parts = [x for x in (cve.get("kind"), cve.get("path")) if x]
    if cve.get("cvss") is not None:
        parts.append(f"CVSS {cve['cvss']:.1f}")
    if cve.get("epss") is not None:
        parts.append(f"EPSS {cve['epss'] * 100:.0f}%")
    if cve.get("kev"):
        parts.append("exploited in the wild" + (" (ransomware)" if cve.get("kev_ransomware") else ""))
    if cve.get("poc"):
        parts.append("public PoC")
    return " · ".join(parts)


def product_label(cve: dict) -> str:
    if cve.get("kev_product"):
        return cve["kev_product"]
    if cve.get("prod"):
        return cve["prod"].replace(" (other)", "").replace(" (enterprise software)", "")
    vendor = (cve.get("vendors") or [""])[0].replace("_", " ")
    product = (cve.get("products") or [""])[0].replace("_", " ")
    return " ".join(x for x in (vendor, product) if x).strip().title()


def format_alert(cve: dict, level: int, match: tuple[str, str] | None) -> dict:
    reason, priority, tags = LEVELS[level]
    label = product_label(cve)
    body = (cve.get("why") or cve.get("title") or cve.get("desc") or "").strip()
    if len(body) > 280:
        body = body[:277].rsplit(" ", 1)[0] + "…"
    lines = [reason + (f": {match[0]}" if match else ""), facts(cve), body]
    if cve.get("kev_due"):
        lines.append(f"CISA patch deadline {cve['kev_due']}")
    return {
        "title": cve["id"] + (f" · {label}" if label else ""),
        "message": "\n".join(x for x in lines if x),
        "priority": priority,
        "tags": tags,
    }


def send_alerts(alerts: list[tuple[dict, int, tuple | None]], *, server, topic, portal_url, bundle_over=5) -> int:
    """alerts: (cve, level, matched watchlist entry). Returns notifications sent."""
    if not alerts:
        return 0
    alerts = sorted(alerts, key=lambda a: (-a[1], -(a[0].get("score") or 0)))
    if len(alerts) > bundle_over:
        top = max(a[1] for a in alerts)
        lines = [f"{c['id']} {product_label(c)} — {LEVELS[lvl][0].lower()}" for c, lvl, _ in alerts[:15]]
        if len(alerts) > 15:
            lines.append(f"… and {len(alerts) - 15} more")
        ok = send(server, topic, title=f"{len(alerts)} new CVE alerts", message="\n".join(lines),
                  priority=LEVELS[top][1], tags=LEVELS[top][2], click=portal_url or None)
        return int(ok)
    sent = 0
    for cve, level, match in alerts:
        sent += send(server, topic, click=cve_link(cve["id"], portal_url), **format_alert(cve, level, match))
    return sent
