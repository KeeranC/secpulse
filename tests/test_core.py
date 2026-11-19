from datetime import timedelta
from pathlib import Path

import yaml

from collector.catalog import Catalog, attack_path, weakness_kind
from collector.cluster import build_stories, categorize
from collector.majors import build_majors
from collector.notify import alert_key, format_alert
from collector.score import Watchlist, alert_level, impact_score, risk_score
from collector.sources.rss import compile_exclude
from collector.sources.vulns import parse_cvelist, parse_nvd
from collector.util import iso, utcnow
from collector.versions import affected, compare, fixed_in, split_name_version

ROOT = Path(__file__).resolve().parents[1]
CAT = Catalog.load(ROOT / "config" / "products.yaml")
CFG = {"watch_cvss": 7.0, "watch_epss": 0.10, "any_epss": 0.50, "any_cvss_with_poc": 9.8,
       "fresh_days": 7, "kev_fresh_days": 5}
NOW = utcnow()


def cve(**kw):
    base = {"id": "CVE-2026-0001", "published": iso(NOW - timedelta(days=1)), "title": "", "desc": "",
            "vendors": [], "products": [], "cvss": None, "epss": None}
    return {**base, **kw}


def item(title, source, hours_ago=1, cves=(), kind="news", weight=3):
    return {"id": f"{source}-{title}"[:40], "title": title, "url": f"https://example.org/{source}", "source": source,
            "kind": kind, "weight": weight, "cat_hint": None, "published": iso(NOW - timedelta(hours=hours_ago)),
            "teaser": "", "cves": list(cves)}


def tagged(**kw):
    """A CVE as enrich() leaves it: with catalogue product and area."""
    c = cve(**kw)
    p = CAT.match_cve(c)
    if p:
        c.update(prod=p["name"], area=p["area"])
    return c


# ---------------------------------------------------------------- catalogue

def test_catalog_matches_by_cpe_and_label():
    assert CAT.match_cve(cve(vendors=["sonicwall"], products=["sonicos"]))["name"] == "SonicWall"
    assert CAT.match_cve(cve(vendors=["linux"], products=["linux_kernel"]))["area"] == "linux-oss-web"


def test_kev_label_beats_downstream_cpe():
    # A PHP flaw whose CPE data also lists an appliance that bundles PHP.
    c = cve(kev_product="PHP", vendors=["paloaltonetworks", "php"], products=["pan-os", "php"])
    assert CAT.match_cve(c)["name"] == "PHP (language runtime)"


def test_free_text_only_counts_where_the_subject_stands():
    assert CAT.match_cve(cve(desc="A flaw in GitLab CE allows ...")) ["name"] == "GitLab"
    # Mentioned in passing, not the vulnerable product.
    assert CAT.match_cve(cve(desc="SomeTool before 2.1 reads the GitHub webhook body without checks")) is None


def test_vendor_name_before_the_product_still_counts_as_subject():
    # A new CVE has no CPE data yet; Oracle writes "Vulnerability in the Oracle Java SE ...".
    c = cve(desc="Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK product of Oracle Java SE "
                 "(component: Compiler). Supported versions that are affected are ...")
    assert CAT.match_cve(c)["name"] == "OpenJDK / Java"
    assert CAT.match_cve(cve(desc="An issue in the Oracle portal mentions Java SE in passing")) is None


def test_big_new_flaw_in_a_broad_product_reaches_the_front_page():
    c = tagged(id="CVE-2026-9", cvss=8.1, path="remote, no login, no user action",
               desc="Vulnerability in the Oracle Java SE product of Oracle Java SE (component: Compiler).")
    out = build_majors({"CVE-2026-9": c}, [], {"CVE-2026-9": {"A", "B", "C"}}, CAT, NOW)
    assert out[0]["product"] == "OpenJDK / Java" and out[0]["broad"] and out[0]["front"]
    assert out[0]["since"] == c["published"][:10]   # the portal ranks events this fresh first


def test_affects_counts_only_as_the_opening_statement():
    c = cve(desc="This issue affects NGINX Plus or NGINX Open Source configurations that use HTTP/2.")
    assert CAT.match_cve(c)["name"] == "nginx"
    c = cve(desc="An unauthenticated SQL injection can occur on any site that uses craft.search to run "
                 "a search. Note that this only affects MySQL/MariaDB.")
    assert CAT.match_cve(c) is None


def test_catalog_text_match_for_headlines():
    names = {p["name"] for p in CAT.match_text("SonicWall warns of SSLVPN attacks")}
    assert "SonicWall" in names


# ---------------------------------------------------------------- triage facts

def test_attack_path_in_plain_words():
    assert attack_path("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "remote, no login, no user action"
    assert attack_path("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "local access needed, needs a user login, no user action"
    assert attack_path("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A") == "remote, needs admin rights, needs user action"
    assert attack_path("") == ""


def test_weakness_kind_from_cwe_and_text():
    assert weakness_kind(["CWE-287"]) == "auth bypass"
    assert weakness_kind(["CWE-787"], "allows remote code execution") == "code execution"
    assert weakness_kind([], "A SQL injection in the login form") == "SQL injection"
    assert weakness_kind([], "") == ""


# ---------------------------------------------------------------- watchlist

WL = Watchlist({"core": ["GitLab", "Proxmox", {"name": "Acme Vault", "keywords": ["AcmeVault"]}, "acme"],
                "areas": ["network-edge"]}, CAT)


def test_core_catalogue_product():
    assert WL.match(tagged(vendors=["gitlab"], products=["gitlab"])) == ("GitLab", "core")


def test_core_keyword_and_free_string():
    assert WL.match(cve(title="AcmeVault privilege escalation")) == ("Acme Vault", "core")
    assert WL.match(cve(vendors=["acme"], products=["foo"])) == ("acme", "core")
    assert WL.match(cve(desc="the acmevaultx tool")) is None


def test_area_match_and_no_match():
    assert WL.match(tagged(vendors=["fortinet"], products=["fortios"])) == ("Fortinet FortiOS", "area") \
        or WL.match(tagged(vendors=["fortinet"], products=["fortios"]))[1] == "area"
    assert WL.match(tagged(vendors=["wordpress"], desc="plugin XSS")) is None


def test_empty_watchlist_matches_nothing():
    assert Watchlist(None).match(cve(vendors=["fortinet"])) is None
    assert Watchlist({}, CAT).match(tagged(vendors=["gitlab"], products=["gitlab"])) is None


# ---------------------------------------------------------------- alert levels

CORE, AREA = ("GitLab", "core"), ("Fortinet", "area")


def test_info_mode_alerts_only_when_exploited():
    wl = Watchlist({"core": [{"name": "Google Chrome / Chromium", "mode": "info"}, "GitLab"]}, CAT)
    assert wl.is_info("Google Chrome / Chromium") and not wl.is_info("GitLab")
    c = tagged(desc="Use after free in Google Chrome prior to 158 allowed a remote attacker ...", cvss=9.6)
    assert wl.match(c) == ("Google Chrome / Chromium", "core")
    info = ("Google Chrome / Chromium", "info")
    assert alert_level(c, info, CFG, NOW) == 0                         # critical, not exploited: quiet
    assert alert_level(dict(c, kev=True, kev_date=iso(NOW)), info, CFG, NOW) == 5


def test_core_plus_exploited_is_top_level():
    c = cve(kev=True, kev_date=iso(NOW - timedelta(days=1)))
    assert alert_level(c, CORE, CFG, NOW) == 5


def test_core_needs_severity_signal():
    assert alert_level(cve(cvss=8.1), CORE, CFG, NOW) == 4
    assert alert_level(cve(cvss=5.0), CORE, CFG, NOW) == 0
    assert alert_level(cve(cvss=5.0, poc=True), CORE, CFG, NOW) == 4
    assert alert_level(cve(), CORE, CFG, NOW) == 0  # not scored yet: re-evaluated next run


def test_areas_never_alert_on_their_own():
    kev = cve(kev=True, kev_date=iso(NOW - timedelta(days=1)), prod="Citrix NetScaler")
    assert alert_level(cve(cvss=9.8), AREA, CFG, NOW) == 0
    assert alert_level(kev, AREA, CFG, NOW) == 0                 # exploited, but nobody writes about it
    assert alert_level({**kev, "news": 3, "cvss": 9.8}, AREA, CFG, NOW) == 2  # same rule as any vendor


def test_any_vendor_needs_a_known_product_and_press():
    kev = dict(kev=True, kev_date=iso(NOW - timedelta(days=2)))
    assert alert_level(cve(**kev, prod="PHP (language runtime)", news=2, epss=0.6), None, CFG, NOW) == 2  # CVSS pending, high EPSS
    assert alert_level(cve(**kev, prod="PHP (language runtime)", news=2, cvss=9.8), None, CFG, NOW) == 2
    assert alert_level(cve(**kev, prod="Cisco BroadWorks", news=2, cvss=7.5), None, CFG, NOW) == 0  # not critical
    # No CVSS yet: low EPSS stays quiet, ransomware use still alerts
    assert alert_level(cve(**kev, prod="Cisco BroadWorks", news=2, cvss=None, epss=0.01), None, CFG, NOW) == 0
    assert alert_level(cve(**kev, prod="Cisco BroadWorks", news=2, cvss=None, epss=0.01, ransomware=True),
                       None, CFG, NOW) == 2
    assert alert_level(cve(**kev, prod="PHP (language runtime)", news=1), None, CFG, NOW) == 0
    assert alert_level(cve(**kev, news=5), None, CFG, NOW) == 0       # GPUStack-style niche product
    assert alert_level(cve(kev=True, kev_date=iso(NOW - timedelta(days=40)), prod="PHP (language runtime)", news=4,
                           published=iso(NOW - timedelta(days=400))), None, CFG, NOW) == 0
    assert alert_level(cve(epss=0.7, prod="GitLab", news=2), None, CFG, NOW) == 1
    assert alert_level(cve(epss=0.7), None, CFG, NOW) == 0
    assert alert_level(cve(cvss=9.8, poc=True, prod="GitLab", news=2), None, CFG, NOW) == 1
    assert alert_level(cve(cvss=9.8, prod="GitLab", news=2), None, CFG, NOW) == 0


def test_old_cves_do_not_alert():
    assert alert_level(cve(cvss=9.9, published=iso(NOW - timedelta(days=30))), CORE, CFG, NOW) == 0


# ---------------------------------------------------------------- scores

def test_risk_score_ranks_exploitation_over_severity():
    assert risk_score(cve(cvss=7.5, kev=True)) > risk_score(cve(cvss=10.0))
    assert risk_score(cve(cvss=10, kev=True, epss=1.0, poc=True)) == 100
    assert risk_score(cve()) == 0


def test_impact_prefers_exploited_broad_and_fresh():
    sonic = tagged(vendors=["sonicwall"], products=["sonicos"], cvss=9.1, kev=True,
                   kev_date=iso(NOW - timedelta(days=6)), published=iso(NOW - timedelta(days=7)))
    niche = cve(cvss=10.0, published=iso(NOW - timedelta(days=1)))
    old = dict(sonic, published=iso(NOW - timedelta(days=50)), kev_date=iso(NOW - timedelta(days=50)))
    assert impact_score(sonic, 2, NOW) > impact_score(niche, 0, NOW)
    assert impact_score(sonic, 2, NOW) > impact_score(old, 2, NOW)


# ---------------------------------------------------------------- majors

def test_majors_group_per_product_and_split_by_exploitation():
    php = dict(kev_product="PHP", vendors=["php"], products=["php"], cvss=9.8, kev=True,
               kev_date=iso(NOW - timedelta(days=3)), path="remote, no login, no user action")
    cves = {
        "CVE-2026-1": tagged(id="CVE-2026-1", **php),
        "CVE-2026-2": tagged(id="CVE-2026-2", **dict(php, cvss=9.1)),
        "CVE-2026-3": tagged(id="CVE-2026-3", vendors=["gitlab"], products=["gitlab"], cvss=9.6),
        "CVE-2026-4": cve(id="CVE-2026-4", vendors=["nobody"], products=["thing"], cvss=7.0),   # filtered out
        "CVE-2026-5": tagged(id="CVE-2026-5", kev_product="PHP", vendors=["php"], products=["php"], kev=True,
                             kev_date=iso(NOW - timedelta(days=90)), published=iso(NOW - timedelta(days=90))),
    }
    out = build_majors(cves, [], {}, CAT, NOW, days=30)
    assert [e["product"] for e in out] == ["PHP (language runtime)", "GitLab"]
    php_e = out[0]
    assert php_e["kev"] and php_e["n_cves"] == 2 and set(php_e["cves"]) == {"CVE-2026-1", "CVE-2026-2"}
    assert not out[1]["kev"]
    assert php_e["headline"] == CAT.find("PHP (language runtime)")["what"]   # says what the product is
    assert not php_e["front"]                                                  # no press yet: not front page
    out = build_majors(cves, [], {"CVE-2026-1": {"A", "B"}}, CAT, NOW, days=30)
    assert out[0]["front"]


def test_majors_from_press_alone():
    s = {"id": "s1", "title": "Linux kernel TCP flaw lets attackers crash servers", "url": "https://example.org/a",
         "updated": iso(NOW - timedelta(days=2)), "kind": "news", "category": "vulnerabilities", "cves": [],
         "n_sources": 3, "prods": ["Linux kernel"], "importance": 7,
         "sources": [{"source": "A", "url": "https://example.org/a"}, {"source": "B", "url": "https://example.org/b"},
                     {"source": "C", "url": "https://example.org/c"}]}
    out = build_majors({}, [s], {}, CAT, NOW)
    assert len(out) == 1 and out[0]["product"] == "Linux kernel" and out[0]["news"] == 3 and not out[0]["kev"]


def test_freshly_named_flaw_reaches_the_front_page_from_one_outlet():
    s = {"id": "s2", "title": "Ruby2Shell: critical flaw in Ruby lets attackers run code", "url": "https://example.org/r",
         "updated": iso(NOW - timedelta(hours=3)), "kind": "news", "category": "vulnerabilities", "cves": [],
         "n_sources": 1, "prods": ["Ruby (language runtime)"], "importance": 7,
         "sources": [{"source": "A", "url": "https://example.org/r"}]}
    out = build_majors({}, [s], {}, CAT, NOW)
    assert out[0]["product"] == "Ruby (language runtime)" and out[0]["named"] and out[0]["front"]
    old = dict(s, updated=iso(NOW - timedelta(days=10)))          # an old name is not news
    assert build_majors({}, [old], {}, CAT, NOW) == []
    plain = dict(s, title="Ruby releases fixes for string flaws")  # one outlet, no name: wait for more
    assert build_majors({}, [plain], {}, CAT, NOW) == []


# ---------------------------------------------------------------- notifications

def test_alert_key_hides_the_cve_id_and_depends_on_secret():
    a, b = alert_key("topic-a", "CVE-2026-0001"), alert_key("topic-b", "CVE-2026-0001")
    assert a != b and "CVE" not in a


def test_alert_message_has_the_essentials():
    msg = format_alert(cve(vendors=["fortinet"], products=["fortios"], cvss=9.8, epss=0.42, kev=True,
                           kev_due="2026-11-20", desc="Unauthenticated RCE."), 5, ("Fortinet", "core"))
    assert msg["title"].startswith("CVE-2026-0001") and "Fortinet Fortios" in msg["title"]
    assert "CVSS 9.8" in msg["message"] and "EPSS 42%" in msg["message"] and msg["priority"] == 5
    assert "Exploited and in your stack: Fortinet" in msg["message"] and "2026-11-20" in msg["message"]


# ---------------------------------------------------------------- noise filter

def test_exclude_patterns_drop_newsletters_and_podcasts():
    rx = compile_exclude(yaml.safe_load((ROOT / "config" / "sources.yaml").read_text(encoding="utf-8"))["exclude"])
    for t in ["Talos Threat Source newsletter: Never be afraid to ask questions",
              "ISC Stormcast For Thursday, November 12th, 2026",
              "Week in review: SonicWall attacks, PHP flaw",
              "ThreatsDay Bulletin: roundup of the week"]:
        assert rx.search(t), t
    for t in ["SonicWall SSLVPN flaw exploited in attacks", "Critical PHP-CGI bug lets attackers run code"]:
        assert not rx.search(t), t


# ---------------------------------------------------------------- clustering

def test_same_event_from_several_outlets_becomes_one_story():
    items = [
        item("Fortinet warns of critical FortiWeb flaw exploited in attacks", "A", 5, ["CVE-2026-1111"], weight=5),
        item("Critical FortiWeb flaw exploited in the wild, Fortinet warns", "B", 4, ["CVE-2026-1111"]),
        item("Fortinet patches actively exploited FortiWeb zero-day", "C", 3, ["CVE-2026-1111"]),
        item("Retailer discloses data breach affecting 2 million customers", "A", 2),
    ]
    stories = build_stories(items, {"CVE-2026-1111"}, CAT, {})
    assert len(stories) == 2
    big = max(stories, key=lambda s: s["n_sources"])
    assert big["n_sources"] == 3 and big["cves"] == ["CVE-2026-1111"]
    assert big["sources"][0]["source"] == "A"          # highest-weight outlet leads
    assert big["category"] == "vulnerabilities"
    assert any("Forti" in p for p in big["prods"])
    assert big["importance"] > min(stories, key=lambda s: s["n_sources"])["importance"]


def test_newsletter_mentioning_exploited_cves_gets_no_bonus():
    kev = {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}
    letter = build_stories([item("Some thoughts on asking questions", "Talos", 1, sorted(kev))], kev, CAT, {})[0]
    about = build_stories([item("Attackers exploit CVE-2026-1 in the wild", "Talos", 1, ["CVE-2026-1"])], kev, CAT, {})[0]
    assert about["importance"] > letter["importance"]


def test_unrelated_and_far_apart_items_stay_separate():
    items = [
        item("Ransomware gang claims attack on hospital chain", "A", 100),
        item("Ransomware gang claims attack on hospital chain", "B", 1),      # same title, 4 days apart
        item("New Android spyware targets journalists", "C", 1),
    ]
    assert len(build_stories(items, set())) == 3


def test_formulaic_advisories_do_not_merge():
    items = [
        item("Cisco IOS XE Software Web UI Privilege Escalation Vulnerability", "Cisco PSIRT", 2, kind="advisory"),
        item("Cisco IOS XE Software SNMP Denial of Service Vulnerability", "Cisco PSIRT", 2, kind="advisory"),
    ]
    assert len(build_stories(items, set())) == 2


def test_categories():
    assert categorize([item("LockBit ransomware hits manufacturer", "A")]) == "ransomware"
    assert categorize([item("Bank confirms data breach after hack", "A")]) == "breaches"
    assert categorize([item("EU lawmakers agree new regulation for vendors", "A")]) == "policy"
    assert categorize([item("A walk through heap grooming", "A", kind="research")]) == "research"


# ---------------------------------------------------------------- parsers

def test_parse_nvd_record():
    rec = parse_nvd({
        "id": "CVE-2026-2222", "published": "2026-11-10T10:15:07.123", "lastModified": "2026-11-11T08:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Buffer overflow in Foo."}],
        "metrics": {"cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 7.0, "vectorString": "CVSS:3.1/AV:L/PR:L/UI:N"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:foo_server:1.0:*:*:*:*:*:*:*"}]}]}],
        "references": [{"url": "https://acme.example/advisory", "tags": ["Vendor Advisory"]},
                       {"url": "https://acme.example/patch", "tags": ["Patch"]}],
    })
    assert rec["cvss"] == 9.8 and rec["severity"] == "CRITICAL"
    assert rec["vector"].startswith("CVSS:3.1/AV:N") and "CWE-787" in rec["cwe"]
    assert rec["fix"] == "https://acme.example/patch"
    assert rec["vendors"] == ["acme"] and rec["products"] == ["foo_server"]
    assert rec["desc"].startswith("Buffer") and not rec["rejected"]


def test_parse_cvelist_record():
    rec = parse_cvelist({
        "cveMetadata": {"cveId": "CVE-2026-3333", "state": "PUBLISHED", "datePublished": "2026-11-11T09:00:00.000Z"},
        "containers": {"cna": {
            "title": "Foo auth bypass",
            "descriptions": [{"lang": "en", "value": "Auth bypass in Foo."}],
            "affected": [{"vendor": "Acme", "product": "Foo"}, {"vendor": "n/a", "product": "n/a"}],
            "metrics": [{"cvssV3_1": {"baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R"}}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-287", "lang": "en"}]}],
        }},
    })
    assert rec["id"] == "CVE-2026-3333" and rec["cvss"] == 8.8 and rec["vendors"] == ["Acme"]
    assert attack_path(rec["vector"]) == "remote, no login, needs user action"
    assert weakness_kind(rec["cwe"]) == "auth bypass"
    assert parse_cvelist({"cveMetadata": {"state": "REJECTED"}}) is None


# ---------------------------------------------------------------- version check

def test_version_compare():
    assert compare("19.5.1", "19.5.10") < 0
    assert compare("19.5", "19.5.0") == 0
    assert compare("v0.83.0", "0.83.0") == 0
    assert compare("0.83.0-rc.1", "0.83.0") < 0           # release candidates come before the release
    assert compare("26.7.9", "26.7.10") < 0


R = [{"v": "*", "si": "19.0", "ee": "19.5.4"}, {"v": "*", "si": "19.4", "ee": "19.4.6"}]


def test_affected_ranges():
    assert affected("19.5.1", R) == "yes" and fixed_in("19.5.1", R) == "19.5.4"
    assert affected("19.5.4", R) == "no"
    assert affected("18.11.2", R) == "no"
    assert affected("19.5.1", []) == "unknown"                      # no data: treat as affected
    assert affected("19.6.0", R, partial=True) == "unknown"         # truncated list: cannot rule it out
    assert affected("26.7.8", [{"v": "26.7.8"}]) == "yes"           # exact version entry
    assert affected("26.7.9", [{"v": "26.7.8"}]) == "no"
    assert affected("5.0", [{"v": "*", "ei": "5.0"}]) == "yes"      # inclusive end
    assert affected(None, R) == "unknown"


def test_split_name_version():
    assert split_name_version("GitLab 19.5.1") == ("GitLab", "19.5.1")
    assert split_name_version("Proxmox VE 9.0") == ("Proxmox VE", "9.0")
    assert split_name_version("Acme Vault") == ("Acme Vault", None)
    assert split_name_version("Veeam v12.3.1") == ("Veeam", "12.3.1")


def test_watchlist_keeps_the_version():
    wl = Watchlist({"core": ["GitLab 19.5.1", "Acme Vault"]}, CAT)
    assert wl.match(tagged(vendors=["gitlab"], products=["gitlab"])) == ("GitLab", "core")
    assert wl.version_of("GitLab") == "19.5.1" and wl.version_of("Acme Vault") is None


def test_nvd_ranges_and_product_filter():
    rec = parse_nvd({
        "id": "CVE-2026-4444", "published": "2026-11-10T10:00:00.000", "descriptions": [], "metrics": {},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*",
             "versionStartIncluding": "19.0", "versionEndExcluding": "19.5.4"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
    })
    assert len(rec["ranges"]) == 2 and rec["ranges"][0] == {"cpe": "gitlab:gitlab", "v": "*", "si": "19.0", "ee": "19.5.4"}
    mine = CAT.ranges_for(CAT.find("GitLab"), rec["ranges"])
    assert mine == [rec["ranges"][0]]                                   # the PAN-OS entry belongs to another product
    assert affected("19.5.1", mine) == "yes"


# ---------------------------------------------------------------- vendor feeds

def test_vendor_items_stay_separate_and_carry_their_product():
    rel = {**item("GitLab Critical Patch Release: 19.5.4, 19.4.6", "GitLab security releases", 3, ["CVE-2026-1111"],
                  kind="vendor", weight=1), "product": "GitLab", "security": True}
    news = item("GitLab patches critical flaw CVE-2026-1111", "A", 2, ["CVE-2026-1111"])
    stories = build_stories([rel, news], set(), CAT, {})
    assert len(stories) == 2
    v = next(s for s in stories if s["kind"] == "vendor")
    assert v["prods"] == ["GitLab"] and v["security"] and v["cves"] == ["CVE-2026-1111"]


def test_vendor_feeds_come_from_the_private_watchlist():
    from collector.main import load_vendor_feeds
    raw = {"core": ["Acme Vault"], "feeds": [
        {"name": "Acme releases", "url": "https://example.org/r.atom", "product": "Acme Vault"},
        {"url": "http://insecure.example/r.atom", "product": "X"},      # not https: dropped
        {"url": "https://example.org/no-product.atom"}]}                 # no product: dropped
    feeds = load_vendor_feeds(raw)
    assert [f["name"] for f in feeds] == ["Acme releases"] and feeds[0]["kind"] == "vendor"
    assert load_vendor_feeds(["GitLab"]) == []
    src = yaml.safe_load((ROOT / "config" / "sources.yaml").read_text(encoding="utf-8"))
    assert not [f for f in src["feeds"] if f.get("kind") == "vendor"]   # never in the public config


def test_nvd_outage_keeps_the_window_for_the_next_run(monkeypatch):
    from collector import main
    from collector.sources import vulns
    calls = []

    def fake(start, end, modified=False):
        calls.append(modified)
        return [], len(calls) > 1          # first call fails (503), second succeeds
    monkeypatch.setattr(vulns, "fetch_nvd_window", fake)
    for name in ("fetch_cvelist_new", "fetch_ghsa"):
        monkeypatch.setattr(vulns, name, lambda *a, **k: [])
    monkeypatch.setattr(vulns, "fetch_epss", lambda ids: {})
    monkeypatch.setattr(vulns, "public_poc", lambda cid: (False, None))
    cfg = main.load_settings()
    state = {"last_run": iso(NOW - timedelta(hours=1))}   # collector ran before, NVD never completed
    main.collect_cves({}, {}, {}, state, cfg, NOW, first_run=False)
    assert "nvd_since" not in state and calls == [False]   # full backfill tried, watermark not moved
    main.collect_cves({}, {}, {}, state, cfg, NOW, first_run=False)
    assert state["nvd_since"] and calls == [False, False]  # retried in full, now recorded


def test_site_assets_are_stamped_so_caches_cannot_mix(tmp_path):
    from collector.build import copy_site
    copy_site(ROOT / "site", tmp_path)
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    import re
    css, js = re.search(r'href="style\.css\?v=(\w{10})"', html), re.search(r'src="app\.js\?v=(\w{10})"', html)
    assert css and js
    (tmp_path / "style.css").write_text("body{}", encoding="utf-8")       # a changed file gets a new stamp
    (ROOT / "site")  # source stays untouched
    src = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    assert "?v=" not in src


def test_bad_watchlist_yaml_never_echoes_its_content(monkeypatch, caplog):
    from collector import main
    monkeypatch.setenv("WATCHLIST_YAML", "core:\n  - SecretProductName\n   bad: [indent")
    assert main.load_watchlist() == []
    assert "SecretProductName" not in caplog.text


def test_article_reader_only_follows_web_links():
    from collector.sources.rss import page_cves
    assert page_cves("file:///etc/passwd") == [] and page_cves("ftp://example.org/x") == []
