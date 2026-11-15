# SecPulse

Personal CVE alerting and a five-minute cybersecurity news portal.

- **Alerts**: a phone push (ntfy) when a CVE hits a product you run, or when a widely deployed product is exploited (or very likely to be) and several outlets cover it.
- **Portal**: a quiet page readable in a minute.
  - **Emergency** (top, only when something is open): any CVE with CVSS ≥ 9.0 in a product you run, plus critical, exploited flaws in widely deployed products that several outlets cover. Each stays until you mark it **Patched**, **Not affected** or **Risk accepted**.

  The **Briefing** tab has three short blocks:
  1. **Your products**: one line per product you run, with **Act** (exploited, public exploit or critical: patch now) or **Check** (look at your version). Products without news share one grey line.
  2. **Big in the industry**: at most five events the industry is talking about, each starting with what the product is.
  3. **News**: the five stories most outlets are covering.

  Every line shows real dates (published, exploited since) and opens on click to show a timeline (published → fix listed → public exploit → exploited → CISA deadline), CVEs, scores, fix and sources. The **Everything** tab has the full vulnerability list, all stories with category filters and the CVE radar. Only your own products get a label; nothing else is coloured except the word "exploited".

A scheduled GitHub Actions job runs the collector every 30 minutes and publishes the portal to GitHub Pages. There is no server and no database.

## Run it locally

```bash
pip install -r requirements.txt
```

```bash
python -m collector.main --dry-run --no-ai
```

`--dry-run` sends nothing and prints every alert that would fire, which is the way to tune the watchlist and thresholds. The first run fetches 30 days of CVE data and takes several minutes. Output goes to `public/`; serve it with:

```bash
python -m http.server 8765 --directory public
```

Local runs read the watchlist from `config/watchlist.yaml` (git-ignored; copy `config/watchlist.example.yaml`).

## Your stack

```yaml
core:            # products you run: names from config/products.yaml, or any vendor/keyword
  - Fortinet FortiOS 7.4.3   # optional version: enables the "am I affected?" check
  - VMware ESXi
  - name: My in-house tool
    keywords: ["acme-toolname"]
areas:           # optional filter under "Everything"; never moves anything up, never alerts
  - microsoft
  - network-edge
feeds:           # optional: security releases straight from the vendor (private, see below)
  - {name: Example releases, url: "https://github.com/example/product/releases.atom", product: VMware ESXi}
```

Areas: `microsoft`, `network-edge` (firewalls, VPN, gateways), `linux-oss-web`, `cloud-virt`, `identity`, `devops`, `endpoint`, `enterprise-apps`.

**Version check.** With a version, each CVE of that product says *affected (fixed in …)*, *not affected* or *no version data yet*, from NVD's affected version ranges. "Not affected" removes it from Act, the Emergency block and phone alerts; missing data counts as affected. New CVEs often have no ranges for a few days.

**Vendor sources.** Security releases straight from the vendor (release feeds, advisory forums) go under `feeds:` in the watchlist, not in `config/sources.yaml`: the list would reveal what you run. Each entry needs `url` and `product` (catalogue name); optional `include`, `exclude` and `security` patterns filter mixed changelogs. Locally they appear under the product in "Your products"; on the public site (`PUBLIC_SITE=1`) they are left out, and a new security release of one of your products arrives as a phone alert instead.

**Handled and muted** items, like the stack, live in this browser only. **Export file / Import file** in the dialog moves them to another browser.

The portal keeps its own copy in the browser (**My stack** button). The dialog's **Copy as YAML** produces the same list for `config/watchlist.yaml` or the `WATCHLIST_YAML` secret, so portal and alerts stay in step.

## Deploy

1. Create a GitHub repository and push this folder to `main`.
2. Repository **Settings → Pages → Source: GitHub Actions**.
3. Install the ntfy app, pick a long random topic name and subscribe to it. Anyone who knows the topic can read it, so treat it like a password.
4. Add repository secrets (**Settings → Secrets and variables → Actions**):

   | Secret | Content |
   |---|---|
   | `NTFY_TOPIC` | your ntfy topic |
   | `WATCHLIST_YAML` | the full content of your `watchlist.yaml` |
   | `ANTHROPIC_API_KEY` | optional: API key for written summaries and the daily brief |
   | `AI_SUMMARY_MODEL`, `AI_BRIEF_MODEL` | optional, needed with the key: model ids for summaries and the brief |
   | `NVD_API_KEY` | optional, raises the NVD rate limit |

5. Run the **collect** workflow once by hand. The first run records the backfill silently and sends a single "SecPulse is live" push; alerts start with the second run.

Without `ANTHROPIC_API_KEY` and the model ids everything works rule-based: triage, verdicts, majors and alerts need no AI. Stories then show the feed teaser instead of a written summary, and the brief is assembled from the top stories. Setting the key later switches summaries on, no code change needed.

Check notifications at any time with `python -m collector.main --test-notify` (needs `NTFY_TOPIC` in the environment).

## Configuration

| File | Purpose |
|---|---|
| `config/settings.yaml` | alert thresholds, brief time and timezone, retention, majors window, AI models and per-run caps |
| `config/sources.yaml` | the feeds, plus `exclude` patterns for newsletters, podcasts and weekly roundups |
| `config/products.yaml` | catalogue of widely deployed products: aliases, CPE ids, area, one-line description |
| `config/watchlist.yaml` | your stack (private) |

Products missing from the catalogue are treated as niche. Add a few lines to `products.yaml` when that is wrong for something you care about.

### When an alert fires

| Trigger | Priority |
|---|---|
| Your product, exploited in the wild | urgent |
| Your product, CVSS ≥ 7, EPSS ≥ 10 % or a public PoC | high |
| Catalogue product, newly exploited, CVSS ≥ 9.0 (or not scored yet), covered by ≥ 2 outlets | default |
| Catalogue product, EPSS ≥ 50 % or CVSS ≥ 9.8 with a public PoC, covered by ≥ 2 outlets | default |

A version in the watchlist suppresses alerts for CVEs whose affected ranges exclude it. A CVE alerts once and again only if it climbs to a higher level. More than five alerts in one run arrive as one bundled notification, so a vendor patch day does not flood the phone.

## Privacy

The Pages site and the `data` branch are public on a free GitHub plan, so nothing derived from the watchlist is written to either:

- the collector uses the watchlist only to decide on notifications;
- the alert log stores keyed hashes, not CVE ids;
- PoC lookups and AI notes are chosen by risk score alone;
- majors, impact score and triage facts do not depend on the watchlist;
- vendor feeds come from the watchlist; their items are neither published, saved to the `data` branch nor named in the CI log;
- CI logs contain counts only (`--dry-run` prints matches and is for local use);
- verdicts and "Your products" are computed in the browser from the list in local storage.

## Known limits

- Scheduled workflows are best-effort: expect alerts within 30 to 60 minutes of publication.
- GitHub pauses scheduled workflows in repositories with no activity for 60 days; re-enable under **Actions** if that happens.
- A new CVE without a CVSS score yet does not alert on the core rule until the score arrives (it is re-checked every run for seven days). The same goes for "big exploited flaw" alerts and foreign emergency entries: an exploited CVE without a score counts only with known ransomware use or EPSS ≥ 50 %.
- Feeds only carry their last 10 to 50 entries, so news from before the first run cannot be fetched; CVE data is complete for the backfill window.
- Product detection is rule-based. A flaw described only in free text may be tagged with the wrong product or none.
- Summaries, when enabled, are machine-written from headlines and feed teasers. Follow the source link before acting on one.

## Tests

```bash
python -m pytest -q
```
