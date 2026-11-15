'use strict';
/* SecPulse portal. Reads the JSON the collector publishes. All feed text is untrusted:
   it is only ever inserted with textContent, and links are limited to http(s).
   Everything that depends on "my stack" (verdicts, version check, handled, muted) is
   computed and stored here, in this browser. */

const $ = (s, r = document) => r.querySelector(s);
const store = {
  get(k, d) { try { const v = localStorage.getItem('sp.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('sp.' + k, JSON.stringify(v)); } catch { /* private mode */ } },
};

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(3)) if (kid != null && kid !== false && kid !== '') el.append(kid);
  return el;
}
const safeUrl = u => (/^https?:\/\//i.test(u || '') ? u : null);
const ext = (url, text, cls) => {
  const u = safeUrl(url);
  return u ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', class: cls }, text) : h('span', { class: cls }, text);
};
const hoursSince = iso => (iso ? (Date.now() - Date.parse(iso)) / 36e5 : 1e9);
function ago(iso) {
  const t = Date.parse(iso);
  if (!t) return '';
  const m = Math.max(0, (Date.now() - t) / 6e4);
  return m < 60 ? `${Math.round(m)} min` : m < 1440 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} d`;
}
/* "6 Nov", or "6 Nov 2025" outside the current year. Dates only, no false precision. */
function day(iso) {
  const t = Date.parse(iso);
  if (!t) return '';
  const d = new Date(t);
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', ...(d.getFullYear() !== new Date().getFullYear() ? { year: 'numeric' } : {}) });
}
const short = name => String(name || '').replace(/ \((other|enterprise software|language runtime|core|client|interpreter|DNS server)\)/, '');
const plural = (n, w) => `${n} ${n === 1 ? w : w.endsWith('y') ? w.slice(0, -1) + 'ies' : w + 's'}`;
const cap = s => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '');
/* "remote, no login, no user action" reads as "remote, no login": the last part is the norm. */
const how = (kind, path) => [kind, String(path || '').replace(/, no user action$/, '')].filter(Boolean).join(', ');
const cveUrl = id => 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(id);
const cvssTxt = v => (v == null ? 'CVSS pending' : 'CVSS ' + Number(v).toFixed(1));
const NOISE_TEASER = /^\s*submitted\s+by\s+\/u\//i;  // Reddit link posts carry no text

const CATS = { vulnerabilities: 'Vulnerabilities', breaches: 'Breaches', ransomware: 'Ransomware', 'threat-actors': 'Threat actors', research: 'Research', policy: 'Policy', tools: 'Tools' };
const AREAS = { microsoft: 'Microsoft', 'network-edge': 'Network / firewall / VPN', 'linux-oss-web': 'Linux / open source / web', 'cloud-virt': 'Cloud / virtualisation', identity: 'Identity / PAM', devops: 'DevOps / source control', endpoint: 'Browsers / endpoints', 'enterprise-apps': 'Enterprise applications' };
const VERDICT = {
  act: ['Act', 'Your product: exploited, public exploit or critical. Patch or mitigate now.'],
  check: ['Check', 'Your product: verify whether your version and setup are affected.'],
};
const HANDLED = { patched: 'Patched', na: 'Not affected', accepted: 'Risk accepted' };
const EMERGENCY_CVSS = 9.0;
const PAGE = { big: 5, news: 5, vulns: 30, stories: 40, cves: 30 };

const S = {
  stories: [], cves: [], majors: [], products: [], brief: {}, meta: {},
  view: store.get('view', 'brief'), q: '', cat: 'all', vf: 'all', more: {},
  read: new Set(store.get('read', [])),
  stack: store.get('stack', null) || { core: store.get('watch', []), areas: [] },
  handled: store.get('handled', {}),          // key -> {s: status, note, at}
  muted: new Set(store.get('muted', [])),     // catalogue product names
  core: [], what: {}, focus: null,
};

/* ---------- versions: same rules as collector/versions.py ---------- */
const PRE = { dev: -4, alpha: -3, a: -3, beta: -2, b: -2, rc: -1, pre: -1 };
const vparse = v => (String(v || '').toLowerCase().replace(/^v/, '').match(/\d+|[a-z]+/g) || []).map(t => (/^\d+$/.test(t) ? Number(t) : (PRE[t] ?? 0)));
function vcmp(a, b) {
  const pa = vparse(a), pb = vparse(b), n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) { const x = pa[i] ?? 0, y = pb[i] ?? 0; if (x !== y) return x < y ? -1 : 1; }
  return 0;
}
function inRange(v, r) {
  const bounded = ['si', 'se', 'ei', 'ee'].some(k => k in r);
  if (r.v && !['*', '-', ''].includes(r.v) && !bounded) return vcmp(v, r.v) === 0;
  if ('si' in r && vcmp(v, r.si) < 0) return false;
  if ('se' in r && vcmp(v, r.se) <= 0) return false;
  if ('ei' in r && vcmp(v, r.ei) > 0) return false;
  if ('ee' in r && vcmp(v, r.ee) >= 0) return false;
  return true;
}
function affected(v, ranges, partial) {
  if (!v || !vparse(v).length || !ranges?.length) return 'unknown';
  if (ranges.some(r => inRange(v, r))) return 'yes';
  return partial ? 'unknown' : 'no';
}
function fixedIn(v, ranges) {
  const c = (ranges || []).filter(r => 'ee' in r && inRange(v, r)).map(r => r.ee).sort(vcmp);
  return c[0] || null;
}
const splitVersion = e => { const m = String(e).trim().match(/^(.*?)\s+v?(\d+(?:[.\-]\w+)*)$/); return m ? [m[1].trim(), m[2]] : [String(e).trim(), null]; };

/* ---------- my stack (local to this browser) ---------- */
const norm = s => String(s || '').toLowerCase().replace(/https?:\/\/\S+/g, ' ').replace(/[\s_\-]+/g, ' ').trim();
const wordRx = w => new RegExp('(?<![a-z0-9])' + norm(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![a-z0-9])');

function compileStack() {
  // "Fortinet FortiOS 7.4.3": a name that names a catalogue product matches it exactly; anything else is a keyword.
  S.core = S.stack.core.map(t => t.trim()).filter(Boolean).map(entry => {
    const [term, version] = splitVersion(entry);
    const rx = wordRx(term);
    const names = new Set(S.products.filter(p => rx.test(norm(p.name))).map(p => p.name));
    return { term, version, rx, names };
  });
  S.what = Object.fromEntries(S.products.map(p => [p.name, p.what]));
}
function coreHit(prods, text, loose) {
  for (const c of S.core) {
    if (prods.some(p => c.names.has(p))) return c;
    if ((c.names.size === 0 || loose) && c.rx.test(norm(text))) return c;
  }
  return null;
}
/* Only your own products get a verdict. Everything else is information, not a task. */
function tag(x, prods, text, loose, f) {
  const c = coreHit(prods, text, loose);
  x._core = c ? c.term : null;
  x._area = S.stack.areas.includes(x.area);
  x._aff = null; x._mine = null; x._fixed = null;
  if (c && c.version && x.ranges !== undefined) {
    x._aff = affected(c.version, x.ranges, x.ranges_partial);
    x._mine = c.version;
    x._fixed = x._aff === 'yes' ? fixedIn(c.version, x.ranges) : null;
  }
  f = f || {};
  x._verdict = !x._core || x._aff === 'no' ? '' : (f.kev || f.poc || (f.cvss || 0) >= 9) ? 'act' : 'check';
}
function tagAll() {
  compileStack();
  for (const c of S.cves) { c.ranges ??= null; tag(c, c.prod ? [c.prod] : [], [c.label, c.title, ...(c.vendors || []), ...(c.products || []), c.vendors?.length ? '' : c.desc].join(' '), false, c); }
  for (const s of S.stories) tag(s, s.prods || [], s.title, s.kind !== 'vendor', s.facts);
  for (const m of S.majors) tag(m, [m.product], m.product, false, m);
}
const verdictBadge = x => x._verdict ? h('span', { class: 'v v-' + x._verdict, title: VERDICT[x._verdict][1] }, VERDICT[x._verdict][0]) : null;
const exploited = (kev, ransomware) => kev ? h('span', { class: 'v v-x', title: 'Used in real attacks (CISA KEV)' + (ransomware ? ', also by ransomware' : '') }, 'Exploited') : null;
const notYours = () => h('span', { class: 'v v-none', title: 'Not one of your products' }, 'Not yours');
/* Small inline icons, built as DOM (no innerHTML, no external files). */
function icon(d, cls) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16'); svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('class', 'ic ' + (cls || ''));
  const p = document.createElementNS(NS, 'path'); p.setAttribute('d', d); svg.append(p);
  return svg;
}
const ICON_WARN = 'M8 1.8 15 14H1L8 1.8zM8 6.4v3.6M8 12v.4';

/* "Is my version affected?" in one phrase, or nothing when no version is set. */
function versionNote(x) {
  if (!x._mine) return null;
  if (x._aff === 'yes') return `your ${x._mine} is affected` + (x._fixed ? `, fixed in ${x._fixed}` : '');
  if (x._aff === 'no') return `your ${x._mine} is not affected`;
  return `your ${x._mine}: no version data yet, treat as affected`;
}

function markRead(id) { S.read.add(id); store.set('read', [...S.read].slice(-3000)); }
const majorKey = m => 'm:' + m.product;
const isHandled = key => !!S.handled[key];
function setHandled(key, status, note) {
  if (status) S.handled[key] = { s: status, note: note || '', at: new Date().toISOString() };
  else delete S.handled[key];
  store.set('handled', S.handled);
  render();
}
function toggleMute(name) {
  S.muted.has(name) ? S.muted.delete(name) : S.muted.add(name);
  store.set('muted', [...S.muted]);
  render();
}

/* ---------- rows: one line, details on click ---------- */
/* A row is a small table line: title + one quiet line on the left, then fixed columns on the
   right (status, CVSS score, date) so that everything lines up down the list. */
function scoreEl(v) {
  if (v === undefined) return null;
  if (v == null) return h('span', { class: 'score s-na' });   // keeps the column, shows nothing
  const n = Number(v);
  return h('span', { class: 'score ' + (n >= 9 ? 's-crit' : n >= 7 ? 's-high' : 's-med'), title: 'CVSS severity score, 0 to 10' }, h('i', null, 'CVSS'), n.toFixed(1));
}
function row({ cls = '', id, lead, badge, main, score, meta, body }) {
  const text = lead
    ? h('div', { class: 'rt' }, h('div', { class: 't' }, lead), main && h('div', { class: 's' }, main))
    : h('div', { class: 'rt' }, h('div', { class: 't' }, main));
  const sum = [text, h('span', { class: 'slot' }, badge), scoreEl(score), meta && h('span', { class: 'meta' }, meta)];
  const kids = (body || []).filter(Boolean);
  if (!kids.length) return h('div', { class: 'row flat ' + cls, id }, sum);
  return h('details', { class: 'row ' + cls, id }, h('summary', null, sum, h('span', { class: 'chev', 'aria-hidden': 'true' })), h('div', { class: 'body' }, kids));
}
const facts = (...bits) => { const t = bits.filter(Boolean).join(' · '); return t ? h('p', { class: 'facts' }, t) : null; };
const linkList = (label, links) => links.length ? h('p', { class: 'links' }, label, ' ', links.flatMap((l, i) => i ? [' · ', l] : [l])) : null;
const cveLinks = ids => ids.map(id => h('a', { href: '#' + id, title: 'Show in CVE radar' }, id));
function moreBtn(key, total, shown) {
  return total > shown ? h('button', { class: 'more', on: { click: () => { S.more[key] = (S.more[key] || 0) + 30; render(); } } }, `Show more (${total - shown})`) : null;
}
/* published → fix → public exploit → exploited → CISA deadline, only what is known. */
function timeline(x) {
  const steps = [
    ['published', x.published], ['fix listed', x.fix_date], ['public exploit', x.poc_date],
    ['exploited (CISA)', x.kev_date], ['CISA deadline', x.kev ? x.due : null],
  ].filter(([, d]) => d).sort((a, b) => String(a[1]).localeCompare(String(b[1])));
  if (!steps.length) return null;
  return h('ol', { class: 'tl' }, steps.map(([label, d]) => h('li', null, h('b', null, day(d)), ' ' + label)));
}
const whenLine = x => x.kev && x.kev_date ? `exploited since ${day(x.kev_date)}` : x.published ? `published ${day(x.published)}` : '';
function handleButtons(key) {
  const note = h('input', { type: 'text', class: 'note', placeholder: 'Note (optional)', 'aria-label': 'Note' });
  return h('div', { class: 'handle' }, h('span', { class: 'hl' }, 'Mark as'),
    h('span', { class: 'group' }, Object.entries(HANDLED).map(([s, label]) => h('button', { type: 'button', on: { click: () => setHandled(key, s, note.value.trim()) } }, label))), note);
}
function muteButton(name) {
  return name && !S.core.some(c => c.names.has(name))
    ? h('button', { type: 'button', class: 'link quiet', on: { click: () => toggleMute(name) } }, S.muted.has(name) ? `Unmute ${short(name)}` : `Mute ${short(name)}`)
    : null;
}

/* ---------- emergency ---------- */
const recent = (x, days) => Math.min(hoursSince(x.published), hoursSince(x.kev_date)) <= days * 24;

/* Is an exploited CVE of this event critical? Unscored exploited CVEs count (NVD lags CISA). */
function exploitedCritical(m) {
  const byId = S._cveById || (S._cveById = new Map(S.cves.map(c => [c.id, c])));
  const kev = m.cves.map(id => byId.get(id)).filter(c => c && c.kev);
  // No score yet: only ransomware use or a high EPSS counts (same rule as the phone alerts).
  const crit = c => c.cvss == null ? !!c.ransomware || (c.epss || 0) >= 0.5 : c.cvss >= EMERGENCY_CVSS;
  if (!kev.length) return m.cvss != null && m.cvss >= EMERGENCY_CVSS;
  return kev.some(crit);
}
/* Highest score among the CVEs of an event that are actually exploited. */
function kevScore(m) {
  const byId = S._cveById || (S._cveById = new Map(S.cves.map(c => [c.id, c])));
  const v = m.cves.map(id => byId.get(id)).filter(c => c && c.kev && c.cvss != null).map(c => c.cvss);
  return v.length ? Math.max(...v) : null;
}
function emergencies() {
  // Your products: anything critical, unless your version is out of range or you handled it.
  const mine = S.cves.filter(c => c._core && (c.cvss || 0) >= EMERGENCY_CVSS && recent(c, 30) && c._aff !== 'no' && !isHandled(c.id))
    .sort((a, b) => (b.kev - a.kev) || (b.cvss - a.cvss));
  // Everyone else: only big, critical and exploited cases the industry is talking about. The
  // exploited CVE itself must be critical: a group's other, unexploited CVEs do not count.
  const big = S.majors.filter(m => !m._core && m.front && m.kev && exploitedCritical(m)
    && hoursSince(m.kev_date) <= 30 * 24 && !S.muted.has(m.product) && !isHandled(majorKey(m)))
    .sort((a, b) => (b.news * 5 + b.impact) - (a.news * 5 + a.impact));
  return { mine, big };
}
function renderEmergency() {
  const { mine, big } = emergencies();
  const box = $('#emergency');
  box.hidden = !mine.length && !big.length;
  box.replaceChildren();
  if (box.hidden) return;
  box.append(h('div', { class: 'sh' }, icon(ICON_WARN), h('h2', null, 'Emergency'),
    h('span', { class: 'sub' }, 'critical, stays here until you mark it'),
    h('span', { class: 'count' }, `${mine.length + big.length} open`)));
  for (const c of mine) {
    box.append(row({
      cls: 'em mine', id: 'em-' + c.id,
      lead: c._core, badge: h('span', { class: 'v v-act' }, 'Act'),
      main: [c.id, cap(how(c.kind, c.path))].filter(Boolean).join(' · '),
      score: c.cvss ?? null, meta: c.kev ? `exploited ${day(c.kev_date)}` : `published ${day(c.published)}`,
      body: [
        h('p', null, c.why || c.title || c.desc || ''),
        facts(versionNote(c), safeUrl(c.fix) ? 'fix available' : 'no fix listed yet', c.poc && 'public exploit'),
        timeline(c),
        h('p', { class: 'links' }, ext(cveUrl(c.id), 'CVE record ↗'), safeUrl(c.fix) && ' · ', safeUrl(c.fix) && ext(c.fix, 'Fix / advisory ↗')),
        handleButtons(c.id),
      ],
    }));
  }
  for (const m of big) {
    box.append(row({
      cls: 'em other', id: 'em-' + majorKey(m),
      lead: short(m.product), badge: notYours(),
      main: [m.headline, how(m.kind, m.path)].filter(Boolean).join(' · '),
      score: kevScore(m), meta: `exploited ${day(m.kev_date)}`,
      body: [
        facts(m.n_cves && plural(m.n_cves, 'CVE'), m.news && `covered by ${plural(m.news, 'outlet')}`, m.ransomware && 'used by ransomware'),
        timeline(m),
        linkList('CVEs:', cveLinks(m.cves)),
        linkList('Read:', [safeUrl(m.fix) && ext(m.fix, 'Fix / advisory ↗'), ...m.stories.map(s => ext(s.url, s.source + ' ↗'))].filter(Boolean)),
        h('p', null, 'Not one of your products. Shown because it is critical, exploited and widely deployed: check whether you run it anywhere.'),
        handleButtons(majorKey(m)), muteButton(m.product),
      ],
    }));
  }
}

/* ---------- A. your products ---------- */
function renderBoard() {
  const box = $('#board');
  box.replaceChildren();
  $('#boardCount').textContent = '';
  if (!S.core.length) {
    box.append(h('div', { class: 'blank' },
      h('p', null, 'Tell SecPulse which products you run, ideally with the version (“Fortinet FortiOS 7.4.3”). They appear here with a clear Act or Check, and nothing else gets that label.'),
      h('button', { class: 'btn primary', on: { click: openStack } }, 'Set my stack')));
    return;
  }
  const quiet = [];
  const rows = [];
  for (const c of S.core) {
    const all = S.cves.filter(x => x._core === c.term && recent(x, 30));
    const open = all.filter(x => !isHandled(x.id) && x._aff !== 'no').sort((a, b) => b.score - a.score);
    const done = all.filter(x => isHandled(x.id)).length;
    const unaff = all.filter(x => !isHandled(x.id) && x._aff === 'no').length;
    const extra = [done && `${done} handled`, unaff && `${unaff} not affected`].filter(Boolean).join(', ');
    const stories = S.stories.filter(s => s._core === c.term && s.kind !== 'vendor' && hoursSince(s.updated) <= 24 * 14)
      .sort((a, b) => b.updated.localeCompare(a.updated));
    const releases = S.stories.filter(s => s._core === c.term && s.kind === 'vendor' && hoursSince(s.updated) <= 24 * 30)
      .sort((a, b) => b.updated.localeCompare(a.updated));
    if (!open.length && !stories.length && !releases.length) { quiet.push(c.term + (extra ? ` (${extra})` : '')); continue; }
    const top = open[0];
    const nKev = open.filter(x => x.kev).length;
    const verdict = open.some(x => x._verdict === 'act') ? 'act' : open.length || stories.length ? 'check' : '';
    const parts = [];
    if (open.length) {
      parts.push(plural(open.length, 'open CVE') + (nKev ? `, ${nKev} exploited` : ''));
      if (top.path) parts.push(how('', top.path));
      parts.push(open.some(x => safeUrl(x.fix)) ? 'fix available' : 'no fix listed');
    }
    if (releases[0]) parts.push(`${releases[0].security ? 'security release' : 'update'} ${day(releases[0].updated)}`);
    if (!open.length && stories.length) parts.push(plural(stories.length, 'story') + ': ' + stories[0].title);
    if (extra) parts.push(extra);
    rows.push({ rank: verdict === 'act' ? 0 : verdict ? 1 : 2, el: row({
      cls: 'prod',
      lead: c.term + (c.version ? ' ' + c.version : ''), badge: verdict ? h('span', { class: 'v v-' + verdict, title: VERDICT[verdict][1] }, VERDICT[verdict][0]) : null,
      main: parts.join(' · '),
      score: open.length ? (Math.max(...open.map(x => x.cvss ?? 0)) || null) : null,
      body: [
        ...open.slice(0, 8).map(x => h('div', { class: 'item' },
          h('a', { href: '#' + x.id }, x.id), ' ', exploited(x.kev, x.ransomware),
          facts(cvssTxt(x.cvss), whenLine(x), cap(how(x.kind, x.path)), versionNote(x)),
          h('p', null, x.why || x.title || x.desc || ''),
          timeline(x),
          safeUrl(x.fix) && h('p', { class: 'links' }, ext(x.fix, 'Fix / advisory ↗')),
          handleButtons(x.id))),
        open.length > 8 && h('p', { class: 'facts' }, `${open.length - 8} more in the CVE radar`),
        releases.length > 0 && h('div', { class: 'item' }, h('p', { class: 'facts' }, 'From the vendor'),
          releases.slice(0, 4).map(s => h('p', null, h('b', null, day(s.updated) + ' '), ext(s.url, s.title), s.security ? ' · security' : ''))),
        ...stories.slice(0, 5).map(s => h('div', { class: 'item' }, storyLink(s), h('span', { class: 'meta' }, ` ${s.sources[0].source} · ${day(s.updated)}`))),
      ],
    }) });
  }
  rows.sort((a, b) => a.rank - b.rank);
  const nAct = rows.filter(r => r.rank === 0).length, nCheck = rows.filter(r => r.rank === 1).length;
  $('#boardCount').textContent = nAct ? `${nAct} need action` : nCheck ? `${nCheck} to check` : 'nothing open';
  box.append(...rows.map(r => r.el));
  if (quiet.length) box.append(h('div', { class: 'row flat quiet' }, h('div', { class: 'rt' }, h('div', { class: 's' }, quiet.join(' · '))), h('span', { class: 'meta' }, 'nothing open')));
}

/* ---------- B. big in the industry ---------- */
function majorRow(m) {
  return row({
    cls: 'major',
    lead: short(m.product), badge: verdictBadge(m) || exploited(m.kev, m.ransomware),
    main: [m.headline || m.what || m.text, how(m.kind, m.path)].filter(Boolean).join(' · '),
    score: m.cvss ?? null,
    meta: m.kev && m.kev_date ? 'exploited ' + day(m.kev_date) : m.published ? day(m.published) : '',
    body: [
      m.what && m.text && m.text !== m.what && h('p', null, m.text),
      facts(m.n_cves && plural(m.n_cves, 'CVE'), m.cvss && 'worst ' + cvssTxt(m.cvss),
        m.poc && 'public exploit', m.ransomware && 'used by ransomware', m.news && `covered by ${plural(m.news, 'outlet')}`),
      timeline(m),
      linkList('CVEs:', cveLinks(m.cves)),
      linkList('Read:', [safeUrl(m.fix) && ext(m.fix, 'Fix / advisory ↗'), ...m.stories.map(s => ext(s.url, s.source + ' ↗'))].filter(Boolean)),
      muteButton(m.product),
    ],
  });
}
function renderBig() {
  // Your own products are already above; emergencies are already above. Rank by press coverage.
  const em = new Set(emergencies().big.map(m => m.product));
  const list = S.majors.filter(m => m.front && !m._core && !em.has(m.product) && !S.muted.has(m.product))
    .sort((a, b) => (b.news * 5 + b.impact) - (a.news * 5 + a.impact));
  $('#big').replaceChildren(...list.slice(0, PAGE.big).map(majorRow),
    h('button', { class: 'more', on: { click: () => setView('all', '#hV') } }, `All vulnerabilities (${S.majors.length}) →`));
}

/* ---------- C. news ---------- */
function storyLink(s) {
  const a = ext(s.url, s.title, 't');
  a.addEventListener('click', () => { markRead(s.id); a.closest('.row')?.classList.add('read'); });
  return a;
}
function storyRow(s) {
  const f = s.facts || {};
  return row({
    cls: 'story' + (S.read.has(s.id) ? ' read' : ''), id: 's-' + s.id,
    badge: verdictBadge(s) || exploited(f.kev, f.ransomware),
    main: storyLink(s),
    meta: `${s.sources[0].source}${s.n_sources > 1 ? ` +${s.n_sources - 1}` : ''} · ${ago(s.updated)}`,
    body: [
      s.summary && !NOISE_TEASER.test(s.summary) && h('p', null, s.summary),
      !s.summary && s.teaser && !NOISE_TEASER.test(s.teaser) && h('p', null, s.teaser),
      (s.prods || [])[0] && S.what[s.prods[0]] && facts(`${short(s.prods[0])}: ${S.what[s.prods[0]]}`),
      (f.cve || s.vkind) && facts(cap(how(s.vkind || f.kind, f.path)), f.cve && cvssTxt(f.cvss), f.poc && 'public exploit', safeUrl(f.fix) && 'fix available'),
      linkList('CVEs:', cveLinks(s.cves.slice(0, 6))),
      s.n_sources > 1 && linkList('Also:', s.sources.slice(1, 6).map(x => ext(x.url, x.source))),
      facts(`first reported ${day(s.published || s.updated)}`),
      muteButton((s.prods || [])[0]),
    ],
  });
}
const isBroad = s => (s.prods || []).length > 0 || s.n_sources >= 2 || s.importance >= 5;
const mutedStory = s => (s.prods || []).length > 0 && s.prods.every(p => S.muted.has(p));
function renderNews() {
  const ok = s => !s._core && s.kind !== 'vendor' && !mutedStory(s);
  let pool = S.stories.filter(s => hoursSince(s.updated) <= 24 && ok(s));
  if (pool.length < 8) pool = S.stories.filter(s => hoursSince(s.updated) <= 72 && ok(s));
  pool = pool.filter(s => isBroad(s) && !(s.kind === 'advisory' && s.n_sources === 1));
  const rank = s => s.importance + 2 * (s.n_sources - 1) + ((s.facts || {}).kev ? 2 : 0) - hoursSince(s.updated) / 12;
  const list = pool.sort((a, b) => rank(b) - rank(a)).slice(0, PAGE.news);
  const b = S.brief || {};
  $('#newsSub').textContent = b.ai && b.headline ? b.headline : 'what most outlets are covering';
  $('#news').replaceChildren(...list.map(storyRow),
    h('button', { class: 'more', on: { click: () => setView('all', '#hS') } }, `All stories (${S.stories.length}) →`));
}

/* ---------- everything ---------- */
const matches = (q, ...fields) => fields.flat().filter(Boolean).join(' ').toLowerCase().includes(q);

function renderHandled() {
  const keys = Object.keys(S.handled);
  $('#handledSec').hidden = !keys.length;
  if (!keys.length) return;
  keys.sort((a, b) => S.handled[b].at.localeCompare(S.handled[a].at));
  $('#handled').replaceChildren(...keys.map(k => {
    const x = S.handled[k];
    return h('div', { class: 'row flat' },
      h('div', { class: 'rt' }, h('div', { class: 't' }, k.replace(/^m:/, '')),
        h('div', { class: 's' }, `${HANDLED[x.s] || x.s} on ${day(x.at)}` + (x.note ? ` · ${x.note}` : ''))),
      h('button', { type: 'button', class: 'btn small', on: { click: () => setHandled(k, null) } }, 'Undo'));
  }));
}
function renderVulns() {
  const q = S.q.toLowerCase();
  const filters = { all: 'All', kev: 'Exploited', crit: 'Not exploited yet', ...(S.stack.areas.length ? { areas: 'My areas' } : {}), ...(S.muted.size ? { muted: 'Muted' } : {}) };
  if (!filters[S.vf]) S.vf = 'all';
  let list = S.majors.filter(m => !q || matches(q, m.product, m.what, m.text, m.cves));
  const by = { all: m => !S.muted.has(m.product), kev: m => m.kev, crit: m => !m.kev, areas: m => m._area || m._core, muted: m => S.muted.has(m.product) };
  list = list.filter(by[S.vf]).sort((a, b) => (!!b._core - !!a._core) || (b.impact - a.impact));
  $('#vulnChips').replaceChildren(...Object.entries(filters).map(([k, label]) =>
    h('button', { 'aria-pressed': String(S.vf === k), on: { click: () => { S.vf = k; renderVulns(); } } }, label)));
  const n = PAGE.vulns + (S.more.vulns || 0);
  $('#vulnSub').textContent = `${list.length} events, last 30 days`;
  $('#vulns').replaceChildren(...list.slice(0, n).map(majorRow), moreBtn('vulns', list.length, n));
}
function renderStories() {
  const q = S.q.toLowerCase();
  const base = S.stories.filter(s => s.kind !== 'vendor' || s._core);
  let pool = q ? base.filter(s => matches(q, s.title, s.summary, s.cves, s.prods, s.sources.map(x => x.source)))
    : base.filter(s => hoursSince(s.updated) <= 24 * 7);
  const counts = { all: pool.length };
  for (const s of pool) counts[s.category] = (counts[s.category] || 0) + 1;
  if (S.cat !== 'all') pool = pool.filter(s => s.category === S.cat);
  pool.sort((a, b) => b.updated.localeCompare(a.updated));
  $('#chips').replaceChildren(...['all', ...Object.keys(CATS)].filter(k => k === 'all' || counts[k]).map(k =>
    h('button', { 'aria-pressed': String(S.cat === k), on: { click: () => { S.cat = k; renderStories(); } } },
      k === 'all' ? 'All' : CATS[k], h('i', null, String(counts[k] || 0)))));
  const n = PAGE.stories + (S.more.stories || 0);
  $('#storiesSub').textContent = q ? `${pool.length} match “${S.q}”` : 'last 7 days, newest first';
  $('#stories').replaceChildren(...pool.slice(0, n).map(storyRow), moreBtn('stories', pool.length, n));
  if (!pool.length) $('#stories').append(h('p', { class: 'hint' }, 'Nothing found.'));
}
function cveRow(c) {
  const prod = short(c.prod) || c.label || [c.vendors?.[0], c.products?.[0]].filter(Boolean).join(' ').replace(/_/g, ' ');
  return row({
    cls: 'cve' + (c._aff === 'no' || isHandled(c.id) ? ' done' : ''), id: c.id,
    lead: c.id, badge: verdictBadge(c) || exploited(c.kev, c.ransomware),
    main: [prod, (c.prod && S.what[c.prod]) || '', how(c.kind, c.path)].filter(Boolean).join(' · '),
    score: c.cvss ?? null,
    meta: c.kev && c.kev_date ? 'exploited ' + day(c.kev_date) : day(c.published),
    body: [
      h('p', null, c.why || c.title || c.desc || ''),
      facts(cvssTxt(c.cvss), c.epss != null && 'EPSS ' + (c.epss * 100).toFixed(c.epss < 0.1 ? 1 : 0) + '%',
        c.news && `covered by ${plural(c.news, 'outlet')}`, `risk score ${c.score}`, versionNote(c)),
      timeline(c),
      h('p', { class: 'links' }, ext(cveUrl(c.id), 'CVE record ↗'), safeUrl(c.fix) && ' · ', safeUrl(c.fix) && ext(c.fix, 'Fix / advisory ↗')),
      c._core && (isHandled(c.id) ? h('p', { class: 'facts' }, `${HANDLED[S.handled[c.id].s]} on ${day(S.handled[c.id].at)}`) : handleButtons(c.id)),
    ],
  });
}
function renderRadar() {
  const q = S.q.toLowerCase();
  let pool = S.cves.filter(c => !q || matches(q, c.id, c.title, c.desc, c.label, c.prod, c.kind, c.vendors, c.products));
  pool = pool.sort((a, b) => (!!b._core - !!a._core) || (b.score - a.score));
  const n = PAGE.cves + (S.more.cves || 0);
  let list = pool.slice(0, n);
  if (S.focus && !list.some(c => c.id === S.focus)) {
    const hit = S.cves.find(c => c.id === S.focus);
    if (hit) list = [hit, ...list];
  }
  $('#radarSub').textContent = `${pool.length} CVEs by exploitation risk`;
  $('#radar').replaceChildren(...list.map(cveRow), moreBtn('cves', pool.length, n));
}
function spark(values) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${values.length * 9} 34`);
  svg.setAttribute('aria-hidden', 'true');
  const max = Math.max(1, ...values);
  values.forEach((v, i) => {
    const r = document.createElementNS(NS, 'rect');
    const ht = Math.max(2, (v / max) * 32);
    r.setAttribute('x', i * 9); r.setAttribute('y', 34 - ht); r.setAttribute('width', 6); r.setAttribute('height', ht); r.setAttribute('rx', 1.5);
    if (i === values.length - 1) r.setAttribute('class', 'last');
    svg.append(r);
  });
  return svg;
}
function renderPulse() {
  const t = S.meta.trends, box = $('#pulse');
  box.replaceChildren();
  if (!t) return;
  const sum7 = a => a.slice(-7).reduce((x, y) => x + y, 0);
  box.append(
    h('div', { class: 'tile' }, h('div', null, h('div', { class: 'n' }, String(sum7(t.kev))), h('div', { class: 'l' }, 'newly exploited CVEs, 7 days')), spark(t.kev)),
    h('div', { class: 'tile' }, h('div', null, h('div', { class: 'n' }, String(sum7(t.critical))), h('div', { class: 'l' }, 'critical CVEs published, 7 days')), spark(t.critical)));
}

/* ---------- chrome ---------- */
function renderChrome() {
  const m = S.meta, feeds = m.feeds || {};
  const bad = Object.entries(feeds).filter(([, v]) => typeof v !== 'number').map(([k]) => k);
  const stale = hoursSince(m.generated) > 2 || bad.length > 0;
  $('#status').replaceChildren(
    h('span', { class: 'dot ' + (stale ? 'warn' : 'ok'), title: stale ? 'Data is older than two hours, or a source failed' : 'Up to date' }),
    'Updated ', h('b', null, ago(m.generated) + ' ago'),
    ` · ${Object.keys(feeds).length - bad.length} sources`);
  for (const b of document.querySelectorAll('#tabs button')) b.setAttribute('aria-pressed', String(b.dataset.v === S.view));
  $('#vBrief').hidden = S.view !== 'brief';
  $('#vAll').hidden = S.view !== 'all';
  const n = S.stack.core.length;
  $('#stackBtn').textContent = n ? `My stack (${n})` : 'My stack';
  const dl = (cls, pairs) => h('dl', { class: cls }, pairs.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const badge = (cls, text) => h('span', { class: 'v ' + cls }, text);
  const when = Date.parse(m.generated) ? `${day(m.generated)}, ${new Date(m.generated).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}` : '';
  $('#foot').replaceChildren(
    h('div', { class: 'fcols' },
      h('div', null, h('h3', null, 'Legend'), dl('legend', [
        [badge('v-act', 'Act'), VERDICT.act[1]],
        [badge('v-check', 'Check'), VERDICT.check[1]],
        [badge('v-x', 'Exploited'), 'Used in real attacks, confirmed by CISA.'],
        [badge('v-none', 'Not yours'), 'Widely deployed product outside your stack. Check whether you run it anywhere.'],
        [h('span', { class: 'score s-crit' }, h('i', null, 'CVSS'), '9.8'), 'Severity score, 0 to 10. Red from 9.0, amber from 7.0.'],
      ])),
      h('div', null, h('h3', null, 'How it works'),
        h('p', null, `Emergency lists your products with CVSS ≥ ${EMERGENCY_CVSS.toFixed(1)}, and widely deployed products that are critical and exploited.`),
        h('p', null, 'Version checks use NVD’s affected ranges. New CVEs often have none for days; until then they count as affected.'),
        h('p', null, 'Your stack, handled items and mutes stay in this browser.')),
      h('div', { class: 'keys' }, h('h3', null, 'Keyboard'), dl('kb', [
        [[h('kbd', null, 'j'), ' ', h('kbd', null, 'k')], 'Move'],
        [h('kbd', null, 'Enter'), 'Details'],
        [h('kbd', null, 'o'), 'Open source'],
        [h('kbd', null, '/'), 'Search'],
      ]))),
    bad.length ? h('p', { class: 'bad' }, `Unreachable this run: ${bad.join(', ')}`) : '',
    h('div', { class: 'fbase' },
      h('span', null, h('b', null, 'SecPulse'), ' · Sources: CVE.org, NVD, CISA KEV, FIRST EPSS, GitHub advisories and security news feeds. Rule-based; confirm against the vendor advisory before acting.'),
      when ? h('span', { class: 'when' }, 'Updated ' + when) : ''));
}
function render() {
  renderChrome();
  renderEmergency();
  if (S.view === 'brief') { renderBoard(); renderBig(); renderNews(); }
  else { renderPulse(); renderVulns(); renderStories(); renderRadar(); renderHandled(); }
}
function setView(v, anchor) {
  S.view = v; S.more = {};
  if (!S.q) store.set('view', v);
  render();
  if (anchor) $(anchor)?.scrollIntoView();
  else scrollTo(0, 0);
}

function focusHash() {
  const id = decodeURIComponent(location.hash.slice(1));
  if (!/^CVE-\d{4}-\d+$/.test(id)) return;
  S.focus = id;
  if (S.view !== 'all') { S.view = 'all'; render(); } else renderRadar();
  const el = $('#radar').querySelector('#' + CSS.escape(id));
  if (el) { el.open = true; el.scrollIntoView({ block: 'center' }); el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); }
}

/* ---------- stack dialog, export / import ---------- */
function stackYaml(core, areas) {
  const q = s => '"' + s.replace(/["\\]/g, '') + '"';
  return ['core:', ...core.map(c => '  - ' + q(c)), 'areas:', ...areas.map(a => '  - ' + a)].join('\n') + '\n';
}
function readDialog() {
  return {
    core: $('#coreTxt').value.split('\n').map(x => x.trim()).filter(Boolean).slice(0, 100),
    areas: [...document.querySelectorAll('#areaBox input:checked')].map(i => i.value),
  };
}
function renderMutedList() {
  const box = $('#mutedBox');
  box.replaceChildren(...[...S.muted].sort().map(name =>
    h('button', { type: 'button', class: 'btn small', title: 'Unmute', on: { click: () => { toggleMute(name); renderMutedList(); } } }, short(name) + ' ✕')));
  $('#mutedRow').hidden = !S.muted.size;
}
function openStack() {
  $('#coreTxt').value = S.stack.core.join('\n');
  $('#areaBox').replaceChildren(...Object.entries(AREAS).map(([k, label]) =>
    h('label', null, h('input', { type: 'checkbox', value: k, checked: S.stack.areas.includes(k) }), ' ' + label)));
  $('#yamlOut').hidden = true;
  renderMutedList();
  $('#stackDlg').showModal();
}
function exportState() {
  const data = { secpulse: 1, exported: new Date().toISOString(), stack: S.stack, handled: S.handled, muted: [...S.muted] };
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = h('a', { href: url, download: 'secpulse-state.json' });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function importState(file) {
  try {
    const data = JSON.parse(await file.text());
    if (data?.secpulse !== 1) throw new Error('not a SecPulse file');
    if (data.stack && Array.isArray(data.stack.core)) {
      S.stack = { core: data.stack.core.map(String).slice(0, 100), areas: (data.stack.areas || []).filter(a => AREAS[a]) };
    }
    if (data.handled && typeof data.handled === 'object') {
      S.handled = Object.fromEntries(Object.entries(data.handled).filter(([, v]) => v && HANDLED[v.s])
        .map(([k, v]) => [String(k), { s: v.s, note: String(v.note || '').slice(0, 300), at: String(v.at || '') }]));
    }
    if (Array.isArray(data.muted)) S.muted = new Set(data.muted.map(String));
    store.set('stack', S.stack); store.set('handled', S.handled); store.set('muted', [...S.muted]);
    $('#stackDlg').close(); tagAll(); render();
  } catch (e) {
    $('#ioMsg').textContent = 'Could not import: ' + e.message;
  }
}

/* ---------- events ---------- */
function wire() {
  $('#tabs').addEventListener('click', e => { if (e.target.dataset?.v) { $('#q').value = ''; S.q = ''; setView(e.target.dataset.v); } });
  let timer;
  $('#q').addEventListener('input', e => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      S.q = e.target.value.trim(); S.more = {};
      if (S.q) { S.view = 'all'; S.cat = 'all'; S.vf = 'all'; }
      render();
    }, 160);
  });
  // The button names the theme you switch TO: sun + "Light" while dark, moon + "Dark" while light.
  const sysLight = matchMedia('(prefers-color-scheme: light)');
  const themeNow = () => document.documentElement.dataset.theme || (sysLight.matches ? 'light' : 'dark');
  const showTheme = () => {
    const now = themeNow(), b = $('#themeBtn');
    b.dataset.mode = now;
    $('#themeLbl').textContent = now === 'dark' ? 'Light' : 'Dark';
    b.title = b.ariaLabel = now === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
  };
  $('#themeBtn').addEventListener('click', () => {
    const next = themeNow() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next; store.set('theme', next);
    showTheme();
  });
  sysLight.addEventListener('change', showTheme);
  showTheme();
  const dlg = $('#stackDlg');
  $('#stackBtn').addEventListener('click', openStack);
  $('#yamlBtn').addEventListener('click', async () => {
    const { core, areas } = readDialog();
    const out = $('#yamlOut');
    out.value = stackYaml(core, areas); out.hidden = false; out.select();
    try { await navigator.clipboard.writeText(out.value); $('#yamlBtn').textContent = 'Copied'; } catch { $('#yamlBtn').textContent = 'Select and copy below'; }
  });
  $('#exportBtn').addEventListener('click', exportState);
  $('#importFile').addEventListener('change', e => { if (e.target.files[0]) importState(e.target.files[0]); e.target.value = ''; });
  dlg.addEventListener('close', () => {
    $('#yamlBtn').textContent = 'Copy as YAML';
    $('#ioMsg').textContent = '';
    if (dlg.returnValue !== 'save') return;
    S.stack = readDialog();
    store.set('stack', S.stack); tagAll(); render();
  });
  addEventListener('hashchange', focusHash);
  addEventListener('keydown', e => {
    if (e.target.matches('input, textarea') || e.metaKey || e.ctrlKey || e.altKey) {
      if (e.key === 'Escape') e.target.blur();
      return;
    }
    const scope = [$('#emergency'), S.view === 'brief' ? $('#vBrief') : $('#vAll')];
    const rows = scope.flatMap(el => [...el.querySelectorAll('.row > summary, .row.flat')]);
    const at = rows.indexOf(document.activeElement);
    if (e.key === '/') { e.preventDefault(); $('#q').focus(); }
    else if (e.key === 'j' || e.key === 'k') {
      const next = rows[Math.min(rows.length - 1, Math.max(0, at + (e.key === 'j' ? 1 : -1)))] || rows[0];
      if (next) { if (!next.matches('summary')) next.tabIndex = -1; next.focus(); next.scrollIntoView({ block: 'nearest' }); }
    } else if (e.key === 'o' && at >= 0) {
      const a = rows[at].closest('.row').querySelector('a[target]');
      if (a) a.click();
    }
  });
}

/* Load the published JSON. Tells apart "server unreachable" from "collector has not run yet",
   and retries on its own, so a page opened while the server restarts recovers. */
async function load(attempt = 0) {
  const get = f => fetch('data/' + f, { cache: 'no-cache' }).then(r => {
    if (!r.ok) { const e = new Error(f); e.status = r.status; throw e; }
    return r.json();
  });
  try {
    [S.stories, S.cves, S.brief, S.meta, S.majors, S.products] = await Promise.all(
      ['stories.json', 'cves.json', 'brief.json', 'meta.json', 'majors.json', 'products.json'].map(get));
    $('#empty').hidden = true;
    return true;
  } catch (e) {
    const box = $('#empty');
    box.hidden = false;
    box.replaceChildren(
      e.status === 404
        ? 'No data yet: the collector has not published anything. Run it once (python -m collector.main), then reload.'
        : e instanceof SyntaxError
          ? 'The data is being rewritten right now (collector run in progress). Retrying…'
          : 'Cannot reach the server that serves the portal. Is it running? Retrying…',
      h('br'), h('button', { class: 'btn', on: { click: () => location.reload() } }, 'Reload now'));
    if (e.status !== 404 && attempt < 60) {
      await new Promise(r => setTimeout(r, Math.min(15000, 2000 * (attempt + 1))));
      return load(attempt + 1);
    }
    return false;
  }
}

async function boot() {
  const theme = store.get('theme', null);
  if (theme) document.documentElement.dataset.theme = theme;
  if (!['brief', 'all'].includes(S.view)) S.view = 'brief';
  if (!Array.isArray(S.stack.core)) S.stack = { core: [], areas: [] };
  S.stack.areas = (S.stack.areas || []).filter(a => AREAS[a]);
  if (!S.handled || typeof S.handled !== 'object') S.handled = {};
  wire();
  if (!(await load())) return;
  tagAll();
  $('#app').hidden = false;
  render();
  focusHash();
}
boot();
