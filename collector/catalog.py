"""Product catalogue: recognise widely deployed products in CVE data and headlines,
and turn CVSS vectors and CWE ids into plain words. Everything here is public information."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

_URL = re.compile(r"https?://\S+")


def norm(s) -> str:
    return re.sub(r"[\s_\-]+", " ", str(s or "").lower()).strip()


def kw_re(phrase: str) -> re.Pattern:
    return re.compile(r"(?<![a-z0-9])" + re.escape(norm(phrase)) + r"(?![a-z0-9])")


def clean(text) -> str:
    """Normalised text with URLs removed, so 'github.com/…' links do not count as mentions."""
    return norm(_URL.sub(" ", str(text or "")))


def is_catchall(name: str) -> bool:
    """Catalogue rows like "Fortinet (other)" stand for a vendor, not one product."""
    return "(other)" in name or "(enterprise software)" in name


_AFFECTS_LEAD = re.compile(r"(?:^|\s)(?:affects|impacts)\s(?:the\s)?$")
_SUBJECT_LEAD = re.compile(r"(?:^|(?:^|\s)(?:in|of|for|affecting|within)\s(?:the\s)?)$")


def _is_subject(rx: re.Pattern, text: str, vendors=()) -> bool:
    for m in rx.finditer(text):
        before = text[: m.start()]
        # "in the Oracle Java SE": the vendor's name may stand between "in the" and the product.
        for v in vendors:
            if before.endswith(" " + v + " "):
                before = before[: -len(v) - 1]
                break
        if m.start() <= 12 or _SUBJECT_LEAD.search(before):
            return True
        # "This issue affects NGINX ...": only as the opening statement, not "note that this
        # only affects MySQL" further down, where it names a precondition.
        if m.start() <= 40 and _AFFECTS_LEAD.search(before):
            return True
    return False


class Catalog:
    def __init__(self, products: list[dict]):
        self.products = []
        for p in products or []:
            names = [p["name"], *(p.get("aliases") or [])]
            # "Fortinet (other)" style names are labels, not phrases to search for.
            phrases = [n for n in names if "(" not in n and " / " not in n]
            pairs, vendors = set(), set()
            for c in p.get("cpe") or []:
                v, _, prod = str(c).partition(":")
                (pairs.add((norm(v), norm(prod))) if prod else vendors.add(norm(v)))
            self.products.append({"name": p["name"], "area": p.get("area", ""), "what": p.get("what", ""),
                                  "rx": [kw_re(x) for x in phrases], "pairs": pairs, "vendors": vendors,
                                  "keys": {norm(n) for n in names},
                                  # Vendor names from the CPE ids, for "in the <vendor> <product>".
                                  "prefixes": sorted({v for v, _ in pairs} | vendors, key=len, reverse=True),
                                  "base": norm(p["name"].split(" (")[0])})

    @classmethod
    def load(cls, path: Path) -> "Catalog":
        return cls((yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}).get("products", []))

    def find(self, name: str) -> dict | None:
        key = norm(name)
        return next((p for p in self.products if key in p["keys"]), None)

    def match_cve(self, cve: dict) -> dict | None:
        """Best catalogue product for a CVE: exact vendor:product first, then a phrase in the
        title or KEV label, then vendor only, then a phrase early in the description."""
        vendors = {norm(v) for v in cve.get("vendors") or []}
        products = {norm(p) for p in cve.get("products") or []}
        texts = (clean(cve.get("title", "")), clean(str(cve.get("desc", ""))[:300]))
        # CISA's label names the vulnerable component itself. CPE data also lists downstream
        # products that merely ship it (a PHP flaw lists PAN-OS), so the label goes first.
        label = clean(cve.get("kev_product", ""))
        if label:
            exact_label = next((p for p in self.products if norm(label) in p["keys"] | {p["base"]}), None)
            if exact_label:
                return exact_label
            for p in self.products:
                if any(rx.search(label) for rx in p["rx"]):
                    return p
        exact = [p for p in self.products if any(v in vendors and pr in products for v, pr in p["pairs"])]
        if exact:
            return next((p for p in exact if any(_is_subject(rx, t, p["prefixes"]) for rx in p["rx"] for t in texts)), exact[0])
        for p in self.products:
            if p["vendors"] & vendors:
                return p
        if not vendors:
            # No structured data yet. Free text names other products in passing ("…reads the
            # GitHub webhook body"), so a phrase only counts where the subject of a CVE text
            # normally stands: at the very start, or right after "in", "of", "for", "affecting".
            for text in texts:
                for p in self.products:
                    if any(_is_subject(rx, text, p["prefixes"]) for rx in p["rx"]):
                        return p
        return None

    @staticmethod
    def ranges_for(product: dict, ranges: list[dict]) -> list[dict]:
        """The version ranges that belong to this catalogue product."""
        out = []
        for r in ranges or []:
            v, _, p = str(r.get("cpe", "")).partition(":")
            if (norm(v), norm(p)) in product["pairs"] or norm(v) in product["vendors"]:
                out.append(r)
        return out

    def match_text(self, text: str) -> list[dict]:
        t = clean(text)
        return [p for p in self.products if any(rx.search(t) for rx in p["rx"])]


# ---------------------------------------------------------------- plain-language triage facts

_CWE = {
    "auth bypass": {287, 288, 290, 294, 302, 303, 304, 305, 306, 307, 308, 603, 639, 862, 863, 284, 285, 1390},
    "code execution": {77, 78, 88, 94, 95, 96, 502, 434, 917, 1336, 74, 470, 913},
    "memory corruption": {119, 120, 121, 122, 125, 787, 416, 415, 190, 191, 476, 824, 843, 129, 131},
    "SQL injection": {89},
    "cross-site scripting": {79, 80},
    "path traversal": {22, 23, 35, 36, 73, 59},
    "privilege escalation": {269, 250, 266, 268, 270, 732, 276},
    "SSRF": {918},
    "hard-coded credentials": {798, 259, 321},
    "information disclosure": {200, 201, 203, 209, 532, 522, 312, 319, 538},
    "denial of service": {400, 770, 835, 674, 401, 404, 617},
    "CSRF": {352},
    "XML external entity": {611},
    "open redirect": {601},
}
_CWE_KIND = {n: kind for kind, ids in _CWE.items() for n in ids}
_TEXT_KIND = [
    ("code execution", r"remote code execution|\brce\b|execute arbitrary (code|commands)|command injection|code injection|deserializ"),
    ("auth bypass", r"authentication bypass|bypass(es|ing)? authentication|auth(orization)? bypass|missing authentication|improper authentication|without authentication"),
    ("privilege escalation", r"privilege escalation|elevation of privilege|escalate privileges|gain (root|system|elevated)"),
    ("SQL injection", r"sql injection"),
    ("path traversal", r"path traversal|directory traversal"),
    ("memory corruption", r"buffer overflow|out-of-bounds|use[- ]after[- ]free|memory corruption|heap overflow"),
    ("SSRF", r"server-side request forgery|\bssrf\b"),
    ("information disclosure", r"information disclosure|disclos(e|ure of) sensitive|sensitive information"),
    ("cross-site scripting", r"cross-site scripting|\bxss\b"),
    ("denial of service", r"denial of service|\bdos\b"),
]
_TEXT_KIND = [(k, re.compile(rx, re.I)) for k, rx in _TEXT_KIND]


def weakness_kind(cwes, text: str = "") -> str:
    """What kind of flaw this is, in two or three words. CWE first, description as fallback."""
    kinds = []
    for c in cwes or []:
        m = re.search(r"(\d+)", str(c))
        kind = _CWE_KIND.get(int(m.group(1))) if m else None
        if kind and kind not in kinds:
            kinds.append(kind)
    # A description that says "code execution" outranks a generic memory-corruption CWE.
    for kind, rx in _TEXT_KIND:
        if rx.search(text or ""):
            if kind == "code execution" and kinds and kinds[0] == "memory corruption":
                return "code execution"
            if not kinds:
                return kind
    return kinds[0] if kinds else ""


def attack_path(vector: str) -> str:
    """'remote, no login, no user action' from a CVSS 3.x or 4.0 vector. Empty if unknown."""
    parts = dict(p.split(":", 1) for p in str(vector or "").split("/") if ":" in p)
    av, pr, ui = parts.get("AV"), parts.get("PR"), parts.get("UI")
    if not av:
        return ""
    out = [{"N": "remote", "A": "adjacent network", "L": "local access needed", "P": "physical access needed"}.get(av, "")]
    out.append({"N": "no login", "L": "needs a user login", "H": "needs admin rights"}.get(pr, ""))
    out.append({"N": "no user action", "R": "needs user action", "P": "needs user action", "A": "needs user action"}.get(ui, ""))
    return ", ".join(x for x in out if x)
