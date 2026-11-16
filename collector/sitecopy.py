"""Copy the portal files and stamp the stylesheet and script with a content hash.

Standard library only, with no imports from the rest of the collector: the publish job in
CI runs this from a fresh checkout of main, so the site's code never comes from the job
that handles untrusted feed data.

    python collector/sitecopy.py SITE_DIR OUT_DIR
"""
from __future__ import annotations

import hashlib
import re
import shutil
import sys
from pathlib import Path


def copy_site(site_dir: Path, out_dir: Path) -> None:
    """Without the stamp a browser can pair a fresh index.html with a cached style.css or
    app.js from an older version, which shows a broken page until the cache expires."""
    site_dir, out_dir = Path(site_dir), Path(out_dir)
    shutil.copytree(site_dir, out_dir, dirs_exist_ok=True)
    index = out_dir / "index.html"
    if not index.exists():
        return
    html = index.read_text(encoding="utf-8")

    def stamp(m):
        f = out_dir / m.group(2)
        if not f.exists():
            return m.group(0)
        return f'{m.group(1)}{m.group(2)}?v={hashlib.sha256(f.read_bytes()).hexdigest()[:10]}"'

    html = re.sub(r'((?:href|src)=")(style\.css|app\.js)(?:\?v=\w+)?"', stamp, html)
    index.write_bytes(html.encode("utf-8"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    copy_site(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"site copied from {sys.argv[1]} to {sys.argv[2]}")
