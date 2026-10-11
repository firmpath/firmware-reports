#!/usr/bin/env python3
"""Refresh this repository from Firmpath's published open-source reports.

Reads the list of reports from https://app.firmpath.dev/sitemap.xml, fetches each one as JSON, and writes:
  reports/<slug>.json   the report as published, minus when it was computed and analysed (so a commit means findings changed)
  summary.csv           one row per project: what an NVD scanner reports beside what Firmpath reports
  README.md             the same table, with links to the full reports

Standard library only. Run daily by .github/workflows/update.yml; safe to run by hand.
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
import urllib.request
from pathlib import Path

BASE = "https://app.firmpath.dev"
UA = "firmware-reports-update/1 (+https://github.com/firmpath/firmware-reports)"
ROOT = Path(__file__).resolve().parent.parent


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def comparison(report: dict) -> dict:
    """The same arithmetic as the report page: only vulnerabilities in packages to upgrade."""
    vulns = [v for p in report.get("fix", []) for v in p.get("vulns", [])]
    return {
        "nvd_scanner": sum(1 for v in vulns if v.get("nvd_scanner") is True),
        "firmpath": len(vulns),
        "missed_by_nvd_scanners": sum(1 for v in vulns if v.get("nvd_scanner") is False),
        "not_checked_against_nvd": sum(1 for v in vulns if v.get("nvd_scanner") is None),
    }


def md(text: str) -> str:
    """Report text in a Markdown table cell: no table breaks, links, images or raw HTML."""
    return re.sub(r"([\\`*_\[\]()<>|!#])", r"\\\1", str(text)).replace("\n", " ")


def cell(value):
    """A CSV cell a spreadsheet will not run as a formula."""
    return "'" + value if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def main() -> int:
    sitemap = get(f"{BASE}/sitemap.xml").decode()
    slugs = sorted(set(re.findall(r"<loc>https://app\.firmpath\.dev/reports/([a-z0-9-]+)</loc>", sitemap)))
    if not slugs:
        # An empty sitemap is far likelier to be a fetch problem than every report withdrawn; refuse to delete everything.
        print("update: the sitemap lists no reports; leaving the repository as it is", file=sys.stderr)
        return 1

    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    rows = []
    for slug in slugs:
        report = json.loads(get(f"{BASE}/reports/{slug}.json"))
        # Both change every day whether or not any finding did; kept out, so each commit is a change in findings.
        report.pop("computed_at", None)
        (report.get("release") or {}).pop("analysed_at", None)
        (out / f"{slug}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        c = comparison(report)
        s = report.get("summary", {})
        rows.append({
            "slug": slug, "project": report.get("project", slug), "repository": report.get("repo_url", ""),
            **c, "packages_to_upgrade": s.get("fix", 0), "packages_to_look_at": s.get("look", 0),
            "components": report.get("components", 0),
        })

    # Withdrawn reports leave the repository; their history stays in git.
    for stale in out.glob("*.json"):
        if stale.stem not in slugs:
            stale.unlink()

    rows.sort(key=lambda r: (-r["missed_by_nvd_scanners"], r["project"].lower()))
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    w.writeheader()
    w.writerows({k: cell(v) for k, v in r.items()} for r in rows)
    (ROOT / "summary.csv").write_text(buf.getvalue())

    table = "\n".join(
        f"| [{md(r['project'])}]({BASE}/reports/{r['slug']}) | {r['nvd_scanner']} | **{r['firmpath']}** | "
        f"{r['missed_by_nvd_scanners']} | [data](reports/{r['slug']}.json) |"
        for r in rows
    )
    readme = (ROOT / "scripts" / "README.template.md").read_text().replace("{{TABLE}}", table).replace("{{COUNT}}", str(len(rows)))
    (ROOT / "README.md").write_text(readme)
    print(f"update: {len(rows)} reports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
