"""CLI for the CSP Guardian MVP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from apps.api.app.services.csp_analyzer import analyze_csp, analyze_security_headers
from apps.api.app.services.header_scanner import load_header_fixture, scan_url
from apps.api.app.services.iframe_tester import analyze_iframe_policy, detect_mixed_content
from apps.api.app.services.risk_score import build_markdown_report, explain_cors, summarize


def analyze_scan(scan: dict) -> tuple[dict, list[dict]]:
    """Analyze a loaded or fetched scan."""
    headers = scan["headers"]
    findings = [
        *analyze_csp(headers),
        *analyze_security_headers(headers),
        *analyze_iframe_policy(headers),
        *detect_mixed_content(scan.get("body_preview", "")),
        *explain_cors(headers),
    ]
    return summarize(scan, findings), findings


def write_outputs(out_dir: Path, scan: dict, summary: dict, findings: list[dict]) -> None:
    """Write scan outputs."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scan.json").write_text(json.dumps(scan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(build_markdown_report(summary, findings), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="CSP Guardian header analyzer")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--fixture", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("data/reports"))
    args = parser.parse_args()

    scan = scan_url(args.url) if args.url else load_header_fixture(args.fixture)
    summary, findings = analyze_scan(scan)
    write_outputs(args.out_dir, scan, summary, findings)
    print(f"Analyzed {summary['url']}")
    print(f"Generated {summary['findings']} finding(s)")
    print(f"Risk score: {summary['risk_score']}/100")


if __name__ == "__main__":
    main()
