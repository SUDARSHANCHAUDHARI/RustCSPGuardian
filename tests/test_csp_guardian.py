"""Tests for CSP Guardian MVP."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from apps.api.app.cli import analyze_scan
from apps.api.app.services.header_scanner import load_header_fixture


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data/samples/insecure-site-headers.json"


class CSPGuardianTests(unittest.TestCase):
    def test_fixture_analysis_detects_header_risks(self) -> None:
        scan = load_header_fixture(FIXTURE)
        summary, findings = analyze_scan(scan)
        kinds = {finding["kind"] for finding in findings}

        self.assertGreater(summary["risk_score"], 0)
        self.assertIn("csp.unsafe_inline", kinds)
        self.assertIn("cors.overbroad", kinds)
        self.assertIn("content.mixed_content", kinds)

    def test_cli_writes_report_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "apps.api.app.cli",
                    "--fixture",
                    str(FIXTURE),
                    "--out-dir",
                    tmp,
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            report = Path(tmp, "report.md").read_text(encoding="utf-8")
            findings = json.loads(Path(tmp, "findings.json").read_text(encoding="utf-8"))

            self.assertIn("Risk score", result.stdout)
            self.assertIn("CSP Guardian Report", report)
            self.assertGreaterEqual(len(findings), 5)


if __name__ == "__main__":
    unittest.main()
