"""Risk scoring and reporting for CSP Guardian."""

from __future__ import annotations

from collections import Counter


POINTS = {"critical": 90, "high": 35, "medium": 20, "low": 5}


def score_findings(findings: list[dict]) -> int:
    """Return a 0-100 risk score."""
    return min(100, sum(POINTS.get(str(finding.get("severity")), 0) for finding in findings))


def explain_cors(headers: dict[str, str]) -> list[dict]:
    """Return CORS findings."""
    origin = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower()
    if origin == "*" and credentials == "true":
        severity = "high"
        summary = "CORS allows any origin with credentials enabled."
    elif origin == "*":
        severity = "medium"
        summary = "CORS allows any origin."
    else:
        return []
    return [
        {
            "kind": "cors.overbroad",
            "severity": severity,
            "summary": summary,
            "evidence": {
                "access_control_allow_origin": origin,
                "access_control_allow_credentials": credentials,
            },
        }
    ]


def summarize(scan: dict, findings: list[dict]) -> dict:
    """Return report summary."""
    by_kind = Counter(str(finding["kind"]) for finding in findings)
    by_severity = Counter(str(finding["severity"]) for finding in findings)
    return {
        "url": scan.get("url"),
        "status": scan.get("status"),
        "findings": len(findings),
        "risk_score": score_findings(findings),
        "by_kind": dict(by_kind),
        "by_severity": dict(by_severity),
    }


def build_markdown_report(summary: dict, findings: list[dict]) -> str:
    """Return Markdown report."""
    lines = [
        "# CSP Guardian Report",
        "",
        "## Summary",
        "",
        f"- URL: {summary['url']}",
        f"- HTTP status: {summary['status']}",
        f"- Findings: {summary['findings']}",
        f"- Risk score: {summary['risk_score']}/100",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No header risks detected.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding['summary']}",
                "",
                f"- Severity: `{finding['severity']}`",
                f"- Type: `{finding['kind']}`",
                f"- Evidence: `{finding.get('evidence', {})}`",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
