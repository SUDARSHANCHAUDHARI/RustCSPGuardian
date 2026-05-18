"""Risk scoring and reporting for CSP Guardian."""

from __future__ import annotations

from collections import Counter


POINTS = {"critical": 90, "high": 35, "medium": 20, "low": 5}
GRADE_THRESHOLDS = ((90, "F"), (70, "D"), (45, "C"), (20, "B"), (0, "A"))
NEXT_STEPS = {
    "csp.missing": "Add a Content-Security-Policy header with default-src, script-src, object-src, base-uri, form-action, and frame-ancestors.",
    "csp.default_src_missing": "Add default-src as the fallback directive for resource loading.",
    "csp.script_src_missing": "Add script-src with trusted hosts, nonces, or hashes.",
    "csp.unsafe_inline": "Remove unsafe-inline by moving inline scripts to nonced or hashed script blocks.",
    "csp.wildcard": "Replace wildcard sources with explicit trusted origins.",
    "csp.base_uri_missing": "Add base-uri 'self' or base-uri 'none'.",
    "csp.form_action_missing": "Add form-action with expected submission targets.",
    "csp.upgrade_insecure_requests_missing": "Add upgrade-insecure-requests after verifying HTTPS availability for subresources.",
    "csp.frame_ancestors_missing": "Add frame-ancestors to define exactly where the site may be embedded.",
    "headers.hsts_missing": "Add Strict-Transport-Security after confirming HTTPS is stable.",
    "headers.content_type_options_missing": "Add X-Content-Type-Options: nosniff.",
    "iframe.clickjacking_unprotected": "Set CSP frame-ancestors or X-Frame-Options to prevent clickjacking.",
    "iframe.legacy_and_csp_policy": "Confirm legacy X-Frame-Options and CSP frame-ancestors express the same embed intent.",
    "iframe.frame_ancestors_wildcard": "Replace frame-ancestors wildcard with explicit origins.",
    "content.mixed_content": "Replace http:// subresources with HTTPS URLs.",
    "cors.overbroad": "Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard credentials.",
}


def score_findings(findings: list[dict]) -> int:
    """Return a 0-100 risk score."""
    return min(100, sum(POINTS.get(str(finding.get("severity")), 0) for finding in findings))


def grade_score(score: int) -> str:
    """Return a simple portfolio-friendly security grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "A"


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


def remediation_plan(findings: list[dict]) -> list[dict]:
    """Return prioritized remediation steps."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sorted_findings = sorted(findings, key=lambda item: order.get(str(item.get("severity")), 0), reverse=True)
    plan = []
    for index, finding in enumerate(sorted_findings[:8], start=1):
        kind = str(finding.get("kind", "unknown"))
        plan.append(
            {
                "priority": index,
                "kind": kind,
                "severity": finding.get("severity", "unknown"),
                "action": NEXT_STEPS.get(kind, "Review this finding and update the affected header."),
            }
        )
    return plan


def summarize(scan: dict, findings: list[dict], iframe: dict | None = None) -> dict:
    """Return report summary."""
    by_kind = Counter(str(finding["kind"]) for finding in findings)
    by_severity = Counter(str(finding["severity"]) for finding in findings)
    score = score_findings(findings)
    return {
        "url": scan.get("url"),
        "status": scan.get("status"),
        "findings": len(findings),
        "risk_score": score,
        "grade": grade_score(score),
        "by_kind": dict(by_kind),
        "by_severity": dict(by_severity),
        "iframe": iframe or {},
        "remediation_count": len(remediation_plan(findings)),
    }


def build_markdown_report(summary: dict, findings: list[dict], remediation: list[dict] | None = None) -> str:
    """Return Markdown report."""
    remediation = remediation if remediation is not None else remediation_plan(findings)
    lines = [
        "# CSP Guardian Report",
        "",
        "## Executive Summary",
        "",
        f"- URL: {summary['url']}",
        f"- HTTP status: {summary['status']}",
        f"- Findings: {summary['findings']}",
        f"- Risk score: {summary['risk_score']}/100",
        f"- Grade: {summary['grade']}",
        f"- Iframe mode: {summary.get('iframe', {}).get('mode', 'unknown')}",
        "",
        "## Remediation Plan",
        "",
    ]
    if not remediation:
        lines.append("No remediation steps generated.")
    for item in remediation:
        lines.append(f"{item['priority']}. **{item['severity']}** `{item['kind']}` - {item['action']}")
    lines.extend(
        [
            "",
            "## Findings",
            "",
        ]
    )
    if not findings:
        lines.append("No header risks detected.")
    for finding in findings:
        kind = str(finding["kind"])
        lines.extend(
            [
                f"### {finding['summary']}",
                "",
                f"- Severity: `{finding['severity']}`",
                f"- Type: `{kind}`",
                f"- Evidence: `{finding.get('evidence', {})}`",
                f"- Recommended next step: {NEXT_STEPS.get(kind, 'Review this finding and update the affected header.')}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def build_header_matrix(scan: dict, findings: list[dict]) -> dict:
    """Return pass/fail status for key browser security headers."""
    headers = scan.get("headers", {})
    failed_kinds = {str(finding.get("kind")) for finding in findings}
    checks = {
        "content-security-policy": "csp.missing" not in failed_kinds,
        "strict-transport-security": "strict-transport-security" in headers,
        "x-content-type-options": "x-content-type-options" in headers,
        "frame-ancestors-or-x-frame-options": not any(
            kind in failed_kinds for kind in ("iframe.clickjacking_unprotected", "csp.frame_ancestors_missing")
        ),
        "cors": "cors.overbroad" not in failed_kinds,
        "mixed-content": "content.mixed_content" not in failed_kinds,
    }
    return {
        "url": scan.get("url"),
        "checks": [{"name": name, "status": "pass" if passed else "fail"} for name, passed in checks.items()],
        "passed": sum(1 for passed in checks.values() if passed),
        "failed": sum(1 for passed in checks.values() if not passed),
    }
