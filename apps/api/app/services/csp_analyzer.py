"""Analyze Content Security Policy and related headers."""

from __future__ import annotations


def analyze_csp(headers: dict[str, str]) -> list[dict]:
    """Return CSP findings."""
    csp = headers.get("content-security-policy", "")
    findings: list[dict] = []
    if not csp:
        return [
            {
                "kind": "csp.missing",
                "severity": "high",
                "summary": "Content-Security-Policy header is missing.",
                "evidence": {},
            }
        ]
    lowered = csp.lower()
    if "default-src" not in lowered:
        findings.append(
            {
                "kind": "csp.default_src_missing",
                "severity": "medium",
                "summary": "CSP does not define default-src fallback.",
                "evidence": {"csp": csp},
            }
        )
    if "script-src" not in lowered:
        findings.append(
            {
                "kind": "csp.script_src_missing",
                "severity": "medium",
                "summary": "CSP does not define script-src for JavaScript execution control.",
                "evidence": {"csp": csp},
            }
        )
    if "'unsafe-inline'" in lowered:
        findings.append(
            {
                "kind": "csp.unsafe_inline",
                "severity": "high",
                "summary": "CSP allows unsafe-inline scripts or styles.",
                "evidence": {"csp": csp},
            }
        )
    if "*" in lowered:
        findings.append(
            {
                "kind": "csp.wildcard",
                "severity": "medium",
                "summary": "CSP contains wildcard sources that broaden allowed content.",
                "evidence": {"csp": csp},
            }
        )
    if "base-uri" not in lowered:
        findings.append(
            {
                "kind": "csp.base_uri_missing",
                "severity": "medium",
                "summary": "CSP does not define base-uri to restrict base tag injection.",
                "evidence": {"csp": csp},
            }
        )
    if "form-action" not in lowered:
        findings.append(
            {
                "kind": "csp.form_action_missing",
                "severity": "low",
                "summary": "CSP does not define form-action to restrict form submission targets.",
                "evidence": {"csp": csp},
            }
        )
    if "upgrade-insecure-requests" not in lowered:
        findings.append(
            {
                "kind": "csp.upgrade_insecure_requests_missing",
                "severity": "low",
                "summary": "CSP does not request automatic upgrade of insecure subresources.",
                "evidence": {"csp": csp},
            }
        )
    if "frame-ancestors" not in lowered:
        findings.append(
            {
                "kind": "csp.frame_ancestors_missing",
                "severity": "medium",
                "summary": "CSP does not define frame-ancestors for embed control.",
                "evidence": {"csp": csp},
            }
        )
    return findings


def analyze_security_headers(headers: dict[str, str]) -> list[dict]:
    """Return findings for non-CSP security headers."""
    findings: list[dict] = []
    if "strict-transport-security" not in headers:
        findings.append(
            {
                "kind": "headers.hsts_missing",
                "severity": "medium",
                "summary": "Strict-Transport-Security header is missing.",
                "evidence": {},
            }
        )
    if "x-content-type-options" not in headers:
        findings.append(
            {
                "kind": "headers.content_type_options_missing",
                "severity": "low",
                "summary": "X-Content-Type-Options header is missing.",
                "evidence": {},
            }
        )
    return findings
