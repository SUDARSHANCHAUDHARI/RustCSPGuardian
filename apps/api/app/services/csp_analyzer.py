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
