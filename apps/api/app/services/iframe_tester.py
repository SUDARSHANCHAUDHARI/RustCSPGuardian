"""Analyze iframe and embed compatibility risks."""

from __future__ import annotations


def analyze_iframe_policy(headers: dict[str, str]) -> list[dict]:
    """Return findings related to iframe and clickjacking policy."""
    findings: list[dict] = []
    x_frame = headers.get("x-frame-options", "").lower()
    csp = headers.get("content-security-policy", "").lower()

    if not x_frame and "frame-ancestors" not in csp:
        findings.append(
            {
                "kind": "iframe.clickjacking_unprotected",
                "severity": "high",
                "summary": "No X-Frame-Options or CSP frame-ancestors policy is present.",
                "evidence": {},
            }
        )
    if x_frame in {"deny", "sameorigin"} and "frame-ancestors" in csp:
        findings.append(
            {
                "kind": "iframe.legacy_and_csp_policy",
                "severity": "low",
                "summary": "Both X-Frame-Options and frame-ancestors are configured; verify intended embed behavior.",
                "evidence": {"x_frame_options": x_frame},
            }
        )
    return findings


def detect_mixed_content(body_preview: str) -> list[dict]:
    """Detect obvious mixed-content references in body preview."""
    if "http://" not in body_preview.lower():
        return []
    return [
        {
            "kind": "content.mixed_content",
            "severity": "medium",
            "summary": "Page body references insecure http resources.",
            "evidence": {"preview": body_preview[:160]},
        }
    ]
