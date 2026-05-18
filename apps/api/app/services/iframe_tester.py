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
    if "frame-ancestors *" in csp:
        findings.append(
            {
                "kind": "iframe.frame_ancestors_wildcard",
                "severity": "high",
                "summary": "frame-ancestors allows any embedding origin.",
                "evidence": {"content_security_policy": csp},
            }
        )
    return findings


def iframe_compatibility(headers: dict[str, str]) -> dict:
    """Return iframe compatibility and clickjacking posture."""
    x_frame = headers.get("x-frame-options", "").lower()
    csp = headers.get("content-security-policy", "").lower()
    has_frame_ancestors = "frame-ancestors" in csp

    if x_frame == "deny" or "frame-ancestors 'none'" in csp:
        mode = "blocked"
        explanation = "The page is intentionally blocked from being embedded."
    elif x_frame == "sameorigin" or "frame-ancestors 'self'" in csp:
        mode = "same-origin-only"
        explanation = "Embedding is limited to the same origin."
    elif has_frame_ancestors:
        mode = "restricted"
        explanation = "Embedding is controlled by CSP frame-ancestors."
    else:
        mode = "unprotected"
        explanation = "No explicit iframe policy was found."

    return {
        "mode": mode,
        "x_frame_options": x_frame or None,
        "has_frame_ancestors": has_frame_ancestors,
        "explanation": explanation,
    }


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
