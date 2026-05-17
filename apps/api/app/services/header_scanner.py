"""Fetch or load website response headers."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.request import Request, urlopen


def normalize_headers(headers: dict) -> dict[str, str]:
    """Normalize header names for easier analysis."""
    return {str(key).lower(): str(value) for key, value in headers.items()}


def load_header_fixture(path: Path) -> dict:
    """Load a JSON header fixture."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        "url": payload.get("url", "fixture"),
        "status": int(payload.get("status", 200)),
        "headers": normalize_headers(payload.get("headers", {})),
        "body_preview": str(payload.get("body_preview", "")),
    }


def scan_url(url: str, timeout: int = 10) -> dict:
    """Fetch URL headers using the Python standard library."""
    request = Request(url, headers={"User-Agent": "CSPGuardian/0.1"})
    with urlopen(request, timeout=timeout) as response:  # nosec B310 - user-authorized scanner.
        body_preview = response.read(4096).decode("utf-8", errors="replace")
        return {
            "url": url,
            "status": response.status,
            "headers": normalize_headers(dict(response.headers.items())),
            "body_preview": body_preview,
        }
