# RustCSPGuardian

Rust CLI that checks whether a website can be embedded in an iframe. Detects CSP `frame-ancestors`, `X-Frame-Options`, CORS issues, missing security headers, and mixed content risk.

## Install

```bash
cargo build --release
# binary at target/release/cspguard
```

## Usage

```bash
# Check a single URL
cspguard check https://example.com

# JSON output
cspguard check https://example.com --json

# HTML report
cspguard check https://example.com --html report.html

# Batch check from file (one URL per line)
cspguard batch urls.txt
cspguard batch urls.txt --json
cspguard batch urls.txt --html report.html
```

## What it checks

| Header | Detection |
|---|---|
| `Content-Security-Policy: frame-ancestors` | `none` / `self` / wildcard |
| `X-Frame-Options` | `DENY` / `SAMEORIGIN` |
| `Strict-Transport-Security` | present / missing |
| `Referrer-Policy` | present / missing |
| `Permissions-Policy` | present / missing |
| `Access-Control-Allow-Origin` | wildcard detection |
| Mixed content | HTTP resource on HTTPS page |

## Output

**Terminal** — coloured report with risk level and suggestion  
**JSON** — machine-readable, pipe-friendly  
**HTML** — dark-theme report card, supports batch

## Embed result

| Result | Meaning |
|---|---|
| `Allowed` | No blocking headers found |
| `Blocked` | XFO DENY/SAMEORIGIN or CSP frame-ancestors none |
| `Unknown` | No headers present — behaviour is browser-dependent |

## Redirect following

Follows up to 10 redirects. Reports the final URL if the domain changed.

## Test

```bash
cargo test
```

8 integration tests — XFO, CSP, CORS, redirect, CLI.

## Stack

Rust · clap · tokio · reqwest (rustls-tls) · serde · colored · wiremock
