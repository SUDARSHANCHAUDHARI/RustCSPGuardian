# RustCSPGuardian

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)

RustCSPGuardian is a Rust CLI for checking whether a website can be embedded inside iframe-based environments such as dashboards, kiosk shells, portals, and digital signage players. It inspects frame-blocking headers, CORS signals, redirect behavior, security headers, and mixed-content risk, then reports a clear `Allowed`, `Blocked`, or `Unknown` verdict.

## Why This Exists

Iframe compatibility issues usually show up late: a URL works in a browser tab, but fails when embedded in a signage CMS, admin portal, or web view. RustCSPGuardian gives you a repeatable preflight check so you can validate URLs before adding them to a playlist, dashboard, or customer-facing embed flow.

## Features

- Single URL scan with terminal, JSON, or HTML output.
- Batch scan from a newline-delimited URL file.
- Detects `Content-Security-Policy: frame-ancestors` rules.
- Detects `X-Frame-Options: DENY` and `SAMEORIGIN`.
- Reports missing or present `Strict-Transport-Security`, `Referrer-Policy`, and `Permissions-Policy`.
- Detects wildcard `Access-Control-Allow-Origin`.
- Flags mixed-content risk when HTTPS pages reference HTTP resources.
- Follows redirects and reports the final URL.
- Machine-readable JSON for CI or automation.
- HTML report output for sharing with QA, support, or customers.

## Installation

### From Source

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/RustCSPGuardian.git
cd RustCSPGuardian
cargo build --release
```

The binary is created at:

```bash
target/release/cspguard
```

Optional local install:

```bash
cargo install --path .
```

## Usage

```bash
# Check a single URL
cspguard check https://example.com

# JSON output
cspguard check https://example.com --json

# HTML output
cspguard check https://example.com --html report.html

# Batch check from a file with one URL per line
cspguard batch urls.txt
cspguard batch urls.txt --json
cspguard batch urls.txt --html report.html

# Control redirect depth
cspguard check https://example.com --max-redirects 5
```

## Included Example

This repository includes a small URL list for quick batch experiments:

```bash
cat examples/urls.txt
```

```txt
https://example.com
https://www.rust-lang.org
https://github.com
```

Real CLI help output:

```text
Check whether a website can be embedded in iframe-based digital signage environments

Usage: cspguard <COMMAND>

Commands:
  check    Check a single URL
  batch    Check multiple URLs from a file (one per line)
  history  View scan history
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## What It Checks

| Area | What RustCSPGuardian Looks For |
|---|---|
| CSP frame policy | `frame-ancestors 'none'`, `'self'`, wildcard, or missing policy |
| X-Frame-Options | `DENY`, `SAMEORIGIN`, or missing header |
| Redirects | Final URL and whether the domain changed |
| CORS | Wildcard `Access-Control-Allow-Origin` |
| Security headers | HSTS, Referrer Policy, Permissions Policy |
| Mixed content | HTTP resources referenced from HTTPS pages |

## Verdicts

| Verdict | Meaning |
|---|---|
| `Allowed` | No frame-blocking headers were found. |
| `Blocked` | CSP or X-Frame-Options blocks embedding. |
| `Unknown` | Headers are missing or inconclusive; browser/runtime behavior may vary. |

## Output Formats

Terminal output is designed for quick manual checks. JSON output is stable enough for scripts and CI gates. HTML output is useful when you need to share a readable report with non-engineering stakeholders.

## Example Batch File

```txt
https://example.com
https://dashboard.example.org
https://status.example.net
```

Run:

```bash
cspguard batch urls.txt --html embed-report.html
```

## Development

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

Run these checks locally before publishing changes.

## Project Structure

```text
src/
  cli.rs          Command-line interface
  checker.rs      HTTP fetch and header inspection
  report.rs       Verdict and report models
  output/         Terminal, JSON, and HTML rendering
tests/
  integration_test.rs
```

## Project Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Maintainer notes](docs/NOTES.md)
- [Content plan](docs/CONTENT_PLAN.md)

## Release Status

Current production release: `v1.0.0`

The `v1.0.0` release was verified with formatting, clippy, tests, optimized release build, and `cargo package`.

## License

MIT. See [LICENSE](LICENSE).

## Developer

Built by [Sudarshan Chaudhari](https://github.com/SUDARSHANCHAUDHARI) under SudarshanTechLabs.
