# RustCSPGuardian

[![crates.io](https://img.shields.io/crates/v/cspguardian?logo=rust)](https://crates.io/crates/cspguardian)
[![Downloads](https://img.shields.io/crates/d/cspguardian?logo=rust)](https://crates.io/crates/cspguardian)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)

> A Rust CLI that checks whether a website can be safely embedded in an iframe — for dashboards, kiosks, portals, and digital signage.

**RustCSPGuardian** (installed as the `cspguardian` command) inspects frame-blocking
headers, CORS signals, redirect behavior, security headers, and mixed-content risk,
then reports a clear `Allowed`, `Blocked`, or `Unknown` verdict.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Included Example](#included-example)
- [What It Checks](#what-it-checks)
- [Verdicts](#verdicts)
- [Output Formats](#output-formats)
- [Development](#development)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Release Status](#release-status)
- [License](#license)
- [About](#about)

## Overview

Iframe compatibility issues usually show up late: a URL works in a browser tab, but
fails when embedded in a signage CMS, admin portal, or web view. RustCSPGuardian gives
you a repeatable **preflight check** so you can validate URLs before adding them to a
playlist, dashboard, or customer-facing embed flow.

It is designed for digital-signage operators, kiosk builders, QA engineers, and anyone
who embeds third-party URLs and needs to know — deterministically — whether they will
render or be blocked.

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

### From crates.io (recommended)

```bash
cargo install cspguardian
```

### From source

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/RustCSPGuardian.git
cd RustCSPGuardian
cargo build --release
```

The binary is created at:

```bash
target/release/cspguardian
```

Optional local install from a source checkout:

```bash
cargo install --path .
```

## Usage

```bash
# Check a single URL
cspguardian check https://example.com

# JSON output
cspguardian check https://example.com --json

# HTML output
cspguardian check https://example.com --html report.html

# Batch check from a file with one URL per line
cspguardian batch urls.txt
cspguardian batch urls.txt --json
cspguardian batch urls.txt --html report.html

# Control redirect depth
cspguardian check https://example.com --max-redirects 5
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

Usage: cspguardian <COMMAND>

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

Terminal output is designed for quick manual checks. JSON output is stable enough for
scripts and CI gates. HTML output is useful when you need to share a readable report
with non-engineering stakeholders.

Reports include `remediation_hints` with practical next steps for common blockers, such
as removing `X-Frame-Options: DENY` when embedding is intentional, or adding a specific
`Content-Security-Policy: frame-ancestors` allowlist.

### Example batch file

```txt
https://example.com
https://dashboard.example.org
https://status.example.net
```

Run:

```bash
cspguardian batch urls.txt --html embed-report.html
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

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Maintainer notes](docs/NOTES.md)
- [Content plan](docs/CONTENT_PLAN.md)

## Release Status

Current release: **`v1.1.1`**, published on [crates.io](https://crates.io/crates/cspguardian).

Each release is verified with formatting, Clippy, tests, an optimized release build,
and `cargo package` before publishing.

## License

MIT — see [LICENSE](LICENSE).

---

## About

I'm Sudarshan Chaudhari, a Senior Quality Engineer, Test Automation specialist, and AI systems builder based in Bangkok, Thailand.

I have 13+ years of experience in software quality engineering, working across SaaS, fintech, gaming, web, mobile, cloud, and digital signage platforms. My background combines hands-on test automation with QA leadership, test strategy, CI/CD, release quality, production investigation, and cross-platform validation.

Alongside my professional QA career, I run [SudarshanTechLabs](https://sudarshantechlabs.com/), my independent engineering and product lab where I design, build, test, and ship software across Android, web, AI, cybersecurity, developer tooling, and cross-platform applications.

### What I work on

- ⚙️ **Quality Engineering & Test Automation** — Playwright, Selenium, Cypress, Appium, API testing, automation frameworks, end-to-end testing, CI/CD, release gates, GitHub Actions, risk-based testing, and production validation
- 🤖 **AI Systems & Automation** — AI agents, multi-agent orchestration, MCP servers, AI-assisted QA, prompt tooling, developer workflows, automation systems, and Claude Code plugins
- 📱 **Mobile & Cross-Platform Applications** — Android applications built with Kotlin and Jetpack Compose, Google Play releases, automated build and publishing pipelines, and cross-platform development spanning iOS, web, Windows, and macOS
- 🌐 **Web Applications & Platforms** — Full-stack applications using Next.js, TypeScript, Firebase, Cloudflare, REST APIs, and modern web infrastructure
- 🛠️ **Developer Tooling & CLI Engineering** — Rust, Python, TypeScript, CLI utilities, multi-repository tooling, build automation, release tooling, and engineering productivity systems
- 🛡️ **Cybersecurity & Observability** — Threat detection, log analysis, security auditing, vulnerability assessment, monitoring, and security-focused developer tools
- 📺 **Digital Signage & Device Platforms** — Content validation, playback testing, device compatibility, production investigation, monitoring, and QA across diverse hardware and operating-system environments

My work sits at the intersection of quality engineering, automation, AI, and software development. I approach products with a QA mindset from the beginning: understanding failure modes, designing for testability, automating repetitive work, and building release confidence into the engineering process.

Through SudarshanTechLabs, I also build products and tools from idea to production, covering architecture, development, testing, CI/CD, release automation, monitoring, and ongoing maintenance.

🌐 [sudarshantechlabs.com](https://sudarshantechlabs.com/) · 💼 [LinkedIn](https://linkedin.com/in/sudarshan-chaudhari) · 🐙 [GitHub](https://github.com/SUDARSHANCHAUDHARI) · ✉️ [sunny.sudarshan@gmail.com](mailto:sunny.sudarshan@gmail.com)