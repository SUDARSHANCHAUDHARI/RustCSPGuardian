# CSP Guardian

**Goal:** Website security header and iframe policy analyzer.

**MVP:** Enter URL, scan headers, and explain risks.

## Core Features

- CSP check
- X-Frame-Options check
- iframe compatibility
- cookie security
- mixed content detection
- CORS risk explanation

## Suggested Stack

FastAPI, React, Docker.

## Status

Working CLI MVP.

## Quick Start

Analyze the included offline header fixture:

```bash
python3 -m apps.api.app.cli \
  --fixture data/samples/insecure-site-headers.json \
  --out-dir data/reports
```

Analyze a live URL when network access is available:

```bash
python3 -m apps.api.app.cli --url https://example.com --out-dir data/reports
```

Run tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## MVP Capabilities

- Loads header fixtures or scans live URLs.
- Checks Content-Security-Policy quality.
- Checks iframe/clickjacking policy.
- Checks HSTS and content-type hardening headers.
- Detects simple mixed-content references.
- Explains risky CORS combinations.
- Writes JSON scan data, JSON findings, JSON summary, and a Markdown report.

## Repository Status

This repository contains the production-ready foundation for the CSP Guardian MVP. The current codebase is scaffolded and ready for focused implementation work.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
