# CSP Guardian

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Website security header and iframe policy analyzer for CSP, cookies, CORS, and framing risks.

- **Portfolio group:** Product-style SaaS project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/CSPGuardian
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/CSPGuardian`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

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
- Grades the scanned site with a risk score and letter grade.
- Builds iframe compatibility posture for embed/clickjacking review.
- Writes JSON scan data, findings, summary, header matrix, remediation plan, and a Markdown report.

## Demo Artifacts

- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY_NOTES.md)
- [Demo walkthrough](docs/DEMO.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Sample report](data/reports/report.md)
- [Sample remediation plan](data/reports/remediation-plan.json)
- [Sample header matrix](data/reports/header-matrix.json)

## Docker Demo

```bash
docker compose run --rm cspguardian-demo
```

## Roadmap

- Add FastAPI scan endpoint and React dashboard.
- Add side-by-side before/after policy comparison.
- Add CSP directive parser with source-level scoring.
- Add exportable HTML/PDF report.
- Prepare GitHub release `v0.1.0-mvp`.
