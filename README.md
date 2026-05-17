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
- Writes JSON scan data, JSON findings, JSON summary, and a Markdown report.

## Roadmap

- Polish sample output screenshots or terminal demos
- Add architecture diagram and deeper implementation notes
- Expand test coverage around edge cases
- Add Docker or local demo workflow where useful
- Prepare `v0.1.0-mvp` release notes
