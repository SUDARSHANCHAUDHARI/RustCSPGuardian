# Demo

Run the offline header fixture:

```bash
python3 -m apps.api.app.cli \
  --fixture data/samples/insecure-site-headers.json \
  --out-dir data/reports
```

Expected output:

```text
Analyzed https://insecure.example.test
Generated 12 finding(s)
Risk score: 100/100
Grade: F
```

Generated artifacts:

- `data/reports/scan.json`
- `data/reports/summary.json`
- `data/reports/findings.json`
- `data/reports/header-matrix.json`
- `data/reports/remediation-plan.json`
- `data/reports/report.md`

The fixture demonstrates unsafe inline CSP, wildcard sources, missing fallback directives, missing frame controls, missing HSTS, mixed content, and overbroad CORS.
