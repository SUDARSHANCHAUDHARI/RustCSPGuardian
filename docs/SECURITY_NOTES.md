# Security Notes

CSP Guardian is a defensive website assessment tool. Scan only websites, staging systems, and fixtures you own or have permission to assess.

## Safe Use

- The fixture path is offline and safe for demos.
- Live URL scanning performs a normal HTTP GET and reads a small body preview.
- Do not commit private response bodies, cookies, tokens, session headers, or internal hostnames.
- Findings are policy guidance, not proof of compromise.

## Data Handling

- Redact cookies and authorization headers from any saved live scan.
- Treat body previews as sensitive because they may include page content.
- Keep scans scoped to specific URLs instead of crawling unknown sites.

## Production Controls

- Add authentication before storing scans for multiple users.
- Add allowlisted scan targets for hosted deployments.
- Store only normalized, redacted headers by default.
- Add retention limits for scan history and reports.
