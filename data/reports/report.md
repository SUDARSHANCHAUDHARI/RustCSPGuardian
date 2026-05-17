# CSP Guardian Report

## Summary

- URL: https://insecure.example.test
- HTTP status: 200
- Findings: 9
- Risk score: 100/100

## Findings

### CSP does not define default-src fallback.

- Severity: `medium`
- Type: `csp.default_src_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`

### CSP allows unsafe-inline scripts or styles.

- Severity: `high`
- Type: `csp.unsafe_inline`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`

### CSP contains wildcard sources that broaden allowed content.

- Severity: `medium`
- Type: `csp.wildcard`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`

### CSP does not define frame-ancestors for embed control.

- Severity: `medium`
- Type: `csp.frame_ancestors_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`

### Strict-Transport-Security header is missing.

- Severity: `medium`
- Type: `headers.hsts_missing`
- Evidence: `{}`

### X-Content-Type-Options header is missing.

- Severity: `low`
- Type: `headers.content_type_options_missing`
- Evidence: `{}`

### No X-Frame-Options or CSP frame-ancestors policy is present.

- Severity: `high`
- Type: `iframe.clickjacking_unprotected`
- Evidence: `{}`

### Page body references insecure http resources.

- Severity: `medium`
- Type: `content.mixed_content`
- Evidence: `{'preview': '<html><script src="http://cdn.example.test/app.js"></script></html>'}`

### CORS allows any origin with credentials enabled.

- Severity: `high`
- Type: `cors.overbroad`
- Evidence: `{'access_control_allow_origin': '*', 'access_control_allow_credentials': 'true'}`

