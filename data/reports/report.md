# CSP Guardian Report

## Executive Summary

- URL: https://insecure.example.test
- HTTP status: 200
- Findings: 12
- Risk score: 100/100
- Grade: F
- Iframe mode: unprotected

## Remediation Plan

1. **high** `csp.unsafe_inline` - Remove unsafe-inline by moving inline scripts to nonced or hashed script blocks.
2. **high** `iframe.clickjacking_unprotected` - Set CSP frame-ancestors or X-Frame-Options to prevent clickjacking.
3. **high** `cors.overbroad` - Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard credentials.
4. **medium** `csp.default_src_missing` - Add default-src as the fallback directive for resource loading.
5. **medium** `csp.wildcard` - Replace wildcard sources with explicit trusted origins.
6. **medium** `csp.base_uri_missing` - Add base-uri 'self' or base-uri 'none'.
7. **medium** `csp.frame_ancestors_missing` - Add frame-ancestors to define exactly where the site may be embedded.
8. **medium** `headers.hsts_missing` - Add Strict-Transport-Security after confirming HTTPS is stable.

## Findings

### CSP does not define default-src fallback.

- Severity: `medium`
- Type: `csp.default_src_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Add default-src as the fallback directive for resource loading.

### CSP allows unsafe-inline scripts or styles.

- Severity: `high`
- Type: `csp.unsafe_inline`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Remove unsafe-inline by moving inline scripts to nonced or hashed script blocks.

### CSP contains wildcard sources that broaden allowed content.

- Severity: `medium`
- Type: `csp.wildcard`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Replace wildcard sources with explicit trusted origins.

### CSP does not define base-uri to restrict base tag injection.

- Severity: `medium`
- Type: `csp.base_uri_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Add base-uri 'self' or base-uri 'none'.

### CSP does not define form-action to restrict form submission targets.

- Severity: `low`
- Type: `csp.form_action_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Add form-action with expected submission targets.

### CSP does not request automatic upgrade of insecure subresources.

- Severity: `low`
- Type: `csp.upgrade_insecure_requests_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Add upgrade-insecure-requests after verifying HTTPS availability for subresources.

### CSP does not define frame-ancestors for embed control.

- Severity: `medium`
- Type: `csp.frame_ancestors_missing`
- Evidence: `{'csp': "script-src * 'unsafe-inline'; object-src 'none'"}`
- Recommended next step: Add frame-ancestors to define exactly where the site may be embedded.

### Strict-Transport-Security header is missing.

- Severity: `medium`
- Type: `headers.hsts_missing`
- Evidence: `{}`
- Recommended next step: Add Strict-Transport-Security after confirming HTTPS is stable.

### X-Content-Type-Options header is missing.

- Severity: `low`
- Type: `headers.content_type_options_missing`
- Evidence: `{}`
- Recommended next step: Add X-Content-Type-Options: nosniff.

### No X-Frame-Options or CSP frame-ancestors policy is present.

- Severity: `high`
- Type: `iframe.clickjacking_unprotected`
- Evidence: `{}`
- Recommended next step: Set CSP frame-ancestors or X-Frame-Options to prevent clickjacking.

### Page body references insecure http resources.

- Severity: `medium`
- Type: `content.mixed_content`
- Evidence: `{'preview': '<html><script src="http://cdn.example.test/app.js"></script></html>'}`
- Recommended next step: Replace http:// subresources with HTTPS URLs.

### CORS allows any origin with credentials enabled.

- Severity: `high`
- Type: `cors.overbroad`
- Evidence: `{'access_control_allow_origin': '*', 'access_control_allow_credentials': 'true'}`
- Recommended next step: Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard credentials.

