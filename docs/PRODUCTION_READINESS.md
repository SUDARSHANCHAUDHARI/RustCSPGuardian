# Production Readiness

## Current Status

This repository has a working local MVP with deterministic analysis, safe sample data, generated reports, and tests. It is not production complete yet.

## Required Before Public Release

- Add URL validation and target allowlisting for hosted scanning.
- Add request timeout, redirect, and response-size controls.
- Add structured logging without leaking secrets.
- Redact sensitive response headers before storage.
- Add authentication and authorization before multi-user scan history.
- Add database-backed scan storage with retention policy.
- Run dependency and secret scans before release.

## Definition of Done

- CI passes on pull requests.
- README has setup, usage, and security notes.
- Sample data is safe to publish.
- Error paths are handled clearly.
- No secrets or local machine paths are committed.
