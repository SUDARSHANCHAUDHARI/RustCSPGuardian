# RustCSPGuardian — Claude Code Context

## Purpose
Rust CLI tool that checks whether a website can be embedded in iframe-based digital signage environments.
Detects CSP frame-ancestors, X-Frame-Options, CORS issues, missing security headers, and mixed content risk.

## Type
Rust CLI (cspguard)

## Stack
- Language: Rust (stable)
- CLI: clap
- Async: tokio
- HTTP: reqwest (rustls-tls)
- Serialization: serde + serde_json
- Errors: anyhow + thiserror
- Terminal: colored
- Logging: tracing + tracing-subscriber

## Commands
```bash
cargo run -- check https://example.com
cargo run -- check https://example.com --json
cargo run -- batch urls.txt
cargo run -- batch urls.txt --json
cargo test
cargo clippy
cargo fmt
cargo build --release
```

## Module Structure
```
src/
  main.rs         — entry point, CLI routing
  cli.rs          — clap definitions (Commands enum)
  error.rs        — CspGuardError types
  report.rs       — ScanReport, FramePolicy, SecurityHeaders structs
  scanner/
    mod.rs        — check_url(), risk evaluation, suggestion builder
    headers.rs    — header parsing, XFO/CSP evaluation
  output/
    mod.rs        — re-exports
    terminal.rs   — colored terminal output
    json.rs       — JSON output
tests/
  integration_test.rs  — CLI integration tests
```

## GitHub Repo
https://github.com/SUDARSHANCHAUDHARI/RustCSPGuardian

## Known Issues
None — initial scaffold
