# Architecture

RustCSPGuardian is a small CLI for checking whether a URL can be embedded inside iframe-based environments such as dashboards and digital signage players.

## Goals

- Make embed blockers visible before a rollout.
- Keep scanning logic testable outside the CLI.
- Support human-readable, JSON, and HTML output.
- Avoid storing secrets or private website data.

## Module Layout

| Module | Responsibility |
| --- | --- |
| `src/cli.rs` | CLI commands, flags, and output selection |
| `src/scanner/` | HTTP request handling and response-header interpretation |
| `src/report.rs` | Shared result model used by all outputs |
| `src/output/` | Terminal, JSON, and HTML rendering |
| `src/history.rs` | Local scan history support |
| `src/error.rs` | Project error types |

## Data Flow

1. The CLI parses a single URL or batch file.
2. The scanner sends requests and collects security/embed headers.
3. Header rules classify iframe compatibility and risk signals.
4. A report is created from the scan result.
5. The selected renderer writes terminal, JSON, or HTML output.

## Design Notes

- The scanner owns network behavior; renderers do not perform HTTP work.
- Output models should stay stable so scripts can depend on JSON fields.
- Header checks should be conservative and explain why a URL is blocked or unknown.
- Integration tests use local mock HTTP servers instead of public sites.

## Release Assumptions

- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo package` pass before release.
- GitHub Actions are intentionally not used in this repo.
- Release branches mirror the latest stable documentation and examples.
