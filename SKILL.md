---
name: secret-scan
description: Searches codebases for accidentally committed secrets like API keys, tokens, and passwords
version: 0.1.0
license: Apache-2.0
---

# secret-scan

Scans source code for accidentally committed secrets: AWS keys, API tokens, private keys, passwords, and other sensitive data that should never be in version control.

## See It in Action

Start with [examples/basic-example.md](examples/basic-example.md) to scan a project.

## Examples Index

| File | Description |
|------|-------------|
| [basic-example.md](examples/basic-example.md) | Scan a project and see findings |
| [common-patterns.md](examples/common-patterns.md) | CI integration, severity filters, exclusions |

## Instructions

When a user wants to check for leaked secrets in code:

1. Run `./scripts/run.sh <path>` to scan a directory
2. Review findings sorted by severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Use `--json` for machine-readable output in CI pipelines
4. Use `--min-severity` to filter noise

## Reference

| Flag | Description |
|------|-------------|
| `--min-severity <level>` | Minimum severity to report: critical, high, medium, low (default: low) |
| `--exclude <dirs>` | Comma-separated directories to skip |
| `--json` | Output as JSON array |
| `--files-from <file>` | Read file list from file (use `-` for stdin) |
| `--help` | Show usage |

## Detected Patterns

- AWS Access Keys (AKIA...)
- AWS Secret Keys
- GitHub tokens (ghp_, gho_, ghs_)
- Generic API keys (api_key, apikey patterns)
- Private keys (RSA, DSA, EC, PGP)
- JWT tokens
- Slack tokens
- Stripe keys (sk_live_, pk_live_)
- Database connection strings with passwords
- Generic password assignments
- Base64-encoded secrets (high entropy strings)

## Installation

No dependencies. Uses `grep` with regex patterns.
