# secret-scan

Scan codebases for accidentally committed secrets, API keys, tokens, and passwords using pattern matching.

## Quick Start

```bash
./scripts/run.sh /path/to/project
```

## Prerequisites

- Bash 4+
- grep with `-E` (extended regex) support

## Usage

```bash
# Scan a project
./scripts/run.sh ./my-project

# JSON output for CI integration
./scripts/run.sh --format json ./my-project

# Only high severity
./scripts/run.sh --severity high ./my-project

# Exclude test files
./scripts/run.sh --exclude "*.test.*,*.spec.*" ./my-project
```

## Detected Patterns

- AWS Access Keys and Secret Keys
- Private Keys (RSA, EC, DSA, OpenSSH)
- GitHub Tokens (ghp_, ghs_)
- Generic API keys and secrets
- Database connection strings (Postgres, MySQL, MongoDB)
- Password assignments
- Bearer tokens
- Slack tokens
- Hardcoded IP:port combinations
