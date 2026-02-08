---
name: secret-scan
description: Scan codebases for accidentally committed secrets, API keys, tokens, and passwords using pattern matching.
version: 0.1.0
license: Apache-2.0
---

# secret-scan

Scans a project directory for accidentally committed secrets like API keys, tokens, passwords, and private keys using configurable regex patterns.

## Purpose

Developers accidentally commit secrets to repositories all the time — AWS keys, database passwords, API tokens, private keys. This skill scans files for common secret patterns and reports matches with file location and severity.

## See It in Action

```bash
./scripts/run.sh /path/to/project
```

## Reference

| Flag | Default | Description |
|------|---------|-------------|
| DIR | (required) | Directory to scan |
| --format | text | Output format: text, json |
| --severity | all | Filter: all, high, medium, low |
| --exclude | (none) | Glob patterns to exclude (comma-separated) |
| --help | - | Show usage |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found |
| 1 | Secrets found |
| 2 | Invalid input / usage error |

## Installation

No dependencies. Pure bash + grep implementation.
