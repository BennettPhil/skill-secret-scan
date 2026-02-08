# secret-scan

Searches codebases for accidentally committed secrets like API keys, tokens, and passwords.

## Quick Start

```bash
./scripts/run.sh /path/to/project
```

## Filter by Severity

```bash
./scripts/run.sh --min-severity high /path/to/project
```

## JSON Output for CI

```bash
./scripts/run.sh --json /path/to/project
```

## Pre-commit Hook

```bash
git diff --cached --name-only | xargs ./scripts/run.sh --files-from -
```

## Prerequisites

- Bash, grep (standard Unix tools)
- No external dependencies
