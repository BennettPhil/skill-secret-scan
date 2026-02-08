# Common Patterns

## 1. Scan Current Directory

```bash
./scripts/run.sh .
```

## 2. Scan with Specific Severity Threshold

Only show critical and high severity findings:

```bash
./scripts/run.sh --min-severity high /path/to/project
```

## 3. Exclude Certain Directories

Skip test fixtures and vendor directories:

```bash
./scripts/run.sh --exclude "test,vendor,node_modules" /path/to/project
```

## 4. JSON Output for CI Integration

```bash
./scripts/run.sh --json /path/to/project
```

## 5. Pre-commit Hook Usage

Check only staged files:

```bash
git diff --cached --name-only | xargs ./scripts/run.sh --files-from -
```

Exit code 1 if any secrets found, making it suitable as a pre-commit hook.
