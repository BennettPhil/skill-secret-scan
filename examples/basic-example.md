# Basic Example

> Scan a project directory for accidentally committed secrets.

## Run It

```bash
./scripts/run.sh /path/to/project
```

## Output

```
CRITICAL  src/config.js:12        AWS Access Key          AKIA3EXAMPLE1234ABCD
HIGH      .env:3                  Generic API Key         sk_live_abc123...
HIGH      deploy/secrets.yaml:8   Private Key Header      -----BEGIN RSA PRIV...
MEDIUM    src/api.js:45           Generic Token           token = "eyJhbGci...

Found 4 potential secrets in 2 files
```

## What Just Happened

`secret-scan` recursively searched all files for patterns matching known secret formats: AWS keys, API tokens, private keys, passwords in config files, and more. Results are sorted by severity.
