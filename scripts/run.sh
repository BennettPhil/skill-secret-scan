#!/usr/bin/env bash
set -euo pipefail

# secret-scan: find accidentally committed secrets in source code

TARGET_PATH=""
MIN_SEVERITY="low"
EXCLUDE_DIRS=""
OUTPUT_FORMAT="text"
FILES_FROM=""

usage() {
  cat <<'EOF'
Usage: secret-scan [OPTIONS] <path>

Scan source code for accidentally committed secrets.

Options:
  --min-severity <level>  Minimum severity: critical, high, medium, low (default: low)
  --exclude <dirs>        Comma-separated directories to skip
  --json                  Output as JSON array
  --files-from <file>     Read file list from file (- for stdin)
  --help                  Show this help message
EOF
}

severity_rank() {
  case "$1" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    *)        echo 0 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --min-severity) MIN_SEVERITY="$2"; shift 2 ;;
    --exclude)      EXCLUDE_DIRS="$2"; shift 2 ;;
    --json)         OUTPUT_FORMAT="json"; shift ;;
    --files-from)   FILES_FROM="$2"; shift 2 ;;
    --help)         usage; exit 0 ;;
    -*)             echo "Error: unknown option '$1'" >&2; exit 1 ;;
    *)              TARGET_PATH="$1"; shift ;;
  esac
done

if [ -z "$TARGET_PATH" ] && [ -z "$FILES_FROM" ]; then
  echo "Error: no path specified" >&2
  usage >&2
  exit 1
fi

if [ -n "$TARGET_PATH" ] && [ ! -e "$TARGET_PATH" ]; then
  echo "Error: path '$TARGET_PATH' does not exist" >&2
  exit 1
fi

MIN_RANK=$(severity_rank "$MIN_SEVERITY")

# Build exclude args for grep
EXCLUDE_ARGS=""
if [ -n "$EXCLUDE_DIRS" ]; then
  IFS=',' read -ra DIRS <<< "$EXCLUDE_DIRS"
  for dir in "${DIRS[@]}"; do
    EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude-dir=$dir"
  done
fi

# Always exclude common non-source dirs and binary files
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=__pycache__"
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude-dir=.soup --exclude-dir=vendor --exclude-dir=.venv"
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=*.min.js --exclude=*.min.css --exclude=*.map"
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=*.png --exclude=*.jpg --exclude=*.gif --exclude=*.ico"
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=*.woff --exclude=*.woff2 --exclude=*.ttf"
EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=package-lock.json --exclude=yarn.lock"

# Define secret patterns: severity|name|pattern
PATTERNS=(
  "critical|AWS Access Key|AKIA[0-9A-Z]{16}"
  "critical|AWS Secret Key|aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"
  "critical|Private Key Header|-----BEGIN (RSA |DSA |EC |PGP )?PRIVATE KEY"
  "high|GitHub Token|gh[ps]_[0-9a-zA-Z]{36}"
  "high|GitHub OAuth Token|gho_[0-9a-zA-Z]{36}"
  "high|Slack Token|xox[baprs]-[0-9a-zA-Z-]{10,}"
  "high|Stripe Secret Key|sk_live_[0-9a-zA-Z]{24,}"
  "high|Stripe Publishable Key|pk_live_[0-9a-zA-Z]{24,}"
  "high|Generic API Key Assignment|['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]"
  "high|Generic Secret Assignment|['\"]?secret['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]"
  "medium|JWT Token|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
  "medium|Database URL with Password|[a-z]+://[^:]+:[^@]+@[^/]+"
  "medium|Password Assignment|['\"]?password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"
  "medium|Bearer Token|[Bb]earer\s+[A-Za-z0-9_-]{20,}"
  "low|Generic Token Assignment|['\"]?token['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]"
  "low|Hex Encoded Secret|['\"][0-9a-f]{32,}['\"]"
)

# Get list of files to scan
get_files() {
  if [ -n "$FILES_FROM" ]; then
    if [ "$FILES_FROM" = "-" ]; then
      cat
    else
      cat "$FILES_FROM"
    fi
  else
    # Use find for file listing (to avoid grep binary file warnings)
    if [ -d "$TARGET_PATH" ]; then
      echo "$TARGET_PATH"
    else
      echo "$TARGET_PATH"
    fi
  fi
}

FINDINGS=""
FINDING_COUNT=0

scan_path() {
  local path="$1"

  for pattern_def in "${PATTERNS[@]}"; do
    IFS='|' read -r severity name regex <<< "$pattern_def"

    local sev_rank
    sev_rank=$(severity_rank "$severity")
    if [ "$sev_rank" -lt "$MIN_RANK" ]; then
      continue
    fi

    # shellcheck disable=SC2086
    local matches
    if [ -d "$path" ]; then
      matches=$(grep -rnE $EXCLUDE_ARGS "$regex" "$path" 2>/dev/null || true)
    else
      matches=$(grep -nE "$regex" "$path" 2>/dev/null || true)
    fi

    if [ -n "$matches" ]; then
      while IFS= read -r line; do
        local file lineno content
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        content=$(echo "$line" | cut -d: -f3-)

        # Make path relative
        if [ -d "$TARGET_PATH" ]; then
          file="${file#"$TARGET_PATH"/}"
        fi

        # Truncate long content
        if [ ${#content} -gt 60 ]; then
          content="${content:0:57}..."
        fi
        content=$(echo "$content" | sed 's/^[[:space:]]*//')

        FINDINGS="${FINDINGS}${severity}|${file}:${lineno}|${name}|${content}
"
        ((FINDING_COUNT++)) || true
      done <<< "$matches"
    fi
  done
}

TARGET=$(get_files)
while IFS= read -r path; do
  [ -z "$path" ] && continue
  scan_path "$path"
done <<< "$TARGET"

# Deduplicate findings (same file:line may match multiple patterns)
if [ -n "$FINDINGS" ]; then
  FINDINGS=$(echo "$FINDINGS" | sort -u -t'|' -k2,2)
  FINDING_COUNT=$(echo "$FINDINGS" | grep -c '.' || true)
fi

# Sort by severity (critical first)
if [ -n "$FINDINGS" ]; then
  FINDINGS=$(echo "$FINDINGS" | sort -t'|' -k1,1r)
fi

# Output
if [ -z "$FINDINGS" ] || [ "$FINDING_COUNT" -eq 0 ]; then
  if [ "$OUTPUT_FORMAT" = "json" ]; then
    echo "[]"
  else
    echo "No secrets found"
  fi
  exit 0
fi

# Count files
FILE_COUNT=$(echo "$FINDINGS" | cut -d'|' -f2 | cut -d: -f1 | sort -u | wc -l | tr -d ' ')

if [ "$OUTPUT_FORMAT" = "json" ]; then
  echo "["
  first=true
  while IFS='|' read -r severity location name content; do
    [ -z "$severity" ] && continue
    file=$(echo "$location" | cut -d: -f1)
    lineno=$(echo "$location" | cut -d: -f2)
    if $first; then first=false; else echo ","; fi
    content_escaped=$(echo "$content" | sed 's/"/\\"/g')
    printf '  {"severity": "%s", "file": "%s", "line": %s, "type": "%s", "match": "%s"}' \
      "$severity" "$file" "$lineno" "$name" "$content_escaped"
  done <<< "$FINDINGS"
  echo ""
  echo "]"
else
  while IFS='|' read -r severity location name content; do
    [ -z "$severity" ] && continue
    sev_upper=$(echo "$severity" | tr '[:lower:]' '[:upper:]')
    printf "%-9s %-30s %-23s %s\n" "$sev_upper" "$location" "$name" "$content"
  done <<< "$FINDINGS"
  echo ""
  echo "Found $FINDING_COUNT potential secrets in $FILE_COUNT files"
fi

# Exit 1 if any findings (useful for CI)
exit 1
