#!/usr/bin/env bash
set -euo pipefail

# run.sh — Scan codebase for accidentally committed secrets
# Usage: ./run.sh [OPTIONS] <directory>

FORMAT="text"
SEVERITY="all"
EXCLUDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --exclude) EXCLUDE="$2"; shift 2 ;;
    --help)
      echo "Usage: run.sh [OPTIONS] <directory>"
      echo ""
      echo "Scan for secrets in a codebase."
      echo ""
      echo "Options:"
      echo "  --format text|json      Output format (default: text)"
      echo "  --severity all|high|medium|low  Filter by severity"
      echo "  --exclude PATTERN       Glob patterns to exclude (comma-separated)"
      echo "  --help                  Show this help"
      exit 0
      ;;
    -*) echo "Error: unknown option: $1" >&2; exit 2 ;;
    *)
      if [[ -z "${DIR:-}" ]]; then
        DIR="$1"; shift
      else
        echo "Error: unexpected argument: $1" >&2; exit 2
      fi
      ;;
  esac
done

if [[ -z "${DIR:-}" ]]; then
  echo "Error: directory argument required" >&2
  exit 2
fi

if [[ ! -d "$DIR" ]]; then
  echo "Error: directory not found: $DIR" >&2
  exit 2
fi

# Define patterns with severity
# Format: SEVERITY|PATTERN_NAME|REGEX
PATTERNS=(
  "high|AWS Access Key|AKIA[0-9A-Z]{16}"
  "high|AWS Secret Key|aws_secret_access_key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+=]{40}"
  "high|Private Key|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
  "high|GitHub Token|gh[ps]_[A-Za-z0-9_]{36,}"
  "high|Generic API Key|['\"]?api[_-]?key['\"]?[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9]{20,}['\"]"
  "high|Generic Secret|['\"]?secret[_-]?key['\"]?[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9]{20,}['\"]"
  "medium|Database URL|postgres://[^[:space:]]+:[^[:space:]]+@"
  "medium|Database URL|mysql://[^[:space:]]+:[^[:space:]]+@"
  "medium|Database URL|mongodb(\\+srv)?://[^[:space:]]+:[^[:space:]]+@"
  "medium|Password Assignment|password[[:space:]]*=[[:space:]]*['\"][^'\"]{8,}['\"]"
  "medium|Bearer Token|['\"]Bearer [A-Za-z0-9._-]{20,}['\"]"
  "medium|Slack Token|xox[bporas]-[A-Za-z0-9-]+"
  "low|TODO Secret|TODO.*secret|TODO.*password|TODO.*token|TODO.*key"
  "low|Hardcoded IP|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]+"
)

# Build exclude args for grep
GREP_EXCLUDE_ARGS=""
if [[ -n "$EXCLUDE" ]]; then
  IFS=',' read -ra EXCL_PATTERNS <<< "$EXCLUDE"
  for pat in "${EXCL_PATTERNS[@]}"; do
    pat=$(echo "$pat" | tr -d ' ')
    GREP_EXCLUDE_ARGS="$GREP_EXCLUDE_ARGS --exclude=$pat"
  done
fi

# Scan
declare -a match_files match_lines match_severities match_names match_texts
total=0

for pattern_def in "${PATTERNS[@]}"; do
  IFS='|' read -r sev name regex <<< "$pattern_def"

  # Filter by severity
  if [[ "$SEVERITY" != "all" && "$sev" != "$SEVERITY" ]]; then
    continue
  fi

  # Search for matches, skipping binary files
  matches=$(eval grep -rnI $GREP_EXCLUDE_ARGS --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.soup --exclude='*.lock' --exclude='*.min.js' --exclude='*.min.css' -E "'$regex'" "'$DIR'" 2>/dev/null || true)

  if [[ -n "$matches" ]]; then
    while IFS= read -r match_line; do
      file="${match_line%%:*}"
      rest="${match_line#*:}"
      linenum="${rest%%:*}"
      content="${rest#*:}"

      rel_file="${file#$DIR/}"
      [[ "$rel_file" == "$file" ]] && rel_file="${file#$DIR}"

      match_files+=("$rel_file")
      match_lines+=("$linenum")
      match_severities+=("$sev")
      match_names+=("$name")
      # Truncate long content and mask potential secrets
      clean=$(echo "$content" | sed 's/^[[:space:]]*//' | head -c 120)
      match_texts+=("$clean")
      ((total++))
    done <<< "$matches"
  fi
done

if [[ $total -eq 0 ]]; then
  echo "No secrets found."
  exit 0
fi

# --- JSON output ---
if [[ "$FORMAT" == "json" ]]; then
  echo "["
  for ((i = 0; i < total; i++)); do
    comma=","
    [[ $i -eq $((total - 1)) ]] && comma=""
    escaped=$(echo "${match_texts[$i]}" | sed 's/"/\\"/g')
    echo "  {\"file\": \"${match_files[$i]}\", \"line\": ${match_lines[$i]}, \"severity\": \"${match_severities[$i]}\", \"type\": \"${match_names[$i]}\", \"content\": \"$escaped\"}$comma"
  done
  echo "]"
  exit 1
fi

# --- Text output ---
echo "Found $total potential secret(s):"
echo ""

current_file=""
for ((i = 0; i < total; i++)); do
  if [[ "${match_files[$i]}" != "$current_file" ]]; then
    if [[ -n "$current_file" ]]; then
      echo ""
    fi
    current_file="${match_files[$i]}"
    echo "$current_file:"
  fi
  echo "  L${match_lines[$i]} [${match_severities[$i]}] ${match_names[$i]}: ${match_texts[$i]}"
done

exit 1
