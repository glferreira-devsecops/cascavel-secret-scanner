#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# 🐍 Cascavel Secret Scanner v1.0.0
# Enterprise-grade secret detection for CI/CD pipelines
# Copyright (c) 2026 RET Tecnologia — https://rettecnologia.org
# License: MIT
# ─────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.0.0"
SCAN_PATH="${INPUT_PATH:-.}"
SEVERITY="${INPUT_SEVERITY:-medium}"
FAIL_ON="${INPUT_FAIL_ON:-true}"
EXCLUDE="${INPUT_EXCLUDE:-.git,node_modules,vendor}"
SARIF_ENABLED="${INPUT_SARIF:-true}"
MAX_SIZE="${INPUT_MAX_SIZE:-512}"
SCAN_HISTORY="${INPUT_SCAN_HISTORY:-false}"
BASELINE="${INPUT_BASELINE:-}"
CUSTOM_PATTERNS="${INPUT_CUSTOM_PATTERNS:-}"

REPORT_DIR="${GITHUB_WORKSPACE:-.}/.cascavel"
REPORT_JSON="${REPORT_DIR}/findings.json"
REPORT_SARIF="${REPORT_DIR}/results.sarif"
FINDINGS_FILE=$(mktemp)

mkdir -p "$REPORT_DIR"

# ─── Severity Levels ──────────────────────────────────────
declare -A SEV_WEIGHT
SEV_WEIGHT[low]=1
SEV_WEIGHT[medium]=2
SEV_WEIGHT[high]=3
SEV_WEIGHT[critical]=4

MIN_SEV=${SEV_WEIGHT[$SEVERITY]:-2}

# ─── Pattern Database ─────────────────────────────────────
# Format: ID|SEVERITY|DESCRIPTION|REGEX|CWE
PATTERNS=(
  # ── CRITICAL: Cloud Provider Keys ──
  "aws-access-key|critical|AWS Access Key ID|AKIA[0-9A-Z]{16}|CWE-798"
  "aws-secret-key|critical|AWS Secret Access Key|(?i)aws_secret_access_key[\s]*[=:][\s]*['\"][0-9a-zA-Z/+]{40}['\"]|CWE-798"
  "gcp-service-account|critical|GCP Service Account Key|\"type\":\s*\"service_account\"|CWE-798"
  "azure-storage-key|critical|Azure Storage Account Key|(?i)AccountKey=[0-9a-zA-Z+/=]{86,88}|CWE-798"
  
  # ── CRITICAL: Platform Tokens ──
  "github-token|critical|GitHub Personal Access Token|(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|CWE-798"
  "github-fine-grained|critical|GitHub Fine-Grained Token|github_pat_[A-Za-z0-9_]{22,255}|CWE-798"
  "gitlab-token|critical|GitLab Token|glpat-[0-9a-zA-Z_-]{20,}|CWE-798"
  "slack-bot-token|critical|Slack Bot Token|xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}|CWE-798"
  "slack-user-token|critical|Slack User Token|xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}|CWE-798"
  
  # ── CRITICAL: Payment / Financial ──
  "stripe-live-secret|critical|Stripe Live Secret Key|sk_live_[0-9a-zA-Z]{24,99}|CWE-798"
  "stripe-live-restricted|critical|Stripe Live Restricted Key|rk_live_[0-9a-zA-Z]{24,99}|CWE-798"
  "paypal-access-token|critical|PayPal Access Token|access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}|CWE-798"
  "square-access-token|critical|Square Access Token|sq0atp-[0-9A-Za-z_-]{22}|CWE-798"
  
  # ── CRITICAL: Cryptographic Material ──
  "private-key-rsa|critical|RSA Private Key|-----BEGIN RSA PRIVATE KEY-----|CWE-321"
  "private-key-ec|critical|EC Private Key|-----BEGIN EC PRIVATE KEY-----|CWE-321"
  "private-key-openssh|critical|OpenSSH Private Key|-----BEGIN OPENSSH PRIVATE KEY-----|CWE-321"
  "private-key-dsa|critical|DSA Private Key|-----BEGIN DSA PRIVATE KEY-----|CWE-321"
  "private-key-generic|critical|Private Key (Generic)|-----BEGIN PRIVATE KEY-----|CWE-321"
  "pgp-private|critical|PGP Private Key Block|-----BEGIN PGP PRIVATE KEY BLOCK-----|CWE-321"

  # ── HIGH: API Keys & Tokens ──
  "sendgrid-api-key|high|SendGrid API Key|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|CWE-798"
  "twilio-api-key|high|Twilio API Key|SK[0-9a-fA-F]{32}|CWE-798"
  "mailgun-api-key|high|Mailgun API Key|key-[0-9a-zA-Z]{32}|CWE-798"
  "telegram-bot-token|high|Telegram Bot Token|[0-9]{8,10}:[0-9A-Za-z_-]{35}|CWE-798"
  "firebase-api-key|high|Firebase API Key|AIza[0-9A-Za-z_-]{35}|CWE-798"
  "heroku-api-key|high|Heroku API Key|(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]|CWE-798"
  "jwt-token|high|JSON Web Token (hardcoded)|eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*|CWE-798"
  "slack-webhook|high|Slack Incoming Webhook|https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}|CWE-798"
  "discord-webhook|high|Discord Webhook URL|https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+|CWE-798"
  "supabase-service-role|high|Supabase Service Role Key|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}|CWE-798"

  # ── HIGH: Database & Connection Strings ──
  "database-url|high|Database Connection String|(?i)(postgres|mysql|mongodb|redis|amqp)://[^\s'\"]{10,}|CWE-798"
  "connection-string|high|Connection String with Password|(?i)(password|pwd)=[^;&\s'\"]{3,}|CWE-798"
  
  # ── HIGH: Generic Secrets ──
  "generic-password|high|Generic Hardcoded Password|(?i)(password|passwd|pwd|secret)[\s]*[=:][\s]*['\"][^'\"]{8,}['\"]|CWE-798"
  "generic-api-key|high|Generic API Key Assignment|(?i)(api[_-]?key|apikey|api[_-]?secret)[\s]*[=:][\s]*['\"][^'\"]{8,}['\"]|CWE-798"
  "generic-token|high|Generic Token Assignment|(?i)(auth[_-]?token|access[_-]?token|bearer)[\s]*[=:][\s]*['\"][^'\"]{16,}['\"]|CWE-798"

  # ── MEDIUM: Potential Secrets ──
  "base64-secret|medium|Base64-encoded Secret|(?i)(secret|key|token|password|credential)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}|CWE-798"
  "hex-secret|medium|Hex-encoded Secret (32+ bytes)|(?i)(secret|key|token)['\"]?\s*[:=]\s*['\"]?[0-9a-fA-F]{64,}|CWE-798"
  "ip-with-port|medium|Hardcoded IP with Port|(?<![0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}(?![0-9])|CWE-200"

  # ── LOW: Informational ──
  "todo-secret|low|TODO/FIXME referencing secret|(?i)(todo|fixme|hack|xxx).{0,40}(secret|password|key|token|credential)|CWE-798"
  "env-file-reference|low|.env file committed|^[A-Z_]+=.{1,}$|CWE-200"
)

# ─── Build Exclude Arguments ──────────────────────────────
build_excludes() {
  local args=""
  IFS=',' read -ra EXCL <<< "$EXCLUDE"
  for pattern in "${EXCL[@]}"; do
    pattern=$(echo "$pattern" | xargs)
    if [[ "$pattern" == *.* ]]; then
      args="$args --exclude=$pattern"
    else
      args="$args --exclude-dir=$pattern"
    fi
  done
  echo "$args"
}

EXCLUDE_ARGS=$(build_excludes)

# ─── Load Baseline (known findings to ignore) ─────────────
declare -A BASELINE_HASHES
if [ -n "$BASELINE" ] && [ -f "$BASELINE" ]; then
  while IFS= read -r line; do
    BASELINE_HASHES["$line"]=1
  done < "$BASELINE"
fi

# ─── Banner ───────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  🐍 CASCAVEL SECRET SCANNER v${VERSION}             ║"
echo "  ║  Enterprise Security · RET Tecnologia            ║"
echo "  ║  https://rettecnologia.org                       ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
echo "  📂 Target:    ${SCAN_PATH}"
echo "  🎯 Threshold: ${SEVERITY}"
echo "  🚫 Excludes:  $(echo $EXCLUDE | tr ',' ' ' | wc -w | xargs) patterns"
echo "  📏 Max size:  ${MAX_SIZE}KB"
echo ""
echo "  ────────────────────────────────────────────────────"

# ─── Scan Engine ──────────────────────────────────────────
TOTAL=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
JSON_FINDINGS="[]"

for entry in "${PATTERNS[@]}"; do
  IFS='|' read -r id sev desc regex cwe <<< "$entry"
  
  pat_level=${SEV_WEIGHT[$sev]:-2}
  [ "$pat_level" -lt "$MIN_SEV" ] && continue

  # Find matching files (respecting size limit)
  MATCHES=$(grep -rPn "$regex" "$SCAN_PATH" $EXCLUDE_ARGS \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
    --include="*.go" --include="*.rs" --include="*.java" --include="*.rb" --include="*.php" \
    --include="*.cs" --include="*.c" --include="*.cpp" --include="*.h" \
    --include="*.yml" --include="*.yaml" --include="*.json" --include="*.xml" --include="*.toml" \
    --include="*.cfg" --include="*.conf" --include="*.ini" --include="*.env" --include="*.properties" \
    --include="*.sh" --include="*.bash" --include="*.zsh" --include="*.fish" \
    --include="*.tf" --include="*.hcl" --include="*.dockerfile" --include="Dockerfile" \
    --include="*.md" --include="*.txt" --include="*.html" --include="*.css" \
    --include="*.sql" --include="*.gradle" --include="*.kt" --include="*.swift" \
    --include="*.r" --include="*.R" --include="*.jl" --include="*.ex" --include="*.exs" \
    --include="*.env.*" --include=".env" --include=".env.*" \
    2>/dev/null || true)

  [ -z "$MATCHES" ] && continue

  COUNT=$(echo "$MATCHES" | wc -l | xargs)
  
  # Apply baseline filter
  if [ -n "$BASELINE" ]; then
    FILTERED=""
    while IFS= read -r match; do
      HASH=$(echo "$match" | sha256sum | cut -d' ' -f1)
      if [ -z "${BASELINE_HASHES[$HASH]:-}" ]; then
        FILTERED="${FILTERED}${match}\n"
      fi
    done <<< "$MATCHES"
    MATCHES=$(echo -e "$FILTERED" | sed '/^$/d')
    COUNT=$(echo "$MATCHES" | grep -c '.' || echo 0)
    [ "$COUNT" -eq 0 ] && continue
  fi

  # Severity icon
  case "$sev" in
    critical) ICON="🔴"; ((CRITICAL += COUNT)) ;;
    high)     ICON="🟠"; ((HIGH += COUNT)) ;;
    medium)   ICON="🟡"; ((MEDIUM += COUNT)) ;;
    low)      ICON="🔵"; ((LOW += COUNT)) ;;
  esac

  ((TOTAL += COUNT))

  echo ""
  echo "  ${ICON} [${sev^^}] ${desc} (${cwe})"
  echo "     Found in ${COUNT} location(s):"
  
  echo "$MATCHES" | head -5 | while IFS= read -r line; do
    FILE=$(echo "$line" | cut -d: -f1)
    LINE_NUM=$(echo "$line" | cut -d: -f2)
    # Redact the actual secret value
    SNIPPET=$(echo "$line" | cut -d: -f3- | sed 's/[a-zA-Z0-9_/+=-]\{8,\}/***REDACTED***/g' | cut -c1-80)
    echo "     └─ ${FILE}:${LINE_NUM}  ${SNIPPET}"
  done
  
  [ "$COUNT" -gt 5 ] && echo "     └─ ... and $((COUNT - 5)) more"

  # Build JSON findings
  echo "$MATCHES" | while IFS= read -r line; do
    FILE=$(echo "$line" | cut -d: -f1)
    LINE_NUM=$(echo "$line" | cut -d: -f2)
    echo "${id}|${sev}|${desc}|${cwe}|${FILE}|${LINE_NUM}" >> "$FINDINGS_FILE"
  done
done

# ─── Git History Scan ─────────────────────────────────────
if [ "$SCAN_HISTORY" = "true" ] && command -v git &>/dev/null; then
  echo ""
  echo "  ⏳ Scanning git history (this may take a while)..."
  
  HISTORY_SECRETS=0
  
  # Check last 100 commits for removed secrets
  git -C "$SCAN_PATH" log --all --diff-filter=D --name-only --pretty=format: -n 100 2>/dev/null | \
    sort -u | grep -E '\.(env|pem|key|p12|pfx|jks)$' | while IFS= read -r file; do
      if [ -n "$file" ]; then
        echo "  🔴 [CRITICAL] Sensitive file found in git history: $file"
        ((HISTORY_SECRETS++)) || true
        echo "history-deleted-file|critical|Deleted sensitive file in history|CWE-212|${file}|0" >> "$FINDINGS_FILE"
      fi
    done
  
  ((TOTAL += HISTORY_SECRETS)) || true
fi

# ─── Generate Reports ────────────────────────────────────

# JSON Report
cat > "$REPORT_JSON" << JSONEOF
{
  "scanner": "cascavel-secret-scanner",
  "version": "${VERSION}",
  "vendor": "RET Tecnologia",
  "url": "https://rettecnologia.org",
  "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "configuration": {
    "path": "${SCAN_PATH}",
    "severity_threshold": "${SEVERITY}",
    "scan_history": ${SCAN_HISTORY}
  },
  "summary": {
    "total": ${TOTAL},
    "critical": ${CRITICAL},
    "high": ${HIGH},
    "medium": ${MEDIUM},
    "low": ${LOW}
  },
  "findings": [
$(if [ -f "$FINDINGS_FILE" ] && [ -s "$FINDINGS_FILE" ]; then
  FIRST=true
  while IFS='|' read -r fid fsev fdesc fcwe ffile fline; do
    [ -z "$fid" ] && continue
    if [ "$FIRST" = true ]; then FIRST=false; else echo ","; fi
    printf '    {"id":"%s","severity":"%s","description":"%s","cwe":"%s","file":"%s","line":%s}' \
      "$fid" "$fsev" "$fdesc" "$fcwe" "$ffile" "${fline:-0}"
  done < "$FINDINGS_FILE"
fi)
  ]
}
JSONEOF

# SARIF Report (GitHub Security Tab integration)
if [ "$SARIF_ENABLED" = "true" ]; then
  cat > "$REPORT_SARIF" << SARIFEOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Cascavel Secret Scanner",
        "organization": "RET Tecnologia",
        "version": "${VERSION}",
        "informationUri": "https://github.com/glferreira-devsecops/cascavel-secret-scanner",
        "rules": [
          {"id": "secret/hardcoded-credential", "shortDescription": {"text": "Hardcoded credential detected"}, "defaultConfiguration": {"level": "error"}},
          {"id": "secret/private-key", "shortDescription": {"text": "Private key file detected"}, "defaultConfiguration": {"level": "error"}},
          {"id": "secret/api-key", "shortDescription": {"text": "API key detected"}, "defaultConfiguration": {"level": "warning"}},
          {"id": "secret/generic-secret", "shortDescription": {"text": "Generic secret detected"}, "defaultConfiguration": {"level": "warning"}}
        ]
      }
    },
    "results": [
$(if [ -f "$FINDINGS_FILE" ] && [ -s "$FINDINGS_FILE" ]; then
  FIRST=true
  while IFS='|' read -r fid fsev fdesc fcwe ffile fline; do
    [ -z "$fid" ] && continue
    SARIF_LEVEL="warning"
    [ "$fsev" = "critical" ] && SARIF_LEVEL="error"
    [ "$fsev" = "high" ] && SARIF_LEVEL="error"
    [ "$fsev" = "low" ] && SARIF_LEVEL="note"
    if [ "$FIRST" = true ]; then FIRST=false; else echo ","; fi
    printf '      {"ruleId":"secret/%s","level":"%s","message":{"text":"%s (%s)"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":%s}}}]}' \
      "$fid" "$SARIF_LEVEL" "$fdesc" "$fcwe" "$ffile" "${fline:-1}"
  done < "$FINDINGS_FILE"
fi)
    ]
  }]
}
SARIFEOF
fi

# ─── Summary ──────────────────────────────────────────────
echo ""
echo "  ────────────────────────────────────────────────────"
echo ""
echo "  📊 SCAN RESULTS"
echo "  ────────────────────────────────────────────────────"
echo "  🔴 Critical:  ${CRITICAL}"
echo "  🟠 High:      ${HIGH}"
echo "  🟡 Medium:    ${MEDIUM}"
echo "  🔵 Low:       ${LOW}"
echo "  ────────────────────────────────────────────────────"
echo "  📋 Total:     ${TOTAL} finding(s)"
echo ""
echo "  📄 Report:    ${REPORT_JSON}"
[ "$SARIF_ENABLED" = "true" ] && echo "  🔒 SARIF:     ${REPORT_SARIF}"
echo ""

# ─── Set GitHub Action Outputs ────────────────────────────
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "findings-count=${TOTAL}" >> "$GITHUB_OUTPUT"
  echo "critical-count=${CRITICAL}" >> "$GITHUB_OUTPUT"
  echo "high-count=${HIGH}" >> "$GITHUB_OUTPUT"
  echo "sarif-path=${REPORT_SARIF}" >> "$GITHUB_OUTPUT"
  echo "report-path=${REPORT_JSON}" >> "$GITHUB_OUTPUT"
fi

# ─── GitHub Step Summary ──────────────────────────────────
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat >> "$GITHUB_STEP_SUMMARY" << SUMMARYEOF
### 🐍 Cascavel Secret Scanner Results

| Severity | Count |
|:---------|------:|
| 🔴 Critical | ${CRITICAL} |
| 🟠 High | ${HIGH} |
| 🟡 Medium | ${MEDIUM} |
| 🔵 Low | ${LOW} |
| **Total** | **${TOTAL}** |

> Powered by [RET Tecnologia](https://rettecnologia.org) · Cascavel Secret Scanner v${VERSION}
SUMMARYEOF
fi

# ─── Cleanup ──────────────────────────────────────────────
rm -f "$FINDINGS_FILE"

# ─── Exit Code ────────────────────────────────────────────
if [ "$TOTAL" -gt 0 ]; then
  if [ "$FAIL_ON" = "true" ]; then
    echo "  ❌ Pipeline blocked: ${TOTAL} secret(s) detected"
    echo ""
    echo "  🐍 Cascavel Secret Scanner by RET Tecnologia"
    echo ""
    exit 1
  else
    echo "  ⚠️  ${TOTAL} secret(s) detected (pipeline not blocked)"
    echo ""
  fi
else
  echo "  ✅ No secrets detected — your code is clean!"
  echo ""
fi

echo "  🐍 Cascavel Secret Scanner by RET Tecnologia"
echo ""
