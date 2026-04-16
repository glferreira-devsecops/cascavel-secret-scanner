<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%90%8D_CASCAVEL-Secret_Scanner-FF6B00?style=for-the-badge&labelColor=0D1117&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSIjRkY2QjAwIj48cGF0aCBkPSJNMTIgMUw5IDRoNmwtMy0zek0zIDEzbDMgM2gydjJoOHYtMmgydi0yaDJ2LTJoMlY5aC0ybC0zLTNoLTRMNiA5SDR2Mmgydjd6Ii8+PC9zdmc+" />
</p>

<h1 align="center">🐍 Cascavel Secret Scanner</h1>

<p align="center">
  <strong>Enterprise-grade secret detection for CI/CD pipelines.</strong><br />
  <em>Stop hardcoded credentials from reaching production. One line. Zero config.</em>
</p>

<p align="center">
  <a href="https://github.com/marketplace/actions/cascavel-secret-scanner"><img src="https://img.shields.io/badge/GitHub%20Marketplace-Cascavel%20Secret%20Scanner-2ea44f?style=flat-square&logo=github" alt="Marketplace" /></a>
  <img src="https://img.shields.io/badge/patterns-40+-7C3AED?style=flat-square" alt="40+ patterns" />
  <img src="https://img.shields.io/badge/SARIF-supported-3B82F6?style=flat-square" alt="SARIF" />
  <img src="https://img.shields.io/badge/config-zero-10B981?style=flat-square" alt="Zero config" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-EAB308?style=flat-square" alt="MIT" /></a>
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/by-RET%20Tecnologia-FF6B00?style=flat-square" alt="RET" /></a>
</p>

<br />

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-why-cascavel">Why Cascavel?</a> •
  <a href="#-detection-patterns">Patterns</a> •
  <a href="#-advanced-usage">Advanced</a> •
  <a href="#-inputs">Inputs</a> •
  <a href="#-outputs">Outputs</a>
</p>

---

## 🚀 Quick Start

Add one line to any workflow. That's it.

```yaml
name: Security
on: [push, pull_request]

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-secret-scanner@v1
```

> Your pipeline now catches **AWS keys, GitHub tokens, Stripe secrets, private keys, database passwords**, and 35+ more patterns before they reach production.

---

## 💡 Why Cascavel?

| | Cascavel | Other tools |
|:--|:---------|:------------|
| ⚡ **Setup time** | 1 line, zero config | Config files, Docker images, API keys |
| 🎯 **Patterns** | 40+ curated, severity-classified | Often hundreds of noisy rules |
| 🔒 **SARIF** | Native output → GitHub Security tab | Usually requires adapters |
| 📊 **Step Summary** | Built-in table in workflow run | Manual parsing |
| 🔐 **Redaction** | Automatic in logs | Often leaks the secret itself |
| 📁 **Languages** | 30+ file types, all major ecosystems | Often language-specific |
| 🚫 **Baseline** | Suppress known findings | Limited or absent |
| 🕵️ **Git history** | Optional deep scan of deleted files | Separate tool required |
| 💰 **Cost** | Free & open source | Free tier limits or paid |

---

## 🔍 Detection Patterns

### 🔴 Critical — Immediate credential exposure

| ID | Description | Example Pattern |
|:---|:------------|:----------------|
| `aws-access-key` | AWS Access Key ID | `AKIA...` |
| `aws-secret-key` | AWS Secret Access Key | `aws_secret_access_key = "..."` |
| `gcp-service-account` | GCP Service Account Key | `"type": "service_account"` |
| `azure-storage-key` | Azure Storage Account Key | `AccountKey=...` |
| `github-token` | GitHub PAT / Fine-grained Token | `ghp_...`, `github_pat_...` |
| `gitlab-token` | GitLab Personal Access Token | `glpat-...` |
| `slack-bot-token` | Slack Bot / User Token | `xoxb-...`, `xoxp-...` |
| `stripe-live-secret` | Stripe Live Secret Key | `sk_live_...` |
| `stripe-live-restricted` | Stripe Restricted Key | `rk_live_...` |
| `paypal-access-token` | PayPal Access Token | `access_token$production$...` |
| `square-access-token` | Square Access Token | `sq0atp-...` |
| `private-key-*` | RSA, EC, DSA, OpenSSH, PGP Keys | `-----BEGIN ... PRIVATE KEY-----` |

### 🟠 High — API keys & database credentials

| ID | Description | Example Pattern |
|:---|:------------|:----------------|
| `sendgrid-api-key` | SendGrid | `SG....` |
| `twilio-api-key` | Twilio | `SK` + 32 hex chars |
| `telegram-bot-token` | Telegram Bot | `123456789:ABC-...` |
| `firebase-api-key` | Firebase | `AIza...` |
| `jwt-token` | Hardcoded JWT | `eyJhbGci...` |
| `slack-webhook` | Slack Incoming Webhook | `hooks.slack.com/services/...` |
| `discord-webhook` | Discord Webhook | `discord.com/api/webhooks/...` |
| `supabase-service-role` | Supabase Service Role Key | JWT with specific prefix |
| `database-url` | Database Connection String | `postgres://user:pass@host` |
| `generic-password` | Hardcoded password assignments | `password = "..."` |
| `generic-api-key` | Hardcoded API key assignments | `api_key = "..."` |

### 🟡 Medium & 🔵 Low

| ID | Description |
|:---|:------------|
| `base64-secret` | Base64-encoded credential values |
| `hex-secret` | Long hex strings in secret context |
| `ip-with-port` | Hardcoded internal IP addresses with ports |
| `todo-secret` | TODO/FIXME comments referencing secrets |

---

## 🔧 Advanced Usage

### Upload results to GitHub Security tab

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  id: scan
  with:
    fail-on-findings: 'false'

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.scan.outputs.sarif-path }}
```

### Only report critical and high severity

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  with:
    severity: 'high'
    fail-on-findings: 'true'
```

### Scan with custom exclusions

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  with:
    exclude-paths: '.git,node_modules,vendor,dist,coverage,*.test.js,*.spec.ts,__mocks__'
    max-file-size: '256'
```

### Deep scan including git history

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  with:
    scan-history: 'true'
    severity: 'critical'
```

### Use outputs in subsequent steps

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  id: scan
  with:
    fail-on-findings: 'false'

- name: Notify on critical
  if: steps.scan.outputs.critical-count > 0
  run: |
    echo "🔴 ${{ steps.scan.outputs.critical-count }} critical secrets found!"
    echo "📄 Full report: ${{ steps.scan.outputs.report-path }}"
```

### Suppress known findings with baseline

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  with:
    baseline-file: '.cascavel-baseline'
```

---

## ⚙️ Inputs

| Input | Description | Required | Default |
|:------|:------------|:--------:|:--------|
| `path` | Root path to scan | No | `.` |
| `severity` | Minimum severity: `low` / `medium` / `high` / `critical` | No | `medium` |
| `fail-on-findings` | Block pipeline if secrets are found | No | `true` |
| `exclude-paths` | Comma-separated glob patterns to exclude | No | `.git,node_modules,...` |
| `sarif-output` | Generate SARIF report for Security tab | No | `true` |
| `max-file-size` | Skip files larger than N KB | No | `512` |
| `scan-history` | Scan git history for deleted secrets | No | `false` |
| `baseline-file` | Path to baseline suppression file | No | _(none)_ |
| `custom-patterns` | Path to custom patterns JSON file | No | _(none)_ |

## 📤 Outputs

| Output | Description | Example |
|:-------|:------------|:--------|
| `findings-count` | Total number of secrets detected | `3` |
| `critical-count` | Critical severity findings | `1` |
| `high-count` | High severity findings | `2` |
| `sarif-path` | Path to SARIF report | `.cascavel/results.sarif` |
| `report-path` | Path to JSON report | `.cascavel/findings.json` |

---

## 📊 Example Output

```
  ╔══════════════════════════════════════════════════╗
  ║  🐍 CASCAVEL SECRET SCANNER v1.0.0             ║
  ║  Enterprise Security · RET Tecnologia            ║
  ║  https://rettecnologia.org                       ║
  ╚══════════════════════════════════════════════════╝

  📂 Target:    .
  🎯 Threshold: medium
  🚫 Excludes:  14 patterns
  📏 Max size:  512KB

  ────────────────────────────────────────────────────

  🔴 [CRITICAL] AWS Access Key ID (CWE-798)
     Found in 1 location(s):
     └─ src/config.py:42  aws_key = "***REDACTED***"

  🟠 [HIGH] Slack Incoming Webhook (CWE-798)
     Found in 2 location(s):
     └─ deploy/notify.sh:8  ***REDACTED***
     └─ .env.example:15     ***REDACTED***

  ────────────────────────────────────────────────────

  📊 SCAN RESULTS
  ────────────────────────────────────────────────────
  🔴 Critical:  1
  🟠 High:      2
  🟡 Medium:    0
  🔵 Low:       0
  ────────────────────────────────────────────────────
  📋 Total:     3 finding(s)

  ❌ Pipeline blocked: 3 secret(s) detected

  🐍 Cascavel Secret Scanner by RET Tecnologia
```

**GitHub Step Summary** is also generated automatically:

| Severity | Count |
|:---------|------:|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |
| 🔵 Low | 0 |
| **Total** | **3** |

---

## 📁 Scanned File Types

<details>
<summary>30+ languages and config formats (click to expand)</summary>

**Languages:** `.py` `.js` `.ts` `.jsx` `.tsx` `.go` `.rs` `.java` `.rb` `.php` `.cs` `.c` `.cpp` `.h` `.kt` `.swift` `.r` `.R` `.jl` `.ex` `.exs` `.sh` `.bash` `.zsh` `.fish`

**Config:** `.yml` `.yaml` `.json` `.xml` `.toml` `.cfg` `.conf` `.ini` `.properties` `.env` `.env.*` `.tf` `.hcl` `Dockerfile`

**Other:** `.md` `.txt` `.html` `.css` `.sql` `.gradle`

</details>

---

## 🔗 Cascavel Security Suite

| Action | Description | Status |
|:-------|:------------|:------:|
| [🐍 Secret Scanner](https://github.com/marketplace/actions/cascavel-secret-scanner) | Detect hardcoded credentials | ✅ Live |
| [🛡️ Header Guard](https://github.com/marketplace/actions/cascavel-header-guard) | HTTP security headers analysis | ✅ Live |
| [📦 Dependency Audit](https://github.com/marketplace/actions/cascavel-dependency-audit) | CVE scanning for dependencies | ✅ Live |

### Full security pipeline example

```yaml
name: Cascavel Security Suite
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: 🐍 Scan for secrets
        uses: glferreira-devsecops/cascavel-secret-scanner@v1

      - name: 📦 Audit dependencies
        uses: glferreira-devsecops/cascavel-dependency-audit@v1

      - name: 🛡️ Check security headers
        uses: glferreira-devsecops/cascavel-header-guard@v1
        with:
          urls: 'https://staging.your-app.com'
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

**Adding a new detection pattern:**
1. Edit `scanner.sh`
2. Add to the `PATTERNS` array: `"id|severity|Description|REGEX|CWE-XXX"`
3. Test against known samples
4. Submit a PR

## 📄 License

[MIT](LICENSE) — free for personal and commercial use.

## 🔐 Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) or email contato@rettecnologia.org.

---

<p align="center">
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET%20Tecnologia-Software%20Engineering%20%C2%B7%20Cybersecurity-0D1117?style=for-the-badge&labelColor=FF6B00" /></a>
</p>

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/glferreira-devsecops">Gabriel Ferreira</a> at <a href="https://rettecnologia.org">RET Tecnologia</a> · Brazil 🇧🇷</sub>
</p>
