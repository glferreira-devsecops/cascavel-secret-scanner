<p align="center">
  <img src="https://img.shields.io/badge/🐍_CASCAVEL-Secret_Scanner-FF6B00?style=for-the-badge&labelColor=1a1a2e" />
</p>

<h1 align="center">Cascavel Secret Scanner</h1>

<h3 align="center">Enterprise-grade secret detection for CI/CD pipelines</h3>

<p align="center">
  <a href="https://github.com/marketplace/actions/cascavel-secret-scanner"><img src="https://img.shields.io/badge/GitHub_Marketplace-Available-2ea44f?style=flat-square&logo=github" /></a>
  <img src="https://img.shields.io/badge/Patterns-40+-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/SARIF-Supported-blue?style=flat-square" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00D4FF?style=flat-square" /></a>
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET_Tecnologia-Open_Source-FF6B00?style=flat-square" /></a>
</p>

<p align="center">
  Find hardcoded API keys, tokens, passwords, and credentials in your codebase.<br />
  Zero configuration. 40+ detection patterns. SARIF output for GitHub Security tab.<br />
  <strong>One line to add. Enterprise security for every project.</strong>
</p>

---

## ⚡ Quick Start

Add to any workflow — no configuration required:

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
```

That's it. Your pipeline is now protected.

## 🎯 Features

| Feature | Description |
|:--------|:------------|
| **40+ Detection Patterns** | AWS, GCP, Azure, GitHub, Stripe, Slack, Firebase, and more |
| **Zero Configuration** | Works out of the box with sensible defaults |
| **SARIF Output** | Integrates with GitHub Security tab automatically |
| **Severity Filtering** | Set minimum threshold: `low`, `medium`, `high`, `critical` |
| **Secret Redaction** | Findings in logs are automatically redacted |
| **Git History Scan** | Optionally scan deleted files in commit history |
| **Baseline Support** | Suppress known findings with a baseline file |
| **Custom Patterns** | Add your own detection rules |
| **Multi-language** | Scans 30+ file types across all major languages |
| **GitHub Step Summary** | Beautiful summary table in workflow run |

## 📖 Usage

### Basic (blocks pipeline on findings)

```yaml
name: Security
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-secret-scanner@v1
```

### Advanced Configuration

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  with:
    severity: 'high'              # Only report high and critical
    fail-on-findings: 'true'      # Block the pipeline
    scan-history: 'true'          # Also check git history
    sarif-output: 'true'          # Generate SARIF report
    exclude-paths: '.git,node_modules,vendor,dist,*.test.js'
    max-file-size: '256'          # Skip files larger than 256KB
```

### Upload SARIF to GitHub Security Tab

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  id: scan
  with:
    fail-on-findings: 'false'     # Don't block — just report

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.scan.outputs.sarif-path }}
```

### Use Findings in Subsequent Steps

```yaml
- uses: glferreira-devsecops/cascavel-secret-scanner@v1
  id: scan
  with:
    fail-on-findings: 'false'

- name: Check results
  if: steps.scan.outputs.critical-count > 0
  run: |
    echo "🔴 ${{ steps.scan.outputs.critical-count }} critical secrets found!"
    echo "📄 Report: ${{ steps.scan.outputs.report-path }}"
    exit 1
```

## 🔍 Detection Patterns

### Critical Severity
| Pattern | Description | CWE |
|:--------|:------------|:----|
| AWS Access Key | `AKIA...` prefix detection | CWE-798 |
| AWS Secret Key | Secret access key in assignments | CWE-798 |
| GCP Service Account | Service account JSON key files | CWE-798 |
| Azure Storage Key | Storage account keys | CWE-798 |
| GitHub Token | `ghp_`, `gho_`, `ghs_` tokens | CWE-798 |
| Stripe Live Key | `sk_live_` secret keys | CWE-798 |
| Private Keys | RSA, EC, DSA, OpenSSH, PGP | CWE-321 |

### High Severity
| Pattern | Description | CWE |
|:--------|:------------|:----|
| SendGrid API Key | `SG.` prefix | CWE-798 |
| Twilio API Key | `SK` prefix (32 hex) | CWE-798 |
| Slack Webhook | `hooks.slack.com` URLs | CWE-798 |
| Discord Webhook | Discord API webhook URLs | CWE-798 |
| JWT Token | Hardcoded `eyJ...` tokens | CWE-798 |
| Database URL | Connection strings with credentials | CWE-798 |
| Generic Passwords | `password=`, `secret=` assignments | CWE-798 |

### Medium & Low Severity
| Pattern | Description | CWE |
|:--------|:------------|:----|
| Base64 Secrets | Base64-encoded credential values | CWE-798 |
| Hex Secrets | Long hex strings in secret assignments | CWE-798 |
| Private IPs | Hardcoded internal IP addresses | CWE-200 |
| TODO/FIXME Secrets | Comments referencing secrets | CWE-798 |

## ⚙️ Inputs

| Input | Description | Default |
|:------|:------------|:--------|
| `path` | Root path to scan | `.` |
| `severity` | Minimum severity: `low`, `medium`, `high`, `critical` | `medium` |
| `fail-on-findings` | Exit with error if secrets found | `true` |
| `exclude-paths` | Comma-separated exclude patterns | `.git,node_modules,...` |
| `sarif-output` | Generate SARIF report | `true` |
| `max-file-size` | Max file size in KB | `512` |
| `scan-history` | Scan git history for deleted secrets | `false` |
| `baseline-file` | Path to baseline suppression file | _(none)_ |
| `custom-patterns` | Path to custom patterns JSON | _(none)_ |

## 📤 Outputs

| Output | Description |
|:-------|:------------|
| `findings-count` | Total secrets found |
| `critical-count` | Critical severity count |
| `high-count` | High severity count |
| `sarif-path` | Path to SARIF report |
| `report-path` | Path to JSON report |

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
     └─ src/config.py:42  ***REDACTED***

  🟠 [HIGH] Slack Incoming Webhook (CWE-798)
     Found in 2 location(s):
     └─ deploy/notify.sh:8  https://hooks.slack.com/***REDACTED***
     └─ .env.example:15  ***REDACTED***

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

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🏢 About RET Tecnologia

**RET Tecnologia** provides software engineering, web development, and cybersecurity services.

- 🌐 [rettecnologia.org](https://rettecnologia.org)
- 🐙 [GitHub](https://github.com/Ret-Consultoria)
- 📧 contato@rettecnologia.org

---

<p align="center">
  <sub>🐍 Built with precision by <a href="https://github.com/glferreira-devsecops">@glferreira-devsecops</a> at <a href="https://rettecnologia.org">RET Tecnologia</a></sub>
</p>
