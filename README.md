<p align="center">
  <h1 align="center">🛡️ BrandSentra</h1>
  <p align="center">
    <strong>Digital Risk Protection & Brand Intelligence Suite</strong>
  </p>
  <p align="center">
    Enterprise-grade digital risk protection and brand impersonation detection: live Certificate Transparency monitoring, IDN-aware typosquat and look-alike detection, threat-intel enrichment, alert triage, and a fully client-side analyst console with the Lavender theme.
  </p>
  <p align="center">
    <a href="#-features"><img src="https://img.shields.io/badge/version-2.5.0-aa95f9?style=flat-square" alt="Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python"></a>
    <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-red?style=flat-square" alt="Security"></a>
  </p>
</p>

---

## ✨ Features

- **Shard selection**: CT tailers read all active Certificate Transparency shards where new certificates land.
- **Platform scoring**: Hosting platforms (`pages.dev`, `workers.dev`, `web.app`, etc.) scored once to avoid false-positive inflation.
- **Direct CT Tailing**: Tails RFC 6962 and Static CT API (tiled) logs directly using a built-in DER parser.
- **Deep Match**: Evaluates brand profiles across all logged domains, catching subtle homoglyphs and typos without requiring explicit keyword lists.
- **Custom Rules & Enrichment**: Custom regex detection rules, alert deduplication, and automated enrichment (DNS, RDAP age, threat intel).
- **Proactive Typosquat Watcher**: Permutations of protected brands are periodically generated and resolved over DNS-over-HTTPS.
- **Client-Side Analyst Console**: Fully-featured browser console with the BrandSentra Lavender theme, offline capabilities, and PWA support.
- **STIX 2.1 & SIEM Integration**: STIX 2.1 bundles, CSV/JSON exports, Syslog/CEF, Slack, Discord, and Microsoft Teams notifications.

---

## 🎯 Architecture & Capabilities

### Detection Engine
- **Domain parsing layer** — eTLD+1 extraction for global second-level registries and 90+ free-hosting/tunnelling platforms (`web.app`, `github.io`, `pages.dev`, `ngrok-free.app`, `duckdns.org`...).
- **Phishing detector** — weighted scoring for lure keywords, brand impersonation, TLD risk tiers, structure (deep subdomains, hyphen/digit padding, embedded tokens), Shannon entropy, IDN homoglyphs, and certificate context.
- **Squatting analyzer** — typosquats (omission, transposition, repetition, insertion, keyboard, vowel swap, bitsquat), homoglyphs, leetspeak, hyphenation, combo-squats, TLD swaps, and subdomain abuse.
- **Permutation generator** — generates thousands of technique-tagged look-alike domains per brand across configurable TLDs.

### Brand Protection
- **Built-in Brand Profiles** with aliases, industry, and priority ratings (e.g. NovaPay, Kestrel Mart, Halcyon Health, National Banking Corp, Key Finance House).
- **Custom profiles** configurable via `config.yaml` or through the console settings.
- **Noise control** — legitimate brand domains are allowlisted, deduplication windows prevent alert storms, and strongest match suppresses weaker cross-brand noise.
- **Full Alert Lifecycle** — manage alerts with `open → investigating → resolved / false_positive`, assignee assignment, notes, and historical logs.

### Threat Intelligence & Enrichment
- Out-of-the-box integration with OpenPhish, URLhaus, VirusTotal v3, Google Safe Browsing, PhishTank, and URLScan.io.
- Automatic RDAP registration queries, DNS lookups, and TLS certificate extraction.

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/ishanraj953/BrandSentry.git
cd BrandSentry
python -m venv venv && source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

cp config.yaml config.local.yaml
export BRANDSENTRA_ADMIN_PASSWORD='a-strong-password'
export BRANDSENTRA_API_SECRET='a-long-random-secret'
```

### Command Line

| Command | Purpose |
|---|---|
| `python main.py api` / `demo` | API server + console on <http://localhost:5000> (docs at `/api/v1/docs`) |
| `python main.py monitor` | Live Certificate Transparency monitoring |
| `python main.py scan <domain> [--json] [--intel] [--enrich]` | Analyze a specific domain |
| `python main.py bulk domains.txt [--csv out.csv]` | Analyze a batch list of domains |
| `python main.py permutations novapay.com --tlds com net org --resolve` | Generate and resolve squatting candidates |
| `python main.py watch-squats [--once]` | Proactive typosquat discovery sweep |
| `python main.py report [--days 7] [--json] [--out report.md]` | Generate activity report |
| `python main.py allowlist list | add | remove <domain>` | Manage allowlisted domains |
| `python main.py export-stix --out indicators.json` | Export STIX 2.1 intelligence bundle |
| `python main.py config [--check]` | Validate configuration and security settings |
| `python main.py test-notify` | Send a test notification across configured channels |

---

## 🔌 REST API

Base path `/api/v1`. Interactive Swagger UI documentation is available at `/api/v1/docs`.

| Endpoint | Method | Description |
|---|---|---|
| `/auth/login` · `/auth/me` | POST · GET | Authentication token issuance and validation |
| `/scan/domain` | POST | Full domain risk analysis with optional threat intel |
| `/scan/bulk` | POST | Bulk domain risk analysis |
| `/scans/history` | GET | List recent scan runs |
| `/brands` · `/brands/permutations` | GET · POST | Protected brand profiles and permutation generator |
| `/alerts` · `/alerts/<id>` | GET · PATCH | Alert search, triage, notes, and lifecycle management |
| `/alerts/export` | GET | Export alerts to CSV, JSON, or STIX 2.1 format |
| `/allowlist` · `/allowlist/<domain>` | GET/POST · DELETE | Allowlist management |
| `/intel/<domain>` | GET | Threat intelligence reputation lookup |
| `/enrich/<domain>` | GET | Live DNS, RDAP, and TLS certificate enrichment |
| `/squats/sightings` | GET | Proactive typosquat sightings and status |
| `/stats` | GET | Overall system telemetry and detection statistics |
| `/health` · `/metrics` | GET | Health checks and Prometheus metrics |

---

## 📁 Project Structure

```
BrandSentra/
├── main.py                          # CLI entry point (api, monitor, scan, bulk, watch-squats...)
├── config.yaml                      # Documented configuration file
├── src/
│   ├── core/
│   │   ├── constants.py             # Keyword taxonomies, TLD risk tiers
│   │   ├── phishing_detector.py     # Multi-layer domain risk scoring engine
│   │   ├── domain_analyzer.py       # Squatting techniques & permutation generator
│   │   ├── brand_monitor.py         # Brand profiles & alert generation
│   │   ├── squat_watcher.py         # Proactive permutation DNS resolver
│   │   ├── certstream_monitor.py    # Live CT stream monitor
│   │   ├── ct_tailer.py             # RFC 6962 / Tile CT log tailer
│   │   ├── threat_intel.py          # Threat intelligence feeds
│   │   ├── engine.py                # Pipeline orchestrator
│   │   ├── reports.py               # Markdown, CSV, Prometheus reports
│   │   └── stix_export.py           # STIX 2.1 threat intelligence exporter
│   ├── api/
│   │   ├── app.py                   # REST API factory & routes
│   │   ├── auth.py                  # JWT authentication & RBAC
│   │   ├── ratelimit.py             # Rate limiter
│   │   └── openapi.py               # OpenAPI 3 specification
│   ├── notifications/dispatcher.py  # Dispatcher for Slack, Teams, Email, Webhooks
│   ├── utils/
│   │   ├── domain.py                # Domain parsing, suffixes, IDN, confusables
│   │   ├── x509.py                  # Zero-dependency DER/X.509 certificate parser
│   │   └── network.py               # DNS, RDAP, TLS network enrichment
│   ├── models/database.py           # SQLite storage with migrations
│   └── config/settings.py           # Configuration schema and environment loader
├── index.html                       # Frontpage with 3D Globe & interactive tools
├── demo/                            # Analyst console (Lavender theme)
└── tests/                           # Comprehensive test suite (440+ tests)
```

---

## 🧪 Testing

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## 🔐 Security & Disclaimer

BrandSentra produces automated heuristic intelligence from public data. Flagged domains are candidates for security review. Always verify independently before initiating blocking or takedown procedures.

---

## 📄 License

MIT License.
