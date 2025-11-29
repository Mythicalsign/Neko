# 🐱 Neko - Advanced Bug Bounty Automation Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/bash-5.0+-orange.svg" alt="Bash">
</p>

<p align="center">
  <b>Enterprise-grade reconnaissance and vulnerability scanning for bug bounty hunters</b>
</p>

---

## 🌟 Overview

**Neko** is a sophisticated, modular bug bounty automation framework designed for professional security researchers. Built with enterprise-grade performance in mind, it orchestrates over 100+ security tools across 16 comprehensive phases to provide thorough reconnaissance and vulnerability assessment.

### Key Features

- 🔄 **16 Comprehensive Phases** - From OSINT to vulnerability exploitation
- ⚡ **Enterprise Performance** - Per-tool rate limiting and resource management
- 🛡️ **DOS Prevention** - Intelligent process management to avoid service disruption
- 📊 **Rich Reporting** - HTML, Markdown, and JSON reports with executive summaries
- 🔔 **Real-time Notifications** - Slack, Discord, Telegram integration
- 🎯 **Multiple Scan Modes** - Recon, Full, Passive, Fast, Deep, Custom
- 🧩 **Modular Architecture** - Enable/disable phases and tools as needed
- 🔧 **Highly Configurable** - Extensive configuration options

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Scan Modes](#-scan-modes)
- [Phases Overview](#-phases-overview)
- [Configuration](#-configuration)
- [Rate Limiting](#-rate-limiting)
- [Module Management](#-module-management)
- [Reports](#-reports)
- [Notifications](#-notifications)
- [Tools Reference](#-tools-reference)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Installation

### Prerequisites

- Linux or macOS
- Bash 5.0+
- Go 1.19+
- Python 3.8+
- Root access (for some scanning tools)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/your-repo/neko.git
cd neko

# Run the installer
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y git curl wget jq python3 python3-pip nmap masscan

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ... (see install.sh for full list)

# Install Python tools
pip3 install wafw00f arjun sqlmap ghauri

# Setup Neko
chmod +x neko.sh
sudo ln -s $(pwd)/neko.sh /usr/local/bin/neko
```

### Verify Installation

```bash
./neko.sh --check-tools
```

---

## 🎯 Quick Start

### Basic Scan

```bash
# Full reconnaissance (non-intrusive)
./neko.sh -d example.com

# Fast scan for quick results
./neko.sh -d example.com -f

# Scan with custom output directory
./neko.sh -d example.com -o /path/to/output
```

### Multi-Target Scan

```bash
# Create targets file
echo "example.com" > targets.txt
echo "test.com" >> targets.txt

# Scan all targets
./neko.sh -l targets.txt
```

### Resume Previous Scan

```bash
./neko.sh -d example.com --resume -o previous_output_dir
```

---

## 🔧 Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Recon** | `-r, --recon` | Full reconnaissance (non-intrusive) - **Default** |
| **Full** | `-a, --all` | Complete scan including intrusive attacks |
| **Passive** | `-p, --passive` | OSINT and passive enumeration only |
| **Subs** | `-s, --subs` | Subdomain enumeration only |
| **Web** | `-w, --web` | Web vulnerability scanning only |
| **Fast** | `-f, --fast` | Quick essential checks |
| **Deep** | `--deep` | Extensive scanning (slow) |
| **Custom** | `--custom` | Run specific modules |

### Examples

```bash
# Deep scan with all attacks
./neko.sh -d example.com -a --deep

# Run only specific modules
./neko.sh -d example.com --custom "osint,subdomain,dns"

# Passive OSINT only
./neko.sh -d example.com -p
```

---

## 📊 Phases Overview

### Phase 0: OSINT & Intelligence Gathering
Gather intelligence before active scanning.

| Tool | Purpose | Priority |
|------|---------|----------|
| whois | Domain registration info | High |
| theHarvester | Email/subdomain harvesting | High |
| github-subdomains | GitHub subdomain leaks | High |
| gitlab-subdomains | GitLab subdomain leaks | Medium |
| trufflehog | Secrets in repos | High |
| gitleaks | Git leak detection | High |
| porch-pirate | Postman API leaks | Medium |
| SwaggerSpy | Swagger/OpenAPI leaks | Medium |
| dorks_hunter | Google dorks automation | Medium |
| Spoofy | SPF/DMARC misconfig | Low |

### Phase 1: Subdomain Discovery
Comprehensive subdomain enumeration.

| Category | Tools |
|----------|-------|
| Passive | subfinder, assetfinder, chaos |
| Active | amass, dnsx |
| Certificate | crt, tlsx |
| Bruteforce | puredns, massdns |
| Permutation | gotator, ripgen, regulator |
| Recursive | dsieve |

### Phase 2: DNS Analysis & Enumeration
Deep DNS analysis and record enumeration.

| Tool | Purpose |
|------|---------|
| dnsx | Fast DNS resolution/records |
| dnsrecon | Zone transfers, DNS records |
| massdns | Bulk DNS resolution |
| dig | Zone transfer checks |
| hakip2host | Reverse IP lookup |

### Phase 3: Web Probing & Detection
Identify live web services.

| Tool | Purpose |
|------|---------|
| httpx | HTTP probing with tech detection |
| httprobe | Fast HTTP/HTTPS probing |
| cdncheck | Identify CDN-protected hosts |
| wafw00f | WAF detection |

### Phase 4: Port Scanning & Service Detection
Discover open ports and services.

| Tool | Purpose |
|------|---------|
| masscan | Fast port discovery |
| nmap | Deep service analysis |
| naabu | Fast port scanner |
| smap | Passive port scan (Shodan) |

### Phase 5: Content Discovery & Fuzzing
Discover hidden content and directories.

| Tool | Purpose |
|------|---------|
| ffuf | Primary fuzzing tool |
| feroxbuster | Recursive discovery |
| gobuster | Directory/file bruteforce |
| dirsearch | Quick directory scanning |

### Phase 6: Technology Fingerprinting
Identify technologies and CMS.

| Tool | Purpose |
|------|---------|
| whatweb | Tech fingerprinting |
| nikto | Web vulnerability scanner |
| wpscan | WordPress specific |
| CMSeeK | Multi-CMS detection |

### Phase 7: URL & JavaScript Analysis
Extract endpoints and secrets from JS.

| Tool | Purpose |
|------|---------|
| katana | Web crawler/URL extraction |
| waybackurls | Historical URLs |
| gau | URLs from multiple sources |
| subjs | JS file extraction |
| jsluice | JS secret extraction |
| xnLinkFinder | Link/endpoint extraction |
| trufflehog | Secret detection in JS |

### Phase 8: Parameter Discovery
Find hidden parameters for injection testing.

| Tool | Purpose |
|------|---------|
| arjun | Hidden parameter discovery |
| paramspider | Parameter mining |
| gf | Pattern-based filtering |
| qsreplace | Query string manipulation |
| urless | URL deduplication |

### Phase 9: Vulnerability Scanning
Comprehensive vulnerability assessment.

| Category | Tools |
|----------|-------|
| Template-based | nuclei |
| SQLi | sqlmap, ghauri |
| Command Injection | commix |
| SSTI | tplmap, nuclei |
| SSRF | ssrfmap, nuclei |
| CRLF | crlfuzz |
| CORS | Corsy, nuclei |
| Open Redirect | Oralyzer, nuclei |

### Phase 10: XSS Detection
Cross-site scripting testing.

| Tool | Purpose |
|------|---------|
| dalfox | Primary XSS scanner |
| XSStrike | Manual/DOM XSS |
| Gxss | Parameter reflection check |
| kxss | Quick XSS check |

### Phase 11: Subdomain Takeover
Detect takeover vulnerabilities.

| Tool | Purpose |
|------|---------|
| nuclei | Takeover templates |
| dnsreaper | Cloud-focused |
| dnstake | CNAME takeover |
| subjack | Classic checker |

### Phase 12: Cloud Security
Cloud-specific vulnerabilities.

| Tool | Purpose |
|------|---------|
| S3Scanner | S3 bucket misconfig |
| CloudHunter | Multi-cloud bucket check |
| cloud_enum | Cloud service enumeration |

### Phase 13: Authentication Testing
Auth-specific vulnerabilities.

| Tool | Purpose |
|------|---------|
| brutespray | Service brute-force |
| hydra | Protocol brute-force |
| jwt_tool | JWT analysis/attack |

### Phase 14: API Security
Modern API-focused testing.

| Tool | Purpose |
|------|---------|
| nuclei | API templates |
| kiterunner | API endpoint discovery |
| wfuzz | API fuzzing |

### Phase 15: Report Generation
Generate comprehensive reports.

| Format | Description |
|--------|-------------|
| HTML | Interactive visual report |
| Markdown | Documentation-friendly |
| JSON | Machine-readable export |
| Executive Summary | High-level overview |

---

## ⚙️ Configuration

Configuration is managed through `neko.cfg`. Key sections include:

### API Keys

```bash
# GitHub/GitLab tokens
GITHUB_TOKEN="your_token"
GITLAB_TOKEN="your_token"

# Shodan API
SHODAN_API_KEY="your_key"

# Other APIs
CENSYS_API_ID="your_id"
CENSYS_API_SECRET="your_secret"
VIRUSTOTAL_API_KEY="your_key"
```

### Phase Toggles

```bash
# Enable/disable phases
OSINT_ENABLED=true
SUBDOMAIN_ENABLED=true
DNS_ENABLED=true
WEBPROBE_ENABLED=true
PORTSCAN_ENABLED=true
CONTENT_ENABLED=true
FINGERPRINT_ENABLED=true
URLANALYSIS_ENABLED=true
PARAM_ENABLED=true
VULNSCAN_ENABLED=true
XSS_ENABLED=true
TAKEOVER_ENABLED=true
CLOUD_ENABLED=true
AUTH_ENABLED=false  # Disabled by default (intrusive)
API_ENABLED=true
REPORT_ENABLED=true
```

### Threading

```bash
# Per-tool thread configuration
SUBFINDER_THREADS=100
HTTPX_THREADS=50
NUCLEI_THREADS=25
FFUF_THREADS=50
MASSCAN_THREADS=1000
```

---

## ⏱️ Rate Limiting

Neko implements per-tool rate limiting to prevent DOS and respect target infrastructure:

```bash
# Rate limits (requests per second, 0 = unlimited)
HTTPX_RATELIMIT=150
NUCLEI_RATELIMIT=150
FFUF_RATELIMIT=100
MASSCAN_RATE=1000
SQLMAP_RATELIMIT=10
```

### Resource Management

```bash
# Maximum concurrent operations
MAX_NETWORK_PROCS=5
MAX_CPU_PROCS=4
MAX_IO_PROCS=3
```

---

## 🧩 Module Management

### Running Specific Modules

```bash
# Run single module
./neko.sh -d example.com --custom "subdomain"

# Run multiple modules
./neko.sh -d example.com --custom "osint,subdomain,dns,webprobe"
```

### Available Modules

| Module | Alias | Description |
|--------|-------|-------------|
| osint | - | OSINT & Intelligence |
| subdomain | subs | Subdomain Discovery |
| dns | - | DNS Analysis |
| webprobe | probe | Web Probing |
| portscan | ports | Port Scanning |
| content | fuzz | Content Discovery |
| fingerprint | tech | Technology Detection |
| urlanalysis | urls | URL/JS Analysis |
| param | params | Parameter Discovery |
| vulnscan | vuln | Vulnerability Scanning |
| xss | - | XSS Detection |
| takeover | - | Subdomain Takeover |
| cloud | - | Cloud Security |
| auth | - | Auth Testing |
| api | - | API Security |
| report | - | Report Generation |

### Force Re-run

```bash
# Force re-run completed modules
./neko.sh -d example.com --force
```

---

## 📝 Reports

### Generated Reports

After a scan completes, find reports in `output/<domain>/reports/`:

- `neko_report.html` - Interactive HTML report
- `neko_report.md` - Markdown documentation
- `neko_report.json` - Machine-readable JSON
- `executive_summary.txt` - High-level summary

### Report Features

- **Vulnerability counts** by severity
- **Risk assessment** score
- **Attack surface** metrics
- **Actionable recommendations**
- **POC URLs** for verified vulnerabilities

---

## 🔔 Notifications

### Supported Platforms

```bash
# Enable notifications
NOTIFICATION_ENABLED=true

# Slack
SLACK_WEBHOOK="https://hooks.slack.com/..."

# Discord
DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

# Telegram
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

# ProjectDiscovery Notify
NOTIFY_CONFIG="~/.config/notify/provider-config.yaml"
```

### Notification Events

- Scan started/completed
- Critical vulnerabilities found
- XSS confirmed
- Subdomain takeover detected

---

## 🛠️ Tools Reference

### Essential Tools (Required)

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dnsx | DNS toolkit | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| nmap | Port scanning | `apt install nmap` |
| ffuf | Web fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |

### Recommended Tools

| Tool | Purpose | Install |
|------|---------|---------|
| dalfox | XSS scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| katana | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| puredns | DNS resolver | `go install github.com/d3mondev/puredns/v2@latest` |
| masscan | Fast port scan | `apt install masscan` |
| sqlmap | SQL injection | `pip install sqlmap` |

---

## 📁 Directory Structure

```
neko/
├── neko.sh                 # Main orchestration script
├── neko.cfg                # Configuration file
├── install.sh              # Installer script
├── README.md               # Documentation
├── modules/
│   ├── 00_osint.sh        # OSINT module
│   ├── 01_subdomain.sh    # Subdomain discovery
│   ├── 02_dns.sh          # DNS analysis
│   ├── 03_webprobe.sh     # Web probing
│   ├── 04_portscan.sh     # Port scanning
│   ├── 05_content.sh      # Content discovery
│   ├── 06_fingerprint.sh  # Tech fingerprinting
│   ├── 07_urlanalysis.sh  # URL/JS analysis
│   ├── 08_params.sh       # Parameter discovery
│   ├── 09_vulnscan.sh     # Vulnerability scanning
│   ├── 10_xss.sh          # XSS detection
│   ├── 11_takeover.sh     # Subdomain takeover
│   └── 15_report.sh       # Report generation
├── lib/
│   └── core.sh            # Core library functions
├── wordlists/             # Custom wordlists
├── templates/             # Report templates
├── config/                # Additional configs
└── output/                # Scan results
```

---

## 🔒 Security Considerations

### Responsible Usage

- **Always get authorization** before scanning
- Use appropriate rate limiting
- Respect robots.txt and scope
- Report vulnerabilities responsibly

### Safe Defaults

- Auth testing disabled by default
- Conservative rate limits
- CDN detection to avoid scanning protected hosts
- WAF detection for bypass awareness

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Development Guidelines

- Follow Bash best practices
- Add error handling
- Update documentation
- Test across platforms

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for amazing tools
- [reconftw](https://github.com/six2dez/reconftw) for inspiration
- The bug bounty community for continuous innovation

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any target. The authors are not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  <b>Happy Hunting! 🎯</b>
</p>
