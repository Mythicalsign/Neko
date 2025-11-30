# Neko - Advanced Bug Bounty Automation Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/bash-5.0+-orange.svg" alt="Bash">
</p>

<p align="center">
  <b>Enterprise-grade reconnaissance and vulnerability scanning for bug bounty hunters</b>
</p>

---

## Overview

**Neko** is a sophisticated, modular bug bounty automation framework designed for professional security researchers. Built with enterprise-grade performance in mind, it orchestrates over 100+ security tools across 17 comprehensive phases to provide thorough reconnaissance and vulnerability assessment.

### What's New in v2.0

- **GNU Parallel Processing Engine** - Massive performance improvements with intelligent job distribution
- **Async Pipeline Architecture** - Advanced job queuing with dependency management
- **Cross-Phase Intelligence** - Vulnerability correlation and attack chain detection
- **Automatic Proxy/Tor Rotation** - Evade rate limiting and blocks automatically
- **Plugin Architecture** - Extensible system for custom modules
- **Advanced Error Handling** - Circuit breakers, exponential backoff, and fallback mechanisms
- **9 New Advanced Vulnerability Tests** - Blind XSS, Prototype Pollution, HTTP Smuggling, Race Conditions, and more

### Key Features

- **17 Comprehensive Phases** - From OSINT to advanced exploitation
- **GNU Parallel Integration** - Distributed scanning across multiple cores/machines
- **Intelligent Proxy Rotation** - Automatic Tor/proxy rotation with health monitoring
- **Enterprise Performance** - Per-tool rate limiting and resource management
- **DOS Prevention** - Circuit breakers and intelligent process management
- **Cross-Phase Intelligence** - Automated vulnerability correlation and attack chain detection
- **Plugin System** - Extensible architecture for custom modules
- **Rich Reporting** - HTML, Markdown, JSON, and intelligence reports
- **Real-time Notifications** - Slack, Discord, Telegram integration
- **Multiple Scan Modes** - Recon, Full, Passive, Fast, Deep, Custom

---

## Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Scan Modes](#-scan-modes)
- [Phases Overview](#-phases-overview)
- [Advanced Features v2.0](#-advanced-features-v20)
- [Configuration](#-configuration)
- [Plugin System](#-plugin-system)
- [Reports](#-reports)
- [Tools Reference](#-tools-reference)
- [Contributing](#-contributing)

---

## Installation

### Prerequisites

- Linux or macOS
- Bash 5.0+
- Go 1.19+
- Python 3.8+
- Root access (for some scanning tools)
- GNU Parallel (for parallel processing)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/your-repo/neko.git
cd neko

# Run the installer
chmod +x install.sh
./install.sh
```

### Install GNU Parallel (Required for v2.0 features)

```bash
# Ubuntu/Debian
sudo apt-get install parallel

# macOS
brew install parallel

# CentOS/RHEL
sudo yum install parallel
```

### Verify Installation

```bash
./neko.sh --check-tools
```

---

## Quick Start

### Basic Scan

```bash
# Full reconnaissance (non-intrusive)
./neko.sh -d example.com

# Fast scan for quick results
./neko.sh -d example.com -f

# Full scan including intrusive attacks
./neko.sh -d example.com -a
```

### Advanced Usage

```bash
# Deep scan with parallel processing
./neko.sh -d example.com -a --deep

# Scan with proxy rotation
./neko.sh -d example.com -a --proxy-rotate

# Scan with Tor
./neko.sh -d example.com -a --tor

# Run only advanced vulnerability testing
./neko.sh -d example.com --custom "advanced_vulns"
```

---

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Recon** | `-r, --recon` | Full reconnaissance (non-intrusive) - **Default** |
| **Full** | `-a, --all` | Complete scan including intrusive attacks + advanced vulns |
| **Passive** | `-p, --passive` | OSINT and passive enumeration only |
| **Subs** | `-s, --subs` | Subdomain enumeration only |
| **Web** | `-w, --web` | Web vulnerability scanning only |
| **Fast** | `-f, --fast` | Quick essential checks |
| **Deep** | `--deep` | Extensive scanning (slow) |
| **Custom** | `--custom` | Run specific modules |

---

## Phases Overview

### Phase 0-15: Core Phases

| Phase | Name | Description |
|-------|------|-------------|
| 0 | OSINT | Intelligence gathering, GitHub leaks, dorks |
| 1 | Subdomain | Comprehensive subdomain enumeration |
| 2 | DNS | DNS analysis and zone enumeration |
| 3 | Web Probe | HTTP probing, WAF/CDN detection |
| 4 | Port Scan | Port scanning and service detection |
| 5 | Content | Directory/file fuzzing |
| 6 | Fingerprint | Technology fingerprinting |
| 7 | URL Analysis | URL discovery and JS analysis |
| 8 | Parameters | Hidden parameter discovery |
| 9 | Vuln Scan | Vulnerability scanning (nuclei, sqli, etc.) |
| 10 | XSS | XSS detection and exploitation |
| 11 | Takeover | Subdomain takeover detection |
| 12 | Cloud | Cloud security testing |
| 13 | Auth | Authentication testing |
| 14 | API | API security testing |
| 15 | Report | Report generation |

### Phase 16: Advanced Vulnerability Testing (NEW in v2.0)

| Module | Description |
|--------|-------------|
| **Blind XSS Hunter** | OOB XSS with callback server integration |
| **Prototype Pollution** | DOM and server-side prototype pollution |
| **Web Cache Deception** | Cache poisoning and deception attacks |
| **HTTP Desync** | Request smuggling (CL.TE, TE.CL) |
| **Race Conditions** | TOCTOU and race condition testing |
| **GraphQL Deep Scan** | Introspection, batching, injection |
| **WebSocket Testing** | CSWSH and WebSocket vulnerabilities |
| **OAuth/OIDC Testing** | OAuth flow and OIDC security testing |

---

## Advanced Features v2.0

### GNU Parallel Processing Engine

Dramatically improve scan performance with intelligent parallel processing:

```bash
# Configure in neko.cfg
PARALLEL_ENABLED=true
PARALLEL_JOBS=0            # Auto-detect CPU cores
PARALLEL_LOAD=80           # Max CPU load %
PARALLEL_MEMFREE="1G"      # Minimum free memory
PARALLEL_RETRIES=3         # Retry failed jobs
```

Features:
- Automatic CPU core detection
- Memory-aware job scheduling
- Distributed scanning across multiple machines
- Job retry with exponential backoff
- Real-time progress monitoring

### Async Pipeline Architecture

Advanced job queuing with dependency management:

```bash
# Enable in neko.cfg
PIPELINE_ENABLED=true
PIPELINE_MAX_CONCURRENT=5
PIPELINE_TIMEOUT=7200
```

Features:
- Dependency-based job scheduling
- Priority queue management
- Async callback handling
- Pipeline state persistence
- Job completion notifications

### Cross-Phase Intelligence

Automated vulnerability correlation and attack chain detection:

```bash
# Enable in neko.cfg
INTELLIGENCE_ENABLED=true
INTEL_AUTO_CORRELATE=true
INTEL_ATTACK_CHAINS=true
INTEL_PATTERN_RECOGNITION=true
```

Features:
- SQLite-backed intelligence database
- Cross-phase vulnerability correlation
- Attack chain identification (SSRF→RCE, XSS→ATO, etc.)
- Pattern recognition for common vulnerabilities
- High-value target identification
- Intelligence-based prioritization

### Automatic Proxy/Tor Rotation

Evade rate limiting and blocks automatically:

```bash
# Enable in neko.cfg
PROXY_ROTATION_ENABLED=true
PROXY_ROTATION_INTERVAL=300  # Rotate every 5 minutes
PROXY_LIST_FILE="/path/to/proxies.txt"

# Tor integration
TOR_ENABLED=true
TOR_SOCKS_PORT=9050
```

Features:
- Automatic proxy health monitoring
- Smart rotation on failure
- Tor circuit rotation
- Proxy list auto-update
- Per-request or timed rotation

### Advanced Error Handling

Robust error handling with circuit breakers:

```bash
# Configure in neko.cfg
MAX_RETRIES=3
RETRY_INITIAL_DELAY=1
RETRY_MAX_DELAY=60
CIRCUIT_BREAKER_THRESHOLD=10
```

Features:
- Exponential backoff retry
- Circuit breaker pattern
- Automatic tool fallbacks (subfinder → assetfinder)
- Error rate monitoring
- Automatic recovery mechanisms

---

## Plugin System

Neko v2.0 introduces an extensible plugin architecture:

### Creating a Plugin

```bash
# Create plugin template
./neko.sh --plugin-create my_custom_scanner
```

### Plugin Structure

```bash
#!/usr/bin/env bash

# Metadata function
my_custom_scanner_metadata() {
    cat << 'EOF'
{
    "name": "my_custom_scanner",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Custom vulnerability scanner"
}
EOF
}

# Initialize plugin
my_custom_scanner_init() {
    plugin_register_hook "$HOOK_POST_PHASE" "my_custom_scanner_run" 50
}

# Main function
my_custom_scanner_run() {
    log_info "Running custom scanner..."
    # Your scanning logic here
}
```

### Installing Plugins

```bash
# Install from URL
./neko.sh --plugin-install https://example.com/plugin.sh

# Install from file
./neko.sh --plugin-install /path/to/plugin.sh

# List plugins
./neko.sh --plugin-list

# Enable/disable plugins
./neko.sh --plugin-enable my_plugin
./neko.sh --plugin-disable my_plugin
```

### Available Hooks

| Hook | Description |
|------|-------------|
| `pre_scan` | Before scan starts |
| `post_scan` | After scan completes |
| `pre_phase` | Before each phase |
| `post_phase` | After each phase |
| `on_finding` | When vulnerability found |
| `on_error` | On error occurrence |

---

## Configuration

### Essential Configuration

```bash
# API Keys
GITHUB_TOKEN="your_token"
SHODAN_API_KEY="your_key"
CENSYS_API_ID="your_id"
CENSYS_API_SECRET="your_secret"

# OOB Detection
XSS_HUNTER_URL="https://your.xss.ht"
INTERACTSH_SERVER="oast.pro"
```

### Performance Tuning

```bash
# Parallel Processing
PARALLEL_JOBS=8
PARALLEL_LOAD=80

# Rate Limiting
HTTPX_RATELIMIT=150
NUCLEI_RATELIMIT=150
FFUF_RATELIMIT=100

# Threading
HTTPX_THREADS=50
NUCLEI_THREADS=25
```

### Advanced Vulnerability Testing

```bash
# Enable specific tests
BLIND_XSS_ENABLED=true
PROTOTYPE_POLLUTION_ENABLED=true
CACHE_DECEPTION_ENABLED=true
HTTP_DESYNC_ENABLED=true
RACE_CONDITION_ENABLED=true
GRAPHQL_DEEP_ENABLED=true
WEBSOCKET_ENABLED=true
OAUTH_OIDC_ENABLED=true
```

---

## Reports

### Generated Reports

After a scan completes, find reports in `output/<domain>/reports/`:

- `neko_report.html` - Interactive HTML report
- `neko_report.md` - Markdown documentation
- `neko_report.json` - Machine-readable JSON
- `executive_summary.txt` - High-level summary
- `intelligence_report.md` - Cross-phase intelligence analysis
- `intelligence.json` - Correlation data export

### Intelligence Report Features

- Vulnerability correlation matrix
- Attack chain identification
- High-value target ranking
- Severity distribution
- Actionable recommendations

---

## Directory Structure

```
neko/
├── neko.sh                 # Main orchestration script
├── neko.cfg                # Configuration file
├── install.sh              # Installer script
├── README.md               # Documentation
├── modules/
│   ├── 00_osint.sh        # OSINT module
│   ├── 01_subdomain.sh    # Subdomain discovery
│   ├── ...
│   ├── 15_report.sh       # Report generation
│   └── 16_advanced_vulns.sh # Advanced vulnerability testing (NEW)
├── lib/
│   ├── core.sh            # Core library functions
│   ├── parallel.sh        # GNU Parallel processing (NEW)
│   ├── async_pipeline.sh  # Async pipeline architecture (NEW)
│   ├── intelligence.sh    # Cross-phase intelligence (NEW)
│   ├── proxy_rotation.sh  # Proxy/Tor rotation (NEW)
│   ├── error_handling.sh  # Advanced error handling (NEW)
│   └── plugin.sh          # Plugin architecture (NEW)
├── plugins/               # Plugin directory (NEW)
│   ├── custom/
│   ├── community/
│   └── integrations/
├── config/                # Additional configs
└── output/                # Scan results
```

---

## Security Considerations

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
- Circuit breakers prevent tool abuse

---

## Contributing

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
- Add plugin hooks where appropriate

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for amazing tools
- [reconftw](https://github.com/six2dez/reconftw) for inspiration
- The bug bounty community for continuous innovation

---

## Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any target. The authors are not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  <b>Happy Hunting!</b>
</p>
