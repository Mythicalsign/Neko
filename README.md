# Neko - Advanced Bug Bounty Automation Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-2.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/bash-5.0+-orange.svg" alt="Bash">
</p>

<p align="center">
  <b>Enterprise-grade reconnaissance and vulnerability scanning for bug bounty hunters</b>
</p>

---

## Overview

**Neko** is a sophisticated, modular bug bounty automation framework designed for professional security researchers. Built with enterprise-grade performance in mind, it orchestrates over 100+ security tools across 18 comprehensive phases to provide thorough reconnaissance and vulnerability assessment.

### What's New in v2.1

- **Advanced Queue Management System** - Comprehensive DOS prevention with rate limiting and adaptive throttling
- **Enhanced Error Reporting** - Detailed JSON error reports with stack traces, recovery tracking, and recommendations
- **Data Flow Bus** - Inter-tool communication system for seamless data sharing between tools
- **Advanced Orchestrator** - Dependency-aware phase execution with intelligent scheduling
- **Bettercap Integration** - Full network security testing capabilities (Phase 17)
- **Tool Chaining** - Automatic input/output routing between tools
- **Improved Intelligence Correlation** - Better attack chain detection and vulnerability correlation

### Key Features

- **18 Comprehensive Phases** - From OSINT to advanced exploitation
- **GNU Parallel Integration** - Distributed scanning across multiple cores/machines
- **Queue Management System** - DOS prevention with token bucket rate limiting
- **Data Flow Bus** - Tools work in tandem, sharing results automatically
- **Intelligent Proxy Rotation** - Automatic Tor/proxy rotation with health monitoring
- **Enterprise Performance** - Per-tool rate limiting and resource management
- **Cross-Phase Intelligence** - Automated vulnerability correlation and attack chain detection
- **Bettercap Integration** - Network security testing, SSL analysis, credential detection
- **Plugin System** - Extensible architecture for custom modules
- **Rich Reporting** - HTML, Markdown, JSON, and intelligence reports
- **Real-time Notifications** - Slack, Discord, Telegram integration
- **Multiple Scan Modes** - Recon, Full, Passive, Fast, Deep, Custom

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [Phases Overview](#phases-overview)
- [v2.1 Advanced Features](#v21-advanced-features)
- [Queue Management System](#queue-management-system)
- [Error Reporting System](#error-reporting-system)
- [Data Flow Bus](#data-flow-bus)
- [Bettercap Integration](#bettercap-integration)
- [Configuration](#configuration)
- [Plugin System](#plugin-system)
- [Reports](#reports)
- [Tools Reference](#tools-reference)
- [Contributing](#contributing)

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

### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install parallel bettercap tcpdump

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
./neko.sh -d example.com --custom "advanced_vulns,bettercap"
```

---

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Recon** | `-r, --recon` | Full reconnaissance (non-intrusive) - **Default** |
| **Full** | `-a, --all` | Complete scan including intrusive attacks + advanced vulns + bettercap |
| **Passive** | `-p, --passive` | OSINT and passive enumeration only |
| **Subs** | `-s, --subs` | Subdomain enumeration only |
| **Web** | `-w, --web` | Web vulnerability scanning only |
| **Fast** | `-f, --fast` | Quick essential checks |
| **Deep** | `--deep` | Extensive scanning (slow) |
| **Custom** | `--custom` | Run specific modules |

---

## Phases Overview

### Phase 0-17: Core Phases

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
| 16 | Advanced Vulns | Blind XSS, Prototype Pollution, HTTP Desync, etc. |
| **17** | **Bettercap** | **Network security testing (NEW in v2.1)** |

---

## v2.1 Advanced Features

### Queue Management System (DOS Prevention)

The Queue Management System prevents accidental DOS attacks by controlling tool execution rates:

```bash
# Configure in neko.cfg
QUEUE_ENABLED=true
QUEUE_GLOBAL_RPS=200                    # Global requests per second limit
QUEUE_GLOBAL_BURST=500                  # Maximum burst capacity
QUEUE_ADAPTIVE_ENABLED=true             # Enable adaptive rate limiting
```

Features:
- **Token Bucket Rate Limiting** - Per-queue and global rate limits
- **Adaptive Throttling** - Automatically reduces rates under high CPU/memory
- **Priority Queues** - Critical tasks get executed first
- **Tool-Specific Limits** - Different limits for different tool categories
- **Burst Protection** - Prevents sudden request spikes

Queue Categories:
- `network_intensive` - Masscan, Nmap, Bettercap
- `cpu_intensive` - Nuclei, FFuf, Feroxbuster
- `io_intensive` - Subfinder, Amass
- `http_requests` - HTTPx, Katana, GAU
- `scanning` - SQLMap, Dalfox
- `exploitation` - Active exploitation tools

### Enhanced Error Reporting

Comprehensive JSON error reports with full context:

```bash
# Configure in neko.cfg
ERROR_REPORTING_ENABLED=true
ERROR_REPORT_JSON=true
ERROR_AUTO_RECOVERY=true
```

Features:
- **Detailed JSON Reports** - Every error captured with full context
- **Stack Traces** - Full stack traces for debugging
- **System State Capture** - CPU, memory, disk state at error time
- **Auto-Recovery** - Automatic retry with exponential backoff
- **Recovery Tracking** - Track which errors were recovered
- **Recommendations** - Automatic suggestions based on error patterns

Error Report Example:
```json
{
  "id": "err_1234567890",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "error",
  "category": "tool_error",
  "tool": "nuclei",
  "phase": "vulnscan",
  "message": "Tool execution failed",
  "exit_code": 1,
  "recovery": {
    "attempted": true,
    "successful": false
  },
  "system_state": {
    "cpu_load": "2.5",
    "memory_free": "4096MB"
  }
}
```

### Data Flow Bus (Inter-Tool Communication)

Tools automatically share data through the Data Flow Bus:

```bash
# Configure in neko.cfg
DATA_BUS_ENABLED=true
DATA_BUS_AUTO_FEED=true
```

Features:
- **Automatic Data Routing** - Outputs from one tool feed into related tools
- **Channel-Based Architecture** - Organized data channels (subdomains, hosts, URLs, etc.)
- **Pub/Sub Model** - Tools subscribe to data they need
- **Data Transformation** - Automatic format conversion between tools
- **Caching** - Fast access to frequently used data

Data Channels:
- `subdomain_discovery` - Discovered subdomains
- `resolved_hosts` - DNS resolved hosts
- `live_hosts` - HTTP probed live hosts
- `target_ips` - Target IP addresses
- `web_urls` - Discovered URLs
- `param_urls` - URLs with parameters
- `vulnerabilities` - Discovered vulnerabilities

### Advanced Orchestrator

Dependency-aware execution with intelligent scheduling:

```bash
# Configure in neko.cfg
ORCHESTRATOR_ENABLED=true
ORCHESTRATOR_STRICT_DEPS=true
```

Features:
- **Dependency Graph** - Phases execute in proper order
- **Topological Sorting** - Optimal execution order
- **Parallel Phase Execution** - Independent phases run concurrently
- **State Persistence** - Resume interrupted scans
- **Hook System** - Pre/post phase callbacks

---

## Queue Management System

### Configuration

```bash
# Global settings
QUEUE_GLOBAL_RPS=200                    # Max requests per second globally
QUEUE_GLOBAL_BURST=500                  # Burst capacity

# Per-queue settings (max_concurrent:rate_per_sec:burst:cooldown_ms:priorities)
QUEUE_NETWORK_INTENSIVE="3:10:20:100:5"
QUEUE_CPU_INTENSIVE="4:0:0:0:3"
QUEUE_SCANNING="2:5:10:200:5"

# Adaptive limiting
QUEUE_ADAPTIVE_ENABLED=true
QUEUE_CPU_THRESHOLD=90                  # Reduce rate if CPU > 90%
QUEUE_MEMORY_THRESHOLD=90               # Reduce rate if memory > 90%
```

### Using the Queue System

```bash
# Tools automatically use appropriate queues
# No manual intervention needed

# To run a tool through the queue manually:
queue_run_tool nuclei -l targets.txt -o output.txt

# Get queue statistics:
queue_stats
```

---

## Error Reporting System

### Configuration

```bash
ERROR_REPORTING_ENABLED=true
ERROR_REPORT_JSON=true
ERROR_REPORT_SUMMARY=true
ERROR_AUTO_RECOVERY=true
ERROR_MAX_RETRIES=3
ERROR_NOTIFY_CRITICAL=true
```

### Error Report Output

After a scan, error reports are available in:
- `output/<domain>/reports/errors/<session>_errors.json` - Full JSON report
- `output/<domain>/reports/errors/<session>_summary.txt` - Human-readable summary
- `output/<domain>/reports/errors/detailed_logs/` - Per-error detailed logs

### Error Categories

- `tool_error` - Tool execution failures
- `network_error` - Network/connectivity issues
- `timeout_error` - Operation timeouts
- `resource_error` - Memory/CPU exhaustion
- `dependency_error` - Missing dependencies
- `configuration_error` - Configuration issues

---

## Data Flow Bus

### How It Works

1. **Tools Produce Data** - When a tool runs, its output is automatically published to relevant channels
2. **Data is Transformed** - Output is converted to the appropriate format for each channel
3. **Tools Consume Data** - When a tool runs, it automatically receives input from channels it needs
4. **Data is Cached** - Frequently accessed data is cached for performance

### Channel Flow Example

```
subfinder → subdomain_discovery → dnsx → resolved_hosts → httpx → live_hosts → nuclei
                                      ↘                                      ↗
                                        target_ips → masscan → open_ports →
```

### Manual Data Bus Operations

```bash
# Publish data to a channel
data_bus_publish "subdomain_discovery" "sub1.example.com\nsub2.example.com" "manual"

# Get data from a channel
data_bus_get "live_hosts" "lines"

# Get file path for channel data
data_bus_get_file "web_urls"

# Run a tool with automatic data bus integration
data_bus_run_tool httpx -json -silent
```

---

## Bettercap Integration

### Overview

Phase 17 provides comprehensive network security testing using Bettercap:

- Network reconnaissance and host discovery
- SSL/TLS analysis
- HTTP security header analysis
- Credential detection
- DNS security analysis
- ARP analysis (passive)
- Packet capture and analysis

### Configuration

```bash
# Enable Bettercap (default: true)
BETTERCAP_ENABLED=true

# Network interface (auto-detected if empty)
BETTERCAP_INTERFACE=""

# Operation mode - SAFETY: Passive only by default
BETTERCAP_PASSIVE_ONLY=true

# Feature toggles
BETTERCAP_NET_RECON=true          # Network reconnaissance
BETTERCAP_SSL_STRIP=false         # SSL Strip testing (INTRUSIVE)
BETTERCAP_DNS_SPOOF=false         # DNS spoofing detection (INTRUSIVE)
BETTERCAP_ARP_SPOOF=false         # ARP spoofing detection (INTRUSIVE)
BETTERCAP_HTTP_PROXY=true         # HTTP proxy analysis
BETTERCAP_PACKET_CAPTURE=true     # Packet capture
BETTERCAP_CREDENTIALS=true        # Credential detection
```

### Running Bettercap Phase

```bash
# As part of full scan
./neko.sh -d example.com -a

# Standalone
./neko.sh -d example.com --custom "bettercap"
```

### Bettercap Output

Results are saved in `output/<domain>/bettercap/`:
- `hosts/` - Discovered hosts and services
- `ssl/` - SSL/TLS analysis results
- `captures/` - Packet captures and HTTP analysis
- `credentials/` - Potential credential findings
- `reports/` - Summary reports

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
# Queue Management
QUEUE_GLOBAL_RPS=200
QUEUE_ADAPTIVE_ENABLED=true

# Parallel Processing
PARALLEL_JOBS=8
PARALLEL_LOAD=80

# Rate Limiting
HTTPX_RATELIMIT=150
NUCLEI_RATELIMIT=150
FFUF_RATELIMIT=100
```

### v2.1 Feature Configuration

```bash
# Queue Management
QUEUE_ENABLED=true
QUEUE_GLOBAL_RPS=200
QUEUE_ADAPTIVE_ENABLED=true

# Error Reporting
ERROR_REPORTING_ENABLED=true
ERROR_REPORT_JSON=true
ERROR_AUTO_RECOVERY=true

# Data Flow Bus
DATA_BUS_ENABLED=true
DATA_BUS_AUTO_FEED=true

# Orchestrator
ORCHESTRATOR_ENABLED=true
ORCHESTRATOR_STRICT_DEPS=true

# Bettercap
BETTERCAP_ENABLED=true
BETTERCAP_PASSIVE_ONLY=true
```

---

## Plugin System

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
    
    # Get input from data bus
    local targets=$(data_bus_get "live_hosts" "lines")
    
    # Your scanning logic here
    
    # Publish results to data bus
    data_bus_publish "vulnerabilities" "$findings" "my_custom_scanner"
}
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
- `errors/` - Error reports (v2.1)
  - `*_errors.json` - Detailed JSON error report
  - `*_summary.txt` - Human-readable error summary

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
│   ├── 16_advanced_vulns.sh # Advanced vulnerability testing
│   └── 17_bettercap.sh    # Bettercap network security (NEW)
├── lib/
│   ├── core.sh            # Core library functions
│   ├── parallel.sh        # GNU Parallel processing
│   ├── async_pipeline.sh  # Async pipeline architecture
│   ├── error_handling.sh  # Advanced error handling
│   ├── error_reporting.sh # JSON error reports (NEW)
│   ├── queue_manager.sh   # Queue management system (NEW)
│   ├── data_flow_bus.sh   # Inter-tool communication (NEW)
│   ├── orchestrator.sh    # Advanced orchestration (NEW)
│   ├── proxy_rotation.sh  # Proxy/Tor rotation
│   ├── intelligence.sh    # Cross-phase intelligence
│   └── plugin.sh          # Plugin architecture
├── plugins/               # Plugin directory
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

- Bettercap passive mode only by default
- Auth testing disabled by default
- Conservative rate limits
- CDN detection to avoid scanning protected hosts
- WAF detection for bypass awareness
- Circuit breakers prevent tool abuse
- Queue system prevents DOS attacks

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
- Integrate with Data Flow Bus for data sharing
- Use Queue System for rate-limited tools

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for amazing tools
- [reconftw](https://github.com/six2dez/reconftw) for inspiration
- [Bettercap](https://www.bettercap.org/) for network security testing
- The bug bounty community for continuous innovation

---

## Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any target. The authors are not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  <b>Happy Hunting! 🐱</b>
</p>
