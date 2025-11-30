# Neko - Advanced Bug Bounty Automation Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-2.2.0-blue.svg" alt="Version">
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

### What's New in v2.2

- **Advanced Logging System** - Comprehensive multi-level logging with session tracking, performance metrics, and structured log files
- **Discord Notification System** - Real-time notifications with rich embeds, rate limiting, and intelligent message queuing
- **Enhanced Notification Types** - Vulnerability alerts, phase progress, subdomain takeover notifications, and scan summaries
- **Rate Limit Protection** - Built-in Discord rate limit handling to prevent API throttling
- **Message Batching** - Intelligent message queuing to optimize notification delivery
- **Log Rotation** - Automatic log rotation and archival system

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
- **Discord Notifications** - Real-time Discord webhook notifications with rich embeds
- **Advanced Logging** - Multi-level logging with session tracking and performance metrics
- **Multiple Scan Modes** - Recon, Full, Passive, Fast, Deep, Custom

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [Phases Overview](#phases-overview)
- [v2.2 Advanced Features](#v22-advanced-features)
  - [Advanced Logging System](#advanced-logging-system)
  - [Discord Notification System](#discord-notification-system)
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

## v2.2 Advanced Features

### Advanced Logging System

Neko v2.2 introduces a comprehensive logging system that captures everything happening during automation:

#### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| TRACE | Most detailed logging | Deep debugging |
| DEBUG | Debug information | Development/troubleshooting |
| INFO | General information | Normal operation |
| NOTICE | Notable events | Important milestones |
| WARNING | Warning conditions | Potential issues |
| ERROR | Error conditions | Recoverable errors |
| CRITICAL | Critical conditions | Serious errors |
| ALERT | Action required | Immediate attention |
| EMERGENCY | System unusable | Fatal errors |

#### Log Files Generated

After each scan, the following log files are created in `output/<domain>/logs/`:

```
logs/
├── neko_<session_id>.log          # Main log file
├── errors_<session_id>.log        # Error-specific logs
├── debug_<session_id>.log         # Debug-level logs
├── audit_<session_id>.log         # Security audit trail
├── tools_<session_id>.log         # Tool execution logs
├── network_<session_id>.log       # Network activity logs
├── vulnerabilities_<session_id>.log # Vulnerability findings
├── performance_<session_id>.log   # Performance metrics
├── phases/                        # Per-phase detailed logs
│   ├── phase_0_OSINT_<session>.log
│   ├── phase_1_Subdomain_<session>.log
│   └── ...
├── tools/                         # Per-tool logs
└── archive/                       # Rotated/archived logs
```

#### Configuration

```bash
# Enable advanced logging (default: true)
LOGGING_ENABLED=true

# Set log level (TRACE, DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY)
NEKO_LOG_LEVEL="INFO"

# Log format (simple, detailed, json)
NEKO_LOG_FORMAT="detailed"

# Log rotation settings
NEKO_LOG_MAX_SIZE=104857600    # 100MB
NEKO_LOG_ROTATE=true
NEKO_LOG_ROTATE_COUNT=5

# Enable performance logging
NEKO_LOG_PERFORMANCE=true
NEKO_LOG_NETWORK=true
NEKO_LOG_TOOLS=true
```

#### Log Format Examples

**Detailed Format (Default):**
```
[2024-01-15 10:30:00.123] [session_abc123] [INFO      ] [SUBDOMAIN      ] Discovered 50 new subdomains | source=subfinder
```

**JSON Format:**
```json
{"timestamp": "2024-01-15T10:30:00.123Z", "session_id": "session_abc123", "level": "INFO", "category": "SUBDOMAIN", "message": "Discovered 50 new subdomains", "context": {"source": "subfinder"}}
```

---

### Discord Notification System

Neko v2.2 features a powerful Discord webhook notification system that provides real-time updates during scanning.

#### Features

- **Rich Embed Messages** - Beautiful formatted notifications with colors, fields, and timestamps
- **Rate Limit Protection** - Built-in rate limiting to prevent Discord API throttling (max 25 requests/60 seconds)
- **Message Queuing** - Intelligent message batching and queuing during high activity
- **Notification Types** - Scan start/end, phase progress, vulnerability alerts, subdomain takeovers
- **Severity-Based Colors** - Visual distinction for critical, high, medium, and low severity findings
- **Mentions** - Optional role/user mentions for critical vulnerabilities

#### Setting Up Discord Notifications

1. **Create a Discord Webhook:**
   - Go to your Discord server
   - Navigate to Server Settings → Integrations → Webhooks
   - Click "New Webhook"
   - Copy the webhook URL

2. **Configure in neko.cfg:**
   ```bash
   # Enable Discord notifications
   DISCORD_ENABLED=true
   
   # Set your webhook URL
   DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
   ```

3. **Run a scan:**
   ```bash
   ./neko.sh -d example.com
   ```

#### Configuration Options

```bash
# ═══════════════════════════════════════════════════════════════
# DISCORD WEBHOOK CONFIGURATION
# ═══════════════════════════════════════════════════════════════

# Enable Discord notifications
DISCORD_ENABLED=true

# Discord Webhook URL (REQUIRED)
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/ID/TOKEN"

# Thread ID (optional - send to specific thread)
DISCORD_THREAD_ID=""

# ───────────────────────────────────────────────────────────────
# RATE LIMITING
# ───────────────────────────────────────────────────────────────

# Rate limit settings (Discord allows ~30 requests/60 seconds)
DISCORD_RATE_LIMIT_REQUESTS=25    # Max requests per window
DISCORD_RATE_LIMIT_WINDOW=60      # Window in seconds
DISCORD_MIN_REQUEST_INTERVAL=2    # Min seconds between requests
DISCORD_RETRY_ATTEMPTS=3          # Retry attempts on failure
DISCORD_RETRY_DELAY=5             # Base retry delay

# Message queue (helps prevent rate limiting)
DISCORD_QUEUE_ENABLED=true
DISCORD_QUEUE_BATCH_SIZE=5
DISCORD_QUEUE_FLUSH_INTERVAL=10

# ───────────────────────────────────────────────────────────────
# NOTIFICATION SETTINGS
# ───────────────────────────────────────────────────────────────

# Minimum level to notify
DISCORD_NOTIFY_LEVEL="INFO"

# Include timestamps
DISCORD_INCLUDE_TIMESTAMPS=true

# Mention settings (use Discord IDs)
DISCORD_MENTION_ROLE=""           # Role ID for critical findings
DISCORD_MENTION_USER=""           # User ID for critical findings

# ───────────────────────────────────────────────────────────────
# NOTIFICATION TYPES
# ───────────────────────────────────────────────────────────────

DISCORD_NOTIFY_SCAN_START=true       # Scan started
DISCORD_NOTIFY_SCAN_END=true         # Scan completed
DISCORD_NOTIFY_PHASE_START=true      # Phase started
DISCORD_NOTIFY_PHASE_END=true        # Phase completed
DISCORD_NOTIFY_TOOL_RUN=false        # Tool execution (noisy)
DISCORD_NOTIFY_VULNERABILITIES=true  # Vulnerability findings
DISCORD_NOTIFY_SUBDOMAINS=true       # Subdomain discoveries
DISCORD_NOTIFY_URLS=false            # URL discoveries (noisy)
DISCORD_NOTIFY_PORTS=true            # Open ports
DISCORD_NOTIFY_TAKEOVER=true         # Subdomain takeovers
DISCORD_NOTIFY_ERRORS=true           # Error notifications
DISCORD_NOTIFY_CRITICAL_ONLY=false   # Only critical/high

# Batching (reduce spam)
DISCORD_BATCH_SUBDOMAINS=true
DISCORD_BATCH_SUBDOMAIN_THRESHOLD=10
DISCORD_BATCH_URLS=true
DISCORD_BATCH_URL_THRESHOLD=50

# Summary
DISCORD_SEND_SUMMARY=true            # Send scan summary
DISCORD_SEND_HOURLY_UPDATE=false     # Hourly progress
```

#### Notification Examples

**Scan Start:**
```
🚀 Scan Started
A new bug bounty scan has been initiated.

Target: example.com
Mode: full
Session: 20240115_103000_abc123
Started: 2024-01-15 10:30:00
```

**Vulnerability Found (Critical):**
```
🚨 CRITICAL Vulnerability Found!
A vulnerability has been discovered!

Severity: CRITICAL
Type: SQL Injection
Tool: sqlmap
Target: `https://example.com/api/users?id=1`
Details: Time-based blind SQL injection in user ID parameter

Proof of Concept:
```
id=1' AND SLEEP(5)--
```
```

**Subdomain Takeover:**
```
👑 Potential Subdomain Takeover!
A potential subdomain takeover vulnerability has been identified.

Subdomain: `old-staging.example.com`
Service: AWS S3
Confidence: HIGH
Details: CNAME points to unclaimed S3 bucket
```

**Scan Summary:**
```
📊 Scan Summary Report
Complete summary of the bug bounty scan.

🎯 Target: `example.com`
⏱️ Duration: 2h 15m
🔧 Tools Run: 45
❌ Failed: 2

───────────────────────────
Discovery Results
───────────────────────────
🌐 Subdomains: 150
🔗 URLs: 2,500
⚠️ Errors: 5

───────────────────────────
Vulnerability Summary
───────────────────────────
🚨 Critical: 0
🔴 High: 2
🟠 Medium: 5
🟡 Low: 12
```

#### Testing Discord Integration

Run the included test script to verify your Discord webhook is working:

```bash
./test_discord.sh
```

This will send a series of test notifications to your Discord channel:
- Test embed message
- Scan start/end notifications
- Phase notifications
- Vulnerability alerts (medium/high)
- Subdomain takeover alert
- Error notification
- Scan summary

#### Troubleshooting

**Common Issues:**

1. **"Invalid webhook URL" error:**
   - Ensure the URL starts with `https://discord.com/api/webhooks/`
   - Check for typos in the webhook ID and token

2. **Messages not appearing:**
   - Verify the webhook wasn't deleted in Discord
   - Check if rate limiting is being applied (wait 60 seconds)
   - Ensure `DISCORD_ENABLED=true` in config

3. **Rate limiting errors:**
   - Reduce `DISCORD_RATE_LIMIT_REQUESTS` to 20
   - Increase `DISCORD_MIN_REQUEST_INTERVAL` to 3
   - Enable `DISCORD_QUEUE_ENABLED=true`

4. **Missing notifications:**
   - Check the specific notification type is enabled
   - Verify `DISCORD_NOTIFY_LEVEL` is set appropriately

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

### v2.2 Feature Configuration

```bash
# ═══════════════════════════════════════════════════════════════
# LOGGING SYSTEM
# ═══════════════════════════════════════════════════════════════

LOGGING_ENABLED=true
NEKO_LOG_LEVEL="INFO"
NEKO_LOG_FORMAT="detailed"
NEKO_LOG_MAX_SIZE=104857600
NEKO_LOG_ROTATE=true
NEKO_LOG_ROTATE_COUNT=5
NEKO_LOG_PERFORMANCE=true
NEKO_LOG_NETWORK=true
NEKO_LOG_TOOLS=true

# ═══════════════════════════════════════════════════════════════
# DISCORD NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════

DISCORD_ENABLED=true
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
DISCORD_RATE_LIMIT_REQUESTS=25
DISCORD_RATE_LIMIT_WINDOW=60
DISCORD_QUEUE_ENABLED=true
DISCORD_NOTIFY_VULNERABILITIES=true
DISCORD_NOTIFY_TAKEOVER=true
DISCORD_SEND_SUMMARY=true
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
├── test_discord.sh         # Discord notification test script (v2.2)
├── modules/
│   ├── 00_osint.sh        # OSINT module
│   ├── 01_subdomain.sh    # Subdomain discovery
│   ├── ...
│   ├── 15_report.sh       # Report generation
│   ├── 16_advanced_vulns.sh # Advanced vulnerability testing
│   └── 17_bettercap.sh    # Bettercap network security (v2.1)
├── lib/
│   ├── core.sh            # Core library functions
│   ├── logging.sh         # Advanced logging system (v2.2 NEW)
│   ├── discord_notifications.sh # Discord webhook notifications (v2.2 NEW)
│   ├── parallel.sh        # GNU Parallel processing
│   ├── async_pipeline.sh  # Async pipeline architecture
│   ├── error_handling.sh  # Advanced error handling
│   ├── error_reporting.sh # JSON error reports (v2.1)
│   ├── queue_manager.sh   # Queue management system (v2.1)
│   ├── data_flow_bus.sh   # Inter-tool communication (v2.1)
│   ├── orchestrator.sh    # Advanced orchestration (v2.1)
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
