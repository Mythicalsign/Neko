#!/usr/bin/env bash

# Test script for Discord notification system
# Remove set -e to allow the script to continue after errors
# set -e

# Define the script path and source required files
SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Export necessary variables
export NEKO_VERSION="2.2.0"
export domain="test.example.com"
export mode="test"
export dir="/tmp/neko_test_$$"
export NEKO_SESSION_ID="test_$(date +%s)"

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly RESET='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BLUE}  NEKO Discord Notification System Test${RESET}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo ""

# Create test directory
mkdir -p "$dir/logs"

# Source the configuration
echo -e "${YELLOW}[1/7]${RESET} Loading configuration..."
source "${SCRIPTPATH}/neko.cfg"
echo -e "${GREEN}✓ Configuration loaded${RESET}"

# Check jq is available
if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}Installing jq...${RESET}"
    apt-get update -qq && apt-get install -y -qq jq >/dev/null 2>&1 || true
fi

# Source the logging library
echo -e "${YELLOW}[2/7]${RESET} Loading logging library..."
source "${SCRIPTPATH}/lib/logging.sh"
echo -e "${GREEN}✓ Logging library loaded${RESET}"

# Source the Discord notifications library
echo -e "${YELLOW}[3/7]${RESET} Loading Discord notifications library..."
source "${SCRIPTPATH}/lib/discord_notifications.sh"
echo -e "${GREEN}✓ Discord notifications library loaded${RESET}"

# Initialize logging
echo -e "${YELLOW}[4/7]${RESET} Initializing logging system..."
neko_log_init "$dir"
echo -e "${GREEN}✓ Logging system initialized${RESET}"

# Check webhook URL
echo ""
echo -e "${YELLOW}[5/7]${RESET} Verifying Discord webhook..."
if [[ -z "${DISCORD_WEBHOOK_URL:-}" ]]; then
    echo -e "${RED}✗ DISCORD_WEBHOOK_URL not set!${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ Discord webhook URL configured${RESET}"
echo "    URL: ${DISCORD_WEBHOOK_URL:0:60}..."

# Initialize Discord
echo ""
echo -e "${YELLOW}[6/7]${RESET} Initializing Discord notification system..."
if discord_init "$DISCORD_WEBHOOK_URL"; then
    echo -e "${GREEN}✓ Discord system initialized${RESET}"
else
    echo -e "${RED}✗ Discord initialization failed${RESET}"
    exit 1
fi

# Run test notifications
echo ""
echo -e "${YELLOW}[7/7]${RESET} Sending test notifications..."
echo ""

# Test 1: Simple embed
echo -e "  ${BLUE}→${RESET} Sending test embed message..."
discord_send_embed \
    "Test Notification" \
    "This is a test notification from Neko Bug Bounty Scanner." \
    "INFO" \
    "Test Type|System Test" \
    "Environment|Test" \
    "Timestamp|$(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  ${GREEN}✓${RESET} Test embed sent"
sleep 2

# Test 2: Scan start notification
echo -e "  ${BLUE}→${RESET} Sending scan start notification..."
discord_notify_scan_start "test.example.com" "recon" "Test mode, All phases enabled"
echo -e "  ${GREEN}✓${RESET} Scan start notification sent"
sleep 2

# Test 3: Phase notifications
echo -e "  ${BLUE}→${RESET} Sending phase notifications..."
discord_notify_phase_start "0" "OSINT" "Intelligence gathering phase"
sleep 2
discord_notify_phase_complete "0" "OSINT" "5" "10" "completed"
echo -e "  ${GREEN}✓${RESET} Phase notifications sent"
sleep 2

# Test 4: Subdomain discovery notification
echo -e "  ${BLUE}→${RESET} Sending subdomain discovery notification..."
discord_notify_subdomains "25" "api.test.example.com\nadmin.test.example.com\ndev.test.example.com" "subfinder"
echo -e "  ${GREEN}✓${RESET} Subdomain notification sent"
sleep 2

# Test 5: Vulnerability notification (Medium)
echo -e "  ${BLUE}→${RESET} Sending medium vulnerability notification..."
discord_notify_vulnerability \
    "medium" \
    "Cross-Site Scripting (XSS)" \
    "https://test.example.com/search?q=test" \
    "dalfox" \
    "Reflected XSS vulnerability found in search parameter" \
    "https://test.example.com/search?q=<script>alert(1)</script>"
echo -e "  ${GREEN}✓${RESET} Medium vulnerability notification sent"
sleep 2

# Test 6: High vulnerability notification
echo -e "  ${BLUE}→${RESET} Sending high vulnerability notification..."
discord_notify_vulnerability \
    "high" \
    "SQL Injection" \
    "https://test.example.com/api/users?id=1" \
    "sqlmap" \
    "Time-based blind SQL injection in user ID parameter" \
    "id=1' AND SLEEP(5)--"
echo -e "  ${GREEN}✓${RESET} High vulnerability notification sent"
sleep 2

# Test 7: Takeover notification
echo -e "  ${BLUE}→${RESET} Sending subdomain takeover notification..."
discord_notify_takeover \
    "old-staging.test.example.com" \
    "AWS S3" \
    "high" \
    "CNAME points to unclaimed S3 bucket"
echo -e "  ${GREEN}✓${RESET} Takeover notification sent"
sleep 2

# Test 8: Error notification
echo -e "  ${BLUE}→${RESET} Sending error notification..."
discord_notify_error \
    "Tool Error" \
    "nuclei process exited unexpectedly with code 1" \
    "nuclei" \
    "true"
echo -e "  ${GREEN}✓${RESET} Error notification sent"
sleep 2

# Test 9: Summary report
echo -e "  ${BLUE}→${RESET} Sending scan summary..."
discord_send_summary \
    "test.example.com" \
    "300" \
    '{"subdomains": 25, "urls": 150, "vulns_critical": 0, "vulns_high": 1, "vulns_medium": 2, "vulns_low": 3, "tools_run": 15, "tools_failed": 1, "errors": 2}'
echo -e "  ${GREEN}✓${RESET} Scan summary sent"
sleep 2

# Test 10: Scan complete
echo -e "  ${BLUE}→${RESET} Sending scan complete notification..."
discord_notify_scan_complete "test.example.com" "300" "25" "150" "6" "2"
echo -e "  ${GREEN}✓${RESET} Scan complete notification sent"

# Flush any remaining messages
echo ""
echo -e "${YELLOW}Flushing message queue...${RESET}"
discord_flush_all

# Show Discord stats
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BLUE}  Discord Notification Statistics${RESET}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
discord_get_stats | jq . 2>/dev/null || discord_get_stats
echo ""

# Show logging stats
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BLUE}  Logging Statistics${RESET}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
neko_export_log_stats | jq . 2>/dev/null || neko_export_log_stats
echo ""

# Finalize
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  All tests completed successfully!${RESET}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo ""
echo "Log files created in: $dir/logs/"
ls -la "$dir/logs/" 2>/dev/null || echo "No log files created"
echo ""

# Cleanup
rm -rf "$dir"
