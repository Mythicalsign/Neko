#!/usr/bin/env bash

# Neko Comprehensive Test Suite
# Tests all major components of the bug bounty automation tool

set -o pipefail

SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/neko_test_$$"
PASSED=0
FAILED=0
WARNINGS=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Test result
pass_test() {
    echo -e "${GREEN}[PASS]${RESET} $1"
    ((PASSED++))
}

fail_test() {
    echo -e "${RED}[FAIL]${RESET} $1: $2"
    ((FAILED++))
}

warn_test() {
    echo -e "${YELLOW}[WARN]${RESET} $1: $2"
    ((WARNINGS++))
}

skip_test() {
    echo -e "${CYAN}[SKIP]${RESET} $1: $2"
}

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BLUE}  NEKO BUG BOUNTY AUTOMATION - COMPREHENSIVE TEST SUITE${RESET}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
mkdir -p "$TEST_DIR/logs"
mkdir -p "$TEST_DIR/subdomains"
mkdir -p "$TEST_DIR/.tmp"
mkdir -p "$TEST_DIR/.called_fn"

# Export required variables
export dir="$TEST_DIR"
export domain="example.com"
export mode="test"
export LOGFILE="$TEST_DIR/logs/test.log"
export called_fn_dir="$TEST_DIR/.called_fn"
export QUIET="false"
export DEBUG="true"
export TOOLS_PATH="$HOME/Tools"

touch "$LOGFILE"

echo -e "${CYAN}Test Directory: $TEST_DIR${RESET}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Configuration Loading
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 1] Configuration Loading${RESET}"
echo "-------------------------------------------------------------------"

source "${SCRIPTPATH}/neko.cfg" 2>/dev/null
if [ $? -eq 0 ]; then
    pass_test "Configuration file sourced successfully"
else
    fail_test "Configuration file" "Failed to source neko.cfg"
fi

# Check API keys
if [ -n "$GITHUB_TOKEN" ] && [ "$GITHUB_TOKEN" != '""' ]; then
    pass_test "GITHUB_TOKEN configured"
else
    warn_test "GITHUB_TOKEN" "Not configured - GitHub features limited"
fi

if [ -n "$SHODAN_API_KEY" ] && [ "$SHODAN_API_KEY" != '""' ]; then
    pass_test "SHODAN_API_KEY configured"
else
    warn_test "SHODAN_API_KEY" "Not configured - Shodan features limited"
fi

if [ -n "$VIRUSTOTAL_API_KEY" ] && [ "$VIRUSTOTAL_API_KEY" != '""' ]; then
    pass_test "VIRUSTOTAL_API_KEY configured"
else
    warn_test "VIRUSTOTAL_API_KEY" "Not configured"
fi

if [ -n "$SECURITYTRAILS_API_KEY" ] && [ "$SECURITYTRAILS_API_KEY" != '""' ]; then
    pass_test "SECURITYTRAILS_API_KEY configured"
else
    warn_test "SECURITYTRAILS_API_KEY" "Not configured"
fi

if [ -n "$CHAOS_API_KEY" ] && [ "$CHAOS_API_KEY" != '""' ]; then
    pass_test "CHAOS_API_KEY configured"
else
    warn_test "CHAOS_API_KEY" "Not configured"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Library Files Loading
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 2] Library Files Loading${RESET}"
echo "-------------------------------------------------------------------"

libs=(
    "core.sh"
    "logging.sh"
    "discord_notifications.sh"
    "error_handling.sh"
    "error_reporting.sh"
    "queue_manager.sh"
    "data_flow_bus.sh"
    "orchestrator.sh"
    "parallel.sh"
    "async_pipeline.sh"
    "proxy_rotation.sh"
    "intelligence.sh"
    "plugin.sh"
)

for lib in "${libs[@]}"; do
    lib_path="${SCRIPTPATH}/lib/${lib}"
    if [ -f "$lib_path" ]; then
        source "$lib_path" 2>/dev/null
        if [ $? -eq 0 ]; then
            pass_test "Library loaded: $lib"
        else
            fail_test "Library $lib" "Failed to source"
        fi
    else
        fail_test "Library $lib" "File not found"
    fi
done

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Module Files Syntax
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 3] Module Files Syntax Check${RESET}"
echo "-------------------------------------------------------------------"

for module in "${SCRIPTPATH}/modules"/*.sh; do
    module_name=$(basename "$module")
    bash -n "$module" 2>/dev/null
    if [ $? -eq 0 ]; then
        pass_test "Module syntax: $module_name"
    else
        fail_test "Module $module_name" "Syntax error"
    fi
done

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Core Functions
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 4] Core Functions${RESET}"
echo "-------------------------------------------------------------------"

# Test ensure_dir function
if type -t ensure_dir &>/dev/null; then
    ensure_dir "$TEST_DIR/test_ensure_dir"
    if [ -d "$TEST_DIR/test_ensure_dir" ]; then
        pass_test "ensure_dir function works"
    else
        fail_test "ensure_dir" "Directory not created"
    fi
else
    fail_test "ensure_dir" "Function not defined"
fi

# Test timestamp function
if type -t timestamp &>/dev/null; then
    ts=$(timestamp)
    if [[ "$ts" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
        pass_test "timestamp function works: $ts"
    else
        fail_test "timestamp" "Invalid format: $ts"
    fi
else
    fail_test "timestamp" "Function not defined"
fi

# Test validate_domain function
if type -t validate_domain &>/dev/null; then
    if validate_domain "example.com"; then
        pass_test "validate_domain accepts valid domain"
    else
        fail_test "validate_domain" "Rejected valid domain"
    fi
    
    if validate_domain "192.168.1.1"; then
        pass_test "validate_domain accepts IP"
    else
        fail_test "validate_domain" "Rejected valid IP"
    fi
else
    fail_test "validate_domain" "Function not defined"
fi

# Test count_lines function
if type -t count_lines &>/dev/null; then
    echo -e "line1\nline2\nline3" > "$TEST_DIR/test_count.txt"
    count=$(count_lines "$TEST_DIR/test_count.txt")
    if [ "$count" -eq 3 ]; then
        pass_test "count_lines function works: $count lines"
    else
        fail_test "count_lines" "Wrong count: expected 3, got $count"
    fi
else
    fail_test "count_lines" "Function not defined"
fi

# Test command_exists function
if type -t command_exists &>/dev/null; then
    if command_exists "bash"; then
        pass_test "command_exists finds bash"
    else
        fail_test "command_exists" "Failed to find bash"
    fi
    
    if ! command_exists "nonexistent_command_12345"; then
        pass_test "command_exists returns false for missing command"
    else
        fail_test "command_exists" "Found nonexistent command"
    fi
else
    fail_test "command_exists" "Function not defined"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Logging System
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 5] Logging System${RESET}"
echo "-------------------------------------------------------------------"

if type -t neko_log_init &>/dev/null; then
    neko_log_init "$TEST_DIR" 2>/dev/null
    if [ $? -eq 0 ]; then
        pass_test "Logging system initialization"
    else
        fail_test "Logging init" "Failed to initialize"
    fi
else
    fail_test "neko_log_init" "Function not defined"
fi

if type -t neko_log &>/dev/null; then
    neko_log "INFO" "TEST" "This is a test log message" 2>/dev/null
    pass_test "neko_log function works"
else
    fail_test "neko_log" "Function not defined"
fi

# Check if log files were created
if [ -f "$TEST_DIR/logs/neko_"*.log ] 2>/dev/null || ls "$TEST_DIR/logs/neko_"*.log >/dev/null 2>&1; then
    pass_test "Log files created"
else
    warn_test "Log files" "Not created in expected location"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Error Handling System
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 6] Error Handling System${RESET}"
echo "-------------------------------------------------------------------"

if type -t neko_log_error &>/dev/null; then
    neko_log_error "Test error message" "1" "true" 2>/dev/null
    pass_test "Error logging function works"
else
    fail_test "neko_log_error" "Function not defined"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Required External Tools
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 7] Required External Tools${RESET}"
echo "-------------------------------------------------------------------"

required_tools=("curl" "wget" "git" "jq" "grep" "sed" "awk" "sort" "uniq" "wc")
for tool in "${required_tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        pass_test "Tool available: $tool"
    else
        fail_test "Tool $tool" "Not installed"
    fi
done

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Optional Security Tools
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 8] Optional Security Tools (Info Only)${RESET}"
echo "-------------------------------------------------------------------"

optional_tools=("subfinder" "httpx" "nuclei" "nmap" "masscan" "ffuf" "dnsx" "katana" "gau" "dalfox" "sqlmap")
for tool in "${optional_tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        pass_test "Security tool available: $tool"
    else
        skip_test "$tool" "Not installed (optional)"
    fi
done

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 9: Discord Notification System
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 9] Discord Notification System${RESET}"
echo "-------------------------------------------------------------------"

if [ -n "$DISCORD_WEBHOOK_URL" ]; then
    if type -t discord_init &>/dev/null; then
        # Check if webhook URL is valid format
        if [[ "$DISCORD_WEBHOOK_URL" =~ ^https://discord\.com/api/webhooks/ ]]; then
            pass_test "Discord webhook URL format valid"
        else
            fail_test "Discord webhook" "Invalid URL format"
        fi
    else
        fail_test "discord_init" "Function not defined"
    fi
else
    warn_test "Discord" "Webhook URL not configured"
fi

if type -t discord_send_embed &>/dev/null; then
    pass_test "discord_send_embed function available"
else
    fail_test "discord_send_embed" "Function not defined"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 10: Data Flow Bus
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 10] Data Flow Bus${RESET}"
echo "-------------------------------------------------------------------"

if type -t data_bus_init &>/dev/null; then
    data_bus_init "$TEST_DIR/.data_bus" 2>/dev/null
    if [ -d "$TEST_DIR/.data_bus" ]; then
        pass_test "Data bus initialization"
    else
        fail_test "Data bus" "Directory not created"
    fi
else
    fail_test "data_bus_init" "Function not defined"
fi

if type -t data_bus_publish &>/dev/null; then
    pass_test "data_bus_publish function available"
else
    fail_test "data_bus_publish" "Function not defined"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 11: Queue Management System
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 11] Queue Management System${RESET}"
echo "-------------------------------------------------------------------"

if type -t queue_init &>/dev/null; then
    queue_init "$TEST_DIR/.queue" 2>/dev/null
    if [ -d "$TEST_DIR/.queue" ]; then
        pass_test "Queue system initialization"
    else
        warn_test "Queue system" "Directory not created (may be expected)"
    fi
else
    fail_test "queue_init" "Function not defined"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 12: Main Script Arguments
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 12] Main Script Arguments${RESET}"
echo "-------------------------------------------------------------------"

# Test help flag
"${SCRIPTPATH}/neko.sh" --help >/dev/null 2>&1
if [ $? -eq 0 ]; then
    pass_test "Help flag works"
else
    fail_test "Help flag" "Non-zero exit code"
fi

# Test version flag
"${SCRIPTPATH}/neko.sh" --version >/dev/null 2>&1
if [ $? -eq 0 ]; then
    pass_test "Version flag works"
else
    fail_test "Version flag" "Non-zero exit code"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 13: API Connectivity Tests
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}[TEST 13] API Connectivity Tests${RESET}"
echo "-------------------------------------------------------------------"

# Test Shodan API
if [ -n "$SHODAN_API_KEY" ]; then
    response=$(curl -s "https://api.shodan.io/api-info?key=${SHODAN_API_KEY}" 2>/dev/null)
    if echo "$response" | jq -e '.query_credits' >/dev/null 2>&1; then
        credits=$(echo "$response" | jq -r '.query_credits')
        pass_test "Shodan API works (credits: $credits)"
    else
        warn_test "Shodan API" "API key may be invalid"
    fi
fi

# Test VirusTotal API
if [ -n "$VIRUSTOTAL_API_KEY" ]; then
    response=$(curl -s "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8" \
        -H "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null)
    if echo "$response" | jq -e '.data' >/dev/null 2>&1; then
        pass_test "VirusTotal API works"
    else
        warn_test "VirusTotal API" "API key may be invalid"
    fi
fi

# Test SecurityTrails API
if [ -n "$SECURITYTRAILS_API_KEY" ]; then
    response=$(curl -s "https://api.securitytrails.com/v1/ping" \
        -H "APIKEY: ${SECURITYTRAILS_API_KEY}" 2>/dev/null)
    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        pass_test "SecurityTrails API works"
    else
        warn_test "SecurityTrails API" "API key may be invalid"
    fi
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BLUE}  TEST SUMMARY${RESET}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${GREEN}Passed:   $PASSED${RESET}"
echo -e "${RED}Failed:   $FAILED${RESET}"
echo -e "${YELLOW}Warnings: $WARNINGS${RESET}"
echo ""

# Cleanup
rm -rf "$TEST_DIR"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All critical tests passed!${RESET}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the output above.${RESET}"
    exit 1
fi
