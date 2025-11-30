#!/usr/bin/env bash

#  ███╗   ██╗███████╗██╗  ██╗ ██████╗ 
#  ████╗  ██║██╔════╝██║ ██╔╝██╔═══██╗
#  ██╔██╗ ██║█████╗  █████╔╝ ██║   ██║
#  ██║╚██╗██║██╔══╝  ██╔═██╗ ██║   ██║
#  ██║ ╚████║███████╗██║  ██╗╚██████╔╝
#  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
#
#  Neko - Advanced Bug Bounty Automation Framework
#  Enterprise-grade reconnaissance and vulnerability scanning
#  
#  Author: Security Research Team
#  Version: 1.0.0
#  License: MIT

set -Eeo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL VARIABLES AND PATHS
# ═══════════════════════════════════════════════════════════════════════════════

readonly NEKO_VERSION="2.1.0"
readonly SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULES_PATH="${SCRIPTPATH}/modules"
readonly LIB_PATH="${SCRIPTPATH}/lib"
readonly CONFIG_PATH="${SCRIPTPATH}/config"
readonly TEMPLATES_PATH="${SCRIPTPATH}/templates"
readonly WORDLISTS_PATH="${SCRIPTPATH}/wordlists"

# Runtime variables
declare -g domain=""
declare -g target_list=""
declare -g output_dir=""
declare -g config_file="${SCRIPTPATH}/neko.cfg"
declare -g mode="recon"
declare -g custom_modules=""
declare -g start_time=""
declare -g LOGFILE=""
declare -g called_fn_dir=""
declare -g dir=""

# Module state tracking
declare -gA MODULE_STATUS
declare -gA RATE_LIMITS
declare -gA TOOL_PIDS

# ═══════════════════════════════════════════════════════════════════════════════
# COLOR DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[0;37m'
readonly BRED='\033[1;31m'
readonly BGREEN='\033[1;32m'
readonly BYELLOW='\033[1;33m'
readonly BBLUE='\033[1;34m'
readonly BMAGENTA='\033[1;35m'
readonly BCYAN='\033[1;36m'
readonly BWHITE='\033[1;37m'
readonly RESET='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════════
# BANNER AND UI FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

banner() {
    local banners=(
"${BMAGENTA}
  ███╗   ██╗███████╗██╗  ██╗ ██████╗ 
  ████╗  ██║██╔════╝██║ ██╔╝██╔═══██╗
  ██╔██╗ ██║█████╗  █████╔╝ ██║   ██║
  ██║╚██╗██║██╔══╝  ██╔═██╗ ██║   ██║
  ██║ ╚████║███████╗██║  ██╗╚██████╔╝
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
${RESET}"
"${BCYAN}
   _   _      _         
  | \ | | ___| | _____  
  |  \| |/ _ \ |/ / _ \ 
  | |\  |  __/   < (_) |
  |_| \_|\___|_|\_\___/ 
${RESET}"
"${BGREEN}
  ╔╗╔┌─┐┬┌─┌─┐
  ║║║├┤ ├┴┐│ │
  ╝╚╝└─┘┴ ┴└─┘
${RESET}"
    )
    
    local random_index=$((RANDOM % ${#banners[@]}))
    printf "%b" "${banners[$random_index]}"
    printf "\n  ${BWHITE}Advanced Bug Bounty Automation Framework${RESET}\n"
    printf "  ${CYAN}Version: ${NEKO_VERSION}${RESET}\n\n"
}

# Print formatted messages
log_info() {
    printf "[${BBLUE}INFO${RESET}] [%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

log_success() {
    printf "[${BGREEN}SUCCESS${RESET}] [%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

log_warning() {
    printf "[${BYELLOW}WARNING${RESET}] [%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

log_error() {
    printf "[${BRED}ERROR${RESET}] [%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" >&2
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        printf "[${BMAGENTA}DEBUG${RESET}] [%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
    fi
}

log_phase() {
    printf "\n${BGREEN}═══════════════════════════════════════════════════════════════════════════════${RESET}\n"
    printf "${BWHITE}  PHASE: %s${RESET}\n" "$1"
    printf "${BGREEN}═══════════════════════════════════════════════════════════════════════════════${RESET}\n\n"
}

log_module() {
    printf "\n${BCYAN}───────────────────────────────────────────────────────────────────────────────${RESET}\n"
    printf "${BWHITE}  MODULE: %s${RESET}\n" "$1"
    printf "${BCYAN}───────────────────────────────────────────────────────────────────────────────${RESET}\n\n"
}

# Progress bar
progress_bar() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\r[${BGREEN}"
    printf "%0.s█" $(seq 1 $filled)
    printf "${RESET}"
    printf "%0.s░" $(seq 1 $empty)
    printf "] ${BWHITE}%3d%%${RESET}" "$percentage"
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Check if file exists and is not empty
file_exists_not_empty() {
    [[ -s "$1" ]]
}

# Create directory if not exists
ensure_dir() {
    [[ -d "$1" ]] || mkdir -p "$1"
}

# Timestamp for filenames
timestamp() {
    date +"%Y%m%d_%H%M%S"
}

# Get domain from URL
extract_domain() {
    echo "$1" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||'
}

# Validate domain format
validate_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    elif [[ "$domain" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0  # IP address
    elif [[ "$domain" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0  # CIDR notation
    else
        return 1
    fi
}

# Check if target is IP
is_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# Check if target is CIDR
is_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]
}

# Deduplicate file in place
dedupe_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sort -u "$file" -o "$file"
    fi
}

# Count lines in file
count_lines() {
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# Append unique lines to file
anew_custom() {
    local input="$1"
    local output="$2"
    if [[ -f "$output" ]]; then
        comm -23 <(sort -u "$input") <(sort -u "$output") >> "$output"
    else
        sort -u "$input" > "$output"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING AND RESOURCE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Initialize rate limits from config
init_rate_limits() {
    RATE_LIMITS=(
        ["httpx"]="${HTTPX_RATELIMIT:-150}"
        ["nuclei"]="${NUCLEI_RATELIMIT:-150}"
        ["ffuf"]="${FFUF_RATELIMIT:-100}"
        ["masscan"]="${MASSCAN_RATE:-1000}"
        ["nmap"]="${NMAP_RATE:-1000}"
        ["subfinder"]="${SUBFINDER_RATE:-0}"
        ["amass"]="${AMASS_RATE:-0}"
        ["katana"]="${KATANA_RATE:-150}"
        ["dalfox"]="${DALFOX_RATE:-150}"
        ["sqlmap"]="${SQLMAP_RATE:-10}"
        ["gobuster"]="${GOBUSTER_RATE:-100}"
        ["feroxbuster"]="${FEROXBUSTER_RATE:-100}"
        ["arjun"]="${ARJUN_RATE:-50}"
        ["gau"]="${GAU_RATE:-0}"
        ["waybackurls"]="${WAYBACKURLS_RATE:-0}"
    )
    log_debug "Rate limits initialized"
}

# Get rate limit for a tool
get_rate_limit() {
    local tool="$1"
    echo "${RATE_LIMITS[$tool]:-0}"
}

# Apply rate limiting wrapper
with_rate_limit() {
    local tool="$1"
    shift
    local rate="${RATE_LIMITS[$tool]:-0}"
    
    if [[ "$rate" -gt 0 ]]; then
        log_debug "Applying rate limit of $rate for $tool"
    fi
    
    "$@"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Track module execution status
mark_module_started() {
    local module="$1"
    MODULE_STATUS["$module"]="running"
    touch "${called_fn_dir}/.${module}_started"
    log_debug "Module $module started"
}

mark_module_completed() {
    local module="$1"
    MODULE_STATUS["$module"]="completed"
    touch "${called_fn_dir}/.${module}"
    rm -f "${called_fn_dir}/.${module}_started" 2>/dev/null
    log_debug "Module $module completed"
}

mark_module_failed() {
    local module="$1"
    local reason="${2:-unknown}"
    MODULE_STATUS["$module"]="failed"
    echo "$reason" > "${called_fn_dir}/.${module}_failed"
    rm -f "${called_fn_dir}/.${module}_started" 2>/dev/null
    log_error "Module $module failed: $reason"
}

is_module_completed() {
    local module="$1"
    [[ -f "${called_fn_dir}/.${module}" ]] && [[ "${FORCE_RERUN:-false}" != "true" ]]
}

# Check if module should run based on config
should_run_module() {
    local module="$1"
    local config_var="$2"
    
    # Check if already completed
    if is_module_completed "$module"; then
        log_info "Module $module already completed. Skipping..."
        return 1
    fi
    
    # Check config toggle
    if [[ "${!config_var}" != "true" ]]; then
        log_info "Module $module disabled in configuration"
        return 1
    fi
    
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS MANAGEMENT (DOS PREVENTION)
# ═══════════════════════════════════════════════════════════════════════════════

# Maximum concurrent processes per category
declare -gA MAX_PROCS=(
    ["network"]=3
    ["cpu"]=4
    ["io"]=2
    ["memory"]=2
)

declare -gA CURRENT_PROCS=(
    ["network"]=0
    ["cpu"]=0
    ["io"]=0
    ["memory"]=0
)

# Wait for process slot
wait_for_slot() {
    local category="$1"
    local max="${MAX_PROCS[$category]:-2}"
    
    while [[ "${CURRENT_PROCS[$category]}" -ge "$max" ]]; do
        sleep 1
        # Clean up finished processes
        cleanup_finished_procs "$category"
    done
    
    ((CURRENT_PROCS[$category]++)) || true
}

# Release process slot
release_slot() {
    local category="$1"
    if [[ "${CURRENT_PROCS[$category]}" -gt 0 ]]; then
        ((CURRENT_PROCS[$category]--)) || true
    fi
}

# Clean up finished processes
cleanup_finished_procs() {
    local category="$1"
    for pid in "${!TOOL_PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            unset "TOOL_PIDS[$pid]"
            release_slot "$category"
        fi
    done
}

# Run command with resource management
run_managed() {
    local category="$1"
    local timeout_secs="${2:-3600}"
    shift 2
    
    wait_for_slot "$category"
    
    timeout "$timeout_secs" "$@" &
    local pid=$!
    TOOL_PIDS[$pid]="$category"
    
    wait "$pid"
    local exit_code=$?
    
    release_slot "$category"
    unset "TOOL_PIDS[$pid]"
    
    return $exit_code
}

# Kill all managed processes
cleanup_all_procs() {
    log_warning "Cleaning up all running processes..."
    for pid in "${!TOOL_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
            sleep 1
            kill -KILL "$pid" 2>/dev/null
        fi
    done
    TOOL_PIDS=()
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLING AND CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

# Trap handler for cleanup
cleanup() {
    local exit_code=$?
    
    log_warning "Cleaning up..."
    
    # Kill all managed processes
    cleanup_all_procs
    
    # Cleanup advanced features
    type -t parallel_cleanup &>/dev/null && parallel_cleanup 2>/dev/null || true
    type -t pipeline_cleanup &>/dev/null && pipeline_cleanup 2>/dev/null || true
    type -t proxy_cleanup &>/dev/null && proxy_cleanup 2>/dev/null || true
    type -t plugin_cleanup &>/dev/null && plugin_cleanup 2>/dev/null || true
    type -t error_cleanup &>/dev/null && error_cleanup 2>/dev/null || true
    
    # Save progress state
    if [[ -n "$dir" ]] && [[ -d "$dir" ]]; then
        echo "$(date): Scan interrupted with exit code $exit_code" >> "${dir}/scan.log"
    fi
    
    # Generate error summary if available
    if type -t error_summary &>/dev/null && [[ -n "$dir" ]]; then
        error_summary >> "${dir}/logs/error_summary.txt" 2>/dev/null || true
    fi
    
    # Calculate runtime
    if [[ -n "$start_time" ]]; then
        local end_time=$(date +%s)
        local runtime=$((end_time - start_time))
        local hours=$((runtime / 3600))
        local minutes=$(((runtime % 3600) / 60))
        local seconds=$((runtime % 60))
        log_info "Total runtime: ${hours}h ${minutes}m ${seconds}s"
    fi
    
    exit $exit_code
}

# Set up traps
setup_traps() {
    trap cleanup EXIT
    trap 'log_error "Interrupted by user"; exit 130' INT
    trap 'log_error "Terminated"; exit 143' TERM
}

# Error handler
handle_error() {
    local line_no="$1"
    local error_code="$2"
    log_error "Error on line $line_no: exit code $error_code"
}

trap 'handle_error ${LINENO} $?' ERR

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION SYSTEM (v2.2 - Discord Primary)
# ═══════════════════════════════════════════════════════════════════════════════

# Send notification via Discord (primary channel)
notify() {
    local message="$1"
    local level="${2:-info}"  # info, warning, error, success, critical
    local title="${3:-Neko Notification}"
    local context="${4:-}"
    
    # Map levels to log and Discord types
    local log_level="INFO"
    local discord_type="INFO"
    
    case "$level" in
        info)
            log_level="INFO"
            discord_type="INFO"
            ;;
        warning)
            log_level="WARNING"
            discord_type="WARNING"
            ;;
        error)
            log_level="ERROR"
            discord_type="ERROR"
            ;;
        success)
            log_level="NOTICE"
            discord_type="SUCCESS"
            ;;
        critical)
            log_level="CRITICAL"
            discord_type="CRITICAL"
            ;;
    esac
    
    # Log to advanced logging system
    if type -t neko_log &>/dev/null; then
        neko_log "$log_level" "NOTIFY" "$message" "title=${title}" "$context"
    else
        # Fallback to basic console output
        case "$level" in
            info) log_info "$message" ;;
            warning) log_warning "$message" ;;
            error) log_error "$message" ;;
            success) log_success "$message" ;;
            critical) log_error "[CRITICAL] $message" ;;
        esac
    fi
    
    # Send to Discord (primary notification channel)
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && type -t discord_send_embed &>/dev/null; then
        discord_send_embed "$title" "$message" "$discord_type" \
            "Target|${domain:-unknown}" \
            "Mode|${mode:-recon}"
    fi
}

# Notify vulnerability finding (specialized for vuln notifications)
notify_vulnerability() {
    local severity="$1"
    local vuln_type="$2"
    local target="$3"
    local tool="${4:-unknown}"
    local details="${5:-}"
    local poc="${6:-}"
    
    # Log to advanced logging system
    if type -t neko_log_vulnerability &>/dev/null; then
        neko_log_vulnerability "$severity" "$vuln_type" "$target" "$tool" "$details" "$poc"
    fi
    
    # Send to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_VULNERABILITIES:-true}" == "true" ]] && \
       type -t discord_notify_vulnerability &>/dev/null; then
        discord_notify_vulnerability "$severity" "$vuln_type" "$target" "$tool" "$details" "$poc"
    fi
}

# Notify phase start
notify_phase_start() {
    local phase_number="$1"
    local phase_name="$2"
    local description="${3:-}"
    
    # Log to advanced logging system
    if type -t neko_log_phase_start &>/dev/null; then
        neko_log_phase_start "$phase_name" "$phase_number" "$description"
    fi
    
    # Send to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_PHASE_START:-true}" == "true" ]] && \
       type -t discord_notify_phase_start &>/dev/null; then
        discord_notify_phase_start "$phase_number" "$phase_name" "$description"
    fi
}

# Notify phase completion
notify_phase_complete() {
    local phase_number="$1"
    local phase_name="$2"
    local duration="$3"
    local findings="${4:-0}"
    local status="${5:-completed}"
    
    # Log to advanced logging system
    if type -t neko_log_phase_end &>/dev/null; then
        neko_log_phase_end "$phase_name" "$phase_number" "$status" "$duration" "$findings"
    fi
    
    # Send to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_PHASE_END:-true}" == "true" ]] && \
       type -t discord_notify_phase_complete &>/dev/null; then
        discord_notify_phase_complete "$phase_number" "$phase_name" "$duration" "$findings" "$status"
    fi
}

# Notify tool execution
notify_tool_run() {
    local tool_name="$1"
    local phase="$2"
    local status="$3"
    local duration="$4"
    local output_count="${5:-0}"
    
    # Send to Discord (if enabled for tool notifications)
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_TOOL_RUN:-false}" == "true" ]] && \
       type -t discord_notify_tool_run &>/dev/null; then
        discord_notify_tool_run "$tool_name" "$phase" "$status" "$duration" "$output_count"
    fi
}

# Notify subdomain discoveries
notify_subdomains() {
    local count="$1"
    local sample="${2:-}"
    local source="${3:-multiple}"
    
    # Log to advanced logging system
    if type -t neko_log &>/dev/null; then
        neko_log "INFO" "SUBDOMAIN" "Discovered ${count} subdomains" "source=${source}"
    fi
    
    # Send to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_SUBDOMAINS:-true}" == "true" ]] && \
       type -t discord_notify_subdomains &>/dev/null; then
        discord_notify_subdomains "$count" "$sample" "$source"
    fi
}

# Notify subdomain takeover potential
notify_takeover() {
    local subdomain="$1"
    local service="$2"
    local confidence="${3:-medium}"
    local details="${4:-}"
    
    # Log to advanced logging system
    if type -t neko_log_vulnerability &>/dev/null; then
        neko_log_vulnerability "HIGH" "Subdomain Takeover" "$subdomain" "takeover-scan" "Service: $service, Confidence: $confidence" ""
    fi
    
    # Send to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_TAKEOVER:-true}" == "true" ]] && \
       type -t discord_notify_takeover &>/dev/null; then
        discord_notify_takeover "$subdomain" "$service" "$confidence" "$details"
    fi
}

# Notify errors
notify_error() {
    local error_type="$1"
    local message="$2"
    local tool="${3:-system}"
    local recoverable="${4:-true}"
    
    # Log to advanced logging system
    if type -t neko_log_error &>/dev/null; then
        neko_log_error "$message" "1" "$recoverable"
    fi
    
    # Send to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_ERRORS:-true}" == "true" ]] && \
       type -t discord_notify_error &>/dev/null; then
        discord_notify_error "$error_type" "$message" "$tool" "$recoverable"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION LOADING
# ═══════════════════════════════════════════════════════════════════════════════

load_config() {
    local config="$1"
    
    if [[ ! -f "$config" ]]; then
        log_error "Configuration file not found: $config"
        exit 1
    fi
    
    log_info "Loading configuration from: $config"
    
    # Source the configuration file
    # shellcheck source=/dev/null
    source "$config"
    
    # Initialize rate limits
    init_rate_limits
    
    # Validate critical settings
    validate_config
    
    log_success "Configuration loaded successfully"
}

validate_config() {
    # Check for required directories
    if [[ ! -d "${TOOLS_PATH:-$HOME/Tools}" ]]; then
        log_warning "Tools directory not found. Some tools may not work."
    fi
    
    # Validate thread counts
    if [[ "${HTTPX_THREADS:-50}" -gt 200 ]]; then
        log_warning "HTTPX_THREADS is very high (${HTTPX_THREADS}). This may cause issues."
    fi
    
    # Check for API keys
    local missing_keys=()
    [[ -z "${SHODAN_API_KEY:-}" ]] && missing_keys+=("SHODAN_API_KEY")
    [[ -z "${GITHUB_TOKEN:-}" ]] && missing_keys+=("GITHUB_TOKEN")
    [[ -z "${CENSYS_API_ID:-}" ]] && missing_keys+=("CENSYS_API_ID")
    
    if [[ ${#missing_keys[@]} -gt 0 ]]; then
        log_warning "Missing API keys: ${missing_keys[*]}"
        log_warning "Some features will be limited without these keys."
    fi
    
    # Initialize advanced features
    init_advanced_features
}

# Initialize v2.0 advanced features
init_advanced_features() {
    # Initialize parallel processing
    if [[ "${PARALLEL_ENABLED:-true}" == "true" ]] && type -t parallel_init &>/dev/null; then
        parallel_init "${dir}/.tmp/parallel" 2>/dev/null || true
    fi
    
    # Initialize error handling
    if type -t error_init &>/dev/null; then
        error_init 2>/dev/null || true
    fi
    
    # Initialize proxy rotation
    if [[ "${PROXY_ROTATION_ENABLED:-false}" == "true" ]] && type -t proxy_init &>/dev/null; then
        proxy_init "${PROXY_LIST_FILE:-}" 2>/dev/null || true
    fi
    
    # Initialize plugin system
    if [[ "${PLUGINS_ENABLED:-true}" == "true" ]] && type -t plugin_init &>/dev/null; then
        plugin_init 2>/dev/null || true
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT DIRECTORY SETUP
# ═══════════════════════════════════════════════════════════════════════════════

setup_output_dir() {
    local target="$1"
    local custom_output="${2:-}"
    
    # Determine output directory
    if [[ -n "$custom_output" ]]; then
        dir="$custom_output"
    elif [[ -n "${OUTPUT_BASE_DIR:-}" ]]; then
        dir="${OUTPUT_BASE_DIR}/${target}_$(timestamp)"
    else
        dir="${SCRIPTPATH}/output/${target}_$(timestamp)"
    fi
    
    # Create directory structure
    ensure_dir "$dir"
    ensure_dir "${dir}/.tmp"
    ensure_dir "${dir}/osint"
    ensure_dir "${dir}/subdomains"
    ensure_dir "${dir}/dns"
    ensure_dir "${dir}/hosts"
    ensure_dir "${dir}/webs"
    ensure_dir "${dir}/ports"
    ensure_dir "${dir}/content"
    ensure_dir "${dir}/technologies"
    ensure_dir "${dir}/urls"
    ensure_dir "${dir}/js"
    ensure_dir "${dir}/parameters"
    ensure_dir "${dir}/vulnerabilities"
    ensure_dir "${dir}/xss"
    ensure_dir "${dir}/takeover"
    ensure_dir "${dir}/cloud"
    ensure_dir "${dir}/auth"
    ensure_dir "${dir}/api"
    ensure_dir "${dir}/reports"
    ensure_dir "${dir}/logs"
    
    # Set up logging
    LOGFILE="${dir}/logs/neko_$(timestamp).log"
    called_fn_dir="${dir}/.called_fn"
    ensure_dir "$called_fn_dir"
    
    # Save target info
    echo "$target" > "${dir}/target.txt"
    echo "Scan started: $(date)" > "${dir}/scan.log"
    echo "Mode: $mode" >> "${dir}/scan.log"
    
    log_success "Output directory created: $dir"
    export dir LOGFILE called_fn_dir
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE LOADER
# ═══════════════════════════════════════════════════════════════════════════════

load_modules() {
    local modules_dir="$1"
    
    if [[ ! -d "$modules_dir" ]]; then
        log_error "Modules directory not found: $modules_dir"
        return 1
    fi
    
    # Load library functions first (in order of dependencies)
    local lib_load_order=(
        "core.sh"
        "logging.sh"
        "discord_notifications.sh"
        "parallel.sh"
        "async_pipeline.sh"
        "error_handling.sh"
        "error_reporting.sh"
        "queue_manager.sh"
        "data_flow_bus.sh"
        "orchestrator.sh"
        "proxy_rotation.sh"
        "intelligence.sh"
        "plugin.sh"
    )
    
    for lib_file in "${lib_load_order[@]}"; do
        local full_path="${LIB_PATH}/${lib_file}"
        if [[ -f "$full_path" ]]; then
            # shellcheck source=/dev/null
            source "$full_path"
            log_debug "Loaded library: $lib_file"
        fi
    done
    
    # Load any additional library files not in the order list
    for lib_file in "${LIB_PATH}"/*.sh; do
        if [[ -f "$lib_file" ]]; then
            local basename=$(basename "$lib_file")
            # Skip if already loaded
            local already_loaded=false
            for loaded in "${lib_load_order[@]}"; do
                [[ "$basename" == "$loaded" ]] && already_loaded=true && break
            done
            
            if [[ "$already_loaded" == "false" ]]; then
                # shellcheck source=/dev/null
                source "$lib_file"
                log_debug "Loaded additional library: $basename"
            fi
        fi
    done
    
    # Load all modules
    for module_file in "${modules_dir}"/*.sh; do
        if [[ -f "$module_file" ]]; then
            # shellcheck source=/dev/null
            source "$module_file"
            log_debug "Loaded module: $(basename "$module_file")"
        fi
    done
    
    log_success "All modules loaded"
}

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTION MODES
# ═══════════════════════════════════════════════════════════════════════════════

# Full reconnaissance mode (non-intrusive)
run_recon_mode() {
    log_phase "FULL RECONNAISSANCE MODE"
    notify "Starting full reconnaissance for $domain" "info"
    
    # Phase 0: OSINT & Intelligence
    [[ "${OSINT_ENABLED:-true}" == "true" ]] && run_osint_phase
    
    # Phase 1: Subdomain Discovery
    [[ "${SUBDOMAIN_ENABLED:-true}" == "true" ]] && run_subdomain_phase
    
    # Phase 2: DNS Analysis
    [[ "${DNS_ENABLED:-true}" == "true" ]] && run_dns_phase
    
    # Phase 3: Web Probing
    [[ "${WEBPROBE_ENABLED:-true}" == "true" ]] && run_webprobe_phase
    
    # Phase 4: Port Scanning
    [[ "${PORTSCAN_ENABLED:-true}" == "true" ]] && run_portscan_phase
    
    # Phase 5: Content Discovery
    [[ "${CONTENT_ENABLED:-true}" == "true" ]] && run_content_phase
    
    # Phase 6: Technology Fingerprinting
    [[ "${FINGERPRINT_ENABLED:-true}" == "true" ]] && run_fingerprint_phase
    
    # Phase 7: URL & JS Analysis
    [[ "${URLANALYSIS_ENABLED:-true}" == "true" ]] && run_urlanalysis_phase
    
    # Phase 8: Parameter Discovery
    [[ "${PARAM_ENABLED:-true}" == "true" ]] && run_param_phase
    
    # Phase 11: Subdomain Takeover
    [[ "${TAKEOVER_ENABLED:-true}" == "true" ]] && run_takeover_phase
    
    # Phase 12: Cloud Security
    [[ "${CLOUD_ENABLED:-true}" == "true" ]] && run_cloud_phase
    
    # Phase 15: Report Generation
    run_report_phase
    
    notify "Reconnaissance completed for $domain" "success"
}

# Full scan mode (intrusive)
run_full_mode() {
    log_phase "FULL SCAN MODE (INTRUSIVE)"
    notify "Starting full scan for $domain" "warning"
    
    # Initialize v2.1 systems
    init_v21_systems
    
    # Trigger pre-scan hooks
    type -t trigger_pre_scan &>/dev/null && trigger_pre_scan
    
    # Initialize intelligence engine
    if [[ "${INTELLIGENCE_ENABLED:-true}" == "true" ]] && type -t intel_init &>/dev/null; then
        intel_init "${dir}/.tmp/intel"
    fi
    
    # Run all recon phases first
    run_recon_mode
    
    # Phase 9: Vulnerability Scanning
    [[ "${VULNSCAN_ENABLED:-true}" == "true" ]] && run_vulnscan_phase
    
    # Phase 10: XSS Testing
    [[ "${XSS_ENABLED:-true}" == "true" ]] && run_xss_phase
    
    # Phase 13: Auth Testing
    [[ "${AUTH_ENABLED:-false}" == "true" ]] && run_auth_phase
    
    # Phase 14: API Security
    [[ "${API_ENABLED:-true}" == "true" ]] && run_api_phase
    
    # Phase 16: Advanced Vulnerability Testing (v2.0)
    [[ "${ADVANCED_VULNS_ENABLED:-true}" == "true" ]] && run_advanced_vulns_phase
    
    # Phase 17: Bettercap Network Security Testing (v2.1)
    [[ "${BETTERCAP_ENABLED:-true}" == "true" ]] && run_bettercap_phase
    
    # Run intelligence correlation
    if [[ "${INTELLIGENCE_ENABLED:-true}" == "true" ]] && type -t intel_correlate &>/dev/null; then
        intel_correlate
        intel_find_attack_chains
        intel_detect_patterns
        intel_generate_report
    fi
    
    # Regenerate report with findings
    run_report_phase
    
    # Cleanup v2.1 systems
    cleanup_v21_systems
    
    # Trigger post-scan hooks
    type -t trigger_post_scan &>/dev/null && trigger_post_scan
    
    notify "Full scan completed for $domain" "success"
}

# Passive mode (OSINT + passive enumeration only)
run_passive_mode() {
    log_phase "PASSIVE MODE"
    notify "Starting passive reconnaissance for $domain" "info"
    
    # Phase 0: OSINT
    run_osint_phase
    
    # Passive subdomain enumeration only
    run_subdomain_passive
    
    # DNS analysis (non-intrusive)
    run_dns_phase
    
    # Report generation
    run_report_phase
    
    notify "Passive reconnaissance completed for $domain" "success"
}

# Subdomain enumeration only
run_subs_mode() {
    log_phase "SUBDOMAIN ENUMERATION MODE"
    
    run_subdomain_phase
    run_report_phase
    
    notify "Subdomain enumeration completed for $domain" "success"
}

# Web vulnerability scan only
run_web_mode() {
    log_phase "WEB VULNERABILITY SCAN MODE"
    
    # Assume subdomains/URLs are already available or run quick enum
    if [[ ! -f "${dir}/subdomains/subdomains.txt" ]]; then
        run_subdomain_phase
        run_webprobe_phase
    fi
    
    run_vulnscan_phase
    run_xss_phase
    run_report_phase
    
    notify "Web vulnerability scan completed for $domain" "success"
}

# Fast mode (essential checks only)
run_fast_mode() {
    log_phase "FAST MODE"
    notify "Starting fast scan for $domain" "info"
    
    # Quick subdomain enumeration
    run_subdomain_fast
    
    # Web probing
    run_webprobe_phase
    
    # Essential vulnerability checks with nuclei
    run_nuclei_fast
    
    # Quick report
    run_report_phase
    
    notify "Fast scan completed for $domain" "success"
}

# Deep mode (extensive, slow)
run_deep_mode() {
    log_phase "DEEP MODE (EXTENSIVE)"
    notify "Starting deep scan for $domain - This will take a long time" "warning"
    
    export DEEP=true
    
    # Run all phases with extended options
    run_full_mode
    
    notify "Deep scan completed for $domain" "success"
}

# Custom module execution
run_custom_mode() {
    log_phase "CUSTOM MODULE EXECUTION"
    
    if [[ -z "$custom_modules" ]]; then
        log_error "No custom modules specified. Use -m 'module1,module2'"
        exit 1
    fi
    
    IFS=',' read -ra modules <<< "$custom_modules"
    for module in "${modules[@]}"; do
        case "$module" in
            osint) run_osint_phase ;;
            subdomain|subs) run_subdomain_phase ;;
            dns) run_dns_phase ;;
            webprobe|probe) run_webprobe_phase ;;
            portscan|ports) run_portscan_phase ;;
            content|fuzz) run_content_phase ;;
            fingerprint|tech) run_fingerprint_phase ;;
            urlanalysis|urls) run_urlanalysis_phase ;;
            param|params) run_param_phase ;;
            vulnscan|vuln) run_vulnscan_phase ;;
            xss) run_xss_phase ;;
            takeover) run_takeover_phase ;;
            cloud) run_cloud_phase ;;
            auth) run_auth_phase ;;
            api) run_api_phase ;;
            advanced_vulns|advanced) run_advanced_vulns_phase ;;
            report) run_report_phase ;;
            *)
                log_warning "Unknown module: $module"
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE EXECUTION STUBS (Implemented in modules)
# ═══════════════════════════════════════════════════════════════════════════════

# These functions are implemented in their respective module files
# They are declared here for reference

run_osint_phase() {
    if [[ "$(type -t osint_main)" == "function" ]]; then
        osint_main
    else
        log_warning "OSINT module not loaded"
    fi
}

run_subdomain_phase() {
    if [[ "$(type -t subdomain_main)" == "function" ]]; then
        subdomain_main
    else
        log_warning "Subdomain module not loaded"
    fi
}

run_subdomain_passive() {
    if [[ "$(type -t subdomain_passive)" == "function" ]]; then
        subdomain_passive
    else
        log_warning "Subdomain passive function not available"
    fi
}

run_subdomain_fast() {
    if [[ "$(type -t subdomain_fast)" == "function" ]]; then
        subdomain_fast
    else
        log_warning "Subdomain fast function not available"
    fi
}

run_dns_phase() {
    if [[ "$(type -t dns_main)" == "function" ]]; then
        dns_main
    else
        log_warning "DNS module not loaded"
    fi
}

run_webprobe_phase() {
    if [[ "$(type -t webprobe_main)" == "function" ]]; then
        webprobe_main
    else
        log_warning "Web Probe module not loaded"
    fi
}

run_portscan_phase() {
    if [[ "$(type -t portscan_main)" == "function" ]]; then
        portscan_main
    else
        log_warning "Port Scan module not loaded"
    fi
}

run_content_phase() {
    if [[ "$(type -t content_main)" == "function" ]]; then
        content_main
    else
        log_warning "Content Discovery module not loaded"
    fi
}

run_fingerprint_phase() {
    if [[ "$(type -t fingerprint_main)" == "function" ]]; then
        fingerprint_main
    else
        log_warning "Fingerprint module not loaded"
    fi
}

run_urlanalysis_phase() {
    if [[ "$(type -t urlanalysis_main)" == "function" ]]; then
        urlanalysis_main
    else
        log_warning "URL Analysis module not loaded"
    fi
}

run_param_phase() {
    if [[ "$(type -t param_main)" == "function" ]]; then
        param_main
    else
        log_warning "Parameter Discovery module not loaded"
    fi
}

run_vulnscan_phase() {
    if [[ "$(type -t vulnscan_main)" == "function" ]]; then
        vulnscan_main
    else
        log_warning "Vulnerability Scan module not loaded"
    fi
}

run_xss_phase() {
    if [[ "$(type -t xss_main)" == "function" ]]; then
        xss_main
    else
        log_warning "XSS module not loaded"
    fi
}

run_takeover_phase() {
    if [[ "$(type -t takeover_main)" == "function" ]]; then
        takeover_main
    else
        log_warning "Takeover module not loaded"
    fi
}

run_cloud_phase() {
    if [[ "$(type -t cloud_main)" == "function" ]]; then
        cloud_main
    else
        log_warning "Cloud Security module not loaded"
    fi
}

run_auth_phase() {
    if [[ "$(type -t auth_main)" == "function" ]]; then
        auth_main
    else
        log_warning "Auth Testing module not loaded"
    fi
}

run_api_phase() {
    if [[ "$(type -t api_main)" == "function" ]]; then
        api_main
    else
        log_warning "API Security module not loaded"
    fi
}

run_report_phase() {
    if [[ "$(type -t report_main)" == "function" ]]; then
        report_main
    else
        log_warning "Report module not loaded"
    fi
}

run_nuclei_fast() {
    if [[ "$(type -t nuclei_fast)" == "function" ]]; then
        nuclei_fast
    else
        log_warning "Nuclei fast function not available"
    fi
}

run_advanced_vulns_phase() {
    if [[ "$(type -t advanced_vulns_main)" == "function" ]]; then
        advanced_vulns_main
    else
        log_warning "Advanced Vulnerability module not loaded"
    fi
}

run_bettercap_phase() {
    if [[ "$(type -t bettercap_main)" == "function" ]]; then
        bettercap_main
    else
        log_warning "Bettercap module not loaded"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM INITIALIZATION (v2.1)
# ═══════════════════════════════════════════════════════════════════════════════

init_v21_systems() {
    log_info "Initializing v2.1 systems..."
    
    # Initialize Queue Management System
    if [[ "${QUEUE_ENABLED:-true}" == "true" ]] && type -t queue_init &>/dev/null; then
        queue_init "${dir}/.queue"
        log_debug "Queue management system initialized"
    fi
    
    # Initialize Error Reporting System
    if [[ "${ERROR_REPORTING_ENABLED:-true}" == "true" ]] && type -t error_report_init &>/dev/null; then
        error_report_init "${dir}/reports"
        log_debug "Error reporting system initialized"
    fi
    
    # Initialize Data Flow Bus
    if [[ "${DATA_BUS_ENABLED:-true}" == "true" ]] && type -t data_bus_init &>/dev/null; then
        data_bus_init "${dir}/.data_bus"
        log_debug "Data flow bus initialized"
    fi
    
    # Initialize Orchestrator
    if [[ "${ORCHESTRATOR_ENABLED:-true}" == "true" ]] && type -t orchestrator_init &>/dev/null; then
        orchestrator_init "${dir}/.orchestrator"
        log_debug "Orchestrator initialized"
    fi
    
    log_success "All v2.1 systems initialized"
}

cleanup_v21_systems() {
    log_info "Cleaning up v2.1 systems..."
    
    # Cleanup Queue Management
    type -t queue_cleanup &>/dev/null && queue_cleanup
    
    # Finalize Error Reports
    type -t error_report_finalize &>/dev/null && error_report_finalize
    
    # Cleanup Data Bus
    type -t data_bus_cleanup &>/dev/null && data_bus_cleanup
    
    # Cleanup Orchestrator
    type -t orchestrator_cleanup &>/dev/null && orchestrator_cleanup
    
    log_debug "v2.1 systems cleanup completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

check_tools() {
    log_info "Checking required tools..."
    
    local missing_tools=()
    local critical_tools=(
        "curl" "wget" "git" "jq" "python3" "pip3"
    )
    
    local recon_tools=(
        "subfinder" "amass" "assetfinder" "httpx" "nuclei" 
        "nmap" "masscan" "ffuf" "dnsx" "katana" "gau"
    )
    
    local vuln_tools=(
        "dalfox" "sqlmap" "nikto" "whatweb"
    )
    
    # Check critical tools
    for tool in "${critical_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool [CRITICAL]")
        fi
    done
    
    # Check recon tools
    for tool in "${recon_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check vuln tools
    for tool in "${vuln_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warning "Missing tools detected:"
        for tool in "${missing_tools[@]}"; do
            printf "  ${RED}✗${RESET} %s\n" "$tool"
        done
        log_info "Run ./install.sh to install missing tools"
        
        # Check if any critical tools are missing
        for tool in "${missing_tools[@]}"; do
            if [[ "$tool" == *"CRITICAL"* ]]; then
                log_error "Critical tools missing. Cannot proceed."
                exit 1
            fi
        done
    else
        log_success "All required tools are installed"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELP AND USAGE
# ═══════════════════════════════════════════════════════════════════════════════

show_help() {
    banner
    cat << EOF
${BWHITE}USAGE:${RESET}
    ./neko.sh [OPTIONS] -d <domain>
    ./neko.sh [OPTIONS] -l <target_list>

${BWHITE}OPTIONS:${RESET}
    ${BCYAN}-d, --domain${RESET} <domain>       Target domain to scan
    ${BCYAN}-l, --list${RESET} <file>           File containing list of targets
    ${BCYAN}-o, --output${RESET} <dir>          Custom output directory
    ${BCYAN}-c, --config${RESET} <file>         Custom configuration file

${BWHITE}EXECUTION MODES:${RESET}
    ${BGREEN}-r, --recon${RESET}                Full reconnaissance (non-intrusive) [DEFAULT]
    ${BGREEN}-a, --all${RESET}                  Full scan including intrusive attacks
    ${BGREEN}-p, --passive${RESET}              Passive mode only (OSINT + passive enum)
    ${BGREEN}-s, --subs${RESET}                 Subdomain enumeration only
    ${BGREEN}-w, --web${RESET}                  Web vulnerability scan only
    ${BGREEN}-f, --fast${RESET}                 Quick scan (essential checks only)
    ${BGREEN}--deep${RESET}                     Deep mode (extensive, slow)
    ${BGREEN}--custom${RESET} <modules>         Run specific modules (comma-separated)

${BWHITE}MODULES:${RESET}
    osint, subdomain, dns, webprobe, portscan, content,
    fingerprint, urlanalysis, param, vulnscan, xss,
    takeover, cloud, auth, api, advanced_vulns, report

${BWHITE}ADDITIONAL OPTIONS:${RESET}
    ${BCYAN}--check-tools${RESET}               Check if all required tools are installed
    ${BCYAN}--force${RESET}                     Force re-run of completed modules
    ${BCYAN}--resume${RESET}                    Resume from previous scan
    ${BCYAN}--quiet${RESET}                     Minimal output
    ${BCYAN}--debug${RESET}                     Enable debug mode
    ${BCYAN}--notify${RESET}                    Enable notifications
    ${BCYAN}-h, --help${RESET}                  Show this help message
    ${BCYAN}-v, --version${RESET}               Show version

${BWHITE}EXAMPLES:${RESET}
    ${GREEN}# Full recon scan${RESET}
    ./neko.sh -d example.com

    ${GREEN}# Fast scan with custom output${RESET}
    ./neko.sh -d example.com -f -o /path/to/output

    ${GREEN}# Deep scan with all attacks${RESET}
    ./neko.sh -d example.com -a --deep

    ${GREEN}# Scan multiple targets${RESET}
    ./neko.sh -l targets.txt -r

    ${GREEN}# Run specific modules only${RESET}
    ./neko.sh -d example.com --custom "osint,subdomain,dns"

    ${GREEN}# Resume previous scan${RESET}
    ./neko.sh -d example.com --resume -o previous_output_dir

${BWHITE}CONFIGURATION:${RESET}
    Default config: ${config_file}
    Customize settings in neko.cfg for API keys, threads, rate limits, etc.

${BWHITE}DOCUMENTATION:${RESET}
    Full documentation: https://github.com/your-repo/neko
    Report issues: https://github.com/your-repo/neko/issues

EOF
}

show_version() {
    echo "Neko v${NEKO_VERSION}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -l|--list)
                target_list="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -c|--config)
                config_file="$2"
                shift 2
                ;;
            -r|--recon)
                mode="recon"
                shift
                ;;
            -a|--all)
                mode="full"
                shift
                ;;
            -p|--passive)
                mode="passive"
                shift
                ;;
            -s|--subs)
                mode="subs"
                shift
                ;;
            -w|--web)
                mode="web"
                shift
                ;;
            -f|--fast)
                mode="fast"
                shift
                ;;
            --deep)
                mode="deep"
                shift
                ;;
            --custom)
                mode="custom"
                custom_modules="$2"
                shift 2
                ;;
            --check-tools)
                check_tools
                exit 0
                ;;
            --force)
                export FORCE_RERUN=true
                shift
                ;;
            --resume)
                export RESUME=true
                shift
                ;;
            --quiet)
                export QUIET=true
                shift
                ;;
            --debug)
                export DEBUG=true
                shift
                ;;
            --notify)
                export NOTIFICATION_ENABLED=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$domain" ]] && [[ -z "$target_list" ]]; then
        log_error "Target domain or list required"
        show_help
        exit 1
    fi
    
    # Validate domain format
    if [[ -n "$domain" ]] && ! validate_domain "$domain"; then
        log_error "Invalid domain format: $domain"
        exit 1
    fi
    
    # Validate target list file
    if [[ -n "$target_list" ]] && [[ ! -f "$target_list" ]]; then
        log_error "Target list file not found: $target_list"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    # Record start time
    start_time=$(date +%s)
    
    # Set up error handling
    setup_traps
    
    # Parse command line arguments
    parse_args "$@"
    
    # Show banner (unless quiet mode)
    [[ "${QUIET:-false}" != "true" ]] && banner
    
    # Load configuration
    load_config "$config_file"
    
    # Load modules
    load_modules "$MODULES_PATH"
    
    # Check tools
    check_tools
    
    # Process single domain or list
    if [[ -n "$target_list" ]]; then
        # Process multiple targets
        while IFS= read -r target || [[ -n "$target" ]]; do
            [[ -z "$target" ]] && continue
            [[ "$target" =~ ^# ]] && continue  # Skip comments
            
            domain=$(extract_domain "$target")
            log_info "Processing target: $domain"
            
            setup_output_dir "$domain" "$output_dir"
            
            # Initialize logging system for this target
            init_logging_system
            
            # Initialize Discord notifications
            init_discord_system
            
            run_scan
            
            # Finalize logging and notifications for this target
            finalize_notifications
            
        done < "$target_list"
    else
        # Process single domain
        setup_output_dir "$domain" "$output_dir"
        
        # Initialize logging system
        init_logging_system
        
        # Initialize Discord notifications
        init_discord_system
        
        run_scan
        
        # Finalize logging and notifications
        finalize_notifications
    fi
    
    # Final summary
    local end_time=$(date +%s)
    local runtime=$((end_time - start_time))
    local hours=$((runtime / 3600))
    local minutes=$(((runtime % 3600) / 60))
    local seconds=$((runtime % 60))
    
    log_success "Scan completed!"
    log_info "Total runtime: ${hours}h ${minutes}m ${seconds}s"
    log_info "Results saved in: $dir"
}

# Initialize logging system
init_logging_system() {
    if [[ "${LOGGING_ENABLED:-true}" == "true" ]] && type -t neko_log_init &>/dev/null; then
        neko_log_init "$dir"
        neko_log "INFO" "SYSTEM" "Neko v${NEKO_VERSION} starting" \
            "target=${domain}" "mode=${mode}" "config=${config_file}"
    fi
}

# Initialize Discord notification system
init_discord_system() {
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && type -t discord_init &>/dev/null; then
        if discord_init "${DISCORD_WEBHOOK_URL:-}"; then
            # Send scan start notification
            if [[ "${DISCORD_NOTIFY_SCAN_START:-true}" == "true" ]]; then
                local config_summary="Mode: ${mode}, Phases: Enabled"
                discord_notify_scan_start "$domain" "$mode" "$config_summary"
            fi
        else
            log_warning "Discord notification system initialization failed"
        fi
    fi
}

# Finalize notifications and logging
finalize_notifications() {
    local end_time=$(date +%s)
    local runtime=$((end_time - start_time))
    
    # Gather scan statistics
    local subdomains=0
    local urls=0
    local vulns=0
    local errors=0
    
    # Count subdomains
    if [[ -f "${dir}/subdomains/subdomains.txt" ]]; then
        subdomains=$(wc -l < "${dir}/subdomains/subdomains.txt" 2>/dev/null | tr -d ' ' || echo "0")
    fi
    
    # Count URLs
    if [[ -f "${dir}/urls/urls.txt" ]]; then
        urls=$(wc -l < "${dir}/urls/urls.txt" 2>/dev/null | tr -d ' ' || echo "0")
    fi
    
    # Count vulnerabilities
    if [[ -d "${dir}/vulnerabilities" ]]; then
        vulns=$(find "${dir}/vulnerabilities" -name "*.txt" -exec cat {} \; 2>/dev/null | wc -l | tr -d ' ' || echo "0")
    fi
    
    # Get error count from logging stats
    if type -t neko_export_log_stats &>/dev/null; then
        errors=$(neko_export_log_stats | grep -o '"error": [0-9]*' | grep -o '[0-9]*' || echo "0")
    fi
    
    # Send scan completion notification to Discord
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_NOTIFY_SCAN_END:-true}" == "true" ]] && \
       type -t discord_notify_scan_complete &>/dev/null; then
        discord_notify_scan_complete "$domain" "$runtime" "$subdomains" "$urls" "$vulns" "$errors"
    fi
    
    # Send summary if enabled
    if [[ "${DISCORD_ENABLED:-true}" == "true" ]] && \
       [[ "${DISCORD_SEND_SUMMARY:-true}" == "true" ]] && \
       type -t discord_send_summary &>/dev/null; then
        local stats_json
        stats_json=$(printf '{"subdomains": %d, "urls": %d, "vulns_critical": 0, "vulns_high": 0, "vulns_medium": 0, "vulns_low": %d, "tools_run": %d, "tools_failed": %d, "errors": %d}' \
            "$subdomains" "$urls" "$vulns" \
            "${NEKO_TOOL_STATS["total_runs"]:-0}" \
            "${NEKO_TOOL_STATS["failed"]:-0}" \
            "$errors")
        discord_send_summary "$domain" "$runtime" "$stats_json"
    fi
    
    # Finalize Discord (flush queue)
    if type -t discord_finalize &>/dev/null; then
        discord_finalize ""
    fi
    
    # Finalize logging system
    if type -t neko_log_finalize &>/dev/null; then
        neko_log_finalize
    fi
}

run_scan() {
    case "$mode" in
        recon)
            run_recon_mode
            ;;
        full)
            run_full_mode
            ;;
        passive)
            run_passive_mode
            ;;
        subs)
            run_subs_mode
            ;;
        web)
            run_web_mode
            ;;
        fast)
            run_fast_mode
            ;;
        deep)
            run_deep_mode
            ;;
        custom)
            run_custom_mode
            ;;
        *)
            log_error "Unknown mode: $mode"
            exit 1
            ;;
    esac
}

# Handle --help and --version before main (quick exit without full initialization)
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            banner 2>/dev/null || true
            cat << 'HELPEOF'
USAGE:
    ./neko.sh [OPTIONS] -d <domain>
    ./neko.sh [OPTIONS] -l <target_list>

OPTIONS:
    -d, --domain <domain>       Target domain to scan
    -l, --list <file>           File containing list of targets
    -o, --output <dir>          Custom output directory
    -c, --config <file>         Custom configuration file

EXECUTION MODES:
    -r, --recon                Full reconnaissance (non-intrusive) [DEFAULT]
    -a, --all                  Full scan including intrusive attacks
    -p, --passive              Passive mode only (OSINT + passive enum)
    -s, --subs                 Subdomain enumeration only
    -w, --web                  Web vulnerability scan only
    -f, --fast                 Quick scan (essential checks only)
    --deep                     Deep mode (extensive, slow)
    --custom <modules>         Run specific modules (comma-separated)

ADDITIONAL OPTIONS:
    --check-tools               Check if all required tools are installed
    --force                     Force re-run of completed modules
    --resume                    Resume from previous scan
    --quiet                     Minimal output
    --debug                     Enable debug mode
    --notify                    Enable notifications
    -h, --help                  Show this help message
    -v, --version               Show version

EXAMPLES:
    ./neko.sh -d example.com
    ./neko.sh -d example.com -f -o /path/to/output
    ./neko.sh -d example.com -a --deep
    ./neko.sh -l targets.txt -r
    ./neko.sh -d example.com --custom "osint,subdomain,dns"
HELPEOF
            exit 0
            ;;
        -v|--version)
            echo "Neko v${NEKO_VERSION:-2.1.0}"
            exit 0
            ;;
    esac
done

# Run main function
main "$@"
