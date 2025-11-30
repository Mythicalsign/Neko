#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED LOGGING SYSTEM
# Comprehensive logging framework for bug bounty automation
# Version: 2.2.0
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Log levels (numeric for comparison)
declare -gA LOG_LEVELS=(
    ["TRACE"]=0
    ["DEBUG"]=1
    ["INFO"]=2
    ["NOTICE"]=3
    ["WARNING"]=4
    ["ERROR"]=5
    ["CRITICAL"]=6
    ["ALERT"]=7
    ["EMERGENCY"]=8
)

# Current log level (default: INFO)
declare -g NEKO_LOG_LEVEL="${NEKO_LOG_LEVEL:-INFO}"

# Log file paths
declare -g NEKO_LOG_DIR=""
declare -g NEKO_MAIN_LOG=""
declare -g NEKO_ERROR_LOG=""
declare -g NEKO_DEBUG_LOG=""
declare -g NEKO_AUDIT_LOG=""
declare -g NEKO_TOOL_LOG=""
declare -g NEKO_NETWORK_LOG=""
declare -g NEKO_VULN_LOG=""
declare -g NEKO_PERFORMANCE_LOG=""

# Log formatting
declare -g NEKO_LOG_FORMAT="${NEKO_LOG_FORMAT:-detailed}"  # simple, detailed, json
declare -g NEKO_LOG_TIMESTAMP_FORMAT="%Y-%m-%d %H:%M:%S.%3N"
declare -g NEKO_LOG_MAX_SIZE="${NEKO_LOG_MAX_SIZE:-104857600}"  # 100MB default
declare -g NEKO_LOG_ROTATE="${NEKO_LOG_ROTATE:-true}"
declare -g NEKO_LOG_ROTATE_COUNT="${NEKO_LOG_ROTATE_COUNT:-5}"

# Session tracking
declare -g NEKO_SESSION_ID=""
declare -g NEKO_SESSION_START=""
declare -g NEKO_SESSION_TARGET=""

# Statistics tracking
declare -gA NEKO_LOG_STATS=(
    ["total"]=0
    ["trace"]=0
    ["debug"]=0
    ["info"]=0
    ["notice"]=0
    ["warning"]=0
    ["error"]=0
    ["critical"]=0
    ["alert"]=0
    ["emergency"]=0
)

# Tool execution tracking
declare -gA NEKO_TOOL_STATS=(
    ["total_runs"]=0
    ["successful"]=0
    ["failed"]=0
    ["timeout"]=0
    ["skipped"]=0
)

# ─────────────────────────────────────────────────────────────────────────────
# INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────

# Initialize the logging system
neko_log_init() {
    local output_dir="${1:-${dir:-/tmp/neko_logs}}"
    
    # Generate session ID
    NEKO_SESSION_ID="$(date +%Y%m%d_%H%M%S)_$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 12)"
    NEKO_SESSION_START="$(date +%s)"
    NEKO_SESSION_TARGET="${domain:-unknown}"
    
    # Set up log directory
    NEKO_LOG_DIR="${output_dir}/logs"
    mkdir -p "$NEKO_LOG_DIR"
    mkdir -p "${NEKO_LOG_DIR}/tools"
    mkdir -p "${NEKO_LOG_DIR}/phases"
    mkdir -p "${NEKO_LOG_DIR}/archive"
    
    # Initialize log files
    NEKO_MAIN_LOG="${NEKO_LOG_DIR}/neko_${NEKO_SESSION_ID}.log"
    NEKO_ERROR_LOG="${NEKO_LOG_DIR}/errors_${NEKO_SESSION_ID}.log"
    NEKO_DEBUG_LOG="${NEKO_LOG_DIR}/debug_${NEKO_SESSION_ID}.log"
    NEKO_AUDIT_LOG="${NEKO_LOG_DIR}/audit_${NEKO_SESSION_ID}.log"
    NEKO_TOOL_LOG="${NEKO_LOG_DIR}/tools_${NEKO_SESSION_ID}.log"
    NEKO_NETWORK_LOG="${NEKO_LOG_DIR}/network_${NEKO_SESSION_ID}.log"
    NEKO_VULN_LOG="${NEKO_LOG_DIR}/vulnerabilities_${NEKO_SESSION_ID}.log"
    NEKO_PERFORMANCE_LOG="${NEKO_LOG_DIR}/performance_${NEKO_SESSION_ID}.log"
    
    # Write session header
    _log_session_header
    
    # Set up log rotation
    if [[ "${NEKO_LOG_ROTATE}" == "true" ]]; then
        _setup_log_rotation
    fi
    
    neko_log "INFO" "SYSTEM" "Logging system initialized" "session_id=${NEKO_SESSION_ID}"
    neko_log "INFO" "SYSTEM" "Log directory: ${NEKO_LOG_DIR}"
    
    return 0
}

# Write session header to main log
_log_session_header() {
    local header
    header=$(cat << EOF
═══════════════════════════════════════════════════════════════════════════════
 NEKO BUG BOUNTY AUTOMATION - LOG SESSION
═══════════════════════════════════════════════════════════════════════════════
 Session ID    : ${NEKO_SESSION_ID}
 Start Time    : $(date -d "@${NEKO_SESSION_START}" '+%Y-%m-%d %H:%M:%S %Z')
 Target        : ${NEKO_SESSION_TARGET}
 Hostname      : $(hostname)
 User          : $(whoami)
 Working Dir   : $(pwd)
 Neko Version  : ${NEKO_VERSION:-unknown}
 Log Level     : ${NEKO_LOG_LEVEL}
 Log Format    : ${NEKO_LOG_FORMAT}
═══════════════════════════════════════════════════════════════════════════════

EOF
)
    echo "$header" > "$NEKO_MAIN_LOG"
    echo "$header" > "$NEKO_DEBUG_LOG"
}

# Set up log rotation
_setup_log_rotation() {
    # Check if main log exceeds size limit
    for logfile in "$NEKO_MAIN_LOG" "$NEKO_ERROR_LOG" "$NEKO_DEBUG_LOG"; do
        if [[ -f "$logfile" ]]; then
            local size
            size=$(stat -f%z "$logfile" 2>/dev/null || stat -c%s "$logfile" 2>/dev/null || echo "0")
            if [[ "$size" -gt "$NEKO_LOG_MAX_SIZE" ]]; then
                _rotate_log "$logfile"
            fi
        fi
    done
}

# Rotate a log file
_rotate_log() {
    local logfile="$1"
    local basename="${logfile%.log}"
    
    # Rotate existing backups
    for ((i=NEKO_LOG_ROTATE_COUNT; i>0; i--)); do
        local prev=$((i-1))
        if [[ -f "${basename}.${prev}.log.gz" ]]; then
            mv "${basename}.${prev}.log.gz" "${basename}.${i}.log.gz"
        fi
    done
    
    # Compress and rotate current log
    if [[ -f "$logfile" ]]; then
        gzip -c "$logfile" > "${basename}.0.log.gz"
        : > "$logfile"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CORE LOGGING FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

# Main logging function
# Usage: neko_log <LEVEL> <CATEGORY> <MESSAGE> [CONTEXT...]
neko_log() {
    local level="${1:-INFO}"
    local category="${2:-GENERAL}"
    local message="${3:-}"
    shift 3 2>/dev/null || true
    local context=("$@")
    
    # Check if level should be logged
    local level_num="${LOG_LEVELS[$level]:-2}"
    local current_level_num="${LOG_LEVELS[$NEKO_LOG_LEVEL]:-2}"
    
    if [[ "$level_num" -lt "$current_level_num" ]]; then
        return 0
    fi
    
    # Update statistics (use || true to prevent exit on first increment from 0)
    ((NEKO_LOG_STATS["total"]++)) || true
    ((NEKO_LOG_STATS["${level,,}"]++)) 2>/dev/null || true
    
    # Generate timestamp
    local timestamp
    timestamp=$(date +"$NEKO_LOG_TIMESTAMP_FORMAT" 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")
    
    # Format log entry based on format type
    local log_entry
    case "${NEKO_LOG_FORMAT}" in
        json)
            log_entry=$(_format_json_log "$timestamp" "$level" "$category" "$message" "${context[@]}")
            ;;
        simple)
            log_entry=$(_format_simple_log "$timestamp" "$level" "$message")
            ;;
        detailed|*)
            log_entry=$(_format_detailed_log "$timestamp" "$level" "$category" "$message" "${context[@]}")
            ;;
    esac
    
    # Write to appropriate log files
    _write_log_entry "$level" "$log_entry"
    
    # Console output for important messages
    _console_output "$level" "$message"
}

# Format JSON log entry
_format_json_log() {
    local timestamp="$1"
    local level="$2"
    local category="$3"
    local message="$4"
    shift 4
    local context=("$@")
    
    local context_json=""
    if [[ ${#context[@]} -gt 0 ]]; then
        context_json=", \"context\": {"
        local first=true
        for ctx in "${context[@]}"; do
            if [[ "$ctx" == *"="* ]]; then
                local key="${ctx%%=*}"
                local value="${ctx#*=}"
                [[ "$first" == "true" ]] || context_json+=", "
                context_json+="\"${key}\": \"${value}\""
                first=false
            fi
        done
        context_json+="}"
    fi
    
    printf '{"timestamp": "%s", "session_id": "%s", "level": "%s", "category": "%s", "message": "%s"%s}\n' \
        "$timestamp" "$NEKO_SESSION_ID" "$level" "$category" "$message" "$context_json"
}

# Format simple log entry
_format_simple_log() {
    local timestamp="$1"
    local level="$2"
    local message="$3"
    
    printf "[%s] [%s] %s\n" "$timestamp" "$level" "$message"
}

# Format detailed log entry
_format_detailed_log() {
    local timestamp="$1"
    local level="$2"
    local category="$3"
    local message="$4"
    shift 4
    local context=("$@")
    
    local entry
    entry=$(printf "[%s] [%s] [%-10s] [%-15s] %s" "$timestamp" "$NEKO_SESSION_ID" "$level" "$category" "$message")
    
    if [[ ${#context[@]} -gt 0 ]]; then
        entry+=" |"
        for ctx in "${context[@]}"; do
            entry+=" $ctx"
        done
    fi
    
    printf "%s\n" "$entry"
}

# Write log entry to appropriate files
_write_log_entry() {
    local level="$1"
    local entry="$2"
    
    # Skip if log files not initialized
    [[ -z "$NEKO_MAIN_LOG" ]] && return 0
    
    # Always write to main log
    [[ -n "$NEKO_MAIN_LOG" ]] && echo "$entry" >> "$NEKO_MAIN_LOG" 2>/dev/null || true
    
    # Write to debug log (all levels)
    [[ -n "$NEKO_DEBUG_LOG" ]] && echo "$entry" >> "$NEKO_DEBUG_LOG" 2>/dev/null || true
    
    # Write to error log for warnings and above
    case "$level" in
        WARNING|ERROR|CRITICAL|ALERT|EMERGENCY)
            [[ -n "$NEKO_ERROR_LOG" ]] && echo "$entry" >> "$NEKO_ERROR_LOG" 2>/dev/null || true
            ;;
    esac
    
    # Write to audit log for important actions
    case "$level" in
        NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY)
            [[ -n "$NEKO_AUDIT_LOG" ]] && echo "$entry" >> "$NEKO_AUDIT_LOG" 2>/dev/null || true
            ;;
    esac
}

# Console output with colors
_console_output() {
    local level="$1"
    local message="$2"
    
    # Skip console output in quiet mode
    [[ "${QUIET:-false}" == "true" ]] && return 0
    
    local color=""
    local prefix=""
    
    case "$level" in
        TRACE)
            color="\033[0;90m"  # Dark gray
            prefix="[TRACE]"
            ;;
        DEBUG)
            color="\033[0;36m"  # Cyan
            prefix="[DEBUG]"
            [[ "${DEBUG:-false}" != "true" ]] && return 0
            ;;
        INFO)
            color="\033[0;34m"  # Blue
            prefix="[INFO]"
            ;;
        NOTICE)
            color="\033[0;35m"  # Magenta
            prefix="[NOTICE]"
            ;;
        WARNING)
            color="\033[0;33m"  # Yellow
            prefix="[WARNING]"
            ;;
        ERROR)
            color="\033[0;31m"  # Red
            prefix="[ERROR]"
            ;;
        CRITICAL)
            color="\033[1;31m"  # Bold red
            prefix="[CRITICAL]"
            ;;
        ALERT)
            color="\033[1;33m"  # Bold yellow
            prefix="[ALERT]"
            ;;
        EMERGENCY)
            color="\033[1;37;41m"  # White on red
            prefix="[EMERGENCY]"
            ;;
    esac
    
    local reset="\033[0m"
    local timestamp
    timestamp=$(date +"%H:%M:%S")
    
    printf "%b%s %s %s%b\n" "$color" "$prefix" "[$timestamp]" "$message" "$reset"
}

# ─────────────────────────────────────────────────────────────────────────────
# SPECIALIZED LOGGING FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Log phase start
neko_log_phase_start() {
    local phase_name="$1"
    local phase_number="${2:-0}"
    local description="${3:-}"
    
    local phase_log="${NEKO_LOG_DIR}/phases/phase_${phase_number}_${phase_name}_${NEKO_SESSION_ID}.log"
    
    neko_log "NOTICE" "PHASE" "Starting Phase ${phase_number}: ${phase_name}" \
        "description=${description}" "phase_log=${phase_log}"
    
    # Create phase-specific log
    cat << EOF > "$phase_log"
═══════════════════════════════════════════════════════════════════════════════
 PHASE ${phase_number}: ${phase_name}
═══════════════════════════════════════════════════════════════════════════════
 Start Time: $(date '+%Y-%m-%d %H:%M:%S')
 Target    : ${NEKO_SESSION_TARGET}
 Session   : ${NEKO_SESSION_ID}
───────────────────────────────────────────────────────────────────────────────

EOF
    
    echo "$phase_log"
}

# Log phase end
neko_log_phase_end() {
    local phase_name="$1"
    local phase_number="${2:-0}"
    local status="${3:-completed}"
    local duration="${4:-0}"
    local findings="${5:-0}"
    
    neko_log "NOTICE" "PHASE" "Completed Phase ${phase_number}: ${phase_name}" \
        "status=${status}" "duration=${duration}s" "findings=${findings}"
    
    # Append to phase log
    local phase_log="${NEKO_LOG_DIR}/phases/phase_${phase_number}_${phase_name}_${NEKO_SESSION_ID}.log"
    if [[ -f "$phase_log" ]]; then
        cat << EOF >> "$phase_log"

───────────────────────────────────────────────────────────────────────────────
 END OF PHASE ${phase_number}
───────────────────────────────────────────────────────────────────────────────
 End Time  : $(date '+%Y-%m-%d %H:%M:%S')
 Status    : ${status}
 Duration  : ${duration} seconds
 Findings  : ${findings}
═══════════════════════════════════════════════════════════════════════════════
EOF
    fi
}

# Log tool execution
neko_log_tool_start() {
    local tool_name="$1"
    local phase="${2:-unknown}"
    local target="${3:-}"
    local command="${4:-}"
    
    local tool_start_time=$(date +%s)
    local tool_log="${NEKO_LOG_DIR}/tools/${tool_name}_${NEKO_SESSION_ID}.log"
    
    ((NEKO_TOOL_STATS["total_runs"]++)) || true
    
    neko_log "INFO" "TOOL" "Starting tool: ${tool_name}" \
        "phase=${phase}" "target=${target}" "command_length=${#command}"
    
    # Log to tool-specific file
    cat << EOF >> "$NEKO_TOOL_LOG"
───────────────────────────────────────────────────────────────────────────────
TOOL: ${tool_name}
Time: $(date '+%Y-%m-%d %H:%M:%S')
Phase: ${phase}
Target: ${target}
Command: ${command}
───────────────────────────────────────────────────────────────────────────────
EOF
    
    # Return start time for duration calculation
    echo "$tool_start_time"
}

# Log tool completion
neko_log_tool_end() {
    local tool_name="$1"
    local start_time="$2"
    local exit_code="${3:-0}"
    local output_lines="${4:-0}"
    local output_file="${5:-}"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    local status="SUCCESS"
    if [[ "$exit_code" -eq 124 ]]; then
        status="TIMEOUT"
        ((NEKO_TOOL_STATS["timeout"]++)) || true
        neko_log "WARNING" "TOOL" "Tool timed out: ${tool_name}" \
            "duration=${duration}s" "exit_code=${exit_code}"
    elif [[ "$exit_code" -ne 0 ]]; then
        status="FAILED"
        ((NEKO_TOOL_STATS["failed"]++)) || true
        neko_log "ERROR" "TOOL" "Tool failed: ${tool_name}" \
            "duration=${duration}s" "exit_code=${exit_code}"
    else
        ((NEKO_TOOL_STATS["successful"]++)) || true
        neko_log "INFO" "TOOL" "Tool completed: ${tool_name}" \
            "duration=${duration}s" "output_lines=${output_lines}"
    fi
    
    # Log performance metrics
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] TOOL=${tool_name} STATUS=${status} DURATION=${duration}s EXIT_CODE=${exit_code} OUTPUT_LINES=${output_lines} OUTPUT_FILE=${output_file}" >> "$NEKO_PERFORMANCE_LOG"
}

# Log tool skipped
neko_log_tool_skipped() {
    local tool_name="$1"
    local reason="${2:-already completed}"
    
    ((NEKO_TOOL_STATS["skipped"]++)) || true
    neko_log "DEBUG" "TOOL" "Skipping tool: ${tool_name}" "reason=${reason}"
}

# Log network activity
neko_log_network() {
    local activity_type="$1"
    local target="$2"
    local details="${3:-}"
    local response_code="${4:-}"
    local response_time="${5:-}"
    
    local entry="[$(date '+%Y-%m-%d %H:%M:%S')] [${activity_type}] ${target}"
    [[ -n "$response_code" ]] && entry+=" | code=${response_code}"
    [[ -n "$response_time" ]] && entry+=" | time=${response_time}ms"
    [[ -n "$details" ]] && entry+=" | ${details}"
    
    echo "$entry" >> "$NEKO_NETWORK_LOG"
    
    neko_log "DEBUG" "NETWORK" "${activity_type}: ${target}" \
        "response_code=${response_code}" "response_time=${response_time}"
}

# Log vulnerability finding
neko_log_vulnerability() {
    local severity="$1"
    local vuln_type="$2"
    local target="$3"
    local tool="${4:-unknown}"
    local details="${5:-}"
    local poc="${6:-}"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Write to vulnerability log in structured format
    cat << EOF >> "$NEKO_VULN_LOG"
═══════════════════════════════════════════════════════════════════════════════
VULNERABILITY FOUND
═══════════════════════════════════════════════════════════════════════════════
Timestamp : ${timestamp}
Severity  : ${severity}
Type      : ${vuln_type}
Target    : ${target}
Tool      : ${tool}
Details   : ${details}
PoC       : ${poc}
───────────────────────────────────────────────────────────────────────────────

EOF
    
    # Log to main log
    local level="INFO"
    case "${severity,,}" in
        critical) level="CRITICAL" ;;
        high) level="ALERT" ;;
        medium) level="WARNING" ;;
        low|info) level="NOTICE" ;;
    esac
    
    neko_log "$level" "VULN" "Found ${severity} vulnerability: ${vuln_type}" \
        "target=${target}" "tool=${tool}" "details=${details}"
}

# Log subdomain discovery
neko_log_subdomain() {
    local subdomain="$1"
    local source="${2:-unknown}"
    local resolved_ip="${3:-}"
    
    neko_log "DEBUG" "SUBDOMAIN" "Discovered: ${subdomain}" \
        "source=${source}" "ip=${resolved_ip}"
}

# Log URL discovery
neko_log_url() {
    local url="$1"
    local source="${2:-unknown}"
    local status_code="${3:-}"
    
    neko_log "DEBUG" "URL" "Discovered: ${url}" \
        "source=${source}" "status=${status_code}"
}

# ─────────────────────────────────────────────────────────────────────────────
# ERROR LOGGING
# ─────────────────────────────────────────────────────────────────────────────

# Log error with stack trace
neko_log_error() {
    local message="$1"
    local error_code="${2:-1}"
    local recoverable="${3:-true}"
    
    # Get stack trace
    local stack_trace=""
    local i=1
    while caller $i &>/dev/null; do
        local frame=$(caller $i)
        stack_trace+="  at ${frame}\n"
        ((i++))
    done
    
    # Get system state
    local cpu_load
    cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    local mem_free
    mem_free=$(free -h 2>/dev/null | awk '/^Mem:/ {print $4}' || echo "unknown")
    
    neko_log "ERROR" "ERROR" "$message" \
        "error_code=${error_code}" \
        "recoverable=${recoverable}" \
        "cpu_load=${cpu_load}" \
        "mem_free=${mem_free}"
    
    # Write detailed error to error log
    cat << EOF >> "$NEKO_ERROR_LOG"
═══════════════════════════════════════════════════════════════════════════════
ERROR DETAILS
═══════════════════════════════════════════════════════════════════════════════
Timestamp   : $(date '+%Y-%m-%d %H:%M:%S')
Message     : ${message}
Error Code  : ${error_code}
Recoverable : ${recoverable}
CPU Load    : ${cpu_load}
Memory Free : ${mem_free}
Stack Trace :
$(printf '%b' "$stack_trace")
───────────────────────────────────────────────────────────────────────────────

EOF
}

# Log exception/critical error
neko_log_exception() {
    local message="$1"
    local exception_type="${2:-Unknown}"
    
    neko_log "CRITICAL" "EXCEPTION" "${exception_type}: ${message}"
    neko_log_error "$message" "1" "false"
}

# ─────────────────────────────────────────────────────────────────────────────
# AUDIT LOGGING
# ─────────────────────────────────────────────────────────────────────────────

# Log configuration change
neko_log_config_change() {
    local setting="$1"
    local old_value="$2"
    local new_value="$3"
    
    neko_log "NOTICE" "CONFIG" "Configuration changed: ${setting}" \
        "old_value=${old_value}" "new_value=${new_value}"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] CONFIG_CHANGE: ${setting} | ${old_value} -> ${new_value}" >> "$NEKO_AUDIT_LOG"
}

# Log security event
neko_log_security() {
    local event_type="$1"
    local description="$2"
    local severity="${3:-MEDIUM}"
    
    neko_log "WARNING" "SECURITY" "${event_type}: ${description}" "severity=${severity}"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SECURITY_EVENT: ${event_type} | ${description} | Severity: ${severity}" >> "$NEKO_AUDIT_LOG"
}

# ─────────────────────────────────────────────────────────────────────────────
# PERFORMANCE LOGGING
# ─────────────────────────────────────────────────────────────────────────────

# Log performance metric
neko_log_performance() {
    local metric_name="$1"
    local value="$2"
    local unit="${3:-}"
    local context="${4:-}"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] METRIC=${metric_name} VALUE=${value} UNIT=${unit} CONTEXT=${context}" >> "$NEKO_PERFORMANCE_LOG"
    
    neko_log "DEBUG" "PERF" "${metric_name}=${value}${unit}" "context=${context}"
}

# Start performance timer
neko_perf_start() {
    local timer_name="$1"
    local start_time=$(date +%s%N)
    
    echo "$start_time"
}

# End performance timer and log
neko_perf_end() {
    local timer_name="$1"
    local start_time="$2"
    
    local end_time=$(date +%s%N)
    local duration_ns=$((end_time - start_time))
    local duration_ms=$((duration_ns / 1000000))
    
    neko_log_performance "$timer_name" "$duration_ms" "ms"
    
    echo "$duration_ms"
}

# ─────────────────────────────────────────────────────────────────────────────
# SESSION SUMMARY AND FINALIZATION
# ─────────────────────────────────────────────────────────────────────────────

# Generate session summary
neko_log_session_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - NEKO_SESSION_START))
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    
    local summary
    summary=$(cat << EOF

═══════════════════════════════════════════════════════════════════════════════
 SESSION SUMMARY
═══════════════════════════════════════════════════════════════════════════════
 Session ID     : ${NEKO_SESSION_ID}
 Target         : ${NEKO_SESSION_TARGET}
 Duration       : ${hours}h ${minutes}m ${seconds}s
 End Time       : $(date '+%Y-%m-%d %H:%M:%S %Z')
───────────────────────────────────────────────────────────────────────────────
 LOG STATISTICS
───────────────────────────────────────────────────────────────────────────────
 Total Entries  : ${NEKO_LOG_STATS["total"]}
 TRACE          : ${NEKO_LOG_STATS["trace"]}
 DEBUG          : ${NEKO_LOG_STATS["debug"]}
 INFO           : ${NEKO_LOG_STATS["info"]}
 NOTICE         : ${NEKO_LOG_STATS["notice"]}
 WARNING        : ${NEKO_LOG_STATS["warning"]}
 ERROR          : ${NEKO_LOG_STATS["error"]}
 CRITICAL       : ${NEKO_LOG_STATS["critical"]}
───────────────────────────────────────────────────────────────────────────────
 TOOL STATISTICS
───────────────────────────────────────────────────────────────────────────────
 Total Runs     : ${NEKO_TOOL_STATS["total_runs"]}
 Successful     : ${NEKO_TOOL_STATS["successful"]}
 Failed         : ${NEKO_TOOL_STATS["failed"]}
 Timeout        : ${NEKO_TOOL_STATS["timeout"]}
 Skipped        : ${NEKO_TOOL_STATS["skipped"]}
───────────────────────────────────────────────────────────────────────────────
 LOG FILES
───────────────────────────────────────────────────────────────────────────────
 Main Log       : ${NEKO_MAIN_LOG}
 Error Log      : ${NEKO_ERROR_LOG}
 Debug Log      : ${NEKO_DEBUG_LOG}
 Audit Log      : ${NEKO_AUDIT_LOG}
 Tool Log       : ${NEKO_TOOL_LOG}
 Network Log    : ${NEKO_NETWORK_LOG}
 Vuln Log       : ${NEKO_VULN_LOG}
 Performance    : ${NEKO_PERFORMANCE_LOG}
═══════════════════════════════════════════════════════════════════════════════

EOF
)
    
    echo "$summary" >> "$NEKO_MAIN_LOG"
    echo "$summary"
    
    neko_log "INFO" "SYSTEM" "Session completed" \
        "duration=${duration}s" \
        "total_logs=${NEKO_LOG_STATS["total"]}" \
        "errors=${NEKO_LOG_STATS["error"]}" \
        "warnings=${NEKO_LOG_STATS["warning"]}"
    
    # Return summary data as JSON for Discord notifications
    printf '{"session_id": "%s", "target": "%s", "duration_seconds": %d, "total_logs": %d, "errors": %d, "warnings": %d, "tools_run": %d, "tools_failed": %d}' \
        "$NEKO_SESSION_ID" "$NEKO_SESSION_TARGET" "$duration" \
        "${NEKO_LOG_STATS["total"]}" "${NEKO_LOG_STATS["error"]}" "${NEKO_LOG_STATS["warning"]}" \
        "${NEKO_TOOL_STATS["total_runs"]}" "${NEKO_TOOL_STATS["failed"]}"
}

# Finalize logging system
neko_log_finalize() {
    neko_log "INFO" "SYSTEM" "Finalizing logging system..."
    
    # Generate summary
    local summary_json
    summary_json=$(neko_log_session_summary)
    
    # Archive old logs if rotation enabled
    if [[ "${NEKO_LOG_ROTATE}" == "true" ]]; then
        _archive_old_logs
    fi
    
    echo "$summary_json"
}

# Archive old logs
_archive_old_logs() {
    local archive_dir="${NEKO_LOG_DIR}/archive"
    local archive_date=$(date +%Y%m%d)
    
    # Move logs older than current session to archive
    find "$NEKO_LOG_DIR" -maxdepth 1 -name "*.log" -type f -mmin +1440 2>/dev/null | while read -r logfile; do
        local basename=$(basename "$logfile")
        gzip -c "$logfile" > "${archive_dir}/${archive_date}_${basename}.gz"
        rm -f "$logfile"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Set log level
neko_set_log_level() {
    local new_level="$1"
    
    if [[ -n "${LOG_LEVELS[$new_level]}" ]]; then
        local old_level="$NEKO_LOG_LEVEL"
        NEKO_LOG_LEVEL="$new_level"
        neko_log_config_change "NEKO_LOG_LEVEL" "$old_level" "$new_level"
    else
        neko_log "WARNING" "SYSTEM" "Invalid log level: ${new_level}"
    fi
}

# Get current log file path
neko_get_log_file() {
    local log_type="${1:-main}"
    
    case "$log_type" in
        main) echo "$NEKO_MAIN_LOG" ;;
        error) echo "$NEKO_ERROR_LOG" ;;
        debug) echo "$NEKO_DEBUG_LOG" ;;
        audit) echo "$NEKO_AUDIT_LOG" ;;
        tool) echo "$NEKO_TOOL_LOG" ;;
        network) echo "$NEKO_NETWORK_LOG" ;;
        vuln) echo "$NEKO_VULN_LOG" ;;
        performance) echo "$NEKO_PERFORMANCE_LOG" ;;
        *) echo "$NEKO_MAIN_LOG" ;;
    esac
}

# Export log statistics as JSON
neko_export_log_stats() {
    printf '{"total": %d, "trace": %d, "debug": %d, "info": %d, "notice": %d, "warning": %d, "error": %d, "critical": %d, "alert": %d, "emergency": %d}' \
        "${NEKO_LOG_STATS["total"]}" \
        "${NEKO_LOG_STATS["trace"]}" \
        "${NEKO_LOG_STATS["debug"]}" \
        "${NEKO_LOG_STATS["info"]}" \
        "${NEKO_LOG_STATS["notice"]}" \
        "${NEKO_LOG_STATS["warning"]}" \
        "${NEKO_LOG_STATS["error"]}" \
        "${NEKO_LOG_STATS["critical"]}" \
        "${NEKO_LOG_STATS["alert"]}" \
        "${NEKO_LOG_STATS["emergency"]}"
}

# Shorthand logging functions for convenience
log_trace() { neko_log "TRACE" "GENERAL" "$1" "${@:2}"; }
log_debug() { neko_log "DEBUG" "GENERAL" "$1" "${@:2}"; }
log_info() { neko_log "INFO" "GENERAL" "$1" "${@:2}"; }
log_notice() { neko_log "NOTICE" "GENERAL" "$1" "${@:2}"; }
log_warning() { neko_log "WARNING" "GENERAL" "$1" "${@:2}"; }
log_error() { neko_log "ERROR" "GENERAL" "$1" "${@:2}"; }
log_critical() { neko_log "CRITICAL" "GENERAL" "$1" "${@:2}"; }
log_alert() { neko_log "ALERT" "GENERAL" "$1" "${@:2}"; }
log_emergency() { neko_log "EMERGENCY" "GENERAL" "$1" "${@:2}"; }

# Export functions
export -f neko_log_init neko_log neko_log_phase_start neko_log_phase_end
export -f neko_log_tool_start neko_log_tool_end neko_log_tool_skipped
export -f neko_log_network neko_log_vulnerability neko_log_subdomain neko_log_url
export -f neko_log_error neko_log_exception neko_log_config_change neko_log_security
export -f neko_log_performance neko_perf_start neko_perf_end
export -f neko_log_session_summary neko_log_finalize neko_set_log_level
export -f neko_get_log_file neko_export_log_stats
export -f log_trace log_debug log_info log_notice log_warning log_error log_critical log_alert log_emergency
