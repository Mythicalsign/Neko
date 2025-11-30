#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED ERROR REPORTING SYSTEM
# Comprehensive error handling with detailed JSON error reports
# Version: 2.0.0
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR REPORTING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

declare -g ERROR_REPORT_DIR=""
declare -g ERROR_REPORT_FILE=""
declare -g ERROR_REPORT_SESSION_ID=""
declare -ga ERROR_REPORTS=()
declare -gA ERROR_STATISTICS=(
    ["total"]=0
    ["critical"]=0
    ["error"]=0
    ["warning"]=0
    ["info"]=0
    ["recovered"]=0
    ["unrecovered"]=0
)

# Error severity levels
readonly ERROR_SEVERITY_CRITICAL="critical"
readonly ERROR_SEVERITY_ERROR="error"
readonly ERROR_SEVERITY_WARNING="warning"
readonly ERROR_SEVERITY_INFO="info"

# Error categories
readonly ERROR_CAT_TOOL="tool_error"
readonly ERROR_CAT_NETWORK="network_error"
readonly ERROR_CAT_PERMISSION="permission_error"
readonly ERROR_CAT_TIMEOUT="timeout_error"
readonly ERROR_CAT_RESOURCE="resource_error"
readonly ERROR_CAT_CONFIG="configuration_error"
readonly ERROR_CAT_DEPENDENCY="dependency_error"
readonly ERROR_CAT_VALIDATION="validation_error"
readonly ERROR_CAT_SYSTEM="system_error"
readonly ERROR_CAT_UNKNOWN="unknown_error"

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

error_report_init() {
    local base_dir="${1:-${dir}/reports}"
    
    ERROR_REPORT_DIR="${base_dir}/errors"
    ERROR_REPORT_SESSION_ID="scan_$(date +%Y%m%d_%H%M%S)_$$"
    ERROR_REPORT_FILE="${ERROR_REPORT_DIR}/${ERROR_REPORT_SESSION_ID}_errors.json"
    
    ensure_dir "$ERROR_REPORT_DIR"
    
    # Initialize error report JSON file
    cat > "$ERROR_REPORT_FILE" << EOF
{
    "scan_session": {
        "id": "$ERROR_REPORT_SESSION_ID",
        "target": "${domain:-unknown}",
        "start_time": "$(date -Iseconds)",
        "end_time": null,
        "mode": "${mode:-unknown}",
        "neko_version": "${NEKO_VERSION:-2.0.0}"
    },
    "summary": {
        "total_errors": 0,
        "by_severity": {
            "critical": 0,
            "error": 0,
            "warning": 0,
            "info": 0
        },
        "by_category": {},
        "by_tool": {},
        "by_phase": {},
        "recovery_rate": 0
    },
    "errors": [],
    "recommendations": []
}
EOF
    
    # Create detailed logs directory
    ensure_dir "${ERROR_REPORT_DIR}/detailed_logs"
    
    log_debug "Error reporting system initialized: $ERROR_REPORT_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR RECORDING
# ═══════════════════════════════════════════════════════════════════════════════

# Record a detailed error
error_record() {
    local severity="$1"
    local category="$2"
    local tool="${3:-system}"
    local phase="${4:-unknown}"
    local message="$5"
    local details="${6:-}"
    local exit_code="${7:-1}"
    local command="${8:-}"
    local recovery_attempted="${9:-false}"
    local recovery_successful="${10:-false}"
    
    local timestamp=$(date -Iseconds)
    local error_id="err_$(date +%s%N)_$$"
    
    # Capture stack trace
    local stack_trace=""
    local i=0
    while caller $i > /dev/null 2>&1; do
        local frame=$(caller $i)
        stack_trace+="  at ${frame}\n"
        ((i++))
    done
    
    # Capture environment snapshot
    local env_snapshot=$(env | grep -E "^(PATH|HOME|USER|SHELL|TERM|LANG|LC_)" | head -20 | jq -Rs .)
    
    # Capture system state
    local system_state=""
    system_state=$(cat << EOF
{
    "cpu_load": "$(cat /proc/loadavg 2>/dev/null | awk '{print $1}' || echo 'N/A')",
    "memory_free": "$(free -m 2>/dev/null | awk '/Mem:/ {print $4}' || echo 'N/A')MB",
    "disk_free": "$(df -h . 2>/dev/null | awk 'NR==2 {print $4}' || echo 'N/A')",
    "open_files": "$(lsof 2>/dev/null | wc -l || echo 'N/A')",
    "running_processes": "$(ps aux 2>/dev/null | wc -l || echo 'N/A')"
}
EOF
)
    
    # Build error object
    local error_obj=$(cat << EOF
{
    "id": "$error_id",
    "timestamp": "$timestamp",
    "severity": "$severity",
    "category": "$category",
    "tool": "$tool",
    "phase": "$phase",
    "message": $(printf '%s' "$message" | jq -Rs .),
    "details": $(printf '%s' "$details" | jq -Rs .),
    "exit_code": $exit_code,
    "command": $(printf '%s' "$command" | jq -Rs .),
    "recovery": {
        "attempted": $recovery_attempted,
        "successful": $recovery_successful
    },
    "context": {
        "working_directory": "$PWD",
        "user": "${USER:-unknown}",
        "pid": $$,
        "parent_pid": $PPID
    },
    "stack_trace": $(printf '%b' "$stack_trace" | jq -Rs .),
    "system_state": $system_state,
    "environment": $env_snapshot
}
EOF
)
    
    # Add to in-memory array
    ERROR_REPORTS+=("$error_obj")
    
    # Update statistics
    ((ERROR_STATISTICS["total"]++))
    ((ERROR_STATISTICS["$severity"]++)) 2>/dev/null || ERROR_STATISTICS["$severity"]=1
    
    if [[ "$recovery_successful" == "true" ]]; then
        ((ERROR_STATISTICS["recovered"]++))
    else
        ((ERROR_STATISTICS["unrecovered"]++))
    fi
    
    # Write to report file
    _error_update_report_file "$error_obj" "$severity" "$category" "$tool" "$phase"
    
    # Write detailed log for this error
    local detailed_log="${ERROR_REPORT_DIR}/detailed_logs/${error_id}.json"
    echo "$error_obj" | jq '.' > "$detailed_log"
    
    # Log to console
    case "$severity" in
        "$ERROR_SEVERITY_CRITICAL")
            log_error "[CRITICAL] [$tool] $message"
            notify "CRITICAL ERROR: $message" "error" "$tool"
            ;;
        "$ERROR_SEVERITY_ERROR")
            log_error "[$tool] $message"
            ;;
        "$ERROR_SEVERITY_WARNING")
            log_warning "[$tool] $message"
            ;;
        "$ERROR_SEVERITY_INFO")
            log_info "[$tool] $message"
            ;;
    esac
    
    return 0
}

# Update the main report file
_error_update_report_file() {
    local error_obj="$1"
    local severity="$2"
    local category="$3"
    local tool="$4"
    local phase="$5"
    
    [[ ! -f "$ERROR_REPORT_FILE" ]] && return
    
    # Use jq to update the report file
    local temp_file="${ERROR_REPORT_FILE}.tmp"
    
    jq --argjson err "$error_obj" \
       --arg sev "$severity" \
       --arg cat "$category" \
       --arg tool "$tool" \
       --arg phase "$phase" '
        .errors += [$err] |
        .summary.total_errors += 1 |
        .summary.by_severity[$sev] = ((.summary.by_severity[$sev] // 0) + 1) |
        .summary.by_category[$cat] = ((.summary.by_category[$cat] // 0) + 1) |
        .summary.by_tool[$tool] = ((.summary.by_tool[$tool] // 0) + 1) |
        .summary.by_phase[$phase] = ((.summary.by_phase[$phase] // 0) + 1)
    ' "$ERROR_REPORT_FILE" > "$temp_file" && mv "$temp_file" "$ERROR_REPORT_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SPECIALIZED ERROR RECORDING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Record tool execution error
error_tool_execution() {
    local tool="$1"
    local command="$2"
    local exit_code="$3"
    local stderr_output="$4"
    local phase="${5:-unknown}"
    
    # Determine severity based on exit code
    local severity="$ERROR_SEVERITY_ERROR"
    [[ $exit_code -eq 124 ]] && severity="$ERROR_SEVERITY_WARNING"  # Timeout
    [[ $exit_code -eq 137 ]] && severity="$ERROR_SEVERITY_CRITICAL"  # OOM killed
    
    # Determine category
    local category="$ERROR_CAT_TOOL"
    [[ $exit_code -eq 124 ]] && category="$ERROR_CAT_TIMEOUT"
    [[ $exit_code -eq 137 ]] && category="$ERROR_CAT_RESOURCE"
    [[ $exit_code -eq 127 ]] && category="$ERROR_CAT_DEPENDENCY"
    
    error_record "$severity" "$category" "$tool" "$phase" \
        "Tool execution failed with exit code $exit_code" \
        "$stderr_output" "$exit_code" "$command"
}

# Record network error
error_network() {
    local target="$1"
    local operation="$2"
    local details="${3:-}"
    local tool="${4:-curl}"
    local phase="${5:-unknown}"
    
    error_record "$ERROR_SEVERITY_WARNING" "$ERROR_CAT_NETWORK" "$tool" "$phase" \
        "Network error during $operation to $target" \
        "$details"
}

# Record timeout error
error_timeout() {
    local operation="$1"
    local timeout_seconds="$2"
    local tool="${3:-system}"
    local phase="${4:-unknown}"
    
    error_record "$ERROR_SEVERITY_WARNING" "$ERROR_CAT_TIMEOUT" "$tool" "$phase" \
        "Operation '$operation' timed out after ${timeout_seconds}s" \
        "Consider increasing timeout or reducing workload" 124
}

# Record resource error
error_resource() {
    local resource_type="$1"  # memory, cpu, disk, etc.
    local details="$2"
    local tool="${3:-system}"
    local phase="${4:-unknown}"
    
    error_record "$ERROR_SEVERITY_CRITICAL" "$ERROR_CAT_RESOURCE" "$tool" "$phase" \
        "Resource exhaustion: $resource_type" \
        "$details"
}

# Record dependency error
error_dependency() {
    local dependency="$1"
    local required_by="${2:-system}"
    local phase="${3:-unknown}"
    
    error_record "$ERROR_SEVERITY_ERROR" "$ERROR_CAT_DEPENDENCY" "$required_by" "$phase" \
        "Missing dependency: $dependency" \
        "Please install $dependency to enable this functionality" 127
}

# Record configuration error
error_config() {
    local config_item="$1"
    local issue="$2"
    local phase="${3:-unknown}"
    
    error_record "$ERROR_SEVERITY_WARNING" "$ERROR_CAT_CONFIG" "config" "$phase" \
        "Configuration issue with $config_item" \
        "$issue"
}

# Record validation error
error_validation() {
    local what="$1"
    local issue="$2"
    local tool="${3:-validation}"
    local phase="${4:-unknown}"
    
    error_record "$ERROR_SEVERITY_WARNING" "$ERROR_CAT_VALIDATION" "$tool" "$phase" \
        "Validation failed for $what" \
        "$issue"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SAFE EXECUTION WITH ERROR RECORDING
# ═══════════════════════════════════════════════════════════════════════════════

# Execute command with automatic error recording
error_safe_exec() {
    local tool="$1"
    local phase="$2"
    local timeout="${3:-3600}"
    shift 3
    local cmd="$@"
    
    local start_time=$(date +%s%N)
    local stdout_file=$(mktemp)
    local stderr_file=$(mktemp)
    local exit_code=0
    
    # Execute command
    timeout "$timeout" bash -c "$cmd" > "$stdout_file" 2> "$stderr_file" || exit_code=$?
    
    local end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    
    # Check for errors
    if [[ $exit_code -ne 0 ]]; then
        local stderr_content=$(cat "$stderr_file" | tail -100)
        
        # Try recovery
        local recovery_attempted=false
        local recovery_successful=false
        
        if [[ "${AUTO_RECOVERY:-true}" == "true" ]]; then
            recovery_attempted=true
            
            # Attempt recovery based on error type
            if _error_attempt_recovery "$tool" "$exit_code" "$stderr_content"; then
                recovery_successful=true
                
                # Retry the command
                exit_code=0
                timeout "$timeout" bash -c "$cmd" > "$stdout_file" 2> "$stderr_file" || exit_code=$?
            fi
        fi
        
        if [[ $exit_code -ne 0 ]]; then
            error_tool_execution "$tool" "$cmd" "$exit_code" "$stderr_content" "$phase"
        fi
    fi
    
    # Record execution metrics
    _error_record_execution_metrics "$tool" "$phase" "$duration_ms" "$exit_code"
    
    # Cleanup
    rm -f "$stdout_file" "$stderr_file"
    
    return $exit_code
}

# Attempt automatic recovery
_error_attempt_recovery() {
    local tool="$1"
    local exit_code="$2"
    local stderr="$3"
    
    log_debug "Attempting recovery for $tool (exit: $exit_code)"
    
    case "$exit_code" in
        124)  # Timeout
            # Reduce concurrency/rate
            log_info "Reducing rate limit for $tool due to timeout"
            export "${tool^^}_THREADS"=$((${!${tool^^}_THREADS:-10} / 2))
            return 0
            ;;
        137)  # OOM killed
            # Clear caches, reduce memory usage
            sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
            return 0
            ;;
        127)  # Command not found
            # Try fallback tool
            if [[ -n "${FALLBACK_TOOLS[$tool]:-}" ]]; then
                log_info "Tool $tool not found, using fallback"
                return 0
            fi
            return 1
            ;;
        *)
            # Check stderr for recoverable errors
            if echo "$stderr" | grep -qiE "rate.limit|429|too.many.requests"; then
                log_info "Rate limited, waiting before retry"
                sleep 60
                return 0
            fi
            
            if echo "$stderr" | grep -qiE "connection.reset|connection.refused|timeout"; then
                log_info "Network issue, waiting before retry"
                sleep 10
                return 0
            fi
            
            return 1
            ;;
    esac
}

# Record execution metrics
_error_record_execution_metrics() {
    local tool="$1"
    local phase="$2"
    local duration_ms="$3"
    local exit_code="$4"
    
    local metrics_file="${ERROR_REPORT_DIR}/execution_metrics.jsonl"
    
    echo "{\"tool\":\"$tool\",\"phase\":\"$phase\",\"duration_ms\":$duration_ms,\"exit_code\":$exit_code,\"timestamp\":\"$(date -Iseconds)\"}" \
        >> "$metrics_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

# Finalize the error report
error_report_finalize() {
    [[ ! -f "$ERROR_REPORT_FILE" ]] && return
    
    local end_time=$(date -Iseconds)
    local total=${ERROR_STATISTICS["total"]}
    local recovered=${ERROR_STATISTICS["recovered"]}
    local recovery_rate=0
    
    [[ $total -gt 0 ]] && recovery_rate=$((recovered * 100 / total))
    
    # Generate recommendations
    local recommendations=()
    
    # Analyze errors and generate recommendations
    if [[ ${ERROR_STATISTICS["critical"]:-0} -gt 0 ]]; then
        recommendations+=("Critical errors detected - review system resources and tool configurations")
    fi
    
    if jq -e '.summary.by_category.timeout_error > 5' "$ERROR_REPORT_FILE" > /dev/null 2>&1; then
        recommendations+=("Multiple timeouts detected - consider increasing timeout values or reducing concurrent operations")
    fi
    
    if jq -e '.summary.by_category.resource_error > 0' "$ERROR_REPORT_FILE" > /dev/null 2>&1; then
        recommendations+=("Resource exhaustion detected - increase system resources or reduce scan intensity")
    fi
    
    if jq -e '.summary.by_category.dependency_error > 0' "$ERROR_REPORT_FILE" > /dev/null 2>&1; then
        recommendations+=("Missing dependencies detected - run ./install.sh to install required tools")
    fi
    
    if jq -e '.summary.by_category.network_error > 10' "$ERROR_REPORT_FILE" > /dev/null 2>&1; then
        recommendations+=("High network error rate - check network connectivity and target availability")
    fi
    
    # Convert recommendations to JSON array
    local rec_json=$(printf '%s\n' "${recommendations[@]}" | jq -Rs 'split("\n") | map(select(length > 0))')
    
    # Update final report
    local temp_file="${ERROR_REPORT_FILE}.tmp"
    jq --arg end "$end_time" \
       --argjson rate "$recovery_rate" \
       --argjson recs "$rec_json" '
        .scan_session.end_time = $end |
        .summary.recovery_rate = $rate |
        .recommendations = $recs
    ' "$ERROR_REPORT_FILE" > "$temp_file" && mv "$temp_file" "$ERROR_REPORT_FILE"
    
    # Generate human-readable summary
    _error_generate_summary_report
    
    log_success "Error report finalized: $ERROR_REPORT_FILE"
}

# Generate human-readable summary
_error_generate_summary_report() {
    local summary_file="${ERROR_REPORT_DIR}/${ERROR_REPORT_SESSION_ID}_summary.txt"
    
    cat > "$summary_file" << EOF
═══════════════════════════════════════════════════════════════════════════════
                        NEKO ERROR REPORT SUMMARY
═══════════════════════════════════════════════════════════════════════════════

Scan Session: $ERROR_REPORT_SESSION_ID
Target: ${domain:-unknown}
Generated: $(date)

───────────────────────────────────────────────────────────────────────────────
                            ERROR STATISTICS
───────────────────────────────────────────────────────────────────────────────

Total Errors: ${ERROR_STATISTICS["total"]}

By Severity:
  • Critical:  ${ERROR_STATISTICS["critical"]:-0}
  • Error:     ${ERROR_STATISTICS["error"]:-0}
  • Warning:   ${ERROR_STATISTICS["warning"]:-0}
  • Info:      ${ERROR_STATISTICS["info"]:-0}

Recovery:
  • Recovered:    ${ERROR_STATISTICS["recovered"]:-0}
  • Unrecovered:  ${ERROR_STATISTICS["unrecovered"]:-0}

───────────────────────────────────────────────────────────────────────────────
                           ERRORS BY CATEGORY
───────────────────────────────────────────────────────────────────────────────

$(jq -r '.summary.by_category | to_entries | map("  • \(.key): \(.value)") | .[]' "$ERROR_REPORT_FILE" 2>/dev/null || echo "  No data available")

───────────────────────────────────────────────────────────────────────────────
                            ERRORS BY TOOL
───────────────────────────────────────────────────────────────────────────────

$(jq -r '.summary.by_tool | to_entries | sort_by(-.value) | .[:10] | map("  • \(.key): \(.value)") | .[]' "$ERROR_REPORT_FILE" 2>/dev/null || echo "  No data available")

───────────────────────────────────────────────────────────────────────────────
                            ERRORS BY PHASE
───────────────────────────────────────────────────────────────────────────────

$(jq -r '.summary.by_phase | to_entries | map("  • \(.key): \(.value)") | .[]' "$ERROR_REPORT_FILE" 2>/dev/null || echo "  No data available")

───────────────────────────────────────────────────────────────────────────────
                          CRITICAL ERRORS
───────────────────────────────────────────────────────────────────────────────

$(jq -r '.errors | map(select(.severity == "critical")) | .[:5] | map("[\(.timestamp)] [\(.tool)] \(.message)\n  Details: \(.details[:200])...\n") | .[]' "$ERROR_REPORT_FILE" 2>/dev/null || echo "  No critical errors")

───────────────────────────────────────────────────────────────────────────────
                          RECOMMENDATIONS
───────────────────────────────────────────────────────────────────────────────

$(jq -r '.recommendations | map("  • \(.)") | .[]' "$ERROR_REPORT_FILE" 2>/dev/null || echo "  No recommendations")

───────────────────────────────────────────────────────────────────────────────

Full JSON report: $ERROR_REPORT_FILE
Detailed logs: ${ERROR_REPORT_DIR}/detailed_logs/

═══════════════════════════════════════════════════════════════════════════════
EOF
    
    log_info "Error summary written to: $summary_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR ANALYSIS AND INSIGHTS
# ═══════════════════════════════════════════════════════════════════════════════

# Get most common errors
error_get_common() {
    local limit="${1:-10}"
    
    jq -r --argjson limit "$limit" '
        .errors | group_by(.message) | 
        map({message: .[0].message, count: length, tool: .[0].tool}) |
        sort_by(-.count) | 
        .[:$limit] | 
        map("\(.count)x [\(.tool)] \(.message)") | 
        .[]
    ' "$ERROR_REPORT_FILE" 2>/dev/null
}

# Get error timeline
error_get_timeline() {
    jq -r '
        .errors | 
        group_by(.timestamp[:13]) | 
        map({time: .[0].timestamp[:13], count: length}) | 
        map("\(.time): \(.count) errors") | 
        .[]
    ' "$ERROR_REPORT_FILE" 2>/dev/null
}

# Get tool reliability report
error_tool_reliability() {
    local metrics_file="${ERROR_REPORT_DIR}/execution_metrics.jsonl"
    
    [[ ! -f "$metrics_file" ]] && return
    
    echo "Tool Reliability Report"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    # Process metrics by tool
    cat "$metrics_file" | jq -s '
        group_by(.tool) | 
        map({
            tool: .[0].tool,
            total_runs: length,
            successes: map(select(.exit_code == 0)) | length,
            failures: map(select(.exit_code != 0)) | length,
            avg_duration_ms: (map(.duration_ms) | add / length),
            success_rate: (map(select(.exit_code == 0)) | length) * 100 / length
        }) |
        sort_by(-.total_runs) |
        .[] |
        "\(.tool): \(.success_rate | floor)% success (\(.successes)/\(.total_runs)), avg: \(.avg_duration_ms | floor)ms"
    '
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

error_report_cleanup() {
    # Finalize report
    error_report_finalize
    
    # Archive old reports (keep last 10)
    local archive_dir="${ERROR_REPORT_DIR}/archive"
    ensure_dir "$archive_dir"
    
    # Move old reports to archive
    find "$ERROR_REPORT_DIR" -maxdepth 1 -name "scan_*_errors.json" -mtime +7 \
        -exec mv {} "$archive_dir/" \; 2>/dev/null || true
    
    # Compress archived reports older than 30 days
    find "$archive_dir" -name "*.json" -mtime +30 \
        -exec gzip {} \; 2>/dev/null || true
    
    log_debug "Error reporting cleanup completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION WITH EXISTING ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

# Override the existing record_error function to use new system
_original_record_error() {
    :  # Placeholder for original function
}

# Enhanced record_error that uses both systems
enhanced_record_error() {
    local tool="$1"
    local message="$2"
    local exit_code="${3:-1}"
    local context="${4:-}"
    
    # Call original error tracking
    if type -t _original_record_error &>/dev/null; then
        _original_record_error "$tool" "$message" "$exit_code" "$context"
    fi
    
    # Call new detailed error recording
    local phase="${CURRENT_PHASE:-unknown}"
    local category="$ERROR_CAT_TOOL"
    local severity="$ERROR_SEVERITY_ERROR"
    
    # Determine severity
    [[ $exit_code -ge 128 ]] && severity="$ERROR_SEVERITY_CRITICAL"
    [[ $exit_code -eq 0 ]] && return 0
    
    error_record "$severity" "$category" "$tool" "$phase" "$message" "$context" "$exit_code"
}

# Export functions for use in other modules
export -f error_record error_tool_execution error_network error_timeout
export -f error_resource error_dependency error_config error_validation
export -f error_safe_exec
