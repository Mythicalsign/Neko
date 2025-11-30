#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED ERROR HANDLING & RETRY MECHANISMS
# Robust error handling with fallback mechanisms and recovery
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

declare -gA ERROR_COUNT
declare -gA ERROR_MESSAGES
declare -gA FALLBACK_TOOLS
declare -g ERROR_LOG=""
declare -g MAX_ERRORS_PER_TOOL=5
declare -g CIRCUIT_BREAKER_THRESHOLD=10
declare -g CIRCUIT_BREAKER_RESET=300  # seconds

# Circuit breaker states
declare -gA CIRCUIT_STATE  # open, closed, half-open
declare -gA CIRCUIT_FAILURES
declare -gA CIRCUIT_LAST_FAILURE

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

error_init() {
    ERROR_LOG="${dir}/logs/errors.log"
    ensure_dir "$(dirname "$ERROR_LOG")"
    
    # Initialize fallback tool mappings
    FALLBACK_TOOLS=(
        ["subfinder"]="assetfinder,amass"
        ["assetfinder"]="subfinder,findomain"
        ["httpx"]="httprobe"
        ["nuclei"]="nikto"
        ["ffuf"]="gobuster,feroxbuster,dirsearch"
        ["gobuster"]="ffuf,feroxbuster"
        ["feroxbuster"]="ffuf,gobuster"
        ["puredns"]="massdns,dnsx"
        ["massdns"]="dnsx,puredns"
        ["dnsx"]="massdns,dig"
        ["dalfox"]="xsstrike,kxss"
        ["sqlmap"]="ghauri"
        ["ghauri"]="sqlmap"
        ["katana"]="hakrawler,gospider"
        ["gau"]="waybackurls"
        ["waybackurls"]="gau"
        ["nmap"]="masscan,naabu"
        ["masscan"]="naabu,nmap"
    )
    
    log_debug "Error handling system initialized"
}

# ═══════════════════════════════════════════════════════════════════════════════
# RETRY MECHANISMS
# ═══════════════════════════════════════════════════════════════════════════════

# Execute with exponential backoff retry
retry_with_backoff() {
    local max_retries="${1:-3}"
    local initial_delay="${2:-1}"
    local max_delay="${3:-60}"
    local exponential="${4:-2}"
    shift 4
    local cmd="$@"
    
    local retries=0
    local delay=$initial_delay
    local exit_code=1
    
    while [[ $retries -lt $max_retries ]]; do
        log_debug "Attempt $((retries + 1))/$max_retries: $cmd"
        
        if eval "$cmd"; then
            return 0
        fi
        
        exit_code=$?
        ((retries++))
        
        if [[ $retries -lt $max_retries ]]; then
            log_warning "Command failed (exit: $exit_code). Retrying in ${delay}s..."
            sleep "$delay"
            
            # Exponential backoff with jitter
            delay=$(echo "$delay * $exponential + $RANDOM % 5" | bc 2>/dev/null || echo "$((delay * 2))")
            [[ $delay -gt $max_delay ]] && delay=$max_delay
        fi
    done
    
    log_error "Command failed after $max_retries attempts: $cmd"
    return $exit_code
}

# Execute with simple retry
retry_simple() {
    local max_retries="${1:-3}"
    local delay="${2:-5}"
    shift 2
    local cmd="$@"
    
    local retries=0
    
    while [[ $retries -lt $max_retries ]]; do
        if eval "$cmd"; then
            return 0
        fi
        
        ((retries++))
        [[ $retries -lt $max_retries ]] && sleep "$delay"
    done
    
    return 1
}

# Retry with timeout
retry_with_timeout() {
    local max_retries="${1:-3}"
    local timeout="${2:-300}"
    local delay="${3:-5}"
    shift 3
    local cmd="$@"
    
    local retries=0
    
    while [[ $retries -lt $max_retries ]]; do
        if timeout "$timeout" bash -c "$cmd"; then
            return 0
        fi
        
        local exit_code=$?
        ((retries++))
        
        if [[ $exit_code -eq 124 ]]; then
            log_warning "Command timed out after ${timeout}s"
        fi
        
        [[ $retries -lt $max_retries ]] && sleep "$delay"
    done
    
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# CIRCUIT BREAKER PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

# Check circuit breaker state
circuit_check() {
    local tool="$1"
    local state="${CIRCUIT_STATE[$tool]:-closed}"
    local last_failure="${CIRCUIT_LAST_FAILURE[$tool]:-0}"
    local current_time=$(date +%s)
    
    case "$state" in
        "open")
            # Check if enough time has passed to try again
            if [[ $((current_time - last_failure)) -gt $CIRCUIT_BREAKER_RESET ]]; then
                CIRCUIT_STATE["$tool"]="half-open"
                log_debug "Circuit breaker for $tool: open -> half-open"
                return 0
            fi
            log_debug "Circuit breaker for $tool is OPEN, skipping"
            return 1
            ;;
        "half-open")
            return 0
            ;;
        "closed")
            return 0
            ;;
    esac
}

# Record circuit breaker success
circuit_success() {
    local tool="$1"
    
    CIRCUIT_FAILURES["$tool"]=0
    CIRCUIT_STATE["$tool"]="closed"
    
    log_debug "Circuit breaker for $tool: closed (success)"
}

# Record circuit breaker failure
circuit_failure() {
    local tool="$1"
    
    ((CIRCUIT_FAILURES["$tool"]++)) || CIRCUIT_FAILURES["$tool"]=1
    CIRCUIT_LAST_FAILURE["$tool"]=$(date +%s)
    
    if [[ ${CIRCUIT_FAILURES[$tool]} -ge $CIRCUIT_BREAKER_THRESHOLD ]]; then
        CIRCUIT_STATE["$tool"]="open"
        log_warning "Circuit breaker for $tool: OPEN (${CIRCUIT_FAILURES[$tool]} failures)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# FALLBACK MECHANISMS
# ═══════════════════════════════════════════════════════════════════════════════

# Get fallback tools for a given tool
get_fallback_tools() {
    local tool="$1"
    echo "${FALLBACK_TOOLS[$tool]:-}"
}

# Execute with fallback
execute_with_fallback() {
    local primary_tool="$1"
    shift
    local args="$@"
    
    # Check circuit breaker
    if ! circuit_check "$primary_tool"; then
        log_warning "Skipping $primary_tool (circuit breaker open)"
        # Try fallback immediately
        local fallbacks="${FALLBACK_TOOLS[$primary_tool]:-}"
        if [[ -n "$fallbacks" ]]; then
            IFS=',' read -ra fallback_array <<< "$fallbacks"
            for fallback in "${fallback_array[@]}"; do
                if command_exists "$fallback" && circuit_check "$fallback"; then
                    log_info "Using fallback: $fallback"
                    if eval "$fallback $args" 2>> "$LOGFILE"; then
                        circuit_success "$fallback"
                        return 0
                    fi
                    circuit_failure "$fallback"
                fi
            done
        fi
        return 1
    fi
    
    # Try primary tool
    if command_exists "$primary_tool"; then
        if eval "$primary_tool $args" 2>> "$LOGFILE"; then
            circuit_success "$primary_tool"
            return 0
        fi
        circuit_failure "$primary_tool"
    fi
    
    # Primary failed, try fallbacks
    local fallbacks="${FALLBACK_TOOLS[$primary_tool]:-}"
    if [[ -n "$fallbacks" ]]; then
        IFS=',' read -ra fallback_array <<< "$fallbacks"
        for fallback in "${fallback_array[@]}"; do
            if command_exists "$fallback" && circuit_check "$fallback"; then
                log_info "Primary tool $primary_tool failed, using fallback: $fallback"
                if eval "$fallback $args" 2>> "$LOGFILE"; then
                    circuit_success "$fallback"
                    return 0
                fi
                circuit_failure "$fallback"
            fi
        done
    fi
    
    log_error "All tools failed for operation: $primary_tool $args"
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR RECORDING AND ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

# Record an error
record_error() {
    local tool="$1"
    local message="$2"
    local exit_code="${3:-1}"
    local context="${4:-}"
    
    ((ERROR_COUNT["$tool"]++)) || ERROR_COUNT["$tool"]=1
    ERROR_MESSAGES["$tool:${ERROR_COUNT[$tool]}"]="$message"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$tool] (exit: $exit_code) $message ${context:+[$context]}" >> "$ERROR_LOG"
    
    log_debug "Error recorded: $tool - $message"
}

# Get error count for tool
get_error_count() {
    local tool="$1"
    echo "${ERROR_COUNT[$tool]:-0}"
}

# Check if tool has exceeded error threshold
is_tool_failing() {
    local tool="$1"
    local threshold="${2:-$MAX_ERRORS_PER_TOOL}"
    
    [[ ${ERROR_COUNT[$tool]:-0} -ge $threshold ]]
}

# Get all errors for a tool
get_tool_errors() {
    local tool="$1"
    
    for key in "${!ERROR_MESSAGES[@]}"; do
        if [[ "$key" == "$tool:"* ]]; then
            echo "${ERROR_MESSAGES[$key]}"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# SAFE EXECUTION WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════

# Safe tool execution with full error handling
safe_run() {
    local tool="$1"
    shift
    local args="$@"
    local max_retries="${SAFE_RUN_RETRIES:-3}"
    local timeout="${SAFE_RUN_TIMEOUT:-600}"
    
    # Check if tool is available
    if ! command_exists "$tool"; then
        log_warning "Tool not available: $tool"
        record_error "$tool" "Tool not installed" 127
        
        # Try fallback
        local fallbacks="${FALLBACK_TOOLS[$tool]:-}"
        if [[ -n "$fallbacks" ]]; then
            IFS=',' read -ra fallback_array <<< "$fallbacks"
            for fallback in "${fallback_array[@]}"; do
                if command_exists "$fallback"; then
                    log_info "Using alternative: $fallback"
                    safe_run "$fallback" "$args"
                    return $?
                fi
            done
        fi
        return 127
    fi
    
    # Check circuit breaker
    if ! circuit_check "$tool"; then
        return 1
    fi
    
    # Execute with retry and timeout
    local exit_code=0
    
    if retry_with_timeout "$max_retries" "$timeout" 5 "$tool $args"; then
        circuit_success "$tool"
        return 0
    else
        exit_code=$?
        circuit_failure "$tool"
        record_error "$tool" "Execution failed after $max_retries retries" "$exit_code"
        
        # Try fallback
        execute_with_fallback "$tool" "$args"
        return $?
    fi
}

# Run with graceful degradation
run_graceful() {
    local description="$1"
    shift
    local cmd="$@"
    
    log_debug "Running: $description"
    
    local output
    local exit_code
    
    output=$(eval "$cmd" 2>&1)
    exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log_warning "$description failed (exit: $exit_code)"
        
        # Log detailed error for debugging
        if [[ -n "$output" ]]; then
            echo "[$description] $output" >> "$ERROR_LOG"
        fi
        
        return $exit_code
    fi
    
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# RECOVERY MECHANISMS
# ═══════════════════════════════════════════════════════════════════════════════

# Attempt to recover from common failures
attempt_recovery() {
    local tool="$1"
    local error_type="$2"
    
    log_info "Attempting recovery for $tool ($error_type)..."
    
    case "$error_type" in
        "timeout")
            # Reduce threads/rate for next attempt
            log_info "Reducing concurrency for $tool"
            export "${tool^^}_THREADS"=$(( ${!${tool^^}_THREADS:-10} / 2 ))
            ;;
        "memory")
            # Clear caches, reduce batch size
            log_info "Clearing caches and reducing batch size"
            sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1 || true
            ;;
        "network")
            # Wait and retry with different settings
            log_info "Network issue, waiting before retry"
            sleep 30
            proxy_smart_rotate "network_error" 2>/dev/null || true
            ;;
        "rate_limit")
            # Increase delay between requests
            log_info "Rate limited, increasing delay"
            sleep 60
            export "${tool^^}_RATELIMIT"=$(( ${!${tool^^}_RATELIMIT:-100} / 2 ))
            ;;
        *)
            log_debug "No specific recovery for error type: $error_type"
            ;;
    esac
}

# Detect error type from exit code and output
detect_error_type() {
    local exit_code="$1"
    local output="$2"
    
    case "$exit_code" in
        124) echo "timeout" ;;
        137) echo "memory" ;;  # SIGKILL usually from OOM
        *)
            if echo "$output" | grep -qi "rate.limit\|429\|too many requests"; then
                echo "rate_limit"
            elif echo "$output" | grep -qi "connection\|refused\|timeout\|network"; then
                echo "network"
            elif echo "$output" | grep -qi "memory\|heap\|allocation"; then
                echo "memory"
            else
                echo "unknown"
            fi
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR SUMMARY AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

# Generate error summary
error_summary() {
    cat << EOF
Error Summary:
═══════════════════════════════════════════════════════════════════════════════
EOF
    
    local total_errors=0
    for tool in "${!ERROR_COUNT[@]}"; do
        local count=${ERROR_COUNT[$tool]}
        ((total_errors += count))
        
        local circuit="${CIRCUIT_STATE[$tool]:-closed}"
        local status_icon="✓"
        [[ "$circuit" == "open" ]] && status_icon="✗"
        [[ "$circuit" == "half-open" ]] && status_icon="?"
        
        printf "  %s %-20s: %3d errors (circuit: %s)\n" "$status_icon" "$tool" "$count" "$circuit"
    done
    
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  Total Errors: $total_errors"
    
    if [[ -f "$ERROR_LOG" ]]; then
        echo ""
        echo "Recent Errors:"
        tail -5 "$ERROR_LOG" | sed 's/^/    /'
    fi
}

# Export errors for reporting
export_errors_json() {
    local output_file="${1:-${dir}/reports/errors.json}"
    
    local json="{"
    json+="\"total_errors\": $(echo "${ERROR_COUNT[@]}" | tr ' ' '+' | bc 2>/dev/null || echo 0),"
    json+="\"tools\": {"
    
    local first=true
    for tool in "${!ERROR_COUNT[@]}"; do
        [[ "$first" == "false" ]] && json+=","
        first=false
        json+="\"$tool\": {\"errors\": ${ERROR_COUNT[$tool]}, \"circuit\": \"${CIRCUIT_STATE[$tool]:-closed}\"}"
    done
    
    json+="}}"
    
    echo "$json" | jq '.' > "$output_file" 2>/dev/null || echo "$json" > "$output_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

error_cleanup() {
    # Generate final error report
    if [[ ${#ERROR_COUNT[@]} -gt 0 ]]; then
        error_summary >> "$ERROR_LOG"
    fi
    
    log_debug "Error handling cleanup completed"
}
