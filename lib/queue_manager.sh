#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED QUEUE MANAGEMENT SYSTEM
# Comprehensive queue management to prevent DOS attacks and resource exhaustion
# Version: 2.0.0
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# QUEUE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Queue storage directory
declare -g QUEUE_DIR=""
declare -g QUEUE_LOCK_DIR=""

# Queue types and their configurations
declare -gA QUEUE_CONFIG=(
    # [queue_name]="max_concurrent:rate_per_second:burst_limit:cooldown_ms:priority_levels"
    ["network_intensive"]="3:10:20:100:5"
    ["cpu_intensive"]="4:0:0:0:3"
    ["io_intensive"]="2:0:0:0:3"
    ["memory_intensive"]="2:0:0:0:3"
    ["dns_operations"]="5:50:100:20:3"
    ["http_requests"]="10:100:200:10:5"
    ["scanning"]="2:5:10:200:5"
    ["exploitation"]="1:2:5:500:3"
    ["default"]="5:0:0:0:3"
)

# Tool to queue mapping
declare -gA TOOL_QUEUE_MAP=(
    # Network intensive tools
    ["masscan"]="network_intensive"
    ["nmap"]="network_intensive"
    ["naabu"]="network_intensive"
    ["zmap"]="network_intensive"
    
    # CPU intensive tools
    ["nuclei"]="cpu_intensive"
    ["ffuf"]="cpu_intensive"
    ["feroxbuster"]="cpu_intensive"
    ["gobuster"]="cpu_intensive"
    ["hashcat"]="cpu_intensive"
    
    # I/O intensive tools
    ["amass"]="io_intensive"
    ["subfinder"]="io_intensive"
    ["assetfinder"]="io_intensive"
    
    # Memory intensive
    ["massdns"]="memory_intensive"
    ["puredns"]="memory_intensive"
    
    # DNS operations
    ["dnsx"]="dns_operations"
    ["dnsrecon"]="dns_operations"
    ["dig"]="dns_operations"
    
    # HTTP requests
    ["httpx"]="http_requests"
    ["curl"]="http_requests"
    ["wget"]="http_requests"
    ["katana"]="http_requests"
    ["gau"]="http_requests"
    ["waybackurls"]="http_requests"
    
    # Scanning tools
    ["sqlmap"]="scanning"
    ["dalfox"]="scanning"
    ["xsstrike"]="scanning"
    ["commix"]="scanning"
    ["nikto"]="scanning"
    
    # Exploitation
    ["sqlmap"]="exploitation"
    ["commix"]="exploitation"
    
    # Bettercap
    ["bettercap"]="network_intensive"
)

# Current queue states
declare -gA QUEUE_CURRENT_JOBS
declare -gA QUEUE_TOKENS
declare -gA QUEUE_LAST_REQUEST
declare -gA QUEUE_BURST_COUNT

# Job priority levels
declare -g PRIORITY_CRITICAL=1
declare -g PRIORITY_HIGH=2
declare -g PRIORITY_NORMAL=3
declare -g PRIORITY_LOW=4
declare -g PRIORITY_BACKGROUND=5

# Global rate limiting state
declare -g GLOBAL_REQUESTS_PER_SECOND=200
declare -g GLOBAL_BURST_LIMIT=500
declare -g GLOBAL_CURRENT_RPS=0
declare -g GLOBAL_LAST_RESET=$(date +%s)

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

queue_init() {
    local base_dir="${1:-${dir}/.tmp/queue}"
    QUEUE_DIR="$base_dir"
    QUEUE_LOCK_DIR="${base_dir}/locks"
    
    ensure_dir "$QUEUE_DIR"
    ensure_dir "$QUEUE_LOCK_DIR"
    ensure_dir "${QUEUE_DIR}/jobs"
    ensure_dir "${QUEUE_DIR}/completed"
    ensure_dir "${QUEUE_DIR}/failed"
    ensure_dir "${QUEUE_DIR}/metrics"
    
    # Initialize all queues
    for queue_name in "${!QUEUE_CONFIG[@]}"; do
        _queue_init_single "$queue_name"
    done
    
    # Start queue metrics collector
    _queue_start_metrics_collector &
    
    # Start adaptive rate limiter
    _queue_start_adaptive_limiter &
    
    log_debug "Queue management system initialized at $QUEUE_DIR"
    return 0
}

_queue_init_single() {
    local queue_name="$1"
    
    QUEUE_CURRENT_JOBS["$queue_name"]=0
    QUEUE_TOKENS["$queue_name"]=0
    QUEUE_LAST_REQUEST["$queue_name"]=0
    QUEUE_BURST_COUNT["$queue_name"]=0
    
    # Create queue directory structure
    ensure_dir "${QUEUE_DIR}/${queue_name}"
    
    # Initialize priority queues (using files for persistence)
    for priority in 1 2 3 4 5; do
        touch "${QUEUE_DIR}/${queue_name}/priority_${priority}.queue"
    done
    
    # Create queue state file
    cat > "${QUEUE_DIR}/${queue_name}/state.json" << EOF
{
    "name": "$queue_name",
    "config": "${QUEUE_CONFIG[$queue_name]}",
    "current_jobs": 0,
    "total_processed": 0,
    "total_failed": 0,
    "avg_wait_time_ms": 0,
    "last_updated": "$(date -Iseconds)"
}
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# QUEUE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Enqueue a job
queue_enqueue() {
    local queue_name="$1"
    local job_id="$2"
    local command="$3"
    local priority="${4:-$PRIORITY_NORMAL}"
    local timeout="${5:-3600}"
    local callback="${6:-}"
    
    # Use default queue if not specified
    [[ -z "$queue_name" ]] && queue_name="default"
    
    # Validate queue exists
    if [[ -z "${QUEUE_CONFIG[$queue_name]}" ]]; then
        log_warning "Unknown queue: $queue_name, using default"
        queue_name="default"
    fi
    
    # Generate job ID if not provided
    [[ -z "$job_id" ]] && job_id="job_$(date +%s%N)_$$"
    
    # Create job file
    local job_file="${QUEUE_DIR}/jobs/${job_id}.json"
    local enqueue_time=$(date +%s%N)
    
    cat > "$job_file" << EOF
{
    "id": "$job_id",
    "queue": "$queue_name",
    "command": $(printf '%s' "$command" | jq -Rs .),
    "priority": $priority,
    "timeout": $timeout,
    "callback": "$callback",
    "status": "queued",
    "enqueue_time": $enqueue_time,
    "start_time": null,
    "end_time": null,
    "exit_code": null,
    "retry_count": 0,
    "max_retries": 3,
    "error": null
}
EOF
    
    # Add to priority queue
    echo "$job_id:$enqueue_time" >> "${QUEUE_DIR}/${queue_name}/priority_${priority}.queue"
    
    log_debug "Job $job_id enqueued to $queue_name (priority: $priority)"
    echo "$job_id"
}

# Dequeue and execute next job
queue_dequeue() {
    local queue_name="$1"
    
    # Check if we can run more jobs
    if ! _queue_can_run "$queue_name"; then
        return 1
    fi
    
    # Apply rate limiting
    if ! _queue_rate_limit_check "$queue_name"; then
        return 1
    fi
    
    # Get next job by priority
    local job_id=""
    for priority in 1 2 3 4 5; do
        local queue_file="${QUEUE_DIR}/${queue_name}/priority_${priority}.queue"
        if [[ -s "$queue_file" ]]; then
            # Get and remove first job (atomic with lock)
            job_id=$(_queue_pop_job "$queue_file")
            [[ -n "$job_id" ]] && break
        fi
    done
    
    [[ -z "$job_id" ]] && return 1
    
    # Execute job
    _queue_execute_job "$job_id" "$queue_name"
}

# Pop job from queue file (with lock)
_queue_pop_job() {
    local queue_file="$1"
    local lock_file="${QUEUE_LOCK_DIR}/$(basename "$queue_file").lock"
    
    (
        flock -x 200 || exit 1
        
        if [[ -s "$queue_file" ]]; then
            local first_line=$(head -1 "$queue_file")
            local job_id=$(echo "$first_line" | cut -d: -f1)
            
            # Remove first line
            tail -n +2 "$queue_file" > "${queue_file}.tmp"
            mv "${queue_file}.tmp" "$queue_file"
            
            echo "$job_id"
        fi
    ) 200>"$lock_file"
}

# Execute a job
_queue_execute_job() {
    local job_id="$1"
    local queue_name="$2"
    local job_file="${QUEUE_DIR}/jobs/${job_id}.json"
    
    if [[ ! -f "$job_file" ]]; then
        log_error "Job file not found: $job_file"
        return 1
    fi
    
    # Update job status
    local start_time=$(date +%s%N)
    jq --argjson start "$start_time" '.status = "running" | .start_time = $start' \
        "$job_file" > "${job_file}.tmp" && mv "${job_file}.tmp" "$job_file"
    
    # Increment current jobs
    ((QUEUE_CURRENT_JOBS[$queue_name]++)) || true
    
    # Get job details
    local command=$(jq -r '.command' "$job_file")
    local timeout=$(jq -r '.timeout' "$job_file")
    local callback=$(jq -r '.callback' "$job_file")
    
    log_debug "Executing job $job_id from $queue_name"
    
    # Execute with timeout
    local output_file="${QUEUE_DIR}/jobs/${job_id}.out"
    local error_file="${QUEUE_DIR}/jobs/${job_id}.err"
    local exit_code=0
    
    timeout "$timeout" bash -c "$command" > "$output_file" 2> "$error_file" || exit_code=$?
    
    # Update job completion
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))  # Convert to ms
    
    if [[ $exit_code -eq 0 ]]; then
        jq --argjson end "$end_time" --argjson code "$exit_code" \
            '.status = "completed" | .end_time = $end | .exit_code = $code' \
            "$job_file" > "${job_file}.tmp" && mv "${job_file}.tmp" "$job_file"
        
        mv "$job_file" "${QUEUE_DIR}/completed/"
    else
        local error_msg=$(cat "$error_file" 2>/dev/null | head -5 | tr '\n' ' ')
        jq --argjson end "$end_time" --argjson code "$exit_code" --arg err "$error_msg" \
            '.status = "failed" | .end_time = $end | .exit_code = $code | .error = $err' \
            "$job_file" > "${job_file}.tmp" && mv "${job_file}.tmp" "$job_file"
        
        # Check for retry
        local retry_count=$(jq -r '.retry_count' "$job_file")
        local max_retries=$(jq -r '.max_retries' "$job_file")
        
        if [[ $retry_count -lt $max_retries ]]; then
            # Re-enqueue with delay
            jq '.retry_count += 1 | .status = "queued"' "$job_file" > "${job_file}.tmp" && mv "${job_file}.tmp" "$job_file"
            local priority=$(jq -r '.priority' "$job_file")
            echo "$job_id:$(date +%s%N)" >> "${QUEUE_DIR}/${queue_name}/priority_${priority}.queue"
            log_warning "Job $job_id failed, retry $((retry_count + 1))/$max_retries"
        else
            mv "$job_file" "${QUEUE_DIR}/failed/"
            log_error "Job $job_id failed after $max_retries retries"
        fi
    fi
    
    # Decrement current jobs
    ((QUEUE_CURRENT_JOBS[$queue_name]--)) || true
    
    # Update metrics
    _queue_update_metrics "$queue_name" "$duration" "$exit_code"
    
    # Execute callback if provided
    if [[ -n "$callback" ]] && [[ "$callback" != "null" ]]; then
        eval "$callback '$job_id' '$exit_code' '$output_file'" 2>/dev/null || true
    fi
    
    return $exit_code
}

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING AND DOS PREVENTION
# ═══════════════════════════════════════════════════════════════════════════════

# Check if we can run more jobs in this queue
_queue_can_run() {
    local queue_name="$1"
    local config="${QUEUE_CONFIG[$queue_name]}"
    
    IFS=':' read -r max_concurrent rate_per_second burst_limit cooldown_ms priority_levels <<< "$config"
    
    local current=${QUEUE_CURRENT_JOBS[$queue_name]:-0}
    
    if [[ $current -ge $max_concurrent ]]; then
        log_debug "Queue $queue_name at capacity ($current/$max_concurrent)"
        return 1
    fi
    
    return 0
}

# Token bucket rate limiting
_queue_rate_limit_check() {
    local queue_name="$1"
    local config="${QUEUE_CONFIG[$queue_name]}"
    
    IFS=':' read -r max_concurrent rate_per_second burst_limit cooldown_ms priority_levels <<< "$config"
    
    # Skip if no rate limiting configured
    [[ "$rate_per_second" == "0" ]] && return 0
    
    local now=$(date +%s%N)
    local last_request=${QUEUE_LAST_REQUEST[$queue_name]:-0}
    local tokens=${QUEUE_TOKENS[$queue_name]:-$burst_limit}
    local burst_count=${QUEUE_BURST_COUNT[$queue_name]:-0}
    
    # Calculate tokens to add (token bucket algorithm)
    local elapsed_ns=$((now - last_request))
    local elapsed_sec=$(echo "scale=6; $elapsed_ns / 1000000000" | bc 2>/dev/null || echo "0")
    local tokens_to_add=$(echo "scale=2; $elapsed_sec * $rate_per_second" | bc 2>/dev/null || echo "0")
    
    tokens=$(echo "$tokens + $tokens_to_add" | bc 2>/dev/null || echo "$tokens")
    
    # Cap tokens at burst limit
    if (( $(echo "$tokens > $burst_limit" | bc -l 2>/dev/null || echo "0") )); then
        tokens=$burst_limit
    fi
    
    # Check if we have tokens
    if (( $(echo "$tokens < 1" | bc -l 2>/dev/null || echo "0") )); then
        # Need to wait
        local wait_time=$(echo "scale=3; (1 - $tokens) / $rate_per_second * 1000" | bc 2>/dev/null || echo "100")
        log_debug "Rate limited on $queue_name, waiting ${wait_time}ms"
        
        # Apply cooldown
        sleep "$(echo "scale=3; $wait_time / 1000" | bc 2>/dev/null || echo "0.1")"
        
        return 1
    fi
    
    # Consume a token
    tokens=$(echo "$tokens - 1" | bc 2>/dev/null || echo "$tokens")
    
    QUEUE_TOKENS["$queue_name"]="$tokens"
    QUEUE_LAST_REQUEST["$queue_name"]="$now"
    
    # Global rate limiting
    if ! _queue_global_rate_check; then
        return 1
    fi
    
    return 0
}

# Global rate limiting across all queues
_queue_global_rate_check() {
    local now=$(date +%s)
    
    # Reset counter every second
    if [[ $((now - GLOBAL_LAST_RESET)) -ge 1 ]]; then
        GLOBAL_CURRENT_RPS=0
        GLOBAL_LAST_RESET=$now
    fi
    
    # Check if under global limit
    if [[ $GLOBAL_CURRENT_RPS -ge $GLOBAL_REQUESTS_PER_SECOND ]]; then
        log_debug "Global rate limit reached ($GLOBAL_CURRENT_RPS/$GLOBAL_REQUESTS_PER_SECOND)"
        return 1
    fi
    
    ((GLOBAL_CURRENT_RPS++)) || true
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL TOOL EXECUTION WITH QUEUE
# ═══════════════════════════════════════════════════════════════════════════════

# Execute a tool through the queue system
queue_run_tool() {
    local tool_name="$1"
    shift
    local args="$@"
    local priority="${TOOL_PRIORITY:-$PRIORITY_NORMAL}"
    local timeout="${TOOL_TIMEOUT:-3600}"
    
    # Determine which queue to use
    local queue_name="${TOOL_QUEUE_MAP[$tool_name]:-default}"
    
    # Check if tool exists
    if ! command_exists "$tool_name"; then
        log_error "Tool not found: $tool_name"
        return 127
    fi
    
    # Build command
    local full_command="$tool_name $args"
    
    # Enqueue the job
    local job_id=$(queue_enqueue "$queue_name" "" "$full_command" "$priority" "$timeout")
    
    # For synchronous execution, wait for completion
    if [[ "${QUEUE_ASYNC:-false}" != "true" ]]; then
        queue_wait_job "$job_id"
        return $?
    fi
    
    echo "$job_id"
    return 0
}

# Wait for a specific job to complete
queue_wait_job() {
    local job_id="$1"
    local timeout="${2:-3600}"
    local start_time=$(date +%s)
    
    while true; do
        # Check job status
        local job_file=""
        
        if [[ -f "${QUEUE_DIR}/completed/${job_id}.json" ]]; then
            return 0
        elif [[ -f "${QUEUE_DIR}/failed/${job_id}.json" ]]; then
            local exit_code=$(jq -r '.exit_code' "${QUEUE_DIR}/failed/${job_id}.json")
            return ${exit_code:-1}
        fi
        
        # Check timeout
        local elapsed=$(($(date +%s) - start_time))
        if [[ $elapsed -ge $timeout ]]; then
            log_error "Timeout waiting for job $job_id"
            return 124
        fi
        
        # Try to process queue
        queue_process
        
        sleep 0.1
    done
}

# Process all queues (main loop)
queue_process() {
    for queue_name in "${!QUEUE_CONFIG[@]}"; do
        queue_dequeue "$queue_name" || true
    done
}

# Start queue processor daemon
queue_start_processor() {
    local interval="${1:-0.1}"
    
    log_info "Starting queue processor daemon..."
    
    (
        while [[ -f "${QUEUE_DIR}/.running" ]]; do
            queue_process
            sleep "$interval"
        done
    ) &
    
    echo "$!" > "${QUEUE_DIR}/processor.pid"
    touch "${QUEUE_DIR}/.running"
}

# Stop queue processor daemon
queue_stop_processor() {
    rm -f "${QUEUE_DIR}/.running"
    
    if [[ -f "${QUEUE_DIR}/processor.pid" ]]; then
        local pid=$(cat "${QUEUE_DIR}/processor.pid")
        kill "$pid" 2>/dev/null || true
        rm -f "${QUEUE_DIR}/processor.pid"
    fi
    
    log_info "Queue processor stopped"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

_queue_start_adaptive_limiter() {
    local metrics_interval=30
    
    while [[ -f "${QUEUE_DIR}/.running" ]] 2>/dev/null; do
        sleep "$metrics_interval"
        
        # Check system resources
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'.' -f1 2>/dev/null || echo "50")
        local mem_usage=$(free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}' 2>/dev/null || echo "50")
        local load=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}' || echo "1")
        
        # Adaptive adjustment
        if [[ $cpu_usage -gt 90 ]] || [[ $mem_usage -gt 90 ]]; then
            # Reduce global rate
            GLOBAL_REQUESTS_PER_SECOND=$((GLOBAL_REQUESTS_PER_SECOND * 80 / 100))
            [[ $GLOBAL_REQUESTS_PER_SECOND -lt 50 ]] && GLOBAL_REQUESTS_PER_SECOND=50
            log_warning "High resource usage, reducing global rate to $GLOBAL_REQUESTS_PER_SECOND/s"
        elif [[ $cpu_usage -lt 50 ]] && [[ $mem_usage -lt 50 ]]; then
            # Increase global rate (up to initial value)
            GLOBAL_REQUESTS_PER_SECOND=$((GLOBAL_REQUESTS_PER_SECOND * 110 / 100))
            [[ $GLOBAL_REQUESTS_PER_SECOND -gt 200 ]] && GLOBAL_REQUESTS_PER_SECOND=200
        fi
        
    done 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

_queue_update_metrics() {
    local queue_name="$1"
    local duration_ms="$2"
    local exit_code="$3"
    local timestamp=$(date -Iseconds)
    
    # Append to metrics log
    echo "{\"queue\":\"$queue_name\",\"duration_ms\":$duration_ms,\"exit_code\":$exit_code,\"timestamp\":\"$timestamp\"}" \
        >> "${QUEUE_DIR}/metrics/execution.jsonl"
}

_queue_start_metrics_collector() {
    local metrics_interval=60
    
    while [[ -f "${QUEUE_DIR}/.running" ]] 2>/dev/null; do
        sleep "$metrics_interval"
        
        # Generate metrics summary
        local summary_file="${QUEUE_DIR}/metrics/summary.json"
        
        cat > "$summary_file" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "global_rps": $GLOBAL_REQUESTS_PER_SECOND,
    "queues": {
EOF
        
        local first=true
        for queue_name in "${!QUEUE_CONFIG[@]}"; do
            [[ "$first" == "true" ]] || echo "," >> "$summary_file"
            first=false
            
            cat >> "$summary_file" << EOF
        "$queue_name": {
            "current_jobs": ${QUEUE_CURRENT_JOBS[$queue_name]:-0},
            "tokens": ${QUEUE_TOKENS[$queue_name]:-0}
        }
EOF
        done
        
        echo "    }" >> "$summary_file"
        echo "}" >> "$summary_file"
        
    done 2>/dev/null || true
}

# Get queue statistics
queue_stats() {
    local queue_name="${1:-all}"
    
    cat << EOF
Queue Management System Statistics
═══════════════════════════════════════════════════════════════════════════════
Global Rate Limit: $GLOBAL_REQUESTS_PER_SECOND requests/second
Current Global RPS: $GLOBAL_CURRENT_RPS

Queue Statistics:
EOF
    
    for qname in "${!QUEUE_CONFIG[@]}"; do
        [[ "$queue_name" != "all" ]] && [[ "$queue_name" != "$qname" ]] && continue
        
        local config="${QUEUE_CONFIG[$qname]}"
        IFS=':' read -r max_concurrent rate_per_second burst_limit cooldown_ms priority_levels <<< "$config"
        
        local current=${QUEUE_CURRENT_JOBS[$qname]:-0}
        local tokens=${QUEUE_TOKENS[$qname]:-0}
        
        # Count pending jobs
        local pending=0
        for p in 1 2 3 4 5; do
            local pcount=$(wc -l < "${QUEUE_DIR}/${qname}/priority_${p}.queue" 2>/dev/null || echo "0")
            pending=$((pending + pcount))
        done
        
        cat << EOF
───────────────────────────────────────────────────────────────────────────────
  Queue: $qname
  - Max Concurrent: $max_concurrent
  - Current Jobs: $current
  - Pending Jobs: $pending
  - Rate Limit: $rate_per_second/s (burst: $burst_limit)
  - Available Tokens: $tokens
EOF
    done
    
    echo "═══════════════════════════════════════════════════════════════════════════════"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

queue_cleanup() {
    log_info "Cleaning up queue management system..."
    
    # Stop processor
    queue_stop_processor
    
    # Kill any remaining background processes
    for pid_file in "${QUEUE_DIR}"/*.pid; do
        [[ -f "$pid_file" ]] || continue
        local pid=$(cat "$pid_file")
        kill "$pid" 2>/dev/null || true
        rm -f "$pid_file"
    done
    
    # Generate final metrics
    if [[ -d "${QUEUE_DIR}/metrics" ]]; then
        local completed_count=$(ls -1 "${QUEUE_DIR}/completed/" 2>/dev/null | wc -l)
        local failed_count=$(ls -1 "${QUEUE_DIR}/failed/" 2>/dev/null | wc -l)
        
        cat > "${QUEUE_DIR}/metrics/final_report.json" << EOF
{
    "completed_jobs": $completed_count,
    "failed_jobs": $failed_count,
    "cleanup_time": "$(date -Iseconds)"
}
EOF
    fi
    
    log_debug "Queue management cleanup completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE WRAPPERS FOR COMMON TOOLS
# ═══════════════════════════════════════════════════════════════════════════════

# Run nuclei through queue with DOS protection
queue_nuclei() {
    local targets="$1"
    local output="$2"
    shift 2
    local extra_args="$@"
    
    TOOL_PRIORITY=$PRIORITY_NORMAL TOOL_TIMEOUT=7200 \
        queue_run_tool nuclei -l "$targets" -o "$output" $extra_args
}

# Run httpx through queue with DOS protection
queue_httpx() {
    local targets="$1"
    local output="$2"
    shift 2
    local extra_args="$@"
    
    TOOL_PRIORITY=$PRIORITY_HIGH TOOL_TIMEOUT=1800 \
        queue_run_tool httpx -l "$targets" -o "$output" $extra_args
}

# Run ffuf through queue with DOS protection
queue_ffuf() {
    local url="$1"
    local wordlist="$2"
    local output="$3"
    shift 3
    local extra_args="$@"
    
    TOOL_PRIORITY=$PRIORITY_NORMAL TOOL_TIMEOUT=3600 \
        queue_run_tool ffuf -u "$url" -w "$wordlist" -o "$output" $extra_args
}

# Run nmap through queue with DOS protection
queue_nmap() {
    local targets="$1"
    local output="$2"
    shift 2
    local extra_args="$@"
    
    TOOL_PRIORITY=$PRIORITY_HIGH TOOL_TIMEOUT=7200 \
        queue_run_tool nmap -oA "$output" $extra_args "$targets"
}

# Run masscan through queue with DOS protection
queue_masscan() {
    local targets="$1"
    local output="$2"
    shift 2
    local extra_args="$@"
    
    TOOL_PRIORITY=$PRIORITY_HIGH TOOL_TIMEOUT=3600 \
        queue_run_tool masscan -iL "$targets" -oJ "$output" $extra_args
}
