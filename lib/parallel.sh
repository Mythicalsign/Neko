#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED PARALLEL PROCESSING ENGINE
# GNU Parallel integration with intelligent job management
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# PARALLEL PROCESSING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Default parallel jobs (auto-detect CPU cores)
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
PARALLEL_LOAD="${PARALLEL_LOAD:-80}"  # Max CPU load percentage
PARALLEL_MEMFREE="${PARALLEL_MEMFREE:-1G}"  # Minimum free memory
PARALLEL_TIMEOUT="${PARALLEL_TIMEOUT:-3600}"  # Default job timeout
PARALLEL_RETRIES="${PARALLEL_RETRIES:-3}"  # Retry failed jobs

# Job queue storage
declare -gA PARALLEL_QUEUE
declare -gA JOB_STATUS
declare -gA JOB_RESULTS
declare -g PARALLEL_LOG_DIR=""
declare -g PARALLEL_ENABLED=true

# ═══════════════════════════════════════════════════════════════════════════════
# PARALLEL INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

parallel_init() {
    local log_dir="${1:-${dir}/.tmp/parallel}"
    PARALLEL_LOG_DIR="$log_dir"
    
    ensure_dir "$PARALLEL_LOG_DIR"
    ensure_dir "${PARALLEL_LOG_DIR}/jobs"
    ensure_dir "${PARALLEL_LOG_DIR}/results"
    ensure_dir "${PARALLEL_LOG_DIR}/errors"
    
    # Check if GNU Parallel is available
    if ! command_exists parallel; then
        log_warning "GNU Parallel not installed. Falling back to sequential processing."
        PARALLEL_ENABLED=false
        return 1
    fi
    
    # Configure GNU Parallel defaults
    export PARALLEL_HOME="${HOME}/.parallel"
    mkdir -p "$PARALLEL_HOME"
    
    # Create willcite file to suppress citation notice
    touch "${PARALLEL_HOME}/will-cite"
    
    log_debug "Parallel processing initialized: $PARALLEL_JOBS jobs, ${PARALLEL_LOAD}% max load"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARALLEL EXECUTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Run commands in parallel from a file
parallel_run_file() {
    local input_file="$1"
    local command_template="$2"
    local output_dir="$3"
    local jobs="${4:-$PARALLEL_JOBS}"
    local timeout="${5:-$PARALLEL_TIMEOUT}"
    
    if [[ ! -s "$input_file" ]]; then
        log_warning "Empty input file for parallel execution: $input_file"
        return 1
    fi
    
    if [[ "$PARALLEL_ENABLED" != "true" ]]; then
        # Sequential fallback
        log_info "Running sequentially (parallel disabled)..."
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            eval "$(echo "$command_template" | sed "s|{}|$line|g")"
        done < "$input_file"
        return $?
    fi
    
    local line_count=$(wc -l < "$input_file" | tr -d ' ')
    log_info "Running $line_count jobs in parallel (max $jobs concurrent)..."
    
    parallel \
        --jobs "$jobs" \
        --timeout "$timeout" \
        --load "$PARALLEL_LOAD" \
        --memfree "$PARALLEL_MEMFREE" \
        --retries "$PARALLEL_RETRIES" \
        --bar \
        --progress \
        --joblog "${PARALLEL_LOG_DIR}/jobs/$(basename "$input_file").log" \
        --results "${output_dir:-$PARALLEL_LOG_DIR/results}" \
        "$command_template" :::: "$input_file" \
        2>> "$LOGFILE" || true
    
    return 0
}

# Run multiple commands in parallel
parallel_run_commands() {
    local -a commands=("$@")
    local jobs="${PARALLEL_JOBS}"
    
    if [[ ${#commands[@]} -eq 0 ]]; then
        return 0
    fi
    
    if [[ "$PARALLEL_ENABLED" != "true" ]]; then
        # Sequential fallback
        for cmd in "${commands[@]}"; do
            eval "$cmd" || true
        done
        return 0
    fi
    
    # Create temp command file
    local cmd_file="${PARALLEL_LOG_DIR}/jobs/cmd_$(date +%s).txt"
    printf '%s\n' "${commands[@]}" > "$cmd_file"
    
    log_info "Executing ${#commands[@]} commands in parallel..."
    
    parallel \
        --jobs "$jobs" \
        --timeout "$PARALLEL_TIMEOUT" \
        --load "$PARALLEL_LOAD" \
        --retries "$PARALLEL_RETRIES" \
        --bar \
        :::: "$cmd_file" \
        2>> "$LOGFILE" || true
    
    rm -f "$cmd_file"
    return 0
}

# Parallel processing with pipe input
parallel_pipe() {
    local command="$1"
    local jobs="${2:-$PARALLEL_JOBS}"
    local timeout="${3:-$PARALLEL_TIMEOUT}"
    
    if [[ "$PARALLEL_ENABLED" != "true" ]]; then
        # Sequential with xargs fallback
        xargs -I {} bash -c "$command" 2>> "$LOGFILE"
        return $?
    fi
    
    parallel \
        --jobs "$jobs" \
        --timeout "$timeout" \
        --pipe \
        --block 1M \
        "$command" \
        2>> "$LOGFILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BATCH PROCESSING WITH RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

# Process URLs in batches with rate limiting
parallel_batch_urls() {
    local input_file="$1"
    local command_template="$2"
    local output_file="$3"
    local batch_size="${4:-100}"
    local rate_limit="${5:-50}"  # requests per second
    local jobs="${6:-$PARALLEL_JOBS}"
    
    if [[ ! -s "$input_file" ]]; then
        return 1
    fi
    
    if [[ "$PARALLEL_ENABLED" != "true" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            eval "$(echo "$command_template" | sed "s|{}|$url|g")" >> "$output_file"
            sleep $(echo "scale=3; 1/$rate_limit" | bc 2>/dev/null || echo "0.02")
        done < "$input_file"
        return 0
    fi
    
    local line_count=$(wc -l < "$input_file" | tr -d ' ')
    local delay=$(echo "scale=4; 1/$rate_limit" | bc 2>/dev/null || echo "0.02")
    
    log_info "Processing $line_count URLs (batch: $batch_size, rate: ${rate_limit}/s)..."
    
    parallel \
        --jobs "$jobs" \
        --delay "$delay" \
        --bar \
        "$command_template" :::: "$input_file" \
        >> "$output_file" 2>> "$LOGFILE" || true
    
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED PROCESSING (Multi-host support)
# ═══════════════════════════════════════════════════════════════════════════════

# Initialize distributed processing
parallel_distributed_init() {
    local hosts_file="${1:-${PARALLEL_HOSTS_FILE:-}}"
    
    if [[ -z "$hosts_file" ]] || [[ ! -f "$hosts_file" ]]; then
        log_debug "No distributed hosts configured"
        return 1
    fi
    
    # Test SSH connectivity to hosts
    local valid_hosts=""
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        [[ "$host" =~ ^# ]] && continue
        
        if ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" exit 2>/dev/null; then
            valid_hosts+="$host,"
            log_debug "Host reachable: $host"
        else
            log_warning "Host unreachable: $host"
        fi
    done < "$hosts_file"
    
    export PARALLEL_SSHLOGINFILE="$hosts_file"
    log_success "Distributed processing configured with ${valid_hosts%,}"
    return 0
}

# Run distributed parallel job
parallel_distributed_run() {
    local input_file="$1"
    local command="$2"
    local output_dir="$3"
    
    if [[ -z "${PARALLEL_SSHLOGINFILE:-}" ]]; then
        # Fallback to local parallel
        parallel_run_file "$input_file" "$command" "$output_dir"
        return $?
    fi
    
    log_info "Running distributed parallel job..."
    
    parallel \
        --sshloginfile "$PARALLEL_SSHLOGINFILE" \
        --jobs "$PARALLEL_JOBS" \
        --timeout "$PARALLEL_TIMEOUT" \
        --workdir . \
        --basefile "$input_file" \
        --transfer \
        --return "{}.out" \
        --results "$output_dir" \
        "$command" :::: "$input_file" \
        2>> "$LOGFILE" || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL-SPECIFIC PARALLEL WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════

# Parallel nuclei scanning
parallel_nuclei() {
    local targets_file="$1"
    local output_dir="$2"
    local templates="${3:-}"
    local severity="${4:-$NUCLEI_SEVERITY}"
    local batch_size="${5:-100}"
    
    if [[ ! -s "$targets_file" ]]; then
        return 1
    fi
    
    ensure_dir "$output_dir"
    
    local target_count=$(wc -l < "$targets_file" | tr -d ' ')
    
    if [[ $target_count -lt $batch_size ]]; then
        # Small target list - run directly
        nuclei -l "$targets_file" \
            -severity "$severity" \
            ${templates:+-t "$templates"} \
            -c "${NUCLEI_THREADS:-25}" \
            -rl "${NUCLEI_RATELIMIT:-150}" \
            -silent \
            -o "${output_dir}/findings.txt" \
            -j -output "${output_dir}/findings.json" \
            2>> "$LOGFILE" || true
    else
        # Large target list - split and parallel
        log_info "Splitting $target_count targets for parallel nuclei..."
        
        local split_dir="${output_dir}/.splits"
        ensure_dir "$split_dir"
        
        # Split targets
        split -l $batch_size "$targets_file" "${split_dir}/batch_"
        
        # Run nuclei on each batch in parallel
        local -a nuclei_cmds=()
        for batch in "${split_dir}"/batch_*; do
            nuclei_cmds+=("nuclei -l '$batch' -severity '$severity' ${templates:+-t '$templates'} -c ${NUCLEI_THREADS:-25} -silent -o '${output_dir}/$(basename $batch)_findings.txt' 2>/dev/null")
        done
        
        parallel_run_commands "${nuclei_cmds[@]}"
        
        # Merge results
        cat "${output_dir}/"*_findings.txt > "${output_dir}/findings.txt" 2>/dev/null || true
        rm -rf "$split_dir"
    fi
    
    return 0
}

# Parallel httpx probing
parallel_httpx() {
    local targets_file="$1"
    local output_file="$2"
    local extra_flags="${3:-}"
    
    if [[ ! -s "$targets_file" ]]; then
        return 1
    fi
    
    local target_count=$(wc -l < "$targets_file" | tr -d ' ')
    log_info "Parallel httpx probing $target_count targets..."
    
    httpx -l "$targets_file" \
        -t "${HTTPX_THREADS:-50}" \
        -rl "${HTTPX_RATELIMIT:-150}" \
        -timeout "${HTTPX_TIMEOUT:-10}" \
        ${HTTPX_DEFAULT_FLAGS:-} \
        $extra_flags \
        -o "$output_file" \
        2>> "$LOGFILE" || true
}

# Parallel ffuf fuzzing
parallel_ffuf() {
    local targets_file="$1"
    local wordlist="$2"
    local output_dir="$3"
    local threads_per_target="${4:-20}"
    
    if [[ ! -s "$targets_file" ]] || [[ ! -f "$wordlist" ]]; then
        return 1
    fi
    
    ensure_dir "$output_dir"
    
    local cmd_template="ffuf -u '{}FUZZ' -w '$wordlist' -t $threads_per_target -mc all -fc 404 -sf -noninteractive -o '${output_dir}/\$(echo {} | md5sum | cut -d\" \" -f1).json' 2>/dev/null"
    
    parallel_run_file "$targets_file" "$cmd_template" "$output_dir" "${PARALLEL_JOBS:-4}"
    
    # Merge results
    cat "${output_dir}/"*.json | jq -s 'add' > "${output_dir}/all_results.json" 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# JOB MONITORING AND STATISTICS
# ═══════════════════════════════════════════════════════════════════════════════

# Get parallel execution statistics
parallel_stats() {
    local job_log="${1:-${PARALLEL_LOG_DIR}/jobs/*.log}"
    
    if [[ ! -f "$job_log" ]]; then
        echo "No job logs found"
        return 1
    fi
    
    local total=$(tail -n +2 "$job_log" | wc -l | tr -d ' ')
    local success=$(tail -n +2 "$job_log" | awk '$7 == 0 {count++} END {print count+0}')
    local failed=$(tail -n +2 "$job_log" | awk '$7 != 0 {count++} END {print count+0}')
    local avg_time=$(tail -n +2 "$job_log" | awk '{sum += $4} END {if (NR > 0) print sum/NR; else print 0}')
    
    cat << EOF
Parallel Execution Statistics:
- Total Jobs: $total
- Successful: $success
- Failed: $failed
- Success Rate: $(echo "scale=2; $success * 100 / $total" | bc 2>/dev/null || echo "N/A")%
- Average Time: ${avg_time}s
EOF
}

# Monitor running parallel jobs
parallel_monitor() {
    if ! pgrep -f "parallel" > /dev/null; then
        echo "No parallel jobs running"
        return 0
    fi
    
    echo "Active parallel processes:"
    ps aux | grep "[p]arallel" | head -10
    
    echo ""
    echo "Current load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory usage: $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SEMAPHORE-BASED CONCURRENCY CONTROL
# ═══════════════════════════════════════════════════════════════════════════════

# Create semaphore for rate limiting
sem_init() {
    local name="$1"
    local max_concurrent="${2:-5}"
    
    export SEM_DIR="${PARALLEL_LOG_DIR}/semaphores"
    ensure_dir "$SEM_DIR"
    
    parallel --semaphore --id "$name" --fg --jobs "$max_concurrent" -- true 2>/dev/null || true
    log_debug "Semaphore initialized: $name (max: $max_concurrent)"
}

# Acquire semaphore and run command
sem_run() {
    local name="$1"
    shift
    local cmd="$@"
    
    if [[ "$PARALLEL_ENABLED" != "true" ]]; then
        eval "$cmd"
        return $?
    fi
    
    parallel --semaphore --id "$name" --fg -- "$cmd" 2>> "$LOGFILE"
}

# Wait for all semaphore jobs
sem_wait() {
    local name="$1"
    
    parallel --semaphore --id "$name" --wait 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

parallel_cleanup() {
    # Kill any remaining parallel processes
    pkill -f "parallel.*--semaphore" 2>/dev/null || true
    
    # Clean up temporary files
    if [[ -d "$PARALLEL_LOG_DIR" ]]; then
        rm -rf "${PARALLEL_LOG_DIR}/jobs/"*.tmp 2>/dev/null || true
    fi
    
    log_debug "Parallel cleanup completed"
}
