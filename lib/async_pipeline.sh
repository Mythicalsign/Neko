#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ASYNC PIPELINE ARCHITECTURE
# Advanced job queuing, dependency management, and async execution
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

declare -gA PIPELINE_JOBS
declare -gA PIPELINE_DEPS
declare -gA PIPELINE_STATUS
declare -gA PIPELINE_RESULTS
declare -gA PIPELINE_CALLBACKS
declare -g PIPELINE_DIR=""
declare -g PIPELINE_FIFO=""
declare -g PIPELINE_RUNNING=false

# Job states
readonly JOB_PENDING="pending"
readonly JOB_QUEUED="queued"
readonly JOB_RUNNING="running"
readonly JOB_COMPLETED="completed"
readonly JOB_FAILED="failed"
readonly JOB_SKIPPED="skipped"

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

pipeline_init() {
    local base_dir="${1:-${dir}/.tmp/pipeline}"
    PIPELINE_DIR="$base_dir"
    
    ensure_dir "$PIPELINE_DIR"
    ensure_dir "${PIPELINE_DIR}/jobs"
    ensure_dir "${PIPELINE_DIR}/results"
    ensure_dir "${PIPELINE_DIR}/logs"
    ensure_dir "${PIPELINE_DIR}/fifo"
    
    # Create named pipe for async communication
    PIPELINE_FIFO="${PIPELINE_DIR}/fifo/pipeline_queue"
    [[ -p "$PIPELINE_FIFO" ]] || mkfifo "$PIPELINE_FIFO"
    
    # Initialize state file
    echo "{}" > "${PIPELINE_DIR}/state.json"
    
    log_debug "Pipeline initialized at $PIPELINE_DIR"
}

# ═══════════════════════════════════════════════════════════════════════════════
# JOB MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Add a job to the pipeline
pipeline_add_job() {
    local job_id="$1"
    local command="$2"
    local dependencies="${3:-}"  # Comma-separated job IDs
    local priority="${4:-5}"     # 1-10, higher = more important
    local timeout="${5:-3600}"
    local callback="${6:-}"
    
    PIPELINE_JOBS["$job_id"]="$command"
    PIPELINE_DEPS["$job_id"]="$dependencies"
    PIPELINE_STATUS["$job_id"]="$JOB_PENDING"
    PIPELINE_CALLBACKS["$job_id"]="$callback"
    
    # Store job metadata
    local job_file="${PIPELINE_DIR}/jobs/${job_id}.json"
    cat > "$job_file" << EOF
{
    "id": "$job_id",
    "command": $(echo "$command" | jq -Rs .),
    "dependencies": "$(echo "$dependencies" | tr ',' '\n' | jq -Rs .)",
    "priority": $priority,
    "timeout": $timeout,
    "status": "$JOB_PENDING",
    "created_at": "$(date -Iseconds)",
    "started_at": null,
    "completed_at": null,
    "exit_code": null,
    "output_file": null
}
EOF
    
    log_debug "Pipeline job added: $job_id (priority: $priority, deps: $dependencies)"
}

# Check if job dependencies are satisfied
pipeline_deps_satisfied() {
    local job_id="$1"
    local deps="${PIPELINE_DEPS[$job_id]}"
    
    [[ -z "$deps" ]] && return 0
    
    IFS=',' read -ra dep_array <<< "$deps"
    for dep in "${dep_array[@]}"; do
        [[ -z "$dep" ]] && continue
        local dep_status="${PIPELINE_STATUS[$dep]:-}"
        if [[ "$dep_status" != "$JOB_COMPLETED" ]]; then
            return 1
        fi
    done
    
    return 0
}

# Get next runnable job based on priority
pipeline_next_job() {
    local best_job=""
    local best_priority=0
    
    for job_id in "${!PIPELINE_JOBS[@]}"; do
        local status="${PIPELINE_STATUS[$job_id]}"
        [[ "$status" != "$JOB_PENDING" ]] && continue
        
        if pipeline_deps_satisfied "$job_id"; then
            local job_file="${PIPELINE_DIR}/jobs/${job_id}.json"
            local priority=$(jq -r '.priority' "$job_file" 2>/dev/null || echo "5")
            
            if [[ $priority -gt $best_priority ]]; then
                best_priority=$priority
                best_job="$job_id"
            fi
        fi
    done
    
    echo "$best_job"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ASYNC EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

# Run a single job asynchronously
pipeline_run_job_async() {
    local job_id="$1"
    local command="${PIPELINE_JOBS[$job_id]}"
    local job_file="${PIPELINE_DIR}/jobs/${job_id}.json"
    local output_file="${PIPELINE_DIR}/results/${job_id}.out"
    local error_file="${PIPELINE_DIR}/logs/${job_id}.err"
    
    # Update status
    PIPELINE_STATUS["$job_id"]="$JOB_RUNNING"
    jq --arg status "$JOB_RUNNING" --arg started "$(date -Iseconds)" \
        '.status = $status | .started_at = $started' "$job_file" > "${job_file}.tmp" && \
        mv "${job_file}.tmp" "$job_file"
    
    log_debug "Starting async job: $job_id"
    
    # Run job in background
    (
        local exit_code=0
        eval "$command" > "$output_file" 2> "$error_file" || exit_code=$?
        
        # Update completion status
        if [[ $exit_code -eq 0 ]]; then
            echo "$JOB_COMPLETED" > "${PIPELINE_DIR}/jobs/${job_id}.status"
        else
            echo "$JOB_FAILED:$exit_code" > "${PIPELINE_DIR}/jobs/${job_id}.status"
        fi
        
        # Signal completion through FIFO
        echo "COMPLETE:$job_id:$exit_code" > "$PIPELINE_FIFO" 2>/dev/null || true
    ) &
    
    # Store PID
    echo "$!" > "${PIPELINE_DIR}/jobs/${job_id}.pid"
}

# Process job completion
pipeline_on_complete() {
    local job_id="$1"
    local exit_code="${2:-0}"
    local job_file="${PIPELINE_DIR}/jobs/${job_id}.json"
    
    if [[ $exit_code -eq 0 ]]; then
        PIPELINE_STATUS["$job_id"]="$JOB_COMPLETED"
        log_success "Job completed: $job_id"
    else
        PIPELINE_STATUS["$job_id"]="$JOB_FAILED"
        log_error "Job failed: $job_id (exit code: $exit_code)"
    fi
    
    # Update job file
    jq --arg status "${PIPELINE_STATUS[$job_id]}" \
       --arg completed "$(date -Iseconds)" \
       --argjson exit "$exit_code" \
       '.status = $status | .completed_at = $completed | .exit_code = $exit' \
       "$job_file" > "${job_file}.tmp" && mv "${job_file}.tmp" "$job_file"
    
    # Run callback if defined
    local callback="${PIPELINE_CALLBACKS[$job_id]}"
    if [[ -n "$callback" ]]; then
        log_debug "Running callback for $job_id"
        eval "$callback" "${PIPELINE_DIR}/results/${job_id}.out" "$exit_code" || true
    fi
    
    # Store result for cross-phase intelligence
    PIPELINE_RESULTS["$job_id"]="${PIPELINE_DIR}/results/${job_id}.out"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

# Run the full pipeline
pipeline_run() {
    local max_concurrent="${1:-$PARALLEL_JOBS}"
    local timeout="${2:-7200}"
    
    if [[ ${#PIPELINE_JOBS[@]} -eq 0 ]]; then
        log_warning "No jobs in pipeline"
        return 0
    fi
    
    PIPELINE_RUNNING=true
    local start_time=$(date +%s)
    local running_jobs=0
    
    log_info "Starting pipeline with ${#PIPELINE_JOBS[@]} jobs (max concurrent: $max_concurrent)"
    
    while [[ "$PIPELINE_RUNNING" == "true" ]]; do
        # Check timeout
        local current_time=$(date +%s)
        if [[ $((current_time - start_time)) -gt $timeout ]]; then
            log_error "Pipeline timeout exceeded"
            pipeline_stop
            return 1
        fi
        
        # Process completion signals
        if read -t 0.1 signal < "$PIPELINE_FIFO" 2>/dev/null; then
            IFS=':' read -r action job_id exit_code <<< "$signal"
            if [[ "$action" == "COMPLETE" ]]; then
                pipeline_on_complete "$job_id" "$exit_code"
                ((running_jobs--))
            fi
        fi
        
        # Start new jobs if capacity available
        while [[ $running_jobs -lt $max_concurrent ]]; do
            local next_job=$(pipeline_next_job)
            if [[ -z "$next_job" ]]; then
                break
            fi
            
            pipeline_run_job_async "$next_job"
            ((running_jobs++))
        done
        
        # Check if all jobs complete
        local all_complete=true
        for job_id in "${!PIPELINE_JOBS[@]}"; do
            local status="${PIPELINE_STATUS[$job_id]}"
            if [[ "$status" != "$JOB_COMPLETED" ]] && [[ "$status" != "$JOB_FAILED" ]] && [[ "$status" != "$JOB_SKIPPED" ]]; then
                all_complete=false
                break
            fi
        done
        
        if [[ "$all_complete" == "true" ]]; then
            PIPELINE_RUNNING=false
        fi
        
        sleep 0.1
    done
    
    pipeline_stats
    return 0
}

# Stop pipeline execution
pipeline_stop() {
    PIPELINE_RUNNING=false
    
    # Kill running jobs
    for job_id in "${!PIPELINE_STATUS[@]}"; do
        if [[ "${PIPELINE_STATUS[$job_id]}" == "$JOB_RUNNING" ]]; then
            local pid_file="${PIPELINE_DIR}/jobs/${job_id}.pid"
            if [[ -f "$pid_file" ]]; then
                local pid=$(cat "$pid_file")
                kill -TERM "$pid" 2>/dev/null || true
            fi
            PIPELINE_STATUS["$job_id"]="$JOB_FAILED"
        fi
    done
    
    log_warning "Pipeline stopped"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

# Create standard reconnaissance pipeline
pipeline_create_recon() {
    local target="$1"
    
    pipeline_init
    
    # Phase 1: Subdomain enumeration (parallel)
    pipeline_add_job "subfinder" "subfinder -d '$target' -silent -o '${dir}/subdomains/subfinder.txt'" "" 10 600
    pipeline_add_job "assetfinder" "assetfinder --subs-only '$target' > '${dir}/subdomains/assetfinder.txt'" "" 10 300
    pipeline_add_job "crt" "curl -sL 'https://crt.sh/?q=%25.$target&output=json' | jq -r '.[].name_value' | sort -u > '${dir}/subdomains/crt.txt'" "" 9 300
    
    # Merge subdomains (depends on all subdomain tools)
    pipeline_add_job "merge_subs" "cat '${dir}/subdomains/'*.txt | sort -u > '${dir}/subdomains/all_subs.txt'" "subfinder,assetfinder,crt" 8 60
    
    # Phase 2: DNS resolution (depends on merge)
    pipeline_add_job "dns_resolve" "dnsx -l '${dir}/subdomains/all_subs.txt' -silent -o '${dir}/subdomains/resolved.txt'" "merge_subs" 8 900
    
    # Phase 3: HTTP probing (depends on DNS)
    pipeline_add_job "httpx_probe" "httpx -l '${dir}/subdomains/resolved.txt' -silent -o '${dir}/webs/webs.txt'" "dns_resolve" 7 900
    
    # Phase 4: URL discovery (parallel, depends on httpx)
    pipeline_add_job "katana" "katana -list '${dir}/webs/webs.txt' -silent -o '${dir}/urls/katana.txt'" "httpx_probe" 6 1800
    pipeline_add_job "gau" "cat '${dir}/subdomains/resolved.txt' | gau --o '${dir}/urls/gau.txt'" "dns_resolve" 6 1200
    pipeline_add_job "wayback" "cat '${dir}/subdomains/resolved.txt' | waybackurls > '${dir}/urls/wayback.txt'" "dns_resolve" 6 600
    
    # Merge URLs
    pipeline_add_job "merge_urls" "cat '${dir}/urls/'*.txt | sort -u > '${dir}/urls/all_urls.txt'" "katana,gau,wayback" 5 60
    
    # Phase 5: Vulnerability scanning (depends on URLs)
    pipeline_add_job "nuclei_scan" "nuclei -l '${dir}/urls/all_urls.txt' -severity medium,high,critical -silent -o '${dir}/vulnerabilities/nuclei.txt'" "merge_urls" 5 3600
    
    log_info "Recon pipeline created with ${#PIPELINE_JOBS[@]} jobs"
}

# Create vulnerability-focused pipeline
pipeline_create_vulnscan() {
    local targets_file="$1"
    
    pipeline_init
    
    # Parallel vulnerability checks
    pipeline_add_job "nuclei" "nuclei -l '$targets_file' -severity low,medium,high,critical -silent -o '${dir}/vulns/nuclei.txt'" "" 10 3600
    pipeline_add_job "xss_scan" "dalfox file '$targets_file' -o '${dir}/vulns/xss.txt' --silence" "" 9 1800
    pipeline_add_job "sqli_scan" "for url in \$(cat '$targets_file' | head -50); do ghauri -u \"\$url\" --batch >> '${dir}/vulns/sqli.txt' 2>/dev/null; done" "" 8 3600
    pipeline_add_job "cors_check" "nuclei -l '$targets_file' -tags cors -silent -o '${dir}/vulns/cors.txt'" "" 7 600
    pipeline_add_job "crlf_check" "crlfuzz -l '$targets_file' -s -o '${dir}/vulns/crlf.txt'" "" 7 600
    
    # Aggregate results
    pipeline_add_job "aggregate" "cat '${dir}/vulns/'*.txt | sort -u > '${dir}/vulns/all_findings.txt'" "nuclei,xss_scan,sqli_scan,cors_check,crlf_check" 5 60
}

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE STATISTICS AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

pipeline_stats() {
    local completed=0
    local failed=0
    local skipped=0
    local pending=0
    local total=${#PIPELINE_JOBS[@]}
    
    for job_id in "${!PIPELINE_STATUS[@]}"; do
        case "${PIPELINE_STATUS[$job_id]}" in
            "$JOB_COMPLETED") ((completed++)) ;;
            "$JOB_FAILED") ((failed++)) ;;
            "$JOB_SKIPPED") ((skipped++)) ;;
            "$JOB_PENDING"|"$JOB_QUEUED") ((pending++)) ;;
        esac
    done
    
    cat << EOF

Pipeline Execution Summary:
═══════════════════════════════════════════════════════════════════════════════
  Total Jobs:     $total
  Completed:      $completed
  Failed:         $failed
  Skipped:        $skipped
  Pending:        $pending
  Success Rate:   $(echo "scale=1; $completed * 100 / $total" | bc 2>/dev/null || echo "N/A")%
═══════════════════════════════════════════════════════════════════════════════

EOF
    
    if [[ $failed -gt 0 ]]; then
        echo "Failed Jobs:"
        for job_id in "${!PIPELINE_STATUS[@]}"; do
            if [[ "${PIPELINE_STATUS[$job_id]}" == "$JOB_FAILED" ]]; then
                echo "  - $job_id"
            fi
        done
        echo ""
    fi
}

# Export pipeline results for reporting
pipeline_export() {
    local output_file="${1:-${PIPELINE_DIR}/pipeline_report.json}"
    
    local jobs_json="["
    local first=true
    
    for job_id in "${!PIPELINE_JOBS[@]}"; do
        local job_file="${PIPELINE_DIR}/jobs/${job_id}.json"
        if [[ -f "$job_file" ]]; then
            [[ "$first" == "true" ]] || jobs_json+=","
            first=false
            jobs_json+=$(cat "$job_file")
        fi
    done
    
    jobs_json+="]"
    
    echo "$jobs_json" | jq '.' > "$output_file"
    log_info "Pipeline report exported to $output_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

pipeline_cleanup() {
    pipeline_stop
    
    # Clean up FIFO
    [[ -p "$PIPELINE_FIFO" ]] && rm -f "$PIPELINE_FIFO"
    
    # Clean up PID files
    rm -f "${PIPELINE_DIR}/jobs/"*.pid 2>/dev/null || true
    rm -f "${PIPELINE_DIR}/jobs/"*.status 2>/dev/null || true
    
    log_debug "Pipeline cleanup completed"
}
