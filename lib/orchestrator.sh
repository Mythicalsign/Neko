#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED ORCHESTRATION SYSTEM
# Dependency-aware phase and tool execution with intelligent scheduling
# Version: 2.0.0
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

declare -g ORCHESTRATOR_DIR=""
declare -gA PHASE_STATUS
declare -gA TOOL_STATUS
declare -gA DEPENDENCY_GRAPH
declare -gA REVERSE_DEPENDENCIES
declare -ga EXECUTION_ORDER=()
declare -g ORCHESTRATOR_RUNNING=false

# Phase definitions with dependencies
# Format: "phase_id:description:dependencies:tools:priority:timeout"
declare -gA PHASE_DEFINITIONS=(
    ["osint"]="0:OSINT & Intelligence::theharvester,github-subdomains,trufflehog,gitleaks:1:1800"
    ["subdomain"]="1:Subdomain Discovery:osint:subfinder,amass,assetfinder,crt,puredns:1:3600"
    ["dns"]="2:DNS Analysis:subdomain:dnsx,massdns,dnsrecon:2:1800"
    ["webprobe"]="3:Web Probing:dns:httpx,httprobe:2:1800"
    ["portscan"]="4:Port Scanning:dns:nmap,masscan,naabu:2:3600"
    ["content"]="5:Content Discovery:webprobe:ffuf,feroxbuster,gobuster:3:3600"
    ["fingerprint"]="6:Technology Fingerprinting:webprobe:whatweb,wappalyzer,httpx:3:1800"
    ["urlanalysis"]="7:URL & JS Analysis:webprobe:katana,gau,waybackurls:3:3600"
    ["params"]="8:Parameter Discovery:urlanalysis:arjun,paramspider,gf:4:1800"
    ["vulnscan"]="9:Vulnerability Scanning:params,webprobe:nuclei,nikto:4:7200"
    ["xss"]="10:XSS Testing:params:dalfox,xsstrike,gxss:5:3600"
    ["takeover"]="11:Subdomain Takeover:subdomain:nuclei,subjack,dnsreaper:3:1800"
    ["cloud"]="12:Cloud Security:subdomain:cloud_enum,s3scanner:3:1800"
    ["auth"]="13:Authentication Testing:webprobe:brutespray,hydra:5:3600"
    ["api"]="14:API Security:fingerprint,urlanalysis:kiterunner,graphql-cop:4:3600"
    ["report"]="15:Report Generation:vulnscan,xss:report_generator:6:600"
    ["advanced_vulns"]="16:Advanced Vulnerability Testing:vulnscan,params:blind_xss,prototype_pollution,http_desync:5:7200"
    ["bettercap"]="17:Network Security Testing:portscan,dns:bettercap:4:3600"
)

# Tool definitions with capabilities
# Format: "category:priority:timeout:rate_limit:fallbacks"
declare -gA TOOL_DEFINITIONS=(
    ["subfinder"]="subdomain:1:600:0:assetfinder,findomain"
    ["amass"]="subdomain:2:1800:0:subfinder"
    ["assetfinder"]="subdomain:1:300:0:subfinder"
    ["dnsx"]="dns:1:900:150:massdns"
    ["massdns"]="dns:2:600:0:dnsx"
    ["httpx"]="webprobe:1:1800:150:httprobe"
    ["httprobe"]="webprobe:2:900:0:httpx"
    ["nmap"]="portscan:1:3600:1000:masscan"
    ["masscan"]="portscan:1:1800:1000:nmap"
    ["ffuf"]="content:1:900:100:gobuster"
    ["gobuster"]="content:2:900:100:ffuf"
    ["katana"]="urlanalysis:1:1800:150:gospider"
    ["gau"]="urlanalysis:2:600:0:waybackurls"
    ["waybackurls"]="urlanalysis:2:300:0:gau"
    ["nuclei"]="vulnscan:1:7200:150:nikto"
    ["dalfox"]="xss:1:3600:150:xsstrike"
    ["sqlmap"]="sqli:1:3600:10:ghauri"
    ["arjun"]="params:1:1800:50:"
    ["bettercap"]="network:1:3600:0:"
)

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

orchestrator_init() {
    local base_dir="${1:-${dir}/.orchestrator}"
    ORCHESTRATOR_DIR="$base_dir"
    
    ensure_dir "$ORCHESTRATOR_DIR"
    ensure_dir "${ORCHESTRATOR_DIR}/phases"
    ensure_dir "${ORCHESTRATOR_DIR}/tools"
    ensure_dir "${ORCHESTRATOR_DIR}/logs"
    ensure_dir "${ORCHESTRATOR_DIR}/state"
    
    # Build dependency graph
    _orchestrator_build_dependency_graph
    
    # Calculate execution order
    _orchestrator_calculate_execution_order
    
    # Initialize all systems
    _orchestrator_init_subsystems
    
    # Create state file
    cat > "${ORCHESTRATOR_DIR}/state/orchestrator.json" << EOF
{
    "initialized": "$(date -Iseconds)",
    "target": "${domain:-unknown}",
    "mode": "${mode:-recon}",
    "status": "initialized",
    "phases_total": ${#PHASE_DEFINITIONS[@]},
    "phases_completed": 0,
    "phases_failed": 0,
    "current_phase": null
}
EOF
    
    log_debug "Orchestrator initialized with ${#PHASE_DEFINITIONS[@]} phases"
}

_orchestrator_init_subsystems() {
    # Initialize queue management
    if type -t queue_init &>/dev/null; then
        queue_init "${ORCHESTRATOR_DIR}/queue"
    fi
    
    # Initialize error reporting
    if type -t error_report_init &>/dev/null; then
        error_report_init "${ORCHESTRATOR_DIR}/errors"
    fi
    
    # Initialize data bus
    if type -t data_bus_init &>/dev/null; then
        data_bus_init "${ORCHESTRATOR_DIR}/data_bus"
    fi
    
    # Initialize intelligence engine
    if type -t intel_init &>/dev/null; then
        intel_init "${ORCHESTRATOR_DIR}/intel"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY GRAPH MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

_orchestrator_build_dependency_graph() {
    log_debug "Building dependency graph..."
    
    for phase_id in "${!PHASE_DEFINITIONS[@]}"; do
        local def="${PHASE_DEFINITIONS[$phase_id]}"
        IFS=':' read -r num description deps tools priority timeout <<< "$def"
        
        # Store forward dependencies
        DEPENDENCY_GRAPH["$phase_id"]="$deps"
        
        # Build reverse dependencies
        if [[ -n "$deps" ]]; then
            IFS=',' read -ra dep_array <<< "$deps"
            for dep in "${dep_array[@]}"; do
                dep=$(echo "$dep" | tr -d ' ')
                [[ -z "$dep" ]] && continue
                
                if [[ -z "${REVERSE_DEPENDENCIES[$dep]}" ]]; then
                    REVERSE_DEPENDENCIES["$dep"]="$phase_id"
                else
                    REVERSE_DEPENDENCIES["$dep"]+=",${phase_id}"
                fi
            done
        fi
    done
}

# Topological sort for execution order
_orchestrator_calculate_execution_order() {
    log_debug "Calculating execution order..."
    
    local -A in_degree
    local -a queue=()
    
    # Calculate in-degree for each phase
    for phase_id in "${!PHASE_DEFINITIONS[@]}"; do
        local deps="${DEPENDENCY_GRAPH[$phase_id]}"
        
        if [[ -z "$deps" ]]; then
            in_degree["$phase_id"]=0
            queue+=("$phase_id")
        else
            IFS=',' read -ra dep_array <<< "$deps"
            in_degree["$phase_id"]=${#dep_array[@]}
        fi
    done
    
    # Kahn's algorithm for topological sort
    EXECUTION_ORDER=()
    
    while [[ ${#queue[@]} -gt 0 ]]; do
        # Get phase with lowest priority from queue
        local best_idx=0
        local best_priority=999
        
        for i in "${!queue[@]}"; do
            local phase="${queue[$i]}"
            local def="${PHASE_DEFINITIONS[$phase]}"
            IFS=':' read -r num description deps tools priority timeout <<< "$def"
            
            if [[ $priority -lt $best_priority ]]; then
                best_priority=$priority
                best_idx=$i
            fi
        done
        
        local current="${queue[$best_idx]}"
        unset 'queue[$best_idx]'
        queue=("${queue[@]}")
        
        EXECUTION_ORDER+=("$current")
        
        # Reduce in-degree for dependent phases
        local dependents="${REVERSE_DEPENDENCIES[$current]}"
        if [[ -n "$dependents" ]]; then
            IFS=',' read -ra dep_array <<< "$dependents"
            for dep in "${dep_array[@]}"; do
                dep=$(echo "$dep" | tr -d ' ')
                [[ -z "$dep" ]] && continue
                
                ((in_degree["$dep"]--))
                
                if [[ ${in_degree["$dep"]} -eq 0 ]]; then
                    queue+=("$dep")
                fi
            done
        fi
    done
    
    log_debug "Execution order: ${EXECUTION_ORDER[*]}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

# Check if phase dependencies are satisfied
orchestrator_deps_satisfied() {
    local phase_id="$1"
    local deps="${DEPENDENCY_GRAPH[$phase_id]}"
    
    [[ -z "$deps" ]] && return 0
    
    IFS=',' read -ra dep_array <<< "$deps"
    for dep in "${dep_array[@]}"; do
        dep=$(echo "$dep" | tr -d ' ')
        [[ -z "$dep" ]] && continue
        
        local dep_status="${PHASE_STATUS[$dep]:-pending}"
        
        if [[ "$dep_status" != "completed" ]]; then
            return 1
        fi
    done
    
    return 0
}

# Execute a single phase
orchestrator_run_phase() {
    local phase_id="$1"
    local force="${2:-false}"
    
    # Check if phase exists
    if [[ -z "${PHASE_DEFINITIONS[$phase_id]}" ]]; then
        log_error "Unknown phase: $phase_id"
        return 1
    fi
    
    local def="${PHASE_DEFINITIONS[$phase_id]}"
    IFS=':' read -r num description deps tools priority timeout <<< "$def"
    
    # Check if already completed
    if [[ "${PHASE_STATUS[$phase_id]}" == "completed" ]] && [[ "$force" != "true" ]]; then
        log_info "Phase $phase_id already completed, skipping"
        return 0
    fi
    
    # Check dependencies
    if ! orchestrator_deps_satisfied "$phase_id"; then
        log_warning "Phase $phase_id dependencies not satisfied"
        
        # Get unsatisfied dependencies
        IFS=',' read -ra dep_array <<< "$deps"
        for dep in "${dep_array[@]}"; do
            dep=$(echo "$dep" | tr -d ' ')
            if [[ "${PHASE_STATUS[$dep]:-pending}" != "completed" ]]; then
                log_info "  Missing dependency: $dep (status: ${PHASE_STATUS[$dep]:-pending})"
            fi
        done
        
        return 1
    fi
    
    # Mark phase as running
    PHASE_STATUS["$phase_id"]="running"
    
    # Update state
    jq --arg phase "$phase_id" '.current_phase = $phase | .status = "running"' \
        "${ORCHESTRATOR_DIR}/state/orchestrator.json" > "${ORCHESTRATOR_DIR}/state/orchestrator.json.tmp" && \
        mv "${ORCHESTRATOR_DIR}/state/orchestrator.json.tmp" "${ORCHESTRATOR_DIR}/state/orchestrator.json"
    
    log_phase "PHASE $num: $description"
    
    local phase_start_time=$(date +%s)
    local phase_exit_code=0
    
    # Create phase log
    local phase_log="${ORCHESTRATOR_DIR}/phases/${phase_id}.log"
    
    # Execute phase function
    local phase_func="${phase_id}_main"
    
    if type -t "$phase_func" &>/dev/null; then
        # Use timeout if specified
        if [[ $timeout -gt 0 ]]; then
            timeout "$timeout" bash -c "$phase_func" >> "$phase_log" 2>&1 || phase_exit_code=$?
        else
            "$phase_func" >> "$phase_log" 2>&1 || phase_exit_code=$?
        fi
    else
        # Fallback: run tools directly
        _orchestrator_run_phase_tools "$phase_id" "$tools" "$timeout" >> "$phase_log" 2>&1 || phase_exit_code=$?
    fi
    
    local phase_end_time=$(date +%s)
    local phase_duration=$((phase_end_time - phase_start_time))
    
    # Update status
    if [[ $phase_exit_code -eq 0 ]]; then
        PHASE_STATUS["$phase_id"]="completed"
        log_success "Phase $phase_id completed in ${phase_duration}s"
        
        # Trigger post-phase hooks
        _orchestrator_trigger_hooks "post_phase" "$phase_id"
        
        # Store results in data bus
        _orchestrator_store_phase_results "$phase_id"
    elif [[ $phase_exit_code -eq 124 ]]; then
        PHASE_STATUS["$phase_id"]="timeout"
        log_warning "Phase $phase_id timed out after ${timeout}s"
        
        # Record error
        if type -t error_record &>/dev/null; then
            error_record "warning" "timeout_error" "$phase_id" "$phase_id" \
                "Phase timed out after ${timeout}s" "" 124
        fi
    else
        PHASE_STATUS["$phase_id"]="failed"
        log_error "Phase $phase_id failed with exit code $phase_exit_code"
        
        # Record error
        if type -t error_record &>/dev/null; then
            error_record "error" "phase_error" "$phase_id" "$phase_id" \
                "Phase failed with exit code $phase_exit_code" "" "$phase_exit_code"
        fi
    fi
    
    # Save phase state
    cat > "${ORCHESTRATOR_DIR}/phases/${phase_id}.json" << EOF
{
    "phase_id": "$phase_id",
    "description": "$description",
    "status": "${PHASE_STATUS[$phase_id]}",
    "start_time": $phase_start_time,
    "end_time": $phase_end_time,
    "duration_seconds": $phase_duration,
    "exit_code": $phase_exit_code,
    "tools": "$tools"
}
EOF
    
    return $phase_exit_code
}

# Run tools for a phase
_orchestrator_run_phase_tools() {
    local phase_id="$1"
    local tools="$2"
    local timeout="$3"
    
    [[ -z "$tools" ]] && return 0
    
    IFS=',' read -ra tool_array <<< "$tools"
    
    for tool in "${tool_array[@]}"; do
        tool=$(echo "$tool" | tr -d ' ')
        [[ -z "$tool" ]] && continue
        
        # Check if tool exists
        if ! command_exists "$tool"; then
            log_warning "Tool not found: $tool"
            
            # Try fallback
            local tool_def="${TOOL_DEFINITIONS[$tool]:-}"
            if [[ -n "$tool_def" ]]; then
                IFS=':' read -r category priority tool_timeout rate_limit fallbacks <<< "$tool_def"
                
                if [[ -n "$fallbacks" ]]; then
                    IFS=',' read -ra fallback_array <<< "$fallbacks"
                    for fallback in "${fallback_array[@]}"; do
                        if command_exists "$fallback"; then
                            log_info "Using fallback tool: $fallback"
                            tool="$fallback"
                            break
                        fi
                    done
                fi
            fi
            
            command_exists "$tool" || continue
        fi
        
        log_info "Running tool: $tool"
        
        # Get tool input from data bus
        local input_file=""
        if type -t data_bus_get_tool_input &>/dev/null; then
            input_file=$(mktemp)
            data_bus_get_tool_input "$tool" "all" "$input_file"
        fi
        
        # Run tool through queue if available
        if type -t queue_run_tool &>/dev/null; then
            queue_run_tool "$tool" ${input_file:+-l "$input_file"} || true
        else
            # Direct execution
            local tool_output=$(mktemp)
            timeout "$timeout" "$tool" ${input_file:+-l "$input_file"} -o "$tool_output" 2>> "$LOGFILE" || true
            
            # Store output in data bus
            if type -t data_bus_store_tool_output &>/dev/null && [[ -s "$tool_output" ]]; then
                data_bus_store_tool_output "$tool" "$tool_output"
            fi
            
            rm -f "$tool_output"
        fi
        
        [[ -n "$input_file" ]] && rm -f "$input_file"
        
        TOOL_STATUS["$tool"]="completed"
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATION MODES
# ═══════════════════════════════════════════════════════════════════════════════

# Run all phases in dependency order
orchestrator_run_all() {
    log_info "Starting full orchestration with ${#EXECUTION_ORDER[@]} phases"
    
    ORCHESTRATOR_RUNNING=true
    local start_time=$(date +%s)
    local phases_completed=0
    local phases_failed=0
    
    for phase_id in "${EXECUTION_ORDER[@]}"; do
        # Check if we should run this phase based on mode
        if ! _orchestrator_should_run_phase "$phase_id"; then
            log_debug "Skipping phase $phase_id (not in current mode)"
            continue
        fi
        
        # Check for abort signal
        if [[ "$ORCHESTRATOR_RUNNING" != "true" ]]; then
            log_warning "Orchestration aborted"
            break
        fi
        
        if orchestrator_run_phase "$phase_id"; then
            ((phases_completed++))
        else
            ((phases_failed++))
            
            # Check if we should continue on failure
            if [[ "${ORCHESTRATOR_STOP_ON_FAILURE:-false}" == "true" ]]; then
                log_error "Stopping orchestration due to phase failure"
                break
            fi
        fi
    done
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    ORCHESTRATOR_RUNNING=false
    
    # Update final state
    jq --argjson completed "$phases_completed" --argjson failed "$phases_failed" \
        '.status = "completed" | .phases_completed = $completed | .phases_failed = $failed' \
        "${ORCHESTRATOR_DIR}/state/orchestrator.json" > "${ORCHESTRATOR_DIR}/state/orchestrator.json.tmp" && \
        mv "${ORCHESTRATOR_DIR}/state/orchestrator.json.tmp" "${ORCHESTRATOR_DIR}/state/orchestrator.json"
    
    log_success "Orchestration completed: $phases_completed phases completed, $phases_failed failed"
    log_info "Total duration: ${total_duration}s"
    
    return $phases_failed
}

# Run specific phases
orchestrator_run_phases() {
    local phases="$1"  # Comma-separated list
    
    IFS=',' read -ra phase_array <<< "$phases"
    
    for phase_id in "${phase_array[@]}"; do
        phase_id=$(echo "$phase_id" | tr -d ' ')
        orchestrator_run_phase "$phase_id" || true
    done
}

# Run phases up to a specific phase
orchestrator_run_until() {
    local target_phase="$1"
    
    for phase_id in "${EXECUTION_ORDER[@]}"; do
        orchestrator_run_phase "$phase_id" || true
        
        [[ "$phase_id" == "$target_phase" ]] && break
    done
}

# Check if phase should run based on mode
_orchestrator_should_run_phase() {
    local phase_id="$1"
    
    # Get phase config toggle
    local config_var="${phase_id^^}_ENABLED"
    
    if [[ "${!config_var:-true}" != "true" ]]; then
        return 1
    fi
    
    # Check mode-specific inclusions
    case "$mode" in
        passive)
            # Only run passive phases
            [[ "$phase_id" == "osint" ]] && return 0
            [[ "$phase_id" == "subdomain" ]] && return 0
            [[ "$phase_id" == "dns" ]] && return 0
            [[ "$phase_id" == "report" ]] && return 0
            return 1
            ;;
        fast)
            # Skip slow phases
            [[ "$phase_id" == "portscan" ]] && return 1
            [[ "$phase_id" == "auth" ]] && return 1
            [[ "$phase_id" == "advanced_vulns" ]] && return 1
            ;;
        subs)
            # Only subdomain phases
            [[ "$phase_id" == "osint" ]] && return 0
            [[ "$phase_id" == "subdomain" ]] && return 0
            [[ "$phase_id" == "report" ]] && return 0
            return 1
            ;;
        web)
            # Web-focused phases
            [[ "$phase_id" == "portscan" ]] && return 1
            [[ "$phase_id" == "bettercap" ]] && return 1
            ;;
    esac
    
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# HOOKS AND CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

declare -gA ORCHESTRATOR_HOOKS

# Register a hook
orchestrator_register_hook() {
    local hook_type="$1"  # pre_phase, post_phase, pre_tool, post_tool
    local callback="$2"
    local priority="${3:-50}"
    
    local hook_key="${hook_type}:${priority}:$(date +%s%N)"
    ORCHESTRATOR_HOOKS["$hook_key"]="$callback"
}

# Trigger hooks
_orchestrator_trigger_hooks() {
    local hook_type="$1"
    shift
    local args="$@"
    
    for key in $(printf '%s\n' "${!ORCHESTRATOR_HOOKS[@]}" | grep "^${hook_type}:" | sort); do
        local callback="${ORCHESTRATOR_HOOKS[$key]}"
        eval "$callback $args" 2>/dev/null || true
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# RESULT AGGREGATION
# ═══════════════════════════════════════════════════════════════════════════════

_orchestrator_store_phase_results() {
    local phase_id="$1"
    
    # Map phases to data bus channels
    case "$phase_id" in
        subdomain)
            if [[ -s "${dir}/subdomains/subdomains.txt" ]]; then
                data_bus_publish "subdomain_discovery" "$(cat "${dir}/subdomains/subdomains.txt")" "$phase_id"
            fi
            ;;
        dns)
            if [[ -s "${dir}/subdomains/resolved.txt" ]]; then
                data_bus_publish "resolved_hosts" "$(cat "${dir}/subdomains/resolved.txt")" "$phase_id"
            fi
            ;;
        webprobe)
            if [[ -s "${dir}/webs/webs.txt" ]]; then
                data_bus_publish "live_hosts" "$(cat "${dir}/webs/webs.txt")" "$phase_id"
            fi
            ;;
        portscan)
            if [[ -s "${dir}/ports/ips_live.txt" ]]; then
                data_bus_publish "target_ips" "$(cat "${dir}/ports/ips_live.txt")" "$phase_id"
            fi
            ;;
        urlanalysis)
            if [[ -s "${dir}/urls/urls.txt" ]]; then
                data_bus_publish "web_urls" "$(cat "${dir}/urls/urls.txt")" "$phase_id"
            fi
            ;;
        params)
            if [[ -s "${dir}/parameters/params_all.txt" ]]; then
                data_bus_publish "param_urls" "$(cat "${dir}/parameters/params_all.txt")" "$phase_id"
            fi
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# STATUS AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

orchestrator_status() {
    cat << EOF
Orchestrator Status
═══════════════════════════════════════════════════════════════════════════════

Mode: $mode
Target: ${domain:-unknown}
Running: $ORCHESTRATOR_RUNNING

Phase Status:
EOF
    
    for phase_id in "${EXECUTION_ORDER[@]}"; do
        local def="${PHASE_DEFINITIONS[$phase_id]}"
        IFS=':' read -r num description deps tools priority timeout <<< "$def"
        
        local status="${PHASE_STATUS[$phase_id]:-pending}"
        local status_icon="⏳"
        
        case "$status" in
            completed) status_icon="✅" ;;
            running) status_icon="🔄" ;;
            failed) status_icon="❌" ;;
            timeout) status_icon="⏰" ;;
            skipped) status_icon="⏭️" ;;
        esac
        
        printf "  %s Phase %2s: %-30s [%s]\n" "$status_icon" "$num" "$description" "$status"
    done
    
    echo "═══════════════════════════════════════════════════════════════════════════════"
}

# Get execution plan
orchestrator_plan() {
    cat << EOF
Execution Plan
═══════════════════════════════════════════════════════════════════════════════

Execution Order:
EOF
    
    local step=1
    for phase_id in "${EXECUTION_ORDER[@]}"; do
        if ! _orchestrator_should_run_phase "$phase_id"; then
            continue
        fi
        
        local def="${PHASE_DEFINITIONS[$phase_id]}"
        IFS=':' read -r num description deps tools priority timeout <<< "$def"
        
        printf "%2d. [Phase %s] %s\n" "$step" "$num" "$description"
        printf "    Dependencies: %s\n" "${deps:-none}"
        printf "    Tools: %s\n" "$tools"
        printf "    Timeout: %ss\n\n" "$timeout"
        
        ((step++))
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

orchestrator_cleanup() {
    log_info "Cleaning up orchestrator..."
    
    ORCHESTRATOR_RUNNING=false
    
    # Generate final report
    orchestrator_status > "${ORCHESTRATOR_DIR}/final_status.txt"
    
    # Cleanup subsystems
    type -t queue_cleanup &>/dev/null && queue_cleanup
    type -t error_report_cleanup &>/dev/null && error_report_cleanup
    type -t data_bus_cleanup &>/dev/null && data_bus_cleanup
    
    log_debug "Orchestrator cleanup completed"
}

# Export functions
export -f orchestrator_init orchestrator_run_phase orchestrator_run_all
export -f orchestrator_status orchestrator_deps_satisfied
