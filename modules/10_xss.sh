#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 10: XSS DETECTION & EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Comprehensive XSS vulnerability testing
# Tools: dalfox, XSStrike, Gxss, kxss
# Workflow: gf xss → Gxss (filter reflective) → dalfox (exploit)
# ═══════════════════════════════════════════════════════════════════════════════

xss_main() {
    log_phase "PHASE 10: XSS DETECTION & EXPLOITATION"
    
    if ! should_run_module "xss_main" "XSS_ENABLED"; then
        return 0
    fi
    
    start_func "xss_main" "Starting XSS Detection"
    
    ensure_dir "${dir}/xss"
    ensure_dir "${dir}/.tmp/xss"
    
    # Prepare XSS targets
    xss_prepare_targets
    
    # Run XSS detection functions
    xss_gxss_filter
    xss_dalfox
    xss_xsstrike
    xss_kxss
    xss_aggregate
    
    end_func "XSS detection completed. Results in ${dir}/xss/" "xss_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREPARE XSS TARGETS
# ═══════════════════════════════════════════════════════════════════════════════

xss_prepare_targets() {
    log_info "Preparing targets for XSS testing..."
    
    # Get URLs with parameters
    local param_file=""
    
    if [[ -s "${dir}/parameters/params_all.txt" ]]; then
        param_file="${dir}/parameters/params_all.txt"
    elif [[ -s "${dir}/urls/urls_with_params.txt" ]]; then
        param_file="${dir}/urls/urls_with_params.txt"
    elif [[ -s "${dir}/urls/urls.txt" ]]; then
        # Filter URLs with parameters
        grep "?" "${dir}/urls/urls.txt" > "${dir}/.tmp/xss/urls_with_params.txt" 2>/dev/null || true
        param_file="${dir}/.tmp/xss/urls_with_params.txt"
    fi
    
    if [[ -z "$param_file" ]] || [[ ! -s "$param_file" ]]; then
        log_warning "No URLs with parameters found for XSS testing"
        return 0
    fi
    
    # Filter potential XSS candidates using GF patterns
    if command_exists gf; then
        log_info "Filtering XSS candidates with GF patterns..."
        cat "$param_file" | gf xss | sort -u > "${dir}/.tmp/xss/xss_candidates.txt" 2>/dev/null || true
        
        # If GF returns nothing, use all parameterized URLs
        if [[ ! -s "${dir}/.tmp/xss/xss_candidates.txt" ]]; then
            cat "$param_file" | sort -u > "${dir}/.tmp/xss/xss_candidates.txt"
        fi
    else
        cat "$param_file" | sort -u > "${dir}/.tmp/xss/xss_candidates.txt"
    fi
    
    local candidate_count=$(count_lines "${dir}/.tmp/xss/xss_candidates.txt")
    log_info "Found $candidate_count XSS candidates"
    
    # Limit candidates
    local max_candidates=500
    [[ "${DEEP:-false}" == "true" ]] && max_candidates=2000
    
    if [[ $candidate_count -gt $max_candidates ]]; then
        log_warning "Limiting to first $max_candidates candidates"
        head -n $max_candidates "${dir}/.tmp/xss/xss_candidates.txt" > "${dir}/.tmp/xss/xss_targets.txt"
    else
        cp "${dir}/.tmp/xss/xss_candidates.txt" "${dir}/.tmp/xss/xss_targets.txt"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# GXSS - PARAMETER REFLECTION CHECK
# ═══════════════════════════════════════════════════════════════════════════════

xss_gxss_filter() {
    if ! should_run_module "xss_gxss" "XSS_GXSS"; then
        return 0
    fi
    
    start_subfunc "xss_gxss" "Checking parameter reflection with Gxss"
    
    if ! command_exists Gxss; then
        log_warning "Gxss not installed, skipping reflection check"
        # Use all targets without filtering
        cp "${dir}/.tmp/xss/xss_targets.txt" "${dir}/.tmp/xss/reflected_params.txt" 2>/dev/null || true
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/xss/xss_targets.txt" ]]; then
        log_warning "No XSS targets available"
        return 0
    fi
    
    log_info "Checking for reflected parameters..."
    
    cat "${dir}/.tmp/xss/xss_targets.txt" | \
        Gxss -c 100 \
        > "${dir}/.tmp/xss/reflected_params.txt" 2>> "$LOGFILE" || true
    
    local reflected_count=$(count_lines "${dir}/.tmp/xss/reflected_params.txt")
    log_info "Found $reflected_count URLs with reflected parameters"
    
    # Save reflected params for dalfox
    if [[ -s "${dir}/.tmp/xss/reflected_params.txt" ]]; then
        cp "${dir}/.tmp/xss/reflected_params.txt" "${dir}/xss/reflected_parameters.txt"
    fi
    
    end_subfunc "Gxss found $reflected_count reflected parameters" "xss_gxss"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DALFOX - PRIMARY XSS SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

xss_dalfox() {
    if ! should_run_module "xss_dalfox" "XSS_DALFOX"; then
        return 0
    fi
    
    start_subfunc "xss_dalfox" "Running dalfox XSS scanner"
    
    if ! command_exists dalfox; then
        log_warning "dalfox not installed, skipping"
        return 0
    fi
    
    # Use reflected params if available, otherwise use all targets
    local target_file
    if [[ -s "${dir}/.tmp/xss/reflected_params.txt" ]]; then
        target_file="${dir}/.tmp/xss/reflected_params.txt"
    elif [[ -s "${dir}/.tmp/xss/xss_targets.txt" ]]; then
        target_file="${dir}/.tmp/xss/xss_targets.txt"
    else
        log_warning "No targets for dalfox"
        return 0
    fi
    
    local target_count=$(count_lines "$target_file")
    log_info "Running dalfox on $target_count targets..."
    
    # Limit for dalfox
    local max_targets=200
    [[ "${DEEP:-false}" == "true" ]] && max_targets=1000
    
    if [[ $target_count -gt $max_targets ]]; then
        head -n $max_targets "$target_file" > "${dir}/.tmp/xss/dalfox_targets.txt"
        target_file="${dir}/.tmp/xss/dalfox_targets.txt"
    fi
    
    # Build dalfox command
    local dalfox_cmd="dalfox file $target_file"
    dalfox_cmd+=" -w ${DALFOX_THREADS:-100}"
    dalfox_cmd+=" -o ${dir}/xss/dalfox_results.txt"
    dalfox_cmd+=" --output-all"
    dalfox_cmd+=" --silence"
    dalfox_cmd+=" --no-color"
    
    # Add blind XSS server if configured
    if [[ -n "${XSS_HUNTER_URL:-}" ]]; then
        dalfox_cmd+=" -b $XSS_HUNTER_URL"
    fi
    
    # Add custom payload file if exists
    if [[ -f "${XSS_WORDLIST:-}" ]]; then
        dalfox_cmd+=" --custom-payload $XSS_WORDLIST"
    fi
    
    # Run dalfox
    log_debug "Dalfox command: $dalfox_cmd"
    eval "$dalfox_cmd" 2>> "$LOGFILE" || true
    
    # Parse results
    if [[ -s "${dir}/xss/dalfox_results.txt" ]]; then
        # Extract confirmed XSS
        grep -E "\[V\]|\[POC\]" "${dir}/xss/dalfox_results.txt" \
            > "${dir}/xss/confirmed_xss.txt" 2>/dev/null || true
        
        # Extract POC URLs
        grep -oE "http[s]?://[^ ]+" "${dir}/xss/dalfox_results.txt" | \
            sort -u > "${dir}/xss/xss_poc_urls.txt" 2>/dev/null || true
        
        local confirmed_count=$(count_lines "${dir}/xss/confirmed_xss.txt")
        
        if [[ $confirmed_count -gt 0 ]]; then
            notify "Dalfox found $confirmed_count confirmed XSS vulnerabilities!" "warning"
        fi
    fi
    
    local finding_count=$(count_lines "${dir}/xss/dalfox_results.txt")
    end_subfunc "Dalfox found $finding_count potential XSS" "xss_dalfox"
}

# ═══════════════════════════════════════════════════════════════════════════════
# XSSTRIKE - MANUAL/DOM XSS
# ═══════════════════════════════════════════════════════════════════════════════

xss_xsstrike() {
    if ! should_run_module "xss_xsstrike" "XSS_XSSTRIKE"; then
        return 0
    fi
    
    start_subfunc "xss_xsstrike" "Running XSStrike scanner"
    
    if ! command_exists xsstrike; then
        log_warning "XSStrike not installed, skipping"
        return 0
    fi
    
    local target_file
    if [[ -s "${dir}/.tmp/xss/reflected_params.txt" ]]; then
        target_file="${dir}/.tmp/xss/reflected_params.txt"
    elif [[ -s "${dir}/.tmp/xss/xss_targets.txt" ]]; then
        target_file="${dir}/.tmp/xss/xss_targets.txt"
    else
        log_warning "No targets for XSStrike"
        return 0
    fi
    
    # Limit targets (XSStrike is slower)
    local max_targets=50
    head -n $max_targets "$target_file" > "${dir}/.tmp/xss/xsstrike_targets.txt"
    
    log_info "Running XSStrike on $(count_lines "${dir}/.tmp/xss/xsstrike_targets.txt") targets..."
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        timeout 60 xsstrike -u "$url" \
            --crawl \
            --skip \
            2>> "$LOGFILE" >> "${dir}/xss/xsstrike_results.txt" || true
        
    done < "${dir}/.tmp/xss/xsstrike_targets.txt"
    
    end_subfunc "XSStrike scan completed" "xss_xsstrike"
}

# ═══════════════════════════════════════════════════════════════════════════════
# KXSS - QUICK XSS CHECK
# ═══════════════════════════════════════════════════════════════════════════════

xss_kxss() {
    if ! should_run_module "xss_kxss" "XSS_KXSS"; then
        return 0
    fi
    
    start_subfunc "xss_kxss" "Running kxss quick check"
    
    if ! command_exists kxss; then
        log_warning "kxss not installed, skipping"
        return 0
    fi
    
    local target_file="${dir}/.tmp/xss/xss_targets.txt"
    
    if [[ ! -s "$target_file" ]]; then
        log_warning "No targets for kxss"
        return 0
    fi
    
    log_info "Running kxss..."
    
    cat "$target_file" | kxss \
        > "${dir}/xss/kxss_results.txt" 2>> "$LOGFILE" || true
    
    local kxss_count=$(count_lines "${dir}/xss/kxss_results.txt")
    end_subfunc "kxss found $kxss_count potential XSS" "xss_kxss"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE XSS RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

xss_aggregate() {
    log_info "Aggregating XSS results..."
    
    # Combine all unique XSS findings
    cat "${dir}/xss/"*_results.txt "${dir}/xss/confirmed_xss.txt" 2>/dev/null | \
        sort -u > "${dir}/xss/all_findings.txt" || true
    
    local summary="${dir}/xss/xss_summary.txt"
    
    cat > "$summary" << EOF
XSS Detection Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

CANDIDATES TESTED:
- Total XSS candidates: $(count_lines "${dir}/.tmp/xss/xss_candidates.txt")
- Reflected parameters: $(count_lines "${dir}/.tmp/xss/reflected_params.txt")
- Actually tested: $(count_lines "${dir}/.tmp/xss/xss_targets.txt")

FINDINGS:
- Dalfox findings: $(count_lines "${dir}/xss/dalfox_results.txt")
- Confirmed XSS (Dalfox): $(count_lines "${dir}/xss/confirmed_xss.txt")
- XSStrike findings: $(grep -c "XSS" "${dir}/xss/xsstrike_results.txt" 2>/dev/null || echo "0")
- kxss findings: $(count_lines "${dir}/xss/kxss_results.txt")

CONFIRMED VULNERABILITIES:
$(cat "${dir}/xss/confirmed_xss.txt" 2>/dev/null || echo "None confirmed")

POC URLS:
$(head -10 "${dir}/xss/xss_poc_urls.txt" 2>/dev/null || echo "None")

Detailed results available in ${dir}/xss/
EOF
    
    # Check for confirmed XSS
    local confirmed_count=$(count_lines "${dir}/xss/confirmed_xss.txt")
    if [[ $confirmed_count -gt 0 ]]; then
        notify "Total $confirmed_count confirmed XSS vulnerabilities found!" "warning"
    fi
    
    log_success "XSS aggregation completed"
}
