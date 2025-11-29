#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: PARAMETER DISCOVERY & ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Find hidden parameters for injection testing
# Tools: arjun, paramspider, gf, qsreplace, unfurl, urless
# ═══════════════════════════════════════════════════════════════════════════════

param_main() {
    log_phase "PHASE 8: PARAMETER DISCOVERY"
    
    if ! should_run_module "param_main" "PARAM_ENABLED"; then
        return 0
    fi
    
    start_func "param_main" "Starting Parameter Discovery"
    
    ensure_dir "${dir}/parameters"
    ensure_dir "${dir}/.tmp/params"
    
    # Run parameter discovery functions
    param_arjun
    param_paramspider
    param_gf_patterns
    param_dedupe
    param_aggregate
    
    end_func "Parameter discovery completed. Results in ${dir}/parameters/" "param_main"
}

param_arjun() {
    if ! should_run_module "param_arjun" "PARAM_ARJUN"; then
        return 0
    fi
    
    start_subfunc "param_arjun" "Running Arjun hidden parameter discovery"
    
    if ! command_exists arjun; then
        log_warning "arjun not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts for arjun"
        return 0
    fi
    
    # Limit targets (arjun is slow)
    local max_targets=30
    head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/params/arjun_targets.txt"
    
    log_info "Running arjun on $(count_lines "${dir}/.tmp/params/arjun_targets.txt") targets..."
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        arjun -u "$url" \
            -t "${ARJUN_THREADS:-20}" \
            -oJ "${dir}/.tmp/params/arjun_$(echo "$url" | md5sum | cut -d' ' -f1).json" \
            2>> "$LOGFILE" || true
        
    done < "${dir}/.tmp/params/arjun_targets.txt"
    
    # Merge arjun results
    cat "${dir}/.tmp/params/arjun_"*.json 2>/dev/null | \
        jq -s 'add' > "${dir}/parameters/arjun_results.json" 2>/dev/null || true
    
    end_subfunc "Arjun parameter discovery completed" "param_arjun"
}

param_paramspider() {
    if ! should_run_module "param_paramspider" "PARAM_PARAMSPIDER"; then
        return 0
    fi
    
    start_subfunc "param_paramspider" "Running ParamSpider parameter mining"
    
    if ! command_exists paramspider; then
        log_warning "paramspider not installed, skipping"
        return 0
    fi
    
    log_info "Running paramspider..."
    
    paramspider -d "$domain" \
        -o "${dir}/parameters/paramspider.txt" \
        2>> "$LOGFILE" || true
    
    end_subfunc "ParamSpider completed" "param_paramspider"
}

param_gf_patterns() {
    if ! should_run_module "param_gf" "PARAM_GF"; then
        return 0
    fi
    
    start_subfunc "param_gf" "Applying GF patterns for parameter classification"
    
    if ! command_exists gf; then
        log_warning "gf not installed, skipping pattern matching"
        return 0
    fi
    
    local url_file="${dir}/urls/urls_with_params.txt"
    if [[ ! -s "$url_file" ]]; then
        url_file="${dir}/urls/urls.txt"
    fi
    
    if [[ ! -s "$url_file" ]]; then
        log_warning "No URLs for GF patterns"
        return 0
    fi
    
    ensure_dir "${dir}/parameters/gf"
    
    log_info "Applying GF patterns..."
    
    # Apply various GF patterns
    local patterns=("xss" "sqli" "lfi" "rce" "idor" "ssrf" "redirect" "ssti" "interestingparams" "debug-logic")
    
    for pattern in "${patterns[@]}"; do
        cat "$url_file" | gf "$pattern" \
            > "${dir}/parameters/gf/${pattern}.txt" 2>/dev/null || true
    done
    
    end_subfunc "GF pattern matching completed" "param_gf"
}

param_dedupe() {
    if ! should_run_module "param_dedupe" "PARAM_DEDUPE"; then
        return 0
    fi
    
    start_subfunc "param_dedupe" "Deduplicating URLs by parameters"
    
    local url_file="${dir}/urls/urls_with_params.txt"
    
    if [[ ! -s "$url_file" ]]; then
        log_warning "No URLs with parameters"
        return 0
    fi
    
    # Use urless if available
    if command_exists urless; then
        log_info "Running urless for URL deduplication..."
        cat "$url_file" | urless \
            > "${dir}/parameters/unique_params.txt" 2>> "$LOGFILE" || true
    elif command_exists uro; then
        log_info "Running uro for URL deduplication..."
        cat "$url_file" | uro \
            > "${dir}/parameters/unique_params.txt" 2>> "$LOGFILE" || true
    else
        # Simple deduplication
        sort -u "$url_file" > "${dir}/parameters/unique_params.txt"
    fi
    
    # Use qsreplace to prepare for injection testing
    if command_exists qsreplace; then
        log_info "Preparing injection targets with qsreplace..."
        
        # Create targets for different injection types
        cat "${dir}/parameters/unique_params.txt" | qsreplace "FUZZ" \
            > "${dir}/parameters/fuzz_targets.txt" 2>/dev/null || true
        
        cat "${dir}/parameters/unique_params.txt" | qsreplace "1" \
            > "${dir}/parameters/numeric_targets.txt" 2>/dev/null || true
    fi
    
    end_subfunc "URL deduplication completed" "param_dedupe"
}

param_aggregate() {
    log_info "Aggregating parameter discovery results..."
    
    # Combine all parameters
    cat "${dir}/parameters/"*.txt "${dir}/parameters/gf/"*.txt 2>/dev/null | \
        sort -u > "${dir}/parameters/params_all.txt" || true
    
    local summary="${dir}/parameters/param_summary.txt"
    
    cat > "$summary" << EOF
Parameter Discovery Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Total URLs with Parameters: $(count_lines "${dir}/urls/urls_with_params.txt")
Unique Parameter URLs: $(count_lines "${dir}/parameters/unique_params.txt")
All Parameters: $(count_lines "${dir}/parameters/params_all.txt")

GF Pattern Matches:
- XSS: $(count_lines "${dir}/parameters/gf/xss.txt")
- SQLi: $(count_lines "${dir}/parameters/gf/sqli.txt")
- LFI: $(count_lines "${dir}/parameters/gf/lfi.txt")
- RCE: $(count_lines "${dir}/parameters/gf/rce.txt")
- IDOR: $(count_lines "${dir}/parameters/gf/idor.txt")
- SSRF: $(count_lines "${dir}/parameters/gf/ssrf.txt")
- Redirect: $(count_lines "${dir}/parameters/gf/redirect.txt")
- SSTI: $(count_lines "${dir}/parameters/gf/ssti.txt")

Detailed results in ${dir}/parameters/
EOF
    
    log_success "Parameter aggregation completed"
}
