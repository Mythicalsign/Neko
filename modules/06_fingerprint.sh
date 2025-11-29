#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: WEB TECHNOLOGY & FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Identify technologies, CMS, and web frameworks
# Tools: whatweb, nikto, wpscan, CMSeeK, httpx tech-detect
# ═══════════════════════════════════════════════════════════════════════════════

fingerprint_main() {
    log_phase "PHASE 6: WEB TECHNOLOGY FINGERPRINTING"
    
    if ! should_run_module "fingerprint_main" "FINGERPRINT_ENABLED"; then
        return 0
    fi
    
    start_func "fingerprint_main" "Starting Technology Fingerprinting"
    
    ensure_dir "${dir}/technologies"
    ensure_dir "${dir}/.tmp/tech"
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts for fingerprinting"
        return 0
    fi
    
    # Run fingerprinting functions
    fingerprint_whatweb
    fingerprint_nikto
    fingerprint_cms_detect
    fingerprint_wpscan
    fingerprint_aggregate
    
    end_func "Fingerprinting completed. Results in ${dir}/technologies/" "fingerprint_main"
}

fingerprint_whatweb() {
    if ! should_run_module "fingerprint_whatweb" "FP_WHATWEB"; then
        return 0
    fi
    
    start_subfunc "fingerprint_whatweb" "Running WhatWeb fingerprinting"
    
    if ! command_exists whatweb; then
        log_warning "whatweb not installed, skipping"
        return 0
    fi
    
    local max_targets=100
    head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/tech/whatweb_targets.txt"
    
    log_info "Running whatweb on $(count_lines "${dir}/.tmp/tech/whatweb_targets.txt") targets..."
    
    whatweb -i "${dir}/.tmp/tech/whatweb_targets.txt" \
        --log-json="${dir}/technologies/whatweb.json" \
        --log-brief="${dir}/technologies/whatweb.txt" \
        -a 3 \
        --no-errors \
        2>> "$LOGFILE" || true
    
    end_subfunc "WhatWeb fingerprinting completed" "fingerprint_whatweb"
}

fingerprint_nikto() {
    if ! should_run_module "fingerprint_nikto" "FP_NIKTO"; then
        return 0
    fi
    
    start_subfunc "fingerprint_nikto" "Running Nikto scanning"
    
    if ! command_exists nikto; then
        log_warning "nikto not installed, skipping"
        return 0
    fi
    
    # Nikto is slow, limit targets
    local max_targets=10
    head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/tech/nikto_targets.txt"
    
    ensure_dir "${dir}/technologies/nikto"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        local safe_name=$(echo "$url" | sed 's|https\?://||; s|[:/]|_|g')
        
        timeout "${CMSSCAN_TIMEOUT:-3600}" nikto \
            -h "$url" \
            -o "${dir}/technologies/nikto/${safe_name}.txt" \
            -Format txt \
            -maxtime 300 \
            2>> "$LOGFILE" || true
    done < "${dir}/.tmp/tech/nikto_targets.txt"
    
    end_subfunc "Nikto scanning completed" "fingerprint_nikto"
}

fingerprint_cms_detect() {
    if ! should_run_module "fingerprint_cmseek" "FP_CMSEEK"; then
        return 0
    fi
    
    start_subfunc "fingerprint_cmseek" "Running CMS detection"
    
    # CMSeeK
    if [[ -f "${TOOLS_PATH}/CMSeeK/cmseek.py" ]]; then
        log_info "Running CMSeeK..."
        
        local max_targets=30
        head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/tech/cms_targets.txt"
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            timeout 120 run_python_tool "${TOOLS_PATH}/CMSeeK" \
                -u "$url" --batch \
                >> "${dir}/technologies/cmseek_results.txt" 2>> "$LOGFILE" || true
        done < "${dir}/.tmp/tech/cms_targets.txt"
    fi
    
    end_subfunc "CMS detection completed" "fingerprint_cmseek"
}

fingerprint_wpscan() {
    if ! should_run_module "fingerprint_wpscan" "FP_WPSCAN"; then
        return 0
    fi
    
    start_subfunc "fingerprint_wpscan" "Running WordPress scanning"
    
    if ! command_exists wpscan; then
        log_warning "wpscan not installed, skipping"
        return 0
    fi
    
    # Find WordPress sites
    grep -iE "wordpress|wp-content|wp-admin" "${dir}/technologies/whatweb.txt" 2>/dev/null | \
        grep -oE "https?://[^ ]+" | sort -u > "${dir}/.tmp/tech/wordpress_sites.txt" || true
    
    if [[ ! -s "${dir}/.tmp/tech/wordpress_sites.txt" ]]; then
        log_info "No WordPress sites detected"
        return 0
    fi
    
    ensure_dir "${dir}/technologies/wpscan"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        local safe_name=$(echo "$url" | sed 's|https\?://||; s|[:/]|_|g')
        
        wpscan --url "$url" \
            --enumerate vp,vt,u \
            --random-user-agent \
            --format json \
            --output "${dir}/technologies/wpscan/${safe_name}.json" \
            2>> "$LOGFILE" || true
    done < "${dir}/.tmp/tech/wordpress_sites.txt"
    
    end_subfunc "WordPress scanning completed" "fingerprint_wpscan"
}

fingerprint_aggregate() {
    log_info "Aggregating fingerprint results..."
    
    local summary="${dir}/technologies/tech_summary.txt"
    
    cat > "$summary" << EOF
Technology Fingerprinting Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

WhatWeb Findings:
$(head -30 "${dir}/technologies/whatweb.txt" 2>/dev/null || echo "N/A")

CMS Detected:
$(grep -i "cms\|wordpress\|drupal\|joomla" "${dir}/technologies/"*.txt 2>/dev/null | head -20 || echo "None detected")

WordPress Sites:
$(cat "${dir}/.tmp/tech/wordpress_sites.txt" 2>/dev/null || echo "None")

Detailed results in ${dir}/technologies/
EOF
    
    log_success "Fingerprint aggregation completed"
}
