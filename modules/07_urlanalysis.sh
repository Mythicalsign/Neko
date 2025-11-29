#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: URL & JAVASCRIPT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Extract endpoints and secrets from URLs and JS files
# Tools: katana, waybackurls, gau, urlfinder, subjs, xnLinkFinder,
#        jsluice, sourcemapper, trufflehog, mantra
# ═══════════════════════════════════════════════════════════════════════════════

urlanalysis_main() {
    log_phase "PHASE 7: URL & JAVASCRIPT ANALYSIS"
    
    if ! should_run_module "urlanalysis_main" "URLANALYSIS_ENABLED"; then
        return 0
    fi
    
    start_func "urlanalysis_main" "Starting URL & JS Analysis"
    
    ensure_dir "${dir}/urls"
    ensure_dir "${dir}/js"
    ensure_dir "${dir}/.tmp/urls"
    
    # Run URL analysis functions
    urlanalysis_katana
    urlanalysis_gau
    urlanalysis_wayback
    urlanalysis_js_files
    urlanalysis_js_secrets
    urlanalysis_aggregate
    
    end_func "URL analysis completed. Results in ${dir}/urls/ and ${dir}/js/" "urlanalysis_main"
}

urlanalysis_katana() {
    if ! should_run_module "urlanalysis_katana" "URL_KATANA"; then
        return 0
    fi
    
    start_subfunc "urlanalysis_katana" "Running katana web crawler"
    
    if ! command_exists katana; then
        log_warning "katana not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts for katana"
        return 0
    fi
    
    local web_count=$(count_lines "${dir}/webs/webs.txt")
    local depth=2
    [[ "${DEEP:-false}" == "true" ]] && depth=3
    
    log_info "Running katana on $web_count hosts..."
    
    katana -list "${dir}/webs/webs.txt" \
        -jc \
        -kf all \
        -c "${KATANA_THREADS:-20}" \
        -d $depth \
        -rl "${KATANA_RATELIMIT:-150}" \
        -silent \
        -o "${dir}/.tmp/urls/katana.txt" \
        2>> "$LOGFILE" || true
    
    if [[ -s "${dir}/.tmp/urls/katana.txt" ]]; then
        # Clean and filter URLs
        sed -i '/^.\{2048\}./d' "${dir}/.tmp/urls/katana.txt"  # Remove very long lines
        grep -E "^https?://" "${dir}/.tmp/urls/katana.txt" | \
            sort -u >> "${dir}/urls/urls.txt"
    fi
    
    local katana_count=$(count_lines "${dir}/.tmp/urls/katana.txt")
    end_subfunc "Katana found $katana_count URLs" "urlanalysis_katana"
}

urlanalysis_gau() {
    if ! should_run_module "urlanalysis_gau" "URL_GAU"; then
        return 0
    fi
    
    start_subfunc "urlanalysis_gau" "Running gau (GetAllUrls)"
    
    if ! command_exists gau; then
        log_warning "gau not installed, skipping"
        return 0
    fi
    
    log_info "Running gau..."
    
    echo "$domain" | gau \
        --threads "${GAU_THREADS:-5}" \
        --blacklist png,jpg,gif,jpeg,swf,woff,woff2,svg,css,ico \
        --o "${dir}/.tmp/urls/gau.txt" \
        2>> "$LOGFILE" || true
    
    if [[ -s "${dir}/.tmp/urls/gau.txt" ]]; then
        grep -E "^https?://" "${dir}/.tmp/urls/gau.txt" | \
            grep "$domain" | \
            sort -u >> "${dir}/urls/urls.txt"
    fi
    
    local gau_count=$(count_lines "${dir}/.tmp/urls/gau.txt")
    end_subfunc "GAU found $gau_count URLs" "urlanalysis_gau"
}

urlanalysis_wayback() {
    if ! should_run_module "urlanalysis_wayback" "URL_WAYBACK"; then
        return 0
    fi
    
    start_subfunc "urlanalysis_wayback" "Running waybackurls"
    
    if ! command_exists waybackurls; then
        log_warning "waybackurls not installed, skipping"
        return 0
    fi
    
    log_info "Running waybackurls..."
    
    echo "$domain" | waybackurls \
        > "${dir}/.tmp/urls/wayback.txt" 2>> "$LOGFILE" || true
    
    if [[ -s "${dir}/.tmp/urls/wayback.txt" ]]; then
        grep -E "^https?://" "${dir}/.tmp/urls/wayback.txt" | \
            grep "$domain" | \
            sort -u >> "${dir}/urls/urls.txt"
    fi
    
    local wayback_count=$(count_lines "${dir}/.tmp/urls/wayback.txt")
    end_subfunc "Wayback found $wayback_count URLs" "urlanalysis_wayback"
}

urlanalysis_js_files() {
    if ! should_run_module "urlanalysis_js" "URL_JS_ANALYSIS"; then
        return 0
    fi
    
    start_subfunc "urlanalysis_js" "Extracting and analyzing JavaScript files"
    
    # Extract JS URLs from discovered URLs
    grep -iE "\.js(\?|$)" "${dir}/urls/urls.txt" 2>/dev/null | \
        sort -u > "${dir}/js/js_files.txt" || true
    
    # Use subjs for additional JS discovery
    if command_exists subjs && [[ -s "${dir}/webs/webs.txt" ]]; then
        log_info "Running subjs..."
        cat "${dir}/webs/webs.txt" | subjs \
            >> "${dir}/js/js_files.txt" 2>> "$LOGFILE" || true
    fi
    
    # Deduplicate
    sort -u "${dir}/js/js_files.txt" -o "${dir}/js/js_files.txt"
    
    # xnLinkFinder for endpoint extraction
    if command_exists xnLinkFinder && [[ -s "${dir}/webs/webs.txt" ]]; then
        log_info "Running xnLinkFinder..."
        
        local max_targets=50
        head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/urls/xnlink_targets.txt"
        
        xnLinkFinder -i "${dir}/.tmp/urls/xnlink_targets.txt" \
            -d "${XNLINKFINDER_DEPTH:-3}" \
            -o "${dir}/js/xnlinkfinder_output.txt" \
            2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/js/xnlinkfinder_output.txt" ]]; then
            grep -E "^https?://" "${dir}/js/xnlinkfinder_output.txt" >> "${dir}/urls/urls.txt" 2>/dev/null || true
        fi
    fi
    
    local js_count=$(count_lines "${dir}/js/js_files.txt")
    end_subfunc "Found $js_count JavaScript files" "urlanalysis_js"
}

urlanalysis_js_secrets() {
    if ! should_run_module "urlanalysis_secrets" "URL_SECRETS"; then
        return 0
    fi
    
    start_subfunc "urlanalysis_secrets" "Scanning JavaScript for secrets"
    
    if [[ ! -s "${dir}/js/js_files.txt" ]]; then
        log_warning "No JS files to analyze"
        return 0
    fi
    
    ensure_dir "${dir}/js/secrets"
    
    # Download JS files for analysis
    local max_files=100
    head -n $max_files "${dir}/js/js_files.txt" > "${dir}/.tmp/urls/js_download.txt"
    
    ensure_dir "${dir}/.tmp/urls/js_content"
    
    log_info "Downloading JS files for analysis..."
    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        local safe_name=$(echo "$js_url" | md5sum | cut -d' ' -f1)
        curl -sL -m 30 "$js_url" > "${dir}/.tmp/urls/js_content/${safe_name}.js" 2>/dev/null || true
    done < "${dir}/.tmp/urls/js_download.txt"
    
    # jsluice for secret extraction
    if command_exists jsluice; then
        log_info "Running jsluice..."
        for js_file in "${dir}/.tmp/urls/js_content/"*.js; do
            [[ -f "$js_file" ]] || continue
            jsluice secrets "$js_file" >> "${dir}/js/secrets/jsluice.json" 2>/dev/null || true
            jsluice urls "$js_file" >> "${dir}/js/js_endpoints.txt" 2>/dev/null || true
        done
    fi
    
    # mantra for secret patterns
    if command_exists mantra; then
        log_info "Running mantra..."
        for js_file in "${dir}/.tmp/urls/js_content/"*.js; do
            [[ -f "$js_file" ]] || continue
            mantra -f "$js_file" >> "${dir}/js/secrets/mantra.txt" 2>/dev/null || true
        done
    fi
    
    # trufflehog for secrets
    if command_exists trufflehog && [[ -d "${dir}/.tmp/urls/js_content" ]]; then
        log_info "Running trufflehog on JS files..."
        trufflehog filesystem "${dir}/.tmp/urls/js_content" \
            --json 2>/dev/null | jq -c >> "${dir}/js/secrets/trufflehog.json" || true
    fi
    
    # nuclei JS secrets templates
    if command_exists nuclei && [[ -s "${dir}/js/js_files.txt" ]]; then
        log_info "Running nuclei JS templates..."
        nuclei -l "${dir}/js/js_files.txt" \
            -t "${NUCLEI_TEMPLATES_PATH}/http/exposures/" \
            -tags exposure,token \
            -severity info,low,medium,high,critical \
            -c 10 \
            -silent \
            -o "${dir}/js/secrets/nuclei_js.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "JS secret scanning completed" "urlanalysis_secrets"
}

urlanalysis_aggregate() {
    log_info "Aggregating URL analysis results..."
    
    # Deduplicate all URLs
    sort -u "${dir}/urls/urls.txt" -o "${dir}/urls/urls.txt" 2>/dev/null || true
    
    # Extract URLs with parameters
    grep "?" "${dir}/urls/urls.txt" | sort -u > "${dir}/urls/urls_with_params.txt" 2>/dev/null || true
    
    # Create extensions list
    grep -oE '\.[a-zA-Z0-9]+(\?|$)' "${dir}/urls/urls.txt" 2>/dev/null | \
        sed 's/[?]$//' | sort | uniq -c | sort -rn > "${dir}/urls/extensions.txt" || true
    
    local summary="${dir}/urls/url_summary.txt"
    
    cat > "$summary" << EOF
URL Analysis Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Total URLs: $(count_lines "${dir}/urls/urls.txt")
URLs with Parameters: $(count_lines "${dir}/urls/urls_with_params.txt")
JavaScript Files: $(count_lines "${dir}/js/js_files.txt")
JS Endpoints: $(count_lines "${dir}/js/js_endpoints.txt")

Top Extensions:
$(head -10 "${dir}/urls/extensions.txt" 2>/dev/null || echo "N/A")

JS Secrets Found:
$(wc -l "${dir}/js/secrets/"*.txt "${dir}/js/secrets/"*.json 2>/dev/null | tail -1 || echo "0")

Detailed results in ${dir}/urls/ and ${dir}/js/
EOF
    
    log_success "URL analysis aggregation completed"
}
