#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: WEB PROBING & DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Identify live web services before scanning
# Tools: httpx, httprobe, cdncheck, wafw00f
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_main() {
    log_phase "PHASE 3: WEB PROBING & DETECTION"
    
    if ! should_run_module "webprobe_main" "WEBPROBE_ENABLED"; then
        return 0
    fi
    
    start_func "webprobe_main" "Starting Web Probing"
    
    ensure_dir "${dir}/webs"
    ensure_dir "${dir}/.tmp/webs"
    
    # Run web probing functions
    webprobe_httpx
    webprobe_waf_detection
    webprobe_cdn_detection
    webprobe_screenshots
    webprobe_aggregate
    
    end_func "Web probing completed. Results in ${dir}/webs/" "webprobe_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTPX PROBING
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_httpx() {
    if ! should_run_module "webprobe_httpx" "PROBE_HTTPX"; then
        return 0
    fi
    
    start_subfunc "webprobe_httpx" "Running HTTPx web probing"
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains to probe"
        return 0
    fi
    
    if ! command_exists httpx; then
        log_warning "httpx not installed, trying httprobe..."
        webprobe_httprobe
        return 0
    fi
    
    local sub_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    log_info "Probing $sub_count subdomains..."
    
    # Standard web ports probing
    log_info "Probing standard ports (80, 443)..."
    httpx -l "${dir}/subdomains/subdomains.txt" \
        -t "${HTTPX_THREADS:-50}" \
        -rl "${HTTPX_RATELIMIT:-150}" \
        -timeout "${HTTPX_TIMEOUT:-10}" \
        -retries 2 \
        ${HTTPX_DEFAULT_FLAGS:--follow-redirects -random-agent -status-code -silent -title -web-server -tech-detect -location -content-length} \
        -no-color \
        -json \
        -o "${dir}/.tmp/webs/httpx_standard.json" 2>> "$LOGFILE" || true
    
    # Extract live URLs
    if [[ -s "${dir}/.tmp/webs/httpx_standard.json" ]]; then
        jq -r '.url // empty' "${dir}/.tmp/webs/httpx_standard.json" 2>/dev/null | \
            sort -u >> "${dir}/webs/webs.txt"
    fi
    
    # Extended ports probing (if enabled or deep mode)
    if [[ "${DEEP:-false}" == "true" ]] || [[ "${PROBE_EXTENDED_PORTS:-false}" == "true" ]]; then
        log_info "Probing extended ports..."
        httpx -l "${dir}/subdomains/subdomains.txt" \
            -p "${HTTPX_PORTS:-80,443,8080,8443,8000,8888,3000,5000,9000,9443}" \
            -t "${HTTPX_THREADS:-50}" \
            -rl "${HTTPX_RATELIMIT:-150}" \
            -timeout "${HTTPX_TIMEOUT:-10}" \
            -retries 1 \
            ${HTTPX_DEFAULT_FLAGS} \
            -no-color \
            -json \
            -o "${dir}/.tmp/webs/httpx_extended.json" 2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/webs/httpx_extended.json" ]]; then
            jq -r '.url // empty' "${dir}/.tmp/webs/httpx_extended.json" 2>/dev/null | \
                sort -u >> "${dir}/webs/webs.txt"
        fi
    fi
    
    # Merge JSON files
    cat "${dir}/.tmp/webs/httpx_"*.json 2>/dev/null | \
        jq -s 'unique_by(.url)' > "${dir}/webs/httpx_full.json" 2>/dev/null || true
    
    # Extract various information
    webprobe_extract_httpx_data
    
    # Deduplicate
    sort -u "${dir}/webs/webs.txt" -o "${dir}/webs/webs.txt"
    
    local live_count=$(count_lines "${dir}/webs/webs.txt")
    end_subfunc "Found $live_count live web hosts" "webprobe_httpx"
}

# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACT DATA FROM HTTPX RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_extract_httpx_data() {
    log_info "Extracting data from HTTPx results..."
    
    if [[ ! -s "${dir}/webs/httpx_full.json" ]]; then
        return 0
    fi
    
    # Extract status codes distribution
    jq -r '.status_code // empty' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort | uniq -c | sort -rn > "${dir}/webs/status_codes.txt" || true
    
    # Extract titles
    jq -r 'select(.title) | "\(.url) - \(.title)"' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/titles.txt" || true
    
    # Extract web servers
    jq -r 'select(.webserver) | "\(.url) - \(.webserver)"' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/webservers.txt" || true
    
    # Extract technologies
    jq -r 'select(.tech) | "\(.url) - \(.tech | join(", "))"' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/technologies_quick.txt" || true
    
    # Extract redirects
    jq -r 'select(.location) | "\(.url) -> \(.location)"' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/redirects.txt" || true
    
    # Extract content lengths for potential analysis
    jq -r 'select(.content_length) | "\(.url) - \(.content_length)"' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/content_lengths.txt" || true
    
    # Find interesting status codes
    jq -r 'select(.status_code == 401 or .status_code == 403) | .url' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/auth_required.txt" || true
    
    jq -r 'select(.status_code >= 500) | .url' "${dir}/webs/httpx_full.json" 2>/dev/null | \
        sort -u > "${dir}/webs/server_errors.txt" || true
    
    log_info "HTTPx data extraction completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTPROBE FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_httprobe() {
    start_subfunc "webprobe_httprobe" "Running httprobe web probing"
    
    if ! command_exists httprobe; then
        log_warning "httprobe not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains to probe"
        return 0
    fi
    
    cat "${dir}/subdomains/subdomains.txt" | \
        httprobe -t "${HTTPROBE_THREADS:-50}" -c 50 \
        > "${dir}/webs/webs.txt" 2>> "$LOGFILE" || true
    
    sort -u "${dir}/webs/webs.txt" -o "${dir}/webs/webs.txt"
    
    local live_count=$(count_lines "${dir}/webs/webs.txt")
    end_subfunc "Found $live_count live web hosts" "webprobe_httprobe"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WAF DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_waf_detection() {
    if ! should_run_module "webprobe_waf" "PROBE_WAF"; then
        return 0
    fi
    
    start_subfunc "webprobe_waf" "Running WAF detection"
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts for WAF detection"
        return 0
    fi
    
    local web_count=$(count_lines "${dir}/webs/webs.txt")
    
    # Limit WAF detection for large target sets
    if [[ $web_count -gt 100 ]] && [[ "${DEEP:-false}" != "true" ]]; then
        log_warning "Too many hosts ($web_count), limiting WAF detection to first 100"
        head -n 100 "${dir}/webs/webs.txt" > "${dir}/.tmp/webs/waf_targets.txt"
    else
        cp "${dir}/webs/webs.txt" "${dir}/.tmp/webs/waf_targets.txt"
    fi
    
    # wafw00f
    if command_exists wafw00f; then
        log_info "Running wafw00f..."
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local waf_result=$(wafw00f "$url" 2>/dev/null | grep -E "behind|protected|detected|No WAF" | head -1)
            if [[ -n "$waf_result" ]]; then
                echo "$url: $waf_result" >> "${dir}/webs/waf_detection.txt"
            fi
        done < "${dir}/.tmp/webs/waf_targets.txt"
    fi
    
    # Create WAF summary
    if [[ -s "${dir}/webs/waf_detection.txt" ]]; then
        log_info "Creating WAF summary..."
        
        # Count hosts behind WAF
        local waf_count=$(grep -cv "No WAF" "${dir}/webs/waf_detection.txt" 2>/dev/null || echo "0")
        local no_waf_count=$(grep -c "No WAF" "${dir}/webs/waf_detection.txt" 2>/dev/null || echo "0")
        
        cat > "${dir}/webs/waf_summary.txt" << EOF
WAF Detection Summary
=====================
Hosts behind WAF: $waf_count
Hosts without WAF: $no_waf_count

Detected WAFs:
$(grep -v "No WAF" "${dir}/webs/waf_detection.txt" 2>/dev/null | sort -u || echo "None detected")

Hosts without WAF (potential targets):
$(grep "No WAF" "${dir}/webs/waf_detection.txt" 2>/dev/null | cut -d: -f1 || echo "None")
EOF
    fi
    
    local waf_hosts=$(grep -cv "No WAF" "${dir}/webs/waf_detection.txt" 2>/dev/null || echo "0")
    end_subfunc "Found $waf_hosts hosts behind WAF" "webprobe_waf"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CDN DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_cdn_detection() {
    if ! should_run_module "webprobe_cdn" "PROBE_CDN"; then
        return 0
    fi
    
    start_subfunc "webprobe_cdn" "Running CDN detection"
    
    if [[ ! -s "${dir}/hosts/ips.txt" ]]; then
        log_warning "No IPs for CDN detection"
        return 0
    fi
    
    # cdncheck
    if command_exists cdncheck; then
        log_info "Running cdncheck..."
        
        # Check for CDN
        cdncheck -i "${dir}/hosts/ips.txt" -cdn \
            -o "${dir}/webs/cdn_hosts.txt" 2>> "$LOGFILE" || true
        
        # Check for WAF via cdncheck
        cdncheck -i "${dir}/hosts/ips.txt" -waf \
            -o "${dir}/webs/waf_hosts.txt" 2>> "$LOGFILE" || true
        
        # Get non-CDN hosts (better for scanning)
        cdncheck -i "${dir}/hosts/ips.txt" -nc \
            -o "${dir}/webs/non_cdn_hosts.txt" 2>> "$LOGFILE" || true
    fi
    
    # Create CDN summary
    local cdn_count=$(count_lines "${dir}/webs/cdn_hosts.txt")
    local non_cdn_count=$(count_lines "${dir}/webs/non_cdn_hosts.txt")
    
    cat > "${dir}/webs/cdn_summary.txt" << EOF
CDN Detection Summary
=====================
Hosts behind CDN: $cdn_count
Hosts not behind CDN: $non_cdn_count

CDN Hosts:
$(cat "${dir}/webs/cdn_hosts.txt" 2>/dev/null || echo "None")

Non-CDN Hosts (better targets for scanning):
$(cat "${dir}/webs/non_cdn_hosts.txt" 2>/dev/null || echo "None")
EOF
    
    end_subfunc "Found $cdn_count hosts behind CDN" "webprobe_cdn"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WEB SCREENSHOTS
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_screenshots() {
    if ! should_run_module "webprobe_screenshots" "PROBE_SCREENSHOTS"; then
        return 0
    fi
    
    start_subfunc "webprobe_screenshots" "Capturing web screenshots"
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts for screenshots"
        return 0
    fi
    
    local web_count=$(count_lines "${dir}/webs/webs.txt")
    
    # Limit screenshots for large target sets
    local max_screenshots=100
    if [[ "${DEEP:-false}" == "true" ]]; then
        max_screenshots=500
    fi
    
    if [[ $web_count -gt $max_screenshots ]]; then
        log_warning "Limiting screenshots to first $max_screenshots hosts"
        head -n $max_screenshots "${dir}/webs/webs.txt" > "${dir}/.tmp/webs/screenshot_targets.txt"
    else
        cp "${dir}/webs/webs.txt" "${dir}/.tmp/webs/screenshot_targets.txt"
    fi
    
    ensure_dir "${dir}/webs/screenshots"
    
    # gowitness (preferred)
    if command_exists gowitness; then
        log_info "Running gowitness for screenshots..."
        gowitness file -f "${dir}/.tmp/webs/screenshot_targets.txt" \
            -P "${dir}/webs/screenshots" \
            --disable-db \
            -t "${GOWITNESS_THREADS:-4}" \
            2>> "$LOGFILE" || true
    # Aquatone (alternative)
    elif command_exists aquatone; then
        log_info "Running aquatone for screenshots..."
        cat "${dir}/.tmp/webs/screenshot_targets.txt" | \
            aquatone -out "${dir}/webs/screenshots" \
            -threads "${AQUATONE_THREADS:-2}" \
            -silent 2>> "$LOGFILE" || true
    # eyewitness (alternative)
    elif command_exists eyewitness; then
        log_info "Running eyewitness for screenshots..."
        eyewitness -f "${dir}/.tmp/webs/screenshot_targets.txt" \
            --web \
            -d "${dir}/webs/screenshots" \
            --no-prompt \
            --timeout 30 2>> "$LOGFILE" || true
    else
        log_warning "No screenshot tool available (gowitness, aquatone, or eyewitness)"
    fi
    
    local screenshot_count=$(find "${dir}/webs/screenshots" -name "*.png" -o -name "*.jpg" 2>/dev/null | wc -l)
    end_subfunc "Captured $screenshot_count screenshots" "webprobe_screenshots"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE WEB PROBING RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

webprobe_aggregate() {
    log_info "Aggregating web probing results..."
    
    local summary="${dir}/webs/webprobe_summary.txt"
    
    cat > "$summary" << EOF
Web Probing Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Live Web Hosts: $(count_lines "${dir}/webs/webs.txt")

Status Code Distribution:
$(cat "${dir}/webs/status_codes.txt" 2>/dev/null | head -10 || echo "N/A")

Top Web Servers:
$(awk -F' - ' '{print $2}' "${dir}/webs/webservers.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -5 || echo "N/A")

Hosts Requiring Auth (401/403): $(count_lines "${dir}/webs/auth_required.txt")
Hosts with Server Errors (5xx): $(count_lines "${dir}/webs/server_errors.txt")

WAF Status:
$(head -5 "${dir}/webs/waf_summary.txt" 2>/dev/null || echo "N/A")

CDN Status:
$(head -5 "${dir}/webs/cdn_summary.txt" 2>/dev/null || echo "N/A")

Screenshots: $(find "${dir}/webs/screenshots" -name "*.png" -o -name "*.jpg" 2>/dev/null | wc -l)

Detailed results available in ${dir}/webs/
EOF
    
    log_success "Web probing aggregation completed"
}
