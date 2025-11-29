#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9: VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Comprehensive vulnerability scanning
# Tools: nuclei, sqlmap, ghauri, commix, tplmap, ssrfmap, crlfuzz, Corsy, Oralyzer
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_main() {
    log_phase "PHASE 9: VULNERABILITY SCANNING"
    
    if ! should_run_module "vulnscan_main" "VULNSCAN_ENABLED"; then
        return 0
    fi
    
    start_func "vulnscan_main" "Starting Vulnerability Scanning"
    
    ensure_dir "${dir}/vulnerabilities"
    ensure_dir "${dir}/.tmp/vulns"
    
    # Prepare targets
    vulnscan_prepare_targets
    
    # Run vulnerability scanning functions
    vulnscan_nuclei
    vulnscan_sqli
    vulnscan_command_injection
    vulnscan_ssti
    vulnscan_ssrf
    vulnscan_lfi
    vulnscan_crlf
    vulnscan_cors
    vulnscan_open_redirect
    vulnscan_headers
    vulnscan_aggregate
    
    end_func "Vulnerability scanning completed. Results in ${dir}/vulnerabilities/" "vulnscan_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREPARE TARGETS
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_prepare_targets() {
    log_info "Preparing targets for vulnerability scanning..."
    
    # Prepare URL targets
    if [[ -s "${dir}/urls/urls.txt" ]]; then
        cp "${dir}/urls/urls.txt" "${dir}/.tmp/vulns/url_targets.txt"
    elif [[ -s "${dir}/webs/webs.txt" ]]; then
        cp "${dir}/webs/webs.txt" "${dir}/.tmp/vulns/url_targets.txt"
    fi
    
    # Prepare parameter targets (for injection testing)
    if [[ -s "${dir}/parameters/params_all.txt" ]]; then
        cp "${dir}/parameters/params_all.txt" "${dir}/.tmp/vulns/param_targets.txt"
    elif [[ -s "${dir}/urls/urls_with_params.txt" ]]; then
        cp "${dir}/urls/urls_with_params.txt" "${dir}/.tmp/vulns/param_targets.txt"
    fi
    
    log_info "URL targets: $(count_lines "${dir}/.tmp/vulns/url_targets.txt")"
    log_info "Parameter targets: $(count_lines "${dir}/.tmp/vulns/param_targets.txt")"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NUCLEI - TEMPLATE-BASED SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_nuclei() {
    if ! should_run_module "vulnscan_nuclei" "VULN_NUCLEI"; then
        return 0
    fi
    
    start_subfunc "vulnscan_nuclei" "Running nuclei template scanning"
    
    if ! command_exists nuclei; then
        log_warning "nuclei not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/vulns/url_targets.txt" ]]; then
        log_warning "No targets for nuclei"
        return 0
    fi
    
    local target_count=$(count_lines "${dir}/.tmp/vulns/url_targets.txt")
    log_info "Running nuclei on $target_count targets..."
    
    ensure_dir "${dir}/vulnerabilities/nuclei"
    
    # Build nuclei command
    local nuclei_cmd="nuclei -l ${dir}/.tmp/vulns/url_targets.txt"
    nuclei_cmd+=" -t ${NUCLEI_TEMPLATES_PATH:-$HOME/nuclei-templates}"
    nuclei_cmd+=" -severity ${NUCLEI_SEVERITY:-low,medium,high,critical}"
    nuclei_cmd+=" -c ${NUCLEI_THREADS:-25}"
    nuclei_cmd+=" -rl ${NUCLEI_RATELIMIT:-150}"
    nuclei_cmd+=" -timeout ${NUCLEI_TIMEOUT:-30}"
    nuclei_cmd+=" ${NUCLEI_EXTRA_FLAGS:--silent -retries 2}"
    nuclei_cmd+=" -o ${dir}/vulnerabilities/nuclei/findings.txt"
    nuclei_cmd+=" -j -output ${dir}/vulnerabilities/nuclei/findings.json"
    
    # Exclude tags if specified
    if [[ -n "${NUCLEI_EXCLUDE_TAGS:-}" ]]; then
        nuclei_cmd+=" -etags ${NUCLEI_EXCLUDE_TAGS}"
    fi
    
    # Run nuclei
    log_debug "Nuclei command: $nuclei_cmd"
    eval "$nuclei_cmd" 2>> "$LOGFILE" || true
    
    # Parse nuclei results
    if [[ -s "${dir}/vulnerabilities/nuclei/findings.json" ]]; then
        # Extract by severity
        for severity in critical high medium low info; do
            jq -r "select(.info.severity == \"$severity\") | \"\(.info.name) - \(.host) - \(.matched)\"" \
                "${dir}/vulnerabilities/nuclei/findings.json" 2>/dev/null | \
                sort -u > "${dir}/vulnerabilities/nuclei/${severity}.txt" || true
        done
        
        # Count findings
        local critical_count=$(count_lines "${dir}/vulnerabilities/nuclei/critical.txt")
        local high_count=$(count_lines "${dir}/vulnerabilities/nuclei/high.txt")
        local medium_count=$(count_lines "${dir}/vulnerabilities/nuclei/medium.txt")
        
        if [[ $critical_count -gt 0 ]] || [[ $high_count -gt 0 ]]; then
            notify "Nuclei found $critical_count critical, $high_count high severity issues!" "warning"
        fi
    fi
    
    local finding_count=$(count_lines "${dir}/vulnerabilities/nuclei/findings.txt")
    end_subfunc "Nuclei found $finding_count potential vulnerabilities" "vulnscan_nuclei"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FAST NUCLEI (FOR QUICK MODE)
# ═══════════════════════════════════════════════════════════════════════════════

nuclei_fast() {
    start_subfunc "nuclei_fast" "Running nuclei fast scan"
    
    if ! command_exists nuclei; then
        log_warning "nuclei not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No targets for nuclei"
        return 0
    fi
    
    ensure_dir "${dir}/vulnerabilities/nuclei"
    
    # Fast scan - only high/critical, limited templates
    nuclei -l "${dir}/webs/webs.txt" \
        -t "${NUCLEI_TEMPLATES_PATH:-$HOME/nuclei-templates}" \
        -severity "${NUCLEI_SEVERITY_FAST:-high,critical}" \
        -c "${NUCLEI_THREADS:-25}" \
        -rl "${NUCLEI_RATELIMIT:-150}" \
        -timeout 10 \
        -silent \
        -o "${dir}/vulnerabilities/nuclei/findings_fast.txt" \
        2>> "$LOGFILE" || true
    
    local finding_count=$(count_lines "${dir}/vulnerabilities/nuclei/findings_fast.txt")
    end_subfunc "Fast nuclei found $finding_count potential vulnerabilities" "nuclei_fast"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SQL INJECTION TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_sqli() {
    if ! should_run_module "vulnscan_sqli" "VULN_SQLI"; then
        return 0
    fi
    
    start_subfunc "vulnscan_sqli" "Running SQL injection testing"
    
    if [[ ! -s "${dir}/.tmp/vulns/param_targets.txt" ]]; then
        log_warning "No parameter targets for SQLi testing"
        return 0
    fi
    
    ensure_dir "${dir}/vulnerabilities/sqli"
    
    # Filter potential SQLi URLs using GF patterns
    if command_exists gf; then
        cat "${dir}/.tmp/vulns/param_targets.txt" | gf sqli | \
            sort -u > "${dir}/.tmp/vulns/sqli_candidates.txt" 2>/dev/null || true
    else
        cp "${dir}/.tmp/vulns/param_targets.txt" "${dir}/.tmp/vulns/sqli_candidates.txt"
    fi
    
    local sqli_targets=$(count_lines "${dir}/.tmp/vulns/sqli_candidates.txt")
    
    # Limit targets
    local max_targets=50
    [[ "${DEEP:-false}" == "true" ]] && max_targets=200
    
    if [[ $sqli_targets -gt $max_targets ]]; then
        log_warning "Limiting SQLi testing to first $max_targets URLs"
        head -n $max_targets "${dir}/.tmp/vulns/sqli_candidates.txt" > "${dir}/.tmp/vulns/sqli_targets.txt"
    else
        cp "${dir}/.tmp/vulns/sqli_candidates.txt" "${dir}/.tmp/vulns/sqli_targets.txt"
    fi
    
    # SQLMap
    if [[ "${VULN_SQLI_SQLMAP:-true}" == "true" ]] && command_exists sqlmap; then
        log_info "Running sqlmap..."
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            
            timeout "${SQLMAP_TIMEOUT:-300}" sqlmap \
                -u "$url" \
                --batch \
                --level 2 \
                --risk 2 \
                --threads "${SQLMAP_THREADS:-5}" \
                --timeout 30 \
                --retries 2 \
                --output-dir "${dir}/vulnerabilities/sqli/sqlmap" \
                2>> "$LOGFILE" || true
            
        done < "${dir}/.tmp/vulns/sqli_targets.txt"
    fi
    
    # Ghauri (faster, better detection)
    if [[ "${VULN_SQLI_GHAURI:-true}" == "true" ]] && command_exists ghauri; then
        log_info "Running ghauri..."
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            
            ghauri -u "$url" \
                --batch \
                --level 2 \
                --threads "${GHAURI_THREADS:-5}" \
                >> "${dir}/vulnerabilities/sqli/ghauri_results.txt" 2>> "$LOGFILE" || true
            
        done < "${dir}/.tmp/vulns/sqli_targets.txt"
    fi
    
    end_subfunc "SQLi testing completed" "vulnscan_sqli"
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND INJECTION TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_command_injection() {
    if ! should_run_module "vulnscan_commix" "VULN_COMMIX"; then
        return 0
    fi
    
    start_subfunc "vulnscan_commix" "Running command injection testing"
    
    if ! command_exists commix; then
        log_warning "commix not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/vulns/param_targets.txt" ]]; then
        log_warning "No parameter targets for command injection testing"
        return 0
    fi
    
    ensure_dir "${dir}/vulnerabilities/cmdi"
    
    # Limit targets
    local max_targets=30
    head -n $max_targets "${dir}/.tmp/vulns/param_targets.txt" > "${dir}/.tmp/vulns/cmdi_targets.txt"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        timeout 300 commix \
            --url="$url" \
            --batch \
            --level 2 \
            --output-dir="${dir}/vulnerabilities/cmdi" \
            2>> "$LOGFILE" || true
        
    done < "${dir}/.tmp/vulns/cmdi_targets.txt"
    
    end_subfunc "Command injection testing completed" "vulnscan_commix"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSTI TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_ssti() {
    if ! should_run_module "vulnscan_ssti" "VULN_SSTI"; then
        return 0
    fi
    
    start_subfunc "vulnscan_ssti" "Running SSTI testing"
    
    ensure_dir "${dir}/vulnerabilities/ssti"
    
    # Filter SSTI candidates
    if command_exists gf && [[ -s "${dir}/.tmp/vulns/param_targets.txt" ]]; then
        cat "${dir}/.tmp/vulns/param_targets.txt" | gf ssti | \
            sort -u > "${dir}/.tmp/vulns/ssti_candidates.txt" 2>/dev/null || \
            cp "${dir}/.tmp/vulns/param_targets.txt" "${dir}/.tmp/vulns/ssti_candidates.txt"
    fi
    
    # Use tplmap if available
    if command_exists tplmap && [[ -s "${dir}/.tmp/vulns/ssti_candidates.txt" ]]; then
        log_info "Running tplmap..."
        
        head -n 20 "${dir}/.tmp/vulns/ssti_candidates.txt" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            
            timeout 120 tplmap -u "$url" --level 2 \
                >> "${dir}/vulnerabilities/ssti/tplmap_results.txt" 2>> "$LOGFILE" || true
        done
    fi
    
    # Use nuclei SSTI templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/vulns/ssti_candidates.txt" ]]; then
        log_info "Running nuclei SSTI templates..."
        nuclei -l "${dir}/.tmp/vulns/ssti_candidates.txt" \
            -tags ssti \
            -c 10 \
            -silent \
            -o "${dir}/vulnerabilities/ssti/nuclei_ssti.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "SSTI testing completed" "vulnscan_ssti"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSRF TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_ssrf() {
    if ! should_run_module "vulnscan_ssrf" "VULN_SSRF"; then
        return 0
    fi
    
    start_subfunc "vulnscan_ssrf" "Running SSRF testing"
    
    ensure_dir "${dir}/vulnerabilities/ssrf"
    
    # Filter SSRF candidates
    if command_exists gf && [[ -s "${dir}/.tmp/vulns/param_targets.txt" ]]; then
        cat "${dir}/.tmp/vulns/param_targets.txt" | gf ssrf | \
            sort -u > "${dir}/.tmp/vulns/ssrf_candidates.txt" 2>/dev/null || true
    fi
    
    # Use nuclei SSRF templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/vulns/ssrf_candidates.txt" ]]; then
        log_info "Running nuclei SSRF templates..."
        nuclei -l "${dir}/.tmp/vulns/ssrf_candidates.txt" \
            -tags ssrf \
            -c 10 \
            -silent \
            -o "${dir}/vulnerabilities/ssrf/nuclei_ssrf.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "SSRF testing completed" "vulnscan_ssrf"
}

# ═══════════════════════════════════════════════════════════════════════════════
# LFI TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_lfi() {
    if ! should_run_module "vulnscan_lfi" "VULN_LFI"; then
        return 0
    fi
    
    start_subfunc "vulnscan_lfi" "Running LFI testing"
    
    ensure_dir "${dir}/vulnerabilities/lfi"
    
    # Filter LFI candidates
    if command_exists gf && [[ -s "${dir}/.tmp/vulns/param_targets.txt" ]]; then
        cat "${dir}/.tmp/vulns/param_targets.txt" | gf lfi | \
            sort -u > "${dir}/.tmp/vulns/lfi_candidates.txt" 2>/dev/null || true
    fi
    
    # Use nuclei LFI templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/vulns/lfi_candidates.txt" ]]; then
        log_info "Running nuclei LFI templates..."
        nuclei -l "${dir}/.tmp/vulns/lfi_candidates.txt" \
            -tags lfi \
            -c 10 \
            -silent \
            -o "${dir}/vulnerabilities/lfi/nuclei_lfi.txt" \
            2>> "$LOGFILE" || true
    fi
    
    # Use ffuf for LFI payloads
    if command_exists ffuf && [[ -s "${dir}/.tmp/vulns/lfi_candidates.txt" ]]; then
        local lfi_wordlist="${LFI_WORDLIST:-${TOOLS_PATH}/wordlists/lfi.txt}"
        
        if [[ -f "$lfi_wordlist" ]]; then
            log_info "Running ffuf LFI fuzzing..."
            head -n 20 "${dir}/.tmp/vulns/lfi_candidates.txt" | while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                
                # Replace parameter value with FUZZ
                local fuzz_url=$(echo "$url" | sed 's/=[^&]*/=FUZZ/g')
                
                ffuf -u "$fuzz_url" \
                    -w "$lfi_wordlist" \
                    -t 20 \
                    -mc 200 \
                    -fs 0 \
                    -sf \
                    >> "${dir}/vulnerabilities/lfi/ffuf_lfi.txt" 2>> "$LOGFILE" || true
            done
        fi
    fi
    
    end_subfunc "LFI testing completed" "vulnscan_lfi"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CRLF INJECTION TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_crlf() {
    if ! should_run_module "vulnscan_crlf" "VULN_CRLF"; then
        return 0
    fi
    
    start_subfunc "vulnscan_crlf" "Running CRLF injection testing"
    
    ensure_dir "${dir}/vulnerabilities/crlf"
    
    # Use crlfuzz
    if command_exists crlfuzz && [[ -s "${dir}/.tmp/vulns/url_targets.txt" ]]; then
        log_info "Running crlfuzz..."
        crlfuzz -l "${dir}/.tmp/vulns/url_targets.txt" \
            -c 50 \
            -s \
            -o "${dir}/vulnerabilities/crlf/crlfuzz_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    local crlf_count=$(count_lines "${dir}/vulnerabilities/crlf/crlfuzz_results.txt")
    end_subfunc "Found $crlf_count potential CRLF injection points" "vulnscan_crlf"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CORS MISCONFIGURATION TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_cors() {
    if ! should_run_module "vulnscan_cors" "VULN_CORS"; then
        return 0
    fi
    
    start_subfunc "vulnscan_cors" "Running CORS misconfiguration testing"
    
    ensure_dir "${dir}/vulnerabilities/cors"
    
    # Use Corsy
    if [[ -f "${TOOLS_PATH}/Corsy/corsy.py" ]] && [[ -s "${dir}/.tmp/vulns/url_targets.txt" ]]; then
        log_info "Running Corsy..."
        run_python_tool "${TOOLS_PATH}/Corsy" \
            -i "${dir}/.tmp/vulns/url_targets.txt" \
            -t 20 \
            -o "${dir}/vulnerabilities/cors/corsy_results.json" \
            2>> "$LOGFILE" || true
    fi
    
    # Use nuclei CORS templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/vulns/url_targets.txt" ]]; then
        nuclei -l "${dir}/.tmp/vulns/url_targets.txt" \
            -tags cors \
            -c 10 \
            -silent \
            -o "${dir}/vulnerabilities/cors/nuclei_cors.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "CORS testing completed" "vulnscan_cors"
}

# ═══════════════════════════════════════════════════════════════════════════════
# OPEN REDIRECT TESTING
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_open_redirect() {
    if ! should_run_module "vulnscan_redirect" "VULN_OPEN_REDIRECT"; then
        return 0
    fi
    
    start_subfunc "vulnscan_redirect" "Running open redirect testing"
    
    ensure_dir "${dir}/vulnerabilities/redirect"
    
    # Filter redirect candidates
    if command_exists gf && [[ -s "${dir}/.tmp/vulns/param_targets.txt" ]]; then
        cat "${dir}/.tmp/vulns/param_targets.txt" | gf redirect | \
            sort -u > "${dir}/.tmp/vulns/redirect_candidates.txt" 2>/dev/null || true
    fi
    
    # Use Oralyzer
    if [[ -f "${TOOLS_PATH}/Oralyzer/oralyzer.py" ]] && [[ -s "${dir}/.tmp/vulns/redirect_candidates.txt" ]]; then
        log_info "Running Oralyzer..."
        run_python_tool "${TOOLS_PATH}/Oralyzer" \
            -l "${dir}/.tmp/vulns/redirect_candidates.txt" \
            -p "http://evil.com" \
            >> "${dir}/vulnerabilities/redirect/oralyzer_results.txt" 2>> "$LOGFILE" || true
    fi
    
    # Use nuclei redirect templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/vulns/redirect_candidates.txt" ]]; then
        nuclei -l "${dir}/.tmp/vulns/redirect_candidates.txt" \
            -tags redirect \
            -c 10 \
            -silent \
            -o "${dir}/vulnerabilities/redirect/nuclei_redirect.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "Open redirect testing completed" "vulnscan_redirect"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS CHECK
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_headers() {
    if ! should_run_module "vulnscan_headers" "VULN_HEADERS"; then
        return 0
    fi
    
    start_subfunc "vulnscan_headers" "Checking security headers"
    
    ensure_dir "${dir}/vulnerabilities/headers"
    
    if [[ ! -s "${dir}/.tmp/vulns/url_targets.txt" ]]; then
        log_warning "No targets for header checking"
        return 0
    fi
    
    # Check headers for each target
    local missing_headers_count=0
    
    head -n 50 "${dir}/.tmp/vulns/url_targets.txt" | while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        local headers=$(curl -sI -m 10 "$url" 2>/dev/null)
        
        if [[ -n "$headers" ]]; then
            local missing=""
            
            # Check for important security headers
            echo "$headers" | grep -qi "strict-transport-security" || missing+="HSTS, "
            echo "$headers" | grep -qi "x-frame-options" || missing+="X-Frame-Options, "
            echo "$headers" | grep -qi "x-content-type-options" || missing+="X-Content-Type-Options, "
            echo "$headers" | grep -qi "content-security-policy" || missing+="CSP, "
            echo "$headers" | grep -qi "x-xss-protection" || missing+="X-XSS-Protection, "
            
            if [[ -n "$missing" ]]; then
                echo "$url: Missing: ${missing%, }" >> "${dir}/vulnerabilities/headers/missing_headers.txt"
            fi
        fi
    done
    
    local missing_count=$(count_lines "${dir}/vulnerabilities/headers/missing_headers.txt")
    end_subfunc "Found $missing_count URLs with missing security headers" "vulnscan_headers"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE VULNERABILITY RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

vulnscan_aggregate() {
    log_info "Aggregating vulnerability scanning results..."
    
    local summary="${dir}/vulnerabilities/vuln_summary.txt"
    
    cat > "$summary" << EOF
Vulnerability Scanning Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

NUCLEI FINDINGS:
- Critical: $(count_lines "${dir}/vulnerabilities/nuclei/critical.txt")
- High: $(count_lines "${dir}/vulnerabilities/nuclei/high.txt")
- Medium: $(count_lines "${dir}/vulnerabilities/nuclei/medium.txt")
- Low: $(count_lines "${dir}/vulnerabilities/nuclei/low.txt")
- Info: $(count_lines "${dir}/vulnerabilities/nuclei/info.txt")

INJECTION TESTING:
- SQLi candidates tested: $(count_lines "${dir}/.tmp/vulns/sqli_targets.txt")
- Command injection tested: $(count_lines "${dir}/.tmp/vulns/cmdi_targets.txt")
- SSTI candidates: $(count_lines "${dir}/.tmp/vulns/ssti_candidates.txt")
- LFI candidates: $(count_lines "${dir}/.tmp/vulns/lfi_candidates.txt")

OTHER VULNERABILITIES:
- CRLF findings: $(count_lines "${dir}/vulnerabilities/crlf/crlfuzz_results.txt")
- CORS misconfigs: $(count_lines "${dir}/vulnerabilities/cors/nuclei_cors.txt")
- Open redirects: $(count_lines "${dir}/vulnerabilities/redirect/nuclei_redirect.txt")
- Missing security headers: $(count_lines "${dir}/vulnerabilities/headers/missing_headers.txt")

CRITICAL FINDINGS (REVIEW IMMEDIATELY):
$(cat "${dir}/vulnerabilities/nuclei/critical.txt" 2>/dev/null | head -10 || echo "None")

HIGH SEVERITY FINDINGS:
$(cat "${dir}/vulnerabilities/nuclei/high.txt" 2>/dev/null | head -10 || echo "None")

Detailed results available in ${dir}/vulnerabilities/
EOF
    
    log_success "Vulnerability aggregation completed"
}
