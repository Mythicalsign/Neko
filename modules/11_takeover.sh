#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 11: SUBDOMAIN TAKEOVER DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Detect subdomain takeover vulnerabilities
# Tools: nuclei, dnsreaper, dnstake, subjack
# ═══════════════════════════════════════════════════════════════════════════════

takeover_main() {
    log_phase "PHASE 11: SUBDOMAIN TAKEOVER DETECTION"
    
    if ! should_run_module "takeover_main" "TAKEOVER_ENABLED"; then
        return 0
    fi
    
    start_func "takeover_main" "Starting Subdomain Takeover Detection"
    
    ensure_dir "${dir}/takeover"
    ensure_dir "${dir}/.tmp/takeover"
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains for takeover testing"
        return 0
    fi
    
    # Run takeover detection functions
    takeover_nuclei
    takeover_dnsreaper
    takeover_dnstake
    takeover_subjack
    takeover_aggregate
    
    end_func "Subdomain takeover detection completed. Results in ${dir}/takeover/" "takeover_main"
}

takeover_nuclei() {
    if ! should_run_module "takeover_nuclei" "TAKEOVER_NUCLEI"; then
        return 0
    fi
    
    start_subfunc "takeover_nuclei" "Running nuclei takeover templates"
    
    if ! command_exists nuclei; then
        log_warning "nuclei not installed, skipping"
        return 0
    fi
    
    log_info "Running nuclei subdomain takeover templates..."
    
    nuclei -l "${dir}/subdomains/subdomains.txt" \
        -t "${NUCLEI_TEMPLATES_PATH}/http/takeovers/" \
        -c "${NUCLEI_THREADS:-25}" \
        -rl "${NUCLEI_RATELIMIT:-150}" \
        -silent \
        -o "${dir}/takeover/nuclei_takeover.txt" \
        2>> "$LOGFILE" || true
    
    local nuclei_count=$(count_lines "${dir}/takeover/nuclei_takeover.txt")
    
    if [[ $nuclei_count -gt 0 ]]; then
        notify "Nuclei found $nuclei_count potential subdomain takeovers!" "warning"
    fi
    
    end_subfunc "Nuclei found $nuclei_count potential takeovers" "takeover_nuclei"
}

takeover_dnsreaper() {
    if ! should_run_module "takeover_dnsreaper" "TAKEOVER_DNSREAPER"; then
        return 0
    fi
    
    start_subfunc "takeover_dnsreaper" "Running DNSReaper"
    
    if ! command_exists dnsreaper; then
        log_warning "dnsreaper not installed, skipping"
        return 0
    fi
    
    log_info "Running dnsreaper..."
    
    dnsreaper file --filename "${dir}/subdomains/subdomains.txt" \
        --out "${dir}/takeover/dnsreaper_results.json" \
        --out-format json \
        2>> "$LOGFILE" || true
    
    # Parse results
    if [[ -s "${dir}/takeover/dnsreaper_results.json" ]]; then
        jq -r '.[] | select(.vulnerable == true) | "\(.domain) - \(.signature_name)"' \
            "${dir}/takeover/dnsreaper_results.json" 2>/dev/null \
            > "${dir}/takeover/dnsreaper_vulnerable.txt" || true
    fi
    
    local reaper_count=$(count_lines "${dir}/takeover/dnsreaper_vulnerable.txt")
    end_subfunc "DNSReaper found $reaper_count vulnerable subdomains" "takeover_dnsreaper"
}

takeover_dnstake() {
    if ! should_run_module "takeover_dnstake" "TAKEOVER_DNSTAKE"; then
        return 0
    fi
    
    start_subfunc "takeover_dnstake" "Running dnstake"
    
    if ! command_exists dnstake; then
        log_warning "dnstake not installed, skipping"
        return 0
    fi
    
    log_info "Running dnstake..."
    
    dnstake -l "${dir}/subdomains/subdomains.txt" \
        -c "${DNSTAKE_THREADS:-100}" \
        -o "${dir}/takeover/dnstake_results.txt" \
        2>> "$LOGFILE" || true
    
    local dnstake_count=$(count_lines "${dir}/takeover/dnstake_results.txt")
    end_subfunc "dnstake found $dnstake_count results" "takeover_dnstake"
}

takeover_subjack() {
    if ! should_run_module "takeover_subjack" "TAKEOVER_SUBJACK"; then
        return 0
    fi
    
    start_subfunc "takeover_subjack" "Running subjack"
    
    if ! command_exists subjack; then
        log_warning "subjack not installed, skipping"
        return 0
    fi
    
    log_info "Running subjack..."
    
    subjack -w "${dir}/subdomains/subdomains.txt" \
        -t 100 \
        -timeout 30 \
        -ssl \
        -o "${dir}/takeover/subjack_results.txt" \
        -v \
        2>> "$LOGFILE" || true
    
    end_subfunc "Subjack scan completed" "takeover_subjack"
}

takeover_aggregate() {
    log_info "Aggregating takeover results..."
    
    # Combine all vulnerable findings
    cat "${dir}/takeover/"*_vulnerable.txt "${dir}/takeover/"*_results.txt 2>/dev/null | \
        grep -iE "vulnerable|takeover" | \
        sort -u > "${dir}/takeover/vulnerable.txt" || true
    
    local summary="${dir}/takeover/takeover_summary.txt"
    local vuln_count=$(count_lines "${dir}/takeover/vulnerable.txt")
    
    cat > "$summary" << EOF
Subdomain Takeover Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

VULNERABLE SUBDOMAINS: ${vuln_count}

Nuclei Findings:
$(cat "${dir}/takeover/nuclei_takeover.txt" 2>/dev/null || echo "None")

DNSReaper Findings:
$(cat "${dir}/takeover/dnsreaper_vulnerable.txt" 2>/dev/null || echo "None")

DNSTake Findings:
$(cat "${dir}/takeover/dnstake_results.txt" 2>/dev/null || echo "None")

Subjack Findings:
$(grep -i "vulnerable" "${dir}/takeover/subjack_results.txt" 2>/dev/null || echo "None")

Detailed results in ${dir}/takeover/
EOF
    
    if [[ $vuln_count -gt 0 ]]; then
        notify "Found $vuln_count subdomain takeover vulnerabilities!" "warning"
    fi
    
    log_success "Takeover aggregation completed"
}
