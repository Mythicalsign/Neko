#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 13: AUTHENTICATION & SESSION TESTING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Auth-specific vulnerabilities
# Tools: brutespray, hydra, jwt_tool
# WARNING: This module is intrusive and disabled by default
# ═══════════════════════════════════════════════════════════════════════════════

auth_main() {
    log_phase "PHASE 13: AUTHENTICATION TESTING"
    
    if ! should_run_module "auth_main" "AUTH_ENABLED"; then
        return 0
    fi
    
    start_func "auth_main" "Starting Authentication Testing"
    
    log_warning "Authentication testing is intrusive. Ensure you have authorization."
    
    ensure_dir "${dir}/auth"
    ensure_dir "${dir}/.tmp/auth"
    
    # Run auth testing functions
    auth_brutespray
    auth_jwt_analysis
    auth_default_creds
    auth_aggregate
    
    end_func "Authentication testing completed. Results in ${dir}/auth/" "auth_main"
}

auth_brutespray() {
    if ! should_run_module "auth_brutespray" "AUTH_BRUTESPRAY"; then
        return 0
    fi
    
    start_subfunc "auth_brutespray" "Running service brute-forcing"
    
    if ! command_exists brutespray; then
        log_warning "brutespray not installed, skipping"
        return 0
    fi
    
    # Need nmap results
    if [[ ! -f "${dir}/ports/nmap_results.xml" ]]; then
        log_warning "No nmap results for brutespray"
        return 0
    fi
    
    log_warning "Running brutespray - This is intrusive!"
    
    brutespray \
        -f "${dir}/ports/nmap_results.xml" \
        -t "${BRUTESPRAY_THREADS:-20}" \
        -c "${BRUTESPRAY_CONCURRENCE:-10}" \
        -o "${dir}/auth/brutespray_results.txt" \
        2>> "$LOGFILE" || true
    
    end_subfunc "Brutespray completed" "auth_brutespray"
}

auth_jwt_analysis() {
    if ! should_run_module "auth_jwt" "AUTH_JWT"; then
        return 0
    fi
    
    start_subfunc "auth_jwt" "Running JWT analysis"
    
    # Extract JWTs from discovered URLs/responses
    if [[ -s "${dir}/urls/urls.txt" ]]; then
        # Look for JWT patterns
        grep -ohE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" \
            "${dir}/urls/urls.txt" "${dir}/content/"*.txt "${dir}/js/"*.txt 2>/dev/null | \
            sort -u > "${dir}/auth/found_jwts.txt" || true
    fi
    
    # Use jwt_tool if available
    if command_exists jwt_tool && [[ -s "${dir}/auth/found_jwts.txt" ]]; then
        log_info "Running jwt_tool analysis..."
        
        while IFS= read -r jwt; do
            [[ -z "$jwt" ]] && continue
            jwt_tool "$jwt" >> "${dir}/auth/jwt_analysis.txt" 2>/dev/null || true
        done < "${dir}/auth/found_jwts.txt"
    fi
    
    # nuclei JWT templates
    if command_exists nuclei && [[ -s "${dir}/webs/webs.txt" ]]; then
        nuclei -l "${dir}/webs/webs.txt" \
            -tags jwt \
            -c 10 \
            -silent \
            -o "${dir}/auth/nuclei_jwt.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "JWT analysis completed" "auth_jwt"
}

auth_default_creds() {
    if ! should_run_module "auth_default_creds" "AUTH_DEFAULT_CREDS"; then
        return 0
    fi
    
    start_subfunc "auth_default_creds" "Checking for default credentials"
    
    # nuclei default credential templates
    if command_exists nuclei && [[ -s "${dir}/webs/webs.txt" ]]; then
        log_info "Running nuclei default-login templates..."
        nuclei -l "${dir}/webs/webs.txt" \
            -tags default-login \
            -c 10 \
            -silent \
            -o "${dir}/auth/default_creds.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "Default credential check completed" "auth_default_creds"
}

auth_aggregate() {
    log_info "Aggregating authentication testing results..."
    
    local summary="${dir}/auth/auth_summary.txt"
    
    cat > "$summary" << EOF
Authentication Testing Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

⚠️  WARNING: Authentication testing is intrusive.
    Ensure proper authorization before using results.

Brutespray Results:
$(cat "${dir}/auth/brutespray_results.txt" 2>/dev/null | head -20 || echo "Not run")

JWT Tokens Found: $(count_lines "${dir}/auth/found_jwts.txt")

JWT Analysis:
$(head -20 "${dir}/auth/jwt_analysis.txt" 2>/dev/null || echo "None")

Default Credentials Found:
$(cat "${dir}/auth/default_creds.txt" 2>/dev/null || echo "None")

Detailed results in ${dir}/auth/
EOF
    
    log_success "Auth aggregation completed"
}
