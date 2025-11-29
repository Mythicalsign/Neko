#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 0: OSINT & INTELLIGENCE GATHERING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Gather intelligence before active scanning
# Tools: whois, theHarvester, github-subdomains, gitlab-subdomains, trufflehog,
#        gitleaks, porch-pirate, SwaggerSpy, dorks_hunter, Spoofy
# ═══════════════════════════════════════════════════════════════════════════════

osint_main() {
    log_phase "PHASE 0: OSINT & INTELLIGENCE GATHERING"
    
    if ! should_run_module "osint_main" "OSINT_ENABLED"; then
        return 0
    fi
    
    start_func "osint_main" "Starting OSINT & Intelligence Gathering"
    
    ensure_dir "${dir}/osint"
    ensure_dir "${dir}/.tmp/osint"
    
    # Skip if target is IP address
    if is_ip "$domain" || is_cidr "$domain"; then
        log_info "Target is IP/CIDR, running limited OSINT"
        osint_ip_info
        end_func "OSINT completed (limited for IP target)" "osint_main"
        return 0
    fi
    
    # Run OSINT functions in parallel where possible
    osint_whois &
    local pid_whois=$!
    
    osint_emails &
    local pid_emails=$!
    
    # Wait for quick tasks
    wait $pid_whois
    wait $pid_emails
    
    # Sequential tasks that may depend on previous results
    osint_theharvester
    osint_github_recon
    osint_gitlab_recon
    osint_secret_scanning
    osint_api_leaks
    osint_google_dorks
    osint_spoof_check
    
    # Aggregate results
    osint_aggregate_results
    
    end_func "OSINT phase completed. Results in ${dir}/osint/" "osint_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

osint_whois() {
    if ! should_run_module "osint_whois" "OSINT_WHOIS"; then
        return 0
    fi
    
    start_subfunc "osint_whois" "Running WHOIS lookup"
    
    if command_exists whois; then
        whois "$domain" > "${dir}/osint/whois.txt" 2>> "$LOGFILE"
        
        # Extract useful information
        if [[ -s "${dir}/osint/whois.txt" ]]; then
            grep -iE "Registrant|Admin|Tech|Name Server|Creation|Expir|Updated" \
                "${dir}/osint/whois.txt" > "${dir}/osint/whois_summary.txt" 2>/dev/null || true
            
            # Extract emails from whois
            grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
                "${dir}/osint/whois.txt" | sort -u > "${dir}/osint/whois_emails.txt" 2>/dev/null || true
        fi
        
        end_subfunc "WHOIS lookup completed" "osint_whois"
    else
        log_warning "whois not installed, skipping"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL HARVESTING
# ═══════════════════════════════════════════════════════════════════════════════

osint_emails() {
    if ! should_run_module "osint_emails" "OSINT_THEHARVESTER"; then
        return 0
    fi
    
    start_subfunc "osint_emails" "Harvesting emails and related information"
    
    local email_file="${dir}/osint/emails.txt"
    touch "$email_file"
    
    # theHarvester
    if command_exists theHarvester; then
        log_info "Running theHarvester..."
        theHarvester -d "$domain" -b all -l 500 -f "${dir}/.tmp/osint/theharvester" \
            2>> "$LOGFILE" || true
        
        # Parse theHarvester results
        if [[ -f "${dir}/.tmp/osint/theharvester.json" ]]; then
            jq -r '.emails[]?' "${dir}/.tmp/osint/theharvester.json" 2>/dev/null | \
                sort -u >> "$email_file"
        fi
    fi
    
    # EmailHarvester (if available)
    if [[ -f "${TOOLS_PATH}/EmailHarvester/EmailHarvester.py" ]]; then
        log_info "Running EmailHarvester..."
        run_python_tool "${TOOLS_PATH}/EmailHarvester" -d "$domain" -e all -l 20 \
            2>> "$LOGFILE" | grep "@" >> "$email_file" || true
    fi
    
    # Hunter.io API
    if [[ -n "${HUNTER_API_KEY:-}" ]]; then
        log_info "Querying Hunter.io..."
        curl -sL "https://api.hunter.io/v2/domain-search?domain=${domain}&api_key=${HUNTER_API_KEY}" \
            2>> "$LOGFILE" | jq -r '.data.emails[]?.value' 2>/dev/null >> "$email_file" || true
    fi
    
    # Deduplicate
    sort -u "$email_file" -o "$email_file"
    
    local email_count=$(count_lines "$email_file")
    end_subfunc "Found $email_count unique emails" "osint_emails"
}

# ═══════════════════════════════════════════════════════════════════════════════
# THEHARVESTER FULL SCAN
# ═══════════════════════════════════════════════════════════════════════════════

osint_theharvester() {
    start_subfunc "osint_theharvester" "Running comprehensive theHarvester scan"
    
    if ! command_exists theHarvester; then
        log_warning "theHarvester not installed, skipping"
        return 0
    fi
    
    # Run with multiple data sources
    local sources=("bing" "google" "linkedin" "twitter" "yahoo" "dnsdumpster" "crtsh")
    
    for source in "${sources[@]}"; do
        log_debug "Querying source: $source"
        theHarvester -d "$domain" -b "$source" -l 200 \
            -f "${dir}/.tmp/osint/harvester_${source}" 2>> "$LOGFILE" || true
    done
    
    # Merge all results
    cat "${dir}/.tmp/osint/harvester_"*.json 2>/dev/null | \
        jq -s 'map(.hosts // []) | add | unique' > "${dir}/osint/harvested_hosts.json" 2>/dev/null || true
    
    end_subfunc "theHarvester scan completed" "osint_theharvester"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════════

osint_github_recon() {
    if ! should_run_module "osint_github_recon" "OSINT_GITHUB_RECON"; then
        return 0
    fi
    
    start_subfunc "osint_github_recon" "Running GitHub reconnaissance"
    
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        log_warning "GITHUB_TOKEN not set, skipping GitHub recon"
        return 0
    fi
    
    local github_dir="${dir}/osint/github"
    ensure_dir "$github_dir"
    
    # github-subdomains
    if command_exists github-subdomains; then
        log_info "Running github-subdomains..."
        github-subdomains -d "$domain" -t "$GITHUB_TOKEN" \
            -o "${github_dir}/subdomains.txt" 2>> "$LOGFILE" || true
    fi
    
    # github-endpoints
    if command_exists github-endpoints; then
        log_info "Running github-endpoints..."
        github-endpoints -d "$domain" -t "$GITHUB_TOKEN" \
            -o "${github_dir}/endpoints.txt" 2>> "$LOGFILE" || true
    fi
    
    # gitdorks_go
    if command_exists gitdorks_go; then
        log_info "Running gitdorks_go..."
        gitdorks_go -gd "${TOOLS_PATH}/gitdorks_go/Dorks/smalldorks.txt" \
            -nws 20 -target "$domain" -tf <(echo "$GITHUB_TOKEN") -ew 3 \
            > "${github_dir}/dorks.txt" 2>> "$LOGFILE" || true
    fi
    
    # enumerepo - find organization repos
    if command_exists enumerepo; then
        log_info "Running enumerepo..."
        local company_name=$(echo "$domain" | sed 's/\..*//')
        enumerepo -token-string "$GITHUB_TOKEN" -usernames <(echo "$company_name") \
            -o "${github_dir}/repos.json" 2>> "$LOGFILE" || true
    fi
    
    end_subfunc "GitHub reconnaissance completed" "osint_github_recon"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GITLAB RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════════

osint_gitlab_recon() {
    if ! should_run_module "osint_gitlab_recon" "OSINT_GITLAB_RECON"; then
        return 0
    fi
    
    start_subfunc "osint_gitlab_recon" "Running GitLab reconnaissance"
    
    if [[ -z "${GITLAB_TOKEN:-}" ]]; then
        log_warning "GITLAB_TOKEN not set, skipping GitLab recon"
        return 0
    fi
    
    local gitlab_dir="${dir}/osint/gitlab"
    ensure_dir "$gitlab_dir"
    
    # gitlab-subdomains
    if command_exists gitlab-subdomains; then
        log_info "Running gitlab-subdomains..."
        gitlab-subdomains -d "$domain" -t "$GITLAB_TOKEN" \
            > "${gitlab_dir}/subdomains.txt" 2>> "$LOGFILE" || true
    fi
    
    end_subfunc "GitLab reconnaissance completed" "osint_gitlab_recon"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECRET SCANNING (TRUFFLEHOG, GITLEAKS)
# ═══════════════════════════════════════════════════════════════════════════════

osint_secret_scanning() {
    if ! should_run_module "osint_secret_scanning" "OSINT_TRUFFLEHOG"; then
        return 0
    fi
    
    start_subfunc "osint_secret_scanning" "Scanning for leaked secrets"
    
    local secrets_dir="${dir}/osint/secrets"
    ensure_dir "$secrets_dir"
    
    # Get company name for org scanning
    local company_name=$(echo "$domain" | sed 's/\..*//')
    
    # Trufflehog - scan GitHub org
    if command_exists trufflehog && [[ -n "${GITHUB_TOKEN:-}" ]]; then
        log_info "Running trufflehog on GitHub org..."
        GITHUB_TOKEN="$GITHUB_TOKEN" trufflehog github --org="$company_name" \
            --json 2>> "$LOGFILE" | jq -c > "${secrets_dir}/trufflehog_github.json" || true
    fi
    
    # Gitleaks - if we have cloned repos
    if command_exists gitleaks && [[ -d "${dir}/.tmp/osint/repos" ]]; then
        log_info "Running gitleaks on cloned repositories..."
        for repo_dir in "${dir}/.tmp/osint/repos"/*; do
            if [[ -d "$repo_dir" ]]; then
                local repo_name=$(basename "$repo_dir")
                gitleaks detect --source "$repo_dir" --no-banner --no-color \
                    -r "${secrets_dir}/gitleaks_${repo_name}.json" 2>> "$LOGFILE" || true
            fi
        done
    fi
    
    # Merge all secret findings
    cat "${secrets_dir}"/*.json 2>/dev/null | jq -s 'add' \
        > "${secrets_dir}/all_secrets.json" 2>/dev/null || true
    
    local secret_count=$(jq 'length' "${secrets_dir}/all_secrets.json" 2>/dev/null || echo "0")
    end_subfunc "Found $secret_count potential secrets" "osint_secret_scanning"
}

# ═══════════════════════════════════════════════════════════════════════════════
# API LEAK DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

osint_api_leaks() {
    if ! should_run_module "osint_api_leaks" "OSINT_PORCH_PIRATE"; then
        return 0
    fi
    
    start_subfunc "osint_api_leaks" "Scanning for API leaks"
    
    local api_dir="${dir}/osint/api_leaks"
    ensure_dir "$api_dir"
    
    # porch-pirate - Postman API leaks
    if command_exists porch-pirate; then
        log_info "Running porch-pirate for Postman leaks..."
        porch-pirate -s "$domain" -l 25 --dump \
            > "${api_dir}/postman_leaks.txt" 2>> "$LOGFILE" || true
        
        # Scan postman leaks for secrets
        if [[ -s "${api_dir}/postman_leaks.txt" ]] && command_exists trufflehog; then
            trufflehog filesystem "${api_dir}/postman_leaks.txt" -j \
                2>/dev/null | jq -c > "${api_dir}/postman_secrets.json" || true
        fi
    fi
    
    # SwaggerSpy - Swagger/OpenAPI leaks
    if [[ -f "${TOOLS_PATH}/SwaggerSpy/swaggerspy.py" ]]; then
        log_info "Running SwaggerSpy..."
        pushd "${TOOLS_PATH}/SwaggerSpy" > /dev/null 2>&1
        run_python_tool "${TOOLS_PATH}/SwaggerSpy" "$domain" \
            2>> "$LOGFILE" | grep -i "[*]\|URL" > "${api_dir}/swagger_leaks.txt" || true
        popd > /dev/null 2>&1
    fi
    
    end_subfunc "API leak scan completed" "osint_api_leaks"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GOOGLE DORKS
# ═══════════════════════════════════════════════════════════════════════════════

osint_google_dorks() {
    if ! should_run_module "osint_google_dorks" "OSINT_GOOGLE_DORKS"; then
        return 0
    fi
    
    start_subfunc "osint_google_dorks" "Running Google dorks"
    
    local dorks_dir="${dir}/osint/dorks"
    ensure_dir "$dorks_dir"
    
    # dorks_hunter
    if [[ -f "${TOOLS_PATH}/dorks_hunter/dorks_hunter.py" ]]; then
        log_info "Running dorks_hunter..."
        run_python_tool "${TOOLS_PATH}/dorks_hunter" -d "$domain" \
            -o "${dorks_dir}/dorks_hunter.txt" 2>> "$LOGFILE" || true
    fi
    
    # xnldorker
    if command_exists xnldorker; then
        log_info "Running xnldorker..."
        xnldorker -d "$domain" -o "${dorks_dir}/xnldorker.txt" 2>> "$LOGFILE" || true
    fi
    
    # Generate manual dorks file
    cat > "${dorks_dir}/manual_dorks.txt" << EOF
# Google Dorks for ${domain}
# Copy these into Google search

# Sensitive files
site:${domain} ext:sql | ext:db | ext:log | ext:cfg | ext:bak
site:${domain} ext:xml | ext:conf | ext:json | ext:yml
site:${domain} ext:doc | ext:pdf | ext:xls | ext:xlsx

# Exposed data
site:${domain} intitle:"index of"
site:${domain} inurl:admin | inurl:login | inurl:wp-admin
site:${domain} intext:"password" | intext:"secret" | intext:"api_key"

# Subdomains and services
site:*.${domain}
site:${domain} inurl:jenkins | inurl:gitlab | inurl:jira

# Error messages
site:${domain} "error" | "warning" | "fatal" | "exception"
site:${domain} "mysql" | "sql syntax" | "syntax error"

# Cloud storage
site:s3.amazonaws.com "${domain}"
site:storage.googleapis.com "${domain}"
site:blob.core.windows.net "${domain}"

# Code repositories
site:github.com "${domain}"
site:gitlab.com "${domain}"
site:bitbucket.org "${domain}"
site:pastebin.com "${domain}"
EOF
    
    end_subfunc "Google dorks generated" "osint_google_dorks"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SPF/DMARC SPOOF CHECK
# ═══════════════════════════════════════════════════════════════════════════════

osint_spoof_check() {
    if ! should_run_module "osint_spoof_check" "OSINT_SPOOF_CHECK"; then
        return 0
    fi
    
    start_subfunc "osint_spoof_check" "Checking for spoofable domains"
    
    local spoof_dir="${dir}/osint/spoof"
    ensure_dir "$spoof_dir"
    
    # Spoofy
    if [[ -f "${TOOLS_PATH}/Spoofy/spoofy.py" ]]; then
        log_info "Running Spoofy..."
        pushd "${TOOLS_PATH}/Spoofy" > /dev/null 2>&1
        run_python_tool "${TOOLS_PATH}/Spoofy" -d "$domain" \
            > "${spoof_dir}/spoofy.txt" 2>> "$LOGFILE" || true
        popd > /dev/null 2>&1
    fi
    
    # Manual SPF/DMARC check
    log_info "Checking SPF and DMARC records..."
    
    # SPF record
    dig TXT "$domain" +short | grep -i "spf" > "${spoof_dir}/spf_record.txt" 2>/dev/null || true
    
    # DMARC record
    dig TXT "_dmarc.${domain}" +short > "${spoof_dir}/dmarc_record.txt" 2>/dev/null || true
    
    # Analyze records
    local spf_exists=false
    local dmarc_exists=false
    
    [[ -s "${spoof_dir}/spf_record.txt" ]] && spf_exists=true
    [[ -s "${spoof_dir}/dmarc_record.txt" ]] && dmarc_exists=true
    
    # Create summary
    cat > "${spoof_dir}/summary.txt" << EOF
Email Security Analysis for ${domain}
=====================================

SPF Record Found: $spf_exists
DMARC Record Found: $dmarc_exists

SPF Record:
$(cat "${spoof_dir}/spf_record.txt" 2>/dev/null || echo "Not found")

DMARC Record:
$(cat "${spoof_dir}/dmarc_record.txt" 2>/dev/null || echo "Not found")

Analysis:
EOF
    
    if [[ "$spf_exists" == "false" ]]; then
        echo "- WARNING: No SPF record found. Domain may be spoofable." >> "${spoof_dir}/summary.txt"
    fi
    
    if [[ "$dmarc_exists" == "false" ]]; then
        echo "- WARNING: No DMARC record found. Email spoofing protection is weak." >> "${spoof_dir}/summary.txt"
    fi
    
    end_subfunc "Spoof check completed" "osint_spoof_check"
}

# ═══════════════════════════════════════════════════════════════════════════════
# IP INFO (FOR IP TARGETS)
# ═══════════════════════════════════════════════════════════════════════════════

osint_ip_info() {
    start_subfunc "osint_ip_info" "Gathering IP information"
    
    local ip_dir="${dir}/osint/ip_info"
    ensure_dir "$ip_dir"
    
    # Whois for IP
    if command_exists whois; then
        whois "$domain" > "${ip_dir}/whois.txt" 2>> "$LOGFILE" || true
    fi
    
    # Shodan lookup
    if [[ -n "${SHODAN_API_KEY:-}" ]] && command_exists shodan; then
        log_info "Querying Shodan..."
        shodan host "$domain" > "${ip_dir}/shodan.txt" 2>> "$LOGFILE" || true
    fi
    
    # Reverse DNS
    dig -x "$domain" +short > "${ip_dir}/reverse_dns.txt" 2>/dev/null || true
    
    # ASN lookup
    curl -sL "https://ipinfo.io/${domain}/json" > "${ip_dir}/ipinfo.json" 2>/dev/null || true
    
    end_subfunc "IP info gathered" "osint_ip_info"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

osint_aggregate_results() {
    log_info "Aggregating OSINT results..."
    
    local summary="${dir}/osint/osint_summary.txt"
    
    cat > "$summary" << EOF
OSINT Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

EOF
    
    # Count emails
    if [[ -f "${dir}/osint/emails.txt" ]]; then
        local email_count=$(count_lines "${dir}/osint/emails.txt")
        echo "Emails Found: $email_count" >> "$summary"
    fi
    
    # Count GitHub subdomains
    if [[ -f "${dir}/osint/github/subdomains.txt" ]]; then
        local gh_sub_count=$(count_lines "${dir}/osint/github/subdomains.txt")
        echo "GitHub Subdomains: $gh_sub_count" >> "$summary"
    fi
    
    # Count secrets
    if [[ -f "${dir}/osint/secrets/all_secrets.json" ]]; then
        local secret_count=$(jq 'length' "${dir}/osint/secrets/all_secrets.json" 2>/dev/null || echo "0")
        echo "Potential Secrets: $secret_count" >> "$summary"
    fi
    
    echo "" >> "$summary"
    echo "Detailed results available in ${dir}/osint/" >> "$summary"
    
    log_success "OSINT aggregation completed"
}
