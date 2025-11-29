#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: SUBDOMAIN DISCOVERY (ENHANCED)
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Comprehensive subdomain enumeration
# Tools: subfinder, assetfinder, amass, crt, github-subdomains, puredns, dnsx,
#        gotator, ripgen, regulator, dsieve, tlsx
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_main() {
    log_phase "PHASE 1: SUBDOMAIN DISCOVERY"
    
    if ! should_run_module "subdomain_main" "SUBDOMAIN_ENABLED"; then
        return 0
    fi
    
    start_func "subdomain_main" "Starting Subdomain Discovery"
    
    ensure_dir "${dir}/subdomains"
    ensure_dir "${dir}/.tmp/subs"
    
    # Skip if target is IP
    if is_ip "$domain" || is_cidr "$domain"; then
        log_info "Target is IP/CIDR, skipping subdomain enumeration"
        echo "$domain" > "${dir}/subdomains/subdomains.txt"
        end_func "IP/CIDR target - no subdomain enumeration" "subdomain_main"
        return 0
    fi
    
    # Update resolvers
    resolvers_update_quick_local
    
    # === PASSIVE ENUMERATION ===
    subdomain_passive
    
    # === CERTIFICATE TRANSPARENCY ===
    subdomain_crt
    
    # === GITHUB/GITLAB SUBDOMAINS ===
    subdomain_github
    
    # === ACTIVE ENUMERATION ===
    subdomain_active
    
    # === TLS CERTIFICATE ANALYSIS ===
    subdomain_tls
    
    # === DNS BRUTEFORCE ===
    subdomain_bruteforce
    
    # === PERMUTATION ===
    subdomain_permutation
    
    # === RECURSIVE ENUMERATION ===
    subdomain_recursive
    
    # === WEB SCRAPING ===
    subdomain_scraping
    
    # === FINAL RESOLUTION ===
    subdomain_resolve_all
    
    # Count results
    local sub_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    end_func "Found $sub_count unique subdomains" "subdomain_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_passive() {
    if ! should_run_module "subdomain_passive" "SUB_PASSIVE"; then
        return 0
    fi
    
    start_subfunc "subdomain_passive" "Running passive subdomain enumeration"
    
    local passive_file="${dir}/.tmp/subs/passive.txt"
    touch "$passive_file"
    
    # Subfinder - Primary passive tool
    if command_exists subfinder; then
        log_info "Running subfinder..."
        subfinder -all -d "$domain" \
            -t "${SUBFINDER_THREADS:-100}" \
            -max-time "${SUBFINDER_TIMEOUT:-180}" \
            -silent \
            -o "${dir}/.tmp/subs/subfinder.txt" 2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/subfinder.txt" ]]; then
            cat "${dir}/.tmp/subs/subfinder.txt" >> "$passive_file"
        fi
    fi
    
    # Assetfinder
    if command_exists assetfinder; then
        log_info "Running assetfinder..."
        assetfinder --subs-only "$domain" \
            > "${dir}/.tmp/subs/assetfinder.txt" 2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/assetfinder.txt" ]]; then
            cat "${dir}/.tmp/subs/assetfinder.txt" >> "$passive_file"
        fi
    fi
    
    # Amass passive
    if command_exists amass && [[ "${SUB_AMASS:-true}" == "true" ]]; then
        log_info "Running amass passive..."
        timeout "${AMASS_TIMEOUT:-600}" amass enum -passive -d "$domain" \
            -o "${dir}/.tmp/subs/amass_passive.txt" 2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/amass_passive.txt" ]]; then
            cat "${dir}/.tmp/subs/amass_passive.txt" >> "$passive_file"
        fi
    fi
    
    # Findomain (if installed)
    if command_exists findomain; then
        log_info "Running findomain..."
        findomain -t "$domain" -q \
            -u "${dir}/.tmp/subs/findomain.txt" 2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/findomain.txt" ]]; then
            cat "${dir}/.tmp/subs/findomain.txt" >> "$passive_file"
        fi
    fi
    
    # Clean and deduplicate
    sed 's/^\*\.//' "$passive_file" | sort -u -o "$passive_file"
    
    local count=$(count_lines "$passive_file")
    end_subfunc "Passive enumeration: $count subdomains" "subdomain_passive"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE TRANSPARENCY
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_crt() {
    if ! should_run_module "subdomain_crt" "SUB_CRT"; then
        return 0
    fi
    
    start_subfunc "subdomain_crt" "Querying certificate transparency logs"
    
    local crt_file="${dir}/.tmp/subs/crt.txt"
    touch "$crt_file"
    
    # crt tool (ProjectDiscovery)
    if command_exists crt; then
        log_info "Running crt..."
        crt -s -json -l "${CTR_LIMIT:-999999}" "$domain" 2>> "$LOGFILE" | \
            jq -r '.[].subdomain' 2>/dev/null | \
            sed 's/^\*\.//' >> "$crt_file" || true
    else
        # Fallback to crt.sh API
        log_info "Querying crt.sh API..."
        curl -sL "https://crt.sh/?q=%25.${domain}&output=json" 2>> "$LOGFILE" | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/^\*\.//' | \
            sort -u >> "$crt_file" || true
    fi
    
    # Clean
    sort -u "$crt_file" -o "$crt_file"
    
    local count=$(count_lines "$crt_file")
    end_subfunc "Certificate transparency: $count subdomains" "subdomain_crt"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB SUBDOMAIN DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_github() {
    if ! should_run_module "subdomain_github" "SUB_GITHUB"; then
        return 0
    fi
    
    start_subfunc "subdomain_github" "Discovering subdomains from GitHub"
    
    local github_file="${dir}/.tmp/subs/github.txt"
    touch "$github_file"
    
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        log_warning "GITHUB_TOKEN not set, skipping GitHub subdomain discovery"
        return 0
    fi
    
    # github-subdomains
    if command_exists github-subdomains; then
        log_info "Running github-subdomains..."
        if [[ "${DEEP:-false}" == "true" ]]; then
            github-subdomains -d "$domain" -t "$GITHUB_TOKEN" \
                -o "${dir}/.tmp/subs/github_subs.txt" 2>> "$LOGFILE" || true
        else
            github-subdomains -d "$domain" -k -q -t "$GITHUB_TOKEN" \
                -o "${dir}/.tmp/subs/github_subs.txt" 2>> "$LOGFILE" || true
        fi
        
        if [[ -s "${dir}/.tmp/subs/github_subs.txt" ]]; then
            cat "${dir}/.tmp/subs/github_subs.txt" >> "$github_file"
        fi
    fi
    
    # gitlab-subdomains
    if command_exists gitlab-subdomains && [[ -n "${GITLAB_TOKEN:-}" ]]; then
        log_info "Running gitlab-subdomains..."
        gitlab-subdomains -d "$domain" -t "$GITLAB_TOKEN" \
            >> "$github_file" 2>> "$LOGFILE" || true
    fi
    
    sort -u "$github_file" -o "$github_file"
    
    local count=$(count_lines "$github_file")
    end_subfunc "GitHub/GitLab: $count subdomains" "subdomain_github"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVE SUBDOMAIN RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_active() {
    start_subfunc "subdomain_active" "Running active subdomain resolution"
    
    # Merge all passive results
    cat "${dir}/.tmp/subs/"*.txt 2>/dev/null | \
        grep -E "\.$domain$|^$domain$" | \
        sort -u > "${dir}/.tmp/subs/all_unresolved.txt"
    
    if [[ ! -s "${dir}/.tmp/subs/all_unresolved.txt" ]]; then
        log_warning "No subdomains found to resolve"
        return 0
    fi
    
    local unresolved_count=$(count_lines "${dir}/.tmp/subs/all_unresolved.txt")
    log_info "Resolving $unresolved_count subdomains..."
    
    # Use puredns for resolution
    if command_exists puredns; then
        log_info "Running puredns resolve..."
        puredns resolve "${dir}/.tmp/subs/all_unresolved.txt" \
            -w "${dir}/.tmp/subs/resolved.txt" \
            -r "${RESOLVERS}" \
            --resolvers-trusted "${RESOLVERS_TRUSTED}" \
            -l "${PUREDNS_PUBLIC_LIMIT:-0}" \
            --rate-limit-trusted "${PUREDNS_TRUSTED_LIMIT:-400}" \
            --wildcard-tests "${PUREDNS_WILDCARDTEST_LIMIT:-30}" \
            --wildcard-batch "${PUREDNS_WILDCARDBATCH_LIMIT:-1500000}" \
            2>> "$LOGFILE" || true
    elif command_exists dnsx; then
        # Fallback to dnsx
        log_info "Running dnsx resolve..."
        dnsx -l "${dir}/.tmp/subs/all_unresolved.txt" \
            -r "${RESOLVERS_TRUSTED}" \
            -t "${DNSX_THREADS:-150}" \
            -silent \
            -o "${dir}/.tmp/subs/resolved.txt" 2>> "$LOGFILE" || true
    elif command_exists massdns; then
        # Fallback to massdns
        log_info "Running massdns resolve..."
        massdns -r "${RESOLVERS}" \
            -t A \
            -o S \
            -w "${dir}/.tmp/subs/massdns_output.txt" \
            "${dir}/.tmp/subs/all_unresolved.txt" 2>> "$LOGFILE" || true
        
        # Parse massdns output
        awk '{print $1}' "${dir}/.tmp/subs/massdns_output.txt" | \
            sed 's/\.$//' | sort -u > "${dir}/.tmp/subs/resolved.txt"
    fi
    
    # Add resolved subdomains to main file
    if [[ -s "${dir}/.tmp/subs/resolved.txt" ]]; then
        grep -E "\.$domain$|^$domain$" "${dir}/.tmp/subs/resolved.txt" | \
            grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' | \
            sort -u >> "${dir}/subdomains/subdomains.txt"
    fi
    
    # Add domain itself if it resolves
    echo "$domain" | dnsx -retry 3 -silent -r "${RESOLVERS_TRUSTED}" \
        2>> "$LOGFILE" | sort -u >> "${dir}/subdomains/subdomains.txt" || true
    
    sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
    
    local resolved_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    end_subfunc "Active resolution: $resolved_count resolved subdomains" "subdomain_active"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TLS CERTIFICATE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_tls() {
    if ! should_run_module "subdomain_tls" "SUB_TLS"; then
        return 0
    fi
    
    start_subfunc "subdomain_tls" "Running TLS certificate analysis"
    
    if ! command_exists tlsx; then
        log_warning "tlsx not installed, skipping TLS analysis"
        return 0
    fi
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains to analyze"
        return 0
    fi
    
    local tls_file="${dir}/.tmp/subs/tls_subs.txt"
    
    # Run tlsx
    log_info "Running tlsx..."
    if [[ "${DEEP:-false}" == "true" ]]; then
        tlsx -l "${dir}/subdomains/subdomains.txt" \
            -san -cn -silent -ro \
            -c "${TLSX_THREADS:-1000}" \
            -p "${TLS_PORTS:-443,8443}" \
            -o "$tls_file" 2>> "$LOGFILE" || true
    else
        tlsx -l "${dir}/subdomains/subdomains.txt" \
            -san -cn -silent -ro \
            -c "${TLSX_THREADS:-1000}" \
            -o "$tls_file" 2>> "$LOGFILE" || true
    fi
    
    # Extract subdomains from TLS results
    if [[ -s "$tls_file" ]]; then
        grep -E "\.$domain$|^$domain$" "$tls_file" | \
            sed 's/|__ //' | \
            grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' | \
            sort -u >> "${dir}/.tmp/subs/tls_extracted.txt"
        
        # Resolve newly found TLS subdomains
        if [[ -s "${dir}/.tmp/subs/tls_extracted.txt" ]] && command_exists puredns; then
            puredns resolve "${dir}/.tmp/subs/tls_extracted.txt" \
                -w "${dir}/.tmp/subs/tls_resolved.txt" \
                -r "${RESOLVERS}" \
                --resolvers-trusted "${RESOLVERS_TRUSTED}" \
                2>> "$LOGFILE" || true
            
            if [[ -s "${dir}/.tmp/subs/tls_resolved.txt" ]]; then
                cat "${dir}/.tmp/subs/tls_resolved.txt" >> "${dir}/subdomains/subdomains.txt"
                sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
            fi
        fi
    fi
    
    local tls_count=$(count_lines "${dir}/.tmp/subs/tls_resolved.txt" 2>/dev/null || echo "0")
    end_subfunc "TLS analysis: $tls_count new subdomains" "subdomain_tls"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS BRUTEFORCE
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_bruteforce() {
    if ! should_run_module "subdomain_bruteforce" "SUB_BRUTEFORCE"; then
        return 0
    fi
    
    start_subfunc "subdomain_bruteforce" "Running DNS bruteforce"
    
    if ! command_exists puredns; then
        log_warning "puredns not installed, skipping bruteforce"
        return 0
    fi
    
    # Select wordlist based on mode
    local wordlist
    if [[ "${DEEP:-false}" == "true" ]]; then
        wordlist="${SUBS_WORDLIST_BIG:-${TOOLS_PATH}/wordlists/subdomains-top1million-110000.txt}"
    else
        wordlist="${SUBS_WORDLIST:-${TOOLS_PATH}/wordlists/subdomains.txt}"
    fi
    
    if [[ ! -f "$wordlist" ]]; then
        log_warning "Wordlist not found: $wordlist"
        return 0
    fi
    
    log_info "Running puredns bruteforce with $(count_lines "$wordlist") words..."
    
    puredns bruteforce "$wordlist" "$domain" \
        -w "${dir}/.tmp/subs/bruteforce.txt" \
        -r "${RESOLVERS}" \
        --resolvers-trusted "${RESOLVERS_TRUSTED}" \
        -l "${PUREDNS_PUBLIC_LIMIT:-0}" \
        --rate-limit-trusted "${PUREDNS_TRUSTED_LIMIT:-400}" \
        --wildcard-tests "${PUREDNS_WILDCARDTEST_LIMIT:-30}" \
        --wildcard-batch "${PUREDNS_WILDCARDBATCH_LIMIT:-1500000}" \
        2>> "$LOGFILE" || true
    
    # Add results
    if [[ -s "${dir}/.tmp/subs/bruteforce.txt" ]]; then
        cat "${dir}/.tmp/subs/bruteforce.txt" >> "${dir}/subdomains/subdomains.txt"
        sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
    fi
    
    local brute_count=$(count_lines "${dir}/.tmp/subs/bruteforce.txt" 2>/dev/null || echo "0")
    end_subfunc "Bruteforce: $brute_count new subdomains" "subdomain_bruteforce"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN PERMUTATION
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_permutation() {
    if ! should_run_module "subdomain_permutation" "SUB_PERMUTATION"; then
        return 0
    fi
    
    start_subfunc "subdomain_permutation" "Generating subdomain permutations"
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains for permutation"
        return 0
    fi
    
    local perm_file="${dir}/.tmp/subs/permutations.txt"
    touch "$perm_file"
    
    # Check subdomain count for limits
    local sub_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    if [[ $sub_count -gt ${DEEP_LIMIT:-500} ]] && [[ "${DEEP:-false}" != "true" ]]; then
        log_warning "Too many subdomains ($sub_count), limiting permutation input"
        head -n "${DEEP_LIMIT:-500}" "${dir}/subdomains/subdomains.txt" > "${dir}/.tmp/subs/perm_input.txt"
    else
        cp "${dir}/subdomains/subdomains.txt" "${dir}/.tmp/subs/perm_input.txt"
    fi
    
    # Gotator
    if command_exists gotator; then
        log_info "Running gotator..."
        gotator -sub "${dir}/.tmp/subs/perm_input.txt" \
            -perm "${SUBS_WORDLIST_SMALL:-${TOOLS_PATH}/wordlists/subdomains-top1million-5000.txt}" \
            -depth 1 -numbers 3 -mindup -adv -md \
            -silent 2>> "$LOGFILE" | head -n 500000 >> "$perm_file" || true
    fi
    
    # Ripgen (faster alternative)
    if command_exists ripgen; then
        log_info "Running ripgen..."
        ripgen -d "${dir}/.tmp/subs/perm_input.txt" \
            2>> "$LOGFILE" | head -n 500000 >> "$perm_file" || true
    fi
    
    # Regulator (regex-based)
    if [[ -f "${TOOLS_PATH}/regulator/main.py" ]]; then
        log_info "Running regulator..."
        run_python_tool "${TOOLS_PATH}/regulator" \
            -t "${dir}/.tmp/subs/perm_input.txt" \
            -f "${SUBS_WORDLIST_SMALL}" \
            2>> "$LOGFILE" >> "$perm_file" || true
    fi
    
    # Deduplicate and limit size
    sort -u "$perm_file" | head -n 1000000 > "${perm_file}.tmp"
    mv "${perm_file}.tmp" "$perm_file"
    
    # Resolve permutations
    if [[ -s "$perm_file" ]] && command_exists puredns; then
        log_info "Resolving $(count_lines "$perm_file") permutations..."
        puredns resolve "$perm_file" \
            -w "${dir}/.tmp/subs/perm_resolved.txt" \
            -r "${RESOLVERS}" \
            --resolvers-trusted "${RESOLVERS_TRUSTED}" \
            -l "${PUREDNS_PUBLIC_LIMIT:-0}" \
            2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/perm_resolved.txt" ]]; then
            grep -E "\.$domain$|^$domain$" "${dir}/.tmp/subs/perm_resolved.txt" | \
                sort -u >> "${dir}/subdomains/subdomains.txt"
            sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
        fi
    fi
    
    local perm_count=$(count_lines "${dir}/.tmp/subs/perm_resolved.txt" 2>/dev/null || echo "0")
    end_subfunc "Permutation: $perm_count new subdomains" "subdomain_permutation"
}

# ═══════════════════════════════════════════════════════════════════════════════
# RECURSIVE ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_recursive() {
    if ! should_run_module "subdomain_recursive" "SUB_RECURSIVE"; then
        return 0
    fi
    
    start_subfunc "subdomain_recursive" "Running recursive subdomain enumeration"
    
    # dsieve - recursive passive
    if command_exists dsieve; then
        log_info "Running dsieve..."
        if [[ -s "${dir}/subdomains/subdomains.txt" ]]; then
            dsieve -if "${dir}/subdomains/subdomains.txt" \
                -f 2 \
                -top "${DEEP_RECURSIVE_PASSIVE:-10}" \
                2>> "$LOGFILE" > "${dir}/.tmp/subs/dsieve.txt" || true
            
            if [[ -s "${dir}/.tmp/subs/dsieve.txt" ]]; then
                # Run subfinder on top subdomains found
                while IFS= read -r sub; do
                    [[ -z "$sub" ]] && continue
                    subfinder -d "$sub" -silent 2>> "$LOGFILE" >> "${dir}/.tmp/subs/recursive_passive.txt" || true
                done < "${dir}/.tmp/subs/dsieve.txt"
            fi
        fi
    fi
    
    # Resolve any new subdomains
    if [[ -s "${dir}/.tmp/subs/recursive_passive.txt" ]] && command_exists puredns; then
        puredns resolve "${dir}/.tmp/subs/recursive_passive.txt" \
            -w "${dir}/.tmp/subs/recursive_resolved.txt" \
            -r "${RESOLVERS}" \
            --resolvers-trusted "${RESOLVERS_TRUSTED}" \
            2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/recursive_resolved.txt" ]]; then
            grep -E "\.$domain$" "${dir}/.tmp/subs/recursive_resolved.txt" | \
                sort -u >> "${dir}/subdomains/subdomains.txt"
            sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
        fi
    fi
    
    local recursive_count=$(count_lines "${dir}/.tmp/subs/recursive_resolved.txt" 2>/dev/null || echo "0")
    end_subfunc "Recursive: $recursive_count new subdomains" "subdomain_recursive"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WEB SCRAPING FOR SUBDOMAINS
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_scraping() {
    if ! should_run_module "subdomain_scraping" "SUB_SCRAPING"; then
        return 0
    fi
    
    start_subfunc "subdomain_scraping" "Scraping web pages for subdomains"
    
    # This requires webs to be probed first
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_info "No web hosts available, attempting quick probe..."
        # Quick probe for scraping
        if [[ -s "${dir}/subdomains/subdomains.txt" ]] && command_exists httpx; then
            httpx -l "${dir}/subdomains/subdomains.txt" \
                -silent \
                -t "${HTTPX_THREADS:-50}" \
                -rl "${HTTPX_RATELIMIT:-150}" \
                -timeout "${HTTPX_TIMEOUT:-10}" \
                -o "${dir}/.tmp/subs/quick_probe.txt" 2>> "$LOGFILE" || true
        fi
    fi
    
    local probe_file="${dir}/webs/webs.txt"
    [[ ! -s "$probe_file" ]] && probe_file="${dir}/.tmp/subs/quick_probe.txt"
    
    if [[ ! -s "$probe_file" ]]; then
        log_warning "No web hosts to scrape"
        return 0
    fi
    
    # URLFinder
    if command_exists urlfinder; then
        log_info "Running urlfinder..."
        urlfinder -d "$domain" -all \
            -o "${dir}/.tmp/subs/urlfinder.txt" 2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/urlfinder.txt" ]]; then
            cat "${dir}/.tmp/subs/urlfinder.txt" | \
                grep "$domain" | \
                grep -oE 'https?://[^ ]+' | \
                sed 's/^\*\.//' | \
                unfurl -u domains 2>/dev/null >> "${dir}/.tmp/subs/scraped_subs.txt" || true
        fi
    fi
    
    # CSPRecon
    if command_exists csprecon && [[ -s "$probe_file" ]]; then
        log_info "Running csprecon..."
        cat "$probe_file" | csprecon -s 2>> "$LOGFILE" | \
            grep "$domain" | \
            sed 's/^\*\.//' | \
            sort -u >> "${dir}/.tmp/subs/scraped_subs.txt" || true
    fi
    
    # Resolve scraped subdomains
    if [[ -s "${dir}/.tmp/subs/scraped_subs.txt" ]] && command_exists puredns; then
        sort -u "${dir}/.tmp/subs/scraped_subs.txt" -o "${dir}/.tmp/subs/scraped_subs.txt"
        
        puredns resolve "${dir}/.tmp/subs/scraped_subs.txt" \
            -w "${dir}/.tmp/subs/scraped_resolved.txt" \
            -r "${RESOLVERS}" \
            --resolvers-trusted "${RESOLVERS_TRUSTED}" \
            2>> "$LOGFILE" || true
        
        if [[ -s "${dir}/.tmp/subs/scraped_resolved.txt" ]]; then
            grep -E "\.$domain$|^$domain$" "${dir}/.tmp/subs/scraped_resolved.txt" | \
                sort -u >> "${dir}/subdomains/subdomains.txt"
            sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
        fi
    fi
    
    local scraped_count=$(count_lines "${dir}/.tmp/subs/scraped_resolved.txt" 2>/dev/null || echo "0")
    end_subfunc "Scraping: $scraped_count new subdomains" "subdomain_scraping"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL RESOLUTION AND CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_resolve_all() {
    start_subfunc "subdomain_resolve_all" "Final subdomain resolution and cleanup"
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains found"
        return 0
    fi
    
    # Final deduplication
    sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
    
    # Filter to only valid subdomains of target domain
    grep -E "\.$domain$|^$domain$" "${dir}/subdomains/subdomains.txt" | \
        grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' | \
        sort -u > "${dir}/subdomains/subdomains_clean.txt"
    
    mv "${dir}/subdomains/subdomains_clean.txt" "${dir}/subdomains/subdomains.txt"
    
    # Apply scope filtering if enabled
    if [[ "${USE_INSCOPE:-false}" == "true" ]]; then
        check_inscope "${dir}/subdomains/subdomains.txt"
    fi
    
    # Apply out-of-scope filtering
    if [[ -n "${OUT_OF_SCOPE_FILE:-}" ]] && [[ -f "$OUT_OF_SCOPE_FILE" ]]; then
        delete_out_of_scope "$OUT_OF_SCOPE_FILE" "${dir}/subdomains/subdomains.txt"
    fi
    
    local final_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    end_subfunc "Final count: $final_count subdomains" "subdomain_resolve_all"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FAST MODE SUBDOMAIN DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

subdomain_fast() {
    log_phase "SUBDOMAIN DISCOVERY (FAST MODE)"
    
    start_func "subdomain_fast" "Running fast subdomain discovery"
    
    ensure_dir "${dir}/subdomains"
    ensure_dir "${dir}/.tmp/subs"
    
    if is_ip "$domain" || is_cidr "$domain"; then
        echo "$domain" > "${dir}/subdomains/subdomains.txt"
        end_func "IP/CIDR target" "subdomain_fast"
        return 0
    fi
    
    # Quick passive only
    local fast_file="${dir}/.tmp/subs/fast.txt"
    touch "$fast_file"
    
    # Subfinder only
    if command_exists subfinder; then
        subfinder -d "$domain" -silent -max-time 60 \
            -o "${dir}/.tmp/subs/subfinder_fast.txt" 2>> "$LOGFILE" || true
        cat "${dir}/.tmp/subs/subfinder_fast.txt" >> "$fast_file" 2>/dev/null || true
    fi
    
    # CRT.sh quick
    curl -sL "https://crt.sh/?q=%25.${domain}&output=json" 2>> "$LOGFILE" | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/^\*\.//' | \
        sort -u >> "$fast_file" || true
    
    # Quick resolve
    if command_exists dnsx && [[ -s "$fast_file" ]]; then
        sort -u "$fast_file" | \
            dnsx -r "${RESOLVERS_TRUSTED}" -t 100 -silent \
            > "${dir}/subdomains/subdomains.txt" 2>> "$LOGFILE" || true
    else
        sort -u "$fast_file" > "${dir}/subdomains/subdomains.txt"
    fi
    
    local count=$(count_lines "${dir}/subdomains/subdomains.txt")
    end_func "Fast mode: $count subdomains" "subdomain_fast"
}
