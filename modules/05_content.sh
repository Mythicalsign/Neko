#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: CONTENT DISCOVERY & DIRECTORY FUZZING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Discover hidden directories, files, and endpoints
# Tools: ffuf, feroxbuster, gobuster, dirsearch
# ═══════════════════════════════════════════════════════════════════════════════

content_main() {
    log_phase "PHASE 5: CONTENT DISCOVERY & DIRECTORY FUZZING"
    
    if ! should_run_module "content_main" "CONTENT_ENABLED"; then
        return 0
    fi
    
    start_func "content_main" "Starting Content Discovery"
    
    ensure_dir "${dir}/content"
    ensure_dir "${dir}/.tmp/content"
    
    # Check for web targets
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts available for content discovery"
        return 0
    fi
    
    # Prepare targets
    content_prepare_targets
    
    # Run content discovery functions
    content_ffuf
    content_extensions
    content_vhost
    content_aggregate
    
    end_func "Content discovery completed. Results in ${dir}/content/" "content_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREPARE TARGETS
# ═══════════════════════════════════════════════════════════════════════════════

content_prepare_targets() {
    log_info "Preparing targets for content discovery..."
    
    local web_count=$(count_lines "${dir}/webs/webs.txt")
    local max_targets=50
    
    if [[ "${DEEP:-false}" == "true" ]]; then
        max_targets=200
    fi
    
    # Prioritize targets without WAF
    if [[ -s "${dir}/webs/waf_detection.txt" ]]; then
        grep "No WAF" "${dir}/webs/waf_detection.txt" | \
            cut -d: -f1 > "${dir}/.tmp/content/no_waf_targets.txt" || true
        
        if [[ -s "${dir}/.tmp/content/no_waf_targets.txt" ]]; then
            head -n $max_targets "${dir}/.tmp/content/no_waf_targets.txt" \
                > "${dir}/.tmp/content/fuzz_targets.txt"
            log_info "Using $(count_lines "${dir}/.tmp/content/fuzz_targets.txt") non-WAF targets"
        else
            head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/content/fuzz_targets.txt"
        fi
    else
        head -n $max_targets "${dir}/webs/webs.txt" > "${dir}/.tmp/content/fuzz_targets.txt"
    fi
    
    log_info "Prepared $(count_lines "${dir}/.tmp/content/fuzz_targets.txt") targets for fuzzing"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FFUF - PRIMARY FUZZING TOOL
# ═══════════════════════════════════════════════════════════════════════════════

content_ffuf() {
    if ! should_run_module "content_ffuf" "FUZZ_FFUF"; then
        return 0
    fi
    
    start_subfunc "content_ffuf" "Running ffuf directory fuzzing"
    
    if ! command_exists ffuf; then
        log_warning "ffuf not installed, trying feroxbuster..."
        content_feroxbuster
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/content/fuzz_targets.txt" ]]; then
        log_warning "No targets for fuzzing"
        return 0
    fi
    
    # Select wordlist
    local wordlist
    if [[ "${DEEP:-false}" == "true" ]]; then
        wordlist="${FUZZ_WORDLIST_BIG:-${TOOLS_PATH}/wordlists/raft-large-directories.txt}"
    else
        wordlist="${FUZZ_WORDLIST:-${TOOLS_PATH}/wordlists/fuzz.txt}"
    fi
    
    if [[ ! -f "$wordlist" ]]; then
        # Fallback to a smaller built-in wordlist
        log_warning "Wordlist not found, using minimal wordlist"
        wordlist="${FUZZ_WORDLIST_SMALL:-${TOOLS_PATH}/wordlists/common.txt}"
        
        if [[ ! -f "$wordlist" ]]; then
            # Create minimal wordlist
            cat > "${dir}/.tmp/content/minimal_wordlist.txt" << 'EOF'
admin
api
backup
config
console
dashboard
debug
dev
docs
git
graphql
health
info
login
logout
metrics
phpinfo
readme
robots.txt
server-status
sitemap.xml
status
swagger
test
upload
v1
v2
version
wp-admin
wp-content
.env
.git
.htaccess
EOF
            wordlist="${dir}/.tmp/content/minimal_wordlist.txt"
        fi
    fi
    
    local wordlist_size=$(count_lines "$wordlist")
    log_info "Using wordlist with $wordlist_size words"
    
    ensure_dir "${dir}/content/ffuf"
    
    # Fuzz each target
    local counter=0
    local total=$(count_lines "${dir}/.tmp/content/fuzz_targets.txt")
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        ((counter++))
        
        log_info "[$counter/$total] Fuzzing: $url"
        
        local safe_name=$(echo "$url" | sed 's|https\?://||; s|[:/]|_|g')
        local output_file="${dir}/content/ffuf/${safe_name}.json"
        
        # Run ffuf
        timeout "${FFUF_MAXTIME:-900}" ffuf \
            -u "${url}/FUZZ" \
            -w "$wordlist" \
            -t "${FFUF_THREADS:-50}" \
            -rate "${FFUF_RATELIMIT:-100}" \
            ${FFUF_DEFAULT_FLAGS:--mc all -fc 404 -sf -noninteractive -of json} \
            -o "$output_file" \
            -H "User-Agent: ${USER_AGENT:-Mozilla/5.0}" \
            2>> "$LOGFILE" || true
        
        # Parse results immediately
        if [[ -s "$output_file" ]]; then
            content_parse_ffuf_results "$output_file" "$url"
        fi
        
    done < "${dir}/.tmp/content/fuzz_targets.txt"
    
    # Process results with ffufPostprocessing if available
    if command_exists ffufPostprocessing || [[ -f "${TOOLS_PATH}/ffufPostprocessing/ffufPostprocessing" ]]; then
        log_info "Running ffufPostprocessing..."
        for json_file in "${dir}/content/ffuf/"*.json; do
            [[ -f "$json_file" ]] || continue
            "${TOOLS_PATH}/ffufPostprocessing/ffufPostprocessing" -f "$json_file" \
                -o "${json_file%.json}_filtered.json" 2>> "$LOGFILE" || true
        done
    fi
    
    end_subfunc "ffuf fuzzing completed on $counter targets" "content_ffuf"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARSE FFUF RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

content_parse_ffuf_results() {
    local json_file="$1"
    local base_url="$2"
    
    if [[ ! -s "$json_file" ]]; then
        return 0
    fi
    
    # Extract found paths
    jq -r '.results[]? | "\(.url) [\(.status)] [\(.length) bytes]"' "$json_file" 2>/dev/null | \
        grep -v "null" >> "${dir}/content/found_paths.txt" || true
    
    # Extract interesting status codes
    
    # 200 OK - Found content
    jq -r '.results[]? | select(.status == 200) | .url' "$json_file" 2>/dev/null | \
        grep -v "null" >> "${dir}/content/status_200.txt" || true
    
    # 301/302 Redirects
    jq -r '.results[]? | select(.status == 301 or .status == 302) | .url' "$json_file" 2>/dev/null | \
        grep -v "null" >> "${dir}/content/redirects.txt" || true
    
    # 401/403 - Forbidden (potential bypass)
    jq -r '.results[]? | select(.status == 401 or .status == 403) | .url' "$json_file" 2>/dev/null | \
        grep -v "null" >> "${dir}/content/forbidden.txt" || true
    
    # 500+ Server errors
    jq -r '.results[]? | select(.status >= 500) | .url' "$json_file" 2>/dev/null | \
        grep -v "null" >> "${dir}/content/server_errors.txt" || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# FEROXBUSTER - RECURSIVE FUZZING
# ═══════════════════════════════════════════════════════════════════════════════

content_feroxbuster() {
    if ! should_run_module "content_feroxbuster" "FUZZ_RECURSIVE"; then
        return 0
    fi
    
    start_subfunc "content_feroxbuster" "Running feroxbuster recursive fuzzing"
    
    if ! command_exists feroxbuster; then
        log_warning "feroxbuster not installed, trying gobuster..."
        content_gobuster
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/content/fuzz_targets.txt" ]]; then
        log_warning "No targets for feroxbuster"
        return 0
    fi
    
    # Use smaller wordlist for feroxbuster (recursive takes time)
    local wordlist="${FUZZ_WORDLIST_SMALL:-${TOOLS_PATH}/wordlists/common.txt}"
    [[ ! -f "$wordlist" ]] && wordlist="${dir}/.tmp/content/minimal_wordlist.txt"
    
    ensure_dir "${dir}/content/feroxbuster"
    
    # Limit targets for recursive scanning
    local max_targets=10
    [[ "${DEEP:-false}" == "true" ]] && max_targets=30
    
    head -n $max_targets "${dir}/.tmp/content/fuzz_targets.txt" > "${dir}/.tmp/content/ferox_targets.txt"
    
    log_info "Running feroxbuster on $(count_lines "${dir}/.tmp/content/ferox_targets.txt") targets..."
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        local safe_name=$(echo "$url" | sed 's|https\?://||; s|[:/]|_|g')
        
        timeout "${FFUF_MAXTIME:-900}" feroxbuster \
            -u "$url" \
            -w "$wordlist" \
            -t "${FEROXBUSTER_THREADS:-50}" \
            --rate-limit "${FEROXBUSTER_RATELIMIT:-100}" \
            -d "${FFUF_RECURSION_DEPTH:-2}" \
            -o "${dir}/content/feroxbuster/${safe_name}.txt" \
            --silent \
            --no-state \
            2>> "$LOGFILE" || true
        
    done < "${dir}/.tmp/content/ferox_targets.txt"
    
    # Aggregate results
    cat "${dir}/content/feroxbuster/"*.txt 2>/dev/null | \
        sort -u >> "${dir}/content/found_paths.txt" || true
    
    end_subfunc "feroxbuster completed" "content_feroxbuster"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GOBUSTER - ALTERNATIVE FUZZING
# ═══════════════════════════════════════════════════════════════════════════════

content_gobuster() {
    start_subfunc "content_gobuster" "Running gobuster directory fuzzing"
    
    if ! command_exists gobuster; then
        log_warning "gobuster not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/content/fuzz_targets.txt" ]]; then
        log_warning "No targets for gobuster"
        return 0
    fi
    
    local wordlist="${FUZZ_WORDLIST_SMALL:-${TOOLS_PATH}/wordlists/common.txt}"
    [[ ! -f "$wordlist" ]] && wordlist="${dir}/.tmp/content/minimal_wordlist.txt"
    
    ensure_dir "${dir}/content/gobuster"
    
    head -n 20 "${dir}/.tmp/content/fuzz_targets.txt" | while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        local safe_name=$(echo "$url" | sed 's|https\?://||; s|[:/]|_|g')
        
        gobuster dir \
            -u "$url" \
            -w "$wordlist" \
            -t "${GOBUSTER_THREADS:-50}" \
            -o "${dir}/content/gobuster/${safe_name}.txt" \
            --no-error \
            -q \
            2>> "$LOGFILE" || true
        
    done
    
    end_subfunc "gobuster completed" "content_gobuster"
}

# ═══════════════════════════════════════════════════════════════════════════════
# EXTENSION FUZZING
# ═══════════════════════════════════════════════════════════════════════════════

content_extensions() {
    if ! should_run_module "content_extensions" "FUZZ_EXTENSIONS"; then
        return 0
    fi
    
    start_subfunc "content_extensions" "Running extension fuzzing"
    
    if ! command_exists ffuf; then
        log_warning "ffuf not installed for extension fuzzing"
        return 0
    fi
    
    # Get list of found paths without extensions
    if [[ ! -s "${dir}/content/status_200.txt" ]]; then
        log_warning "No paths found for extension fuzzing"
        return 0
    fi
    
    # Extensions to try
    local extensions="${FFUF_EXTENSIONS:-.php,.asp,.aspx,.jsp,.html,.js,.txt,.xml,.json,.bak,.old,.conf,.config,.sql,.zip,.tar,.gz}"
    
    # Limit paths for extension fuzzing
    local max_paths=100
    head -n $max_paths "${dir}/content/status_200.txt" > "${dir}/.tmp/content/ext_targets.txt"
    
    ensure_dir "${dir}/content/extensions"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        # Skip if already has extension
        [[ "$url" =~ \.[a-zA-Z0-9]{1,5}$ ]] && continue
        
        local safe_name=$(echo "$url" | sed 's|https\?://||; s|[:/]|_|g')
        
        ffuf \
            -u "${url}FUZZ" \
            -w <(echo "$extensions" | tr ',' '\n') \
            -t "${FFUF_THREADS:-50}" \
            -rate "${FFUF_RATELIMIT:-100}" \
            -mc 200,301,302,403 \
            -sf \
            -o "${dir}/content/extensions/${safe_name}.json" \
            -of json \
            2>> "$LOGFILE" || true
        
    done < "${dir}/.tmp/content/ext_targets.txt"
    
    # Aggregate extension findings
    for json_file in "${dir}/content/extensions/"*.json; do
        [[ -f "$json_file" ]] || continue
        jq -r '.results[]? | .url' "$json_file" 2>/dev/null | \
            grep -v "null" >> "${dir}/content/extension_findings.txt" || true
    done
    
    local ext_count=$(count_lines "${dir}/content/extension_findings.txt")
    end_subfunc "Found $ext_count paths with extensions" "content_extensions"
}

# ═══════════════════════════════════════════════════════════════════════════════
# VIRTUAL HOST FUZZING
# ═══════════════════════════════════════════════════════════════════════════════

content_vhost() {
    if ! should_run_module "content_vhost" "FUZZ_VHOST"; then
        return 0
    fi
    
    start_subfunc "content_vhost" "Running virtual host fuzzing"
    
    if ! command_exists ffuf; then
        log_warning "ffuf not installed for vhost fuzzing"
        return 0
    fi
    
    # Need a vhost wordlist
    local vhost_wordlist="${TOOLS_PATH}/wordlists/vhosts.txt"
    if [[ ! -f "$vhost_wordlist" ]]; then
        # Create minimal vhost wordlist
        cat > "${dir}/.tmp/content/vhost_wordlist.txt" << 'EOF'
admin
api
app
beta
blog
cdn
cms
cpanel
dashboard
dev
development
ftp
git
gitlab
internal
jenkins
jira
localhost
mail
mysql
old
portal
prod
production
staging
test
testing
upload
webmail
www
EOF
        vhost_wordlist="${dir}/.tmp/content/vhost_wordlist.txt"
    fi
    
    ensure_dir "${dir}/content/vhosts"
    
    # Get unique IPs/hosts
    local max_hosts=10
    head -n $max_hosts "${dir}/.tmp/content/fuzz_targets.txt" > "${dir}/.tmp/content/vhost_targets.txt"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        local host=$(echo "$url" | sed 's|https\?://||; s|/.*||; s|:.*||')
        local safe_name=$(echo "$host" | sed 's|[:/]|_|g')
        
        ffuf \
            -u "$url" \
            -w "$vhost_wordlist" \
            -H "Host: FUZZ.${domain}" \
            -t "${FFUF_THREADS:-50}" \
            -rate "${FFUF_RATELIMIT:-100}" \
            -mc all \
            -fc 404 \
            -fs 0 \
            -sf \
            -o "${dir}/content/vhosts/${safe_name}.json" \
            -of json \
            2>> "$LOGFILE" || true
        
    done < "${dir}/.tmp/content/vhost_targets.txt"
    
    # Aggregate vhost findings
    for json_file in "${dir}/content/vhosts/"*.json; do
        [[ -f "$json_file" ]] || continue
        jq -r '.results[]? | "\(.input.FUZZ).'"$domain"'"' "$json_file" 2>/dev/null | \
            grep -v "null" >> "${dir}/content/vhost_findings.txt" || true
    done
    
    local vhost_count=$(count_lines "${dir}/content/vhost_findings.txt")
    end_subfunc "Found $vhost_count virtual hosts" "content_vhost"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE CONTENT DISCOVERY RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

content_aggregate() {
    log_info "Aggregating content discovery results..."
    
    # Deduplicate found paths
    sort -u "${dir}/content/found_paths.txt" -o "${dir}/content/found_paths.txt" 2>/dev/null || true
    sort -u "${dir}/content/status_200.txt" -o "${dir}/content/status_200.txt" 2>/dev/null || true
    sort -u "${dir}/content/forbidden.txt" -o "${dir}/content/forbidden.txt" 2>/dev/null || true
    
    local summary="${dir}/content/content_summary.txt"
    
    cat > "$summary" << EOF
Content Discovery Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Total Paths Found: $(count_lines "${dir}/content/found_paths.txt")

By Status Code:
- 200 OK: $(count_lines "${dir}/content/status_200.txt")
- 301/302 Redirects: $(count_lines "${dir}/content/redirects.txt")
- 401/403 Forbidden: $(count_lines "${dir}/content/forbidden.txt")
- 5xx Server Errors: $(count_lines "${dir}/content/server_errors.txt")

Extension Findings: $(count_lines "${dir}/content/extension_findings.txt")
Virtual Host Findings: $(count_lines "${dir}/content/vhost_findings.txt")

Interesting Paths (sample):
$(head -20 "${dir}/content/found_paths.txt" 2>/dev/null || echo "None")

Forbidden Paths (potential bypass):
$(head -10 "${dir}/content/forbidden.txt" 2>/dev/null || echo "None")

Detailed results available in ${dir}/content/
EOF
    
    log_success "Content discovery aggregation completed"
}
