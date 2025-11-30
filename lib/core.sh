#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO CORE LIBRARY
# Common functions used across all modules
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# CORE UTILITY FUNCTIONS (Available globally when library is loaded)
# ═══════════════════════════════════════════════════════════════════════════════

# Check if a command exists (define if not already defined)
if ! type -t command_exists &>/dev/null; then
    command_exists() {
        command -v "$1" &>/dev/null
    }
fi

# Create directory if not exists (define if not already defined)
if ! type -t ensure_dir &>/dev/null; then
    ensure_dir() {
        [[ -d "$1" ]] || mkdir -p "$1"
    }
fi

# Timestamp for filenames (define if not already defined)
if ! type -t timestamp &>/dev/null; then
    timestamp() {
        date +"%Y%m%d_%H%M%S"
    }
fi

# Count lines in file (define if not already defined)
if ! type -t count_lines &>/dev/null; then
    count_lines() {
        local file="$1"
        if [[ -f "$file" ]]; then
            wc -l < "$file" | tr -d ' '
        else
            echo "0"
        fi
    }
fi

# Validate domain format (define if not already defined)
if ! type -t validate_domain &>/dev/null; then
    validate_domain() {
        local domain="$1"
        if [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
            return 0
        elif [[ "$domain" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            return 0
        elif [[ "$domain" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            return 0
        else
            return 1
        fi
    }
fi

# Check if target is IP (define if not already defined)
if ! type -t is_ip &>/dev/null; then
    is_ip() {
        [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
    }
fi

# Check if target is CIDR (define if not already defined)
if ! type -t is_cidr &>/dev/null; then
    is_cidr() {
        [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]
    }
fi

# Deduplicate file in place (define if not already defined)
if ! type -t dedupe_file &>/dev/null; then
    dedupe_file() {
        local file="$1"
        if [[ -f "$file" ]]; then
            sort -u "$file" -o "$file"
        fi
    }
fi

# Check if file exists and is not empty (define if not already defined)
if ! type -t file_exists_not_empty &>/dev/null; then
    file_exists_not_empty() {
        [[ -s "$1" ]]
    }
fi

# Basic log functions fallback (if not defined by logging.sh)
if ! type -t log_info &>/dev/null; then
    log_info() { echo "[INFO] $1"; }
fi
if ! type -t log_success &>/dev/null; then
    log_success() { echo "[SUCCESS] $1"; }
fi
if ! type -t log_warning &>/dev/null; then
    log_warning() { echo "[WARNING] $1"; }
fi
if ! type -t log_error &>/dev/null; then
    log_error() { echo "[ERROR] $1" >&2; }
fi
if ! type -t log_debug &>/dev/null; then
    log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo "[DEBUG] $1"; }
fi
if ! type -t log_module &>/dev/null; then
    log_module() { echo "[MODULE] $1"; }
fi

# Module tracking fallback functions
if ! type -t mark_module_started &>/dev/null; then
    mark_module_started() { :; }
fi
if ! type -t mark_module_completed &>/dev/null; then
    mark_module_completed() { :; }
fi

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE TRACKING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Start function tracking
start_func() {
    local func_name="$1"
    local description="$2"
    
    mark_module_started "$func_name"
    log_module "$description"
    
    # Log to file
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] START: $func_name - $description" >> "$LOGFILE"
}

# End function tracking
end_func() {
    local result="$1"
    local func_name="$2"
    
    mark_module_completed "$func_name"
    log_success "$result"
    
    # Log to file
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] END: $func_name - $result" >> "$LOGFILE"
}

# Start sub-function
start_subfunc() {
    local func_name="$1"
    local description="$2"
    
    log_info "$description"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] START SUB: $func_name" >> "$LOGFILE"
}

# End sub-function
end_subfunc() {
    local result="$1"
    local func_name="$2"
    
    log_info "$result"
    touch "${called_fn_dir}/.${func_name}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] END SUB: $func_name - $result" >> "$LOGFILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FILE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Append unique lines (anew alternative)
append_unique() {
    local input_file="$1"
    local output_file="$2"
    
    if [[ ! -f "$output_file" ]]; then
        cp "$input_file" "$output_file"
        return
    fi
    
    if command_exists anew; then
        cat "$input_file" | anew -q "$output_file"
    else
        # Fallback without anew
        sort -u "$input_file" "$output_file" -o "$output_file"
    fi
}

# Count new lines added
count_new_lines() {
    local new_file="$1"
    local existing_file="$2"
    
    if [[ ! -f "$existing_file" ]]; then
        wc -l < "$new_file" | tr -d ' '
        return
    fi
    
    if command_exists anew; then
        cat "$new_file" | anew "$existing_file" | wc -l | tr -d ' '
    else
        comm -23 <(sort -u "$new_file") <(sort -u "$existing_file") | wc -l | tr -d ' '
    fi
}

# Delete out of scope entries
delete_out_of_scope() {
    local scope_file="$1"
    local target_file="$2"
    
    if [[ ! -f "$scope_file" ]] || [[ ! -f "$target_file" ]]; then
        return
    fi
    
    if command_exists inscope; then
        inscope -remove -scope "$scope_file" < "$target_file" > "${target_file}.tmp"
        mv "${target_file}.tmp" "$target_file"
    else
        # Manual filtering using grep
        while IFS= read -r pattern; do
            [[ -z "$pattern" ]] && continue
            grep -v "$pattern" "$target_file" > "${target_file}.tmp" || true
            mv "${target_file}.tmp" "$target_file"
        done < "$scope_file"
    fi
}

# Check inscope
check_inscope() {
    local input_file="$1"
    
    if [[ "${USE_INSCOPE:-false}" != "true" ]]; then
        return 0
    fi
    
    local scope_file="${SCRIPTPATH}/.scope"
    
    if [[ ! -f "$scope_file" ]]; then
        log_warning "Inscope enabled but .scope file not found"
        return 0
    fi
    
    if command_exists inscope; then
        inscope -scope "$scope_file" < "$input_file" > "${input_file}.tmp"
        mv "${input_file}.tmp" "$input_file"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# RESOLVER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Update DNS resolvers
resolvers_update() {
    log_info "Updating DNS resolvers..."
    
    ensure_dir "${TOOLS_PATH}"
    
    # Download fresh resolvers
    if [[ -n "${RESOLVERS_URL:-}" ]]; then
        curl -sL "$RESOLVERS_URL" -o "${RESOLVERS:-${TOOLS_PATH}/resolvers.txt}" 2>/dev/null || true
    fi
    
    if [[ -n "${RESOLVERS_TRUSTED_URL:-}" ]]; then
        curl -sL "$RESOLVERS_TRUSTED_URL" -o "${RESOLVERS_TRUSTED:-${TOOLS_PATH}/resolvers_trusted.txt}" 2>/dev/null || true
    fi
    
    # Validate resolvers exist
    if [[ ! -f "${RESOLVERS:-${TOOLS_PATH}/resolvers.txt}" ]]; then
        # Create default resolvers
        cat > "${RESOLVERS:-${TOOLS_PATH}/resolvers.txt}" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
    fi
    
    if [[ ! -f "${RESOLVERS_TRUSTED:-${TOOLS_PATH}/resolvers_trusted.txt}" ]]; then
        cat > "${RESOLVERS_TRUSTED:-${TOOLS_PATH}/resolvers_trusted.txt}" << 'EOF'
8.8.8.8
1.1.1.1
9.9.9.9
EOF
    fi
    
    log_success "Resolvers updated"
}

# Quick local resolver update
resolvers_update_quick_local() {
    if [[ ! -f "${RESOLVERS}" ]] || [[ ! -f "${RESOLVERS_TRUSTED}" ]]; then
        resolvers_update
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# URL AND DOMAIN PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

# Extract unique domains from URLs
extract_domains_from_urls() {
    local input_file="$1"
    local output_file="$2"
    
    if command_exists unfurl; then
        cat "$input_file" | unfurl -u domains | sort -u > "$output_file"
    else
        # Fallback using sed
        sed -E 's|https?://||; s|/.*||; s|:.*||' "$input_file" | sort -u > "$output_file"
    fi
}

# Filter URLs by domain
filter_urls_by_domain() {
    local input_file="$1"
    local domain="$2"
    local output_file="$3"
    
    grep -E "https?://[^/]*${domain}" "$input_file" > "$output_file" 2>/dev/null || true
}

# Validate and clean URLs
clean_urls() {
    local input_file="$1"
    local output_file="$2"
    
    # Remove duplicates, empty lines, and invalid URLs
    grep -E '^https?://' "$input_file" 2>/dev/null | \
        sed 's/[[:space:]]*$//' | \
        sort -u > "$output_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

# Check if host is reachable
is_host_reachable() {
    local host="$1"
    local timeout="${2:-5}"
    
    timeout "$timeout" bash -c "echo >/dev/tcp/${host}/443" 2>/dev/null || \
    timeout "$timeout" bash -c "echo >/dev/tcp/${host}/80" 2>/dev/null
}

# Get IP from hostname
resolve_host() {
    local host="$1"
    
    if command_exists dig; then
        dig +short "$host" | head -1
    elif command_exists host; then
        host "$host" | grep "has address" | head -1 | awk '{print $NF}'
    elif command_exists nslookup; then
        nslookup "$host" | grep "Address:" | tail -1 | awk '{print $2}'
    fi
}

# Check if IP is in CDN range
is_cdn_ip() {
    local ip="$1"
    
    if command_exists cdncheck; then
        echo "$ip" | cdncheck -silent | grep -q "cdn" && return 0
    fi
    
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

# Make HTTP request with timeout and retry
http_get() {
    local url="$1"
    local timeout="${2:-30}"
    local retries="${3:-3}"
    
    local curl_opts="-sL -m $timeout --retry $retries -A '${USER_AGENT:-Mozilla/5.0}'"
    
    if [[ -n "${PROXY_URL:-}" ]]; then
        curl_opts+=" -x $PROXY_URL"
    fi
    
    eval "curl $curl_opts '$url'" 2>/dev/null
}

# Check HTTP status code
get_http_status() {
    local url="$1"
    local timeout="${2:-10}"
    
    curl -sL -o /dev/null -w "%{http_code}" -m "$timeout" "$url" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

# Merge JSON files
merge_json_files() {
    local output_file="$1"
    shift
    local input_files=("$@")
    
    if command_exists jq; then
        jq -s 'add' "${input_files[@]}" > "$output_file" 2>/dev/null
    fi
}

# Extract field from JSON
extract_json_field() {
    local json_file="$1"
    local field="$2"
    
    if command_exists jq; then
        jq -r ".$field // empty" "$json_file" 2>/dev/null
    fi
}

# Parse NMAP XML output
parse_nmap_xml() {
    local xml_file="$1"
    local output_dir="$2"
    
    if [[ -f "${TOOLS_PATH}/ultimate-nmap-parser/ultimate-nmap-parser.sh" ]]; then
        bash "${TOOLS_PATH}/ultimate-nmap-parser/ultimate-nmap-parser.sh" "$xml_file" -o "$output_dir"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# PATTERN MATCHING (GF Patterns)
# ═══════════════════════════════════════════════════════════════════════════════

# Apply GF pattern to URLs
apply_gf_pattern() {
    local pattern="$1"
    local input_file="$2"
    local output_file="$3"
    
    if command_exists gf; then
        cat "$input_file" | gf "$pattern" > "$output_file" 2>/dev/null || true
    fi
}

# Extract potential vulnerable parameters
extract_vuln_params() {
    local input_file="$1"
    local output_dir="$2"
    
    ensure_dir "$output_dir"
    
    if command_exists gf; then
        # XSS patterns
        cat "$input_file" | gf xss > "${output_dir}/xss_params.txt" 2>/dev/null || true
        
        # SQLi patterns
        cat "$input_file" | gf sqli > "${output_dir}/sqli_params.txt" 2>/dev/null || true
        
        # LFI patterns
        cat "$input_file" | gf lfi > "${output_dir}/lfi_params.txt" 2>/dev/null || true
        
        # SSRF patterns
        cat "$input_file" | gf ssrf > "${output_dir}/ssrf_params.txt" 2>/dev/null || true
        
        # Redirect patterns
        cat "$input_file" | gf redirect > "${output_dir}/redirect_params.txt" 2>/dev/null || true
        
        # IDOR patterns
        cat "$input_file" | gf idor > "${output_dir}/idor_params.txt" 2>/dev/null || true
        
        # SSTI patterns
        cat "$input_file" | gf ssti > "${output_dir}/ssti_params.txt" 2>/dev/null || true
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# STATISTICS AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

# Get scan statistics
get_scan_stats() {
    local scan_dir="$1"
    
    local stats=""
    
    # Count subdomains
    if [[ -f "${scan_dir}/subdomains/subdomains.txt" ]]; then
        local sub_count=$(wc -l < "${scan_dir}/subdomains/subdomains.txt" | tr -d ' ')
        stats+="Subdomains: $sub_count\n"
    fi
    
    # Count live hosts
    if [[ -f "${scan_dir}/webs/webs.txt" ]]; then
        local web_count=$(wc -l < "${scan_dir}/webs/webs.txt" | tr -d ' ')
        stats+="Live Hosts: $web_count\n"
    fi
    
    # Count URLs
    if [[ -f "${scan_dir}/urls/urls.txt" ]]; then
        local url_count=$(wc -l < "${scan_dir}/urls/urls.txt" | tr -d ' ')
        stats+="URLs: $url_count\n"
    fi
    
    # Count vulnerabilities
    if [[ -d "${scan_dir}/vulnerabilities" ]]; then
        local vuln_count=$(find "${scan_dir}/vulnerabilities" -name "*.txt" -exec cat {} \; 2>/dev/null | wc -l | tr -d ' ')
        stats+="Potential Vulnerabilities: $vuln_count\n"
    fi
    
    printf "%b" "$stats"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════

# Run tool with timeout and logging
run_tool() {
    local tool_name="$1"
    local timeout_secs="${2:-3600}"
    shift 2
    local cmd=("$@")
    
    log_debug "Running: ${cmd[*]}"
    
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] TOOL: $tool_name - ${cmd[*]}" >> "$LOGFILE"
    
    if timeout "$timeout_secs" "${cmd[@]}" 2>> "$LOGFILE"; then
        log_debug "$tool_name completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_warning "$tool_name timed out after ${timeout_secs}s"
        else
            log_warning "$tool_name exited with code $exit_code"
        fi
        return $exit_code
    fi
}

# Run Python tool with venv
run_python_tool() {
    local tool_path="$1"
    local venv_path="${tool_path}/venv/bin/python3"
    local script="${tool_path}/$(basename "$tool_path").py"
    shift
    
    if [[ -f "$venv_path" ]]; then
        "$venv_path" "$script" "$@"
    elif command_exists python3; then
        python3 "$script" "$@"
    else
        log_error "Python not found for $tool_path"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

# Clean temporary files
clean_temp_files() {
    local scan_dir="$1"
    
    if [[ "${CLEANUP_TEMP:-false}" == "true" ]]; then
        rm -rf "${scan_dir}/.tmp" 2>/dev/null || true
        log_info "Temporary files cleaned"
    fi
}

# Clean log files
clean_log_files() {
    local scan_dir="$1"
    
    if [[ "${CLEANUP_LOGS:-false}" == "true" ]]; then
        rm -rf "${scan_dir}/logs" 2>/dev/null || true
        log_info "Log files cleaned"
    fi
}

# Compress output
compress_output() {
    local scan_dir="$1"
    
    if [[ "${COMPRESS_OUTPUT:-false}" == "true" ]]; then
        local archive_name="${scan_dir}.tar.gz"
        tar -czf "$archive_name" -C "$(dirname "$scan_dir")" "$(basename "$scan_dir")"
        log_success "Output compressed to: $archive_name"
    fi
}
