#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: PORT SCANNING & SERVICE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Discover open ports and identify services
# Tools: masscan, nmap, naabu, smap (passive)
# ═══════════════════════════════════════════════════════════════════════════════

portscan_main() {
    log_phase "PHASE 4: PORT SCANNING & SERVICE DETECTION"
    
    if ! should_run_module "portscan_main" "PORTSCAN_ENABLED"; then
        return 0
    fi
    
    start_func "portscan_main" "Starting Port Scanning"
    
    ensure_dir "${dir}/ports"
    ensure_dir "${dir}/.tmp/ports"
    
    # Determine IPs to scan
    portscan_prepare_targets
    
    # Run port scanning functions
    portscan_passive
    portscan_masscan
    portscan_nmap
    portscan_aggregate
    
    end_func "Port scanning completed. Results in ${dir}/ports/" "portscan_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREPARE TARGETS FOR SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

portscan_prepare_targets() {
    log_info "Preparing targets for port scanning..."
    
    # Use non-CDN IPs if available
    if [[ -s "${dir}/webs/non_cdn_hosts.txt" ]]; then
        cp "${dir}/webs/non_cdn_hosts.txt" "${dir}/.tmp/ports/scan_targets.txt"
        log_info "Using non-CDN IPs for scanning"
    elif [[ -s "${dir}/hosts/ips.txt" ]]; then
        cp "${dir}/hosts/ips.txt" "${dir}/.tmp/ports/scan_targets.txt"
        log_info "Using all discovered IPs for scanning"
    elif is_ip "$domain" || is_cidr "$domain"; then
        echo "$domain" > "${dir}/.tmp/ports/scan_targets.txt"
        log_info "Using target IP/CIDR directly"
    else
        # Resolve subdomains to IPs
        if [[ -s "${dir}/subdomains/subdomains.txt" ]] && command_exists dnsx; then
            dnsx -l "${dir}/subdomains/subdomains.txt" \
                -a -resp-only -silent \
                -r "${RESOLVERS_TRUSTED}" \
                -o "${dir}/.tmp/ports/scan_targets.txt" 2>> "$LOGFILE" || true
        fi
    fi
    
    # Filter private/internal IPs
    if [[ -s "${dir}/.tmp/ports/scan_targets.txt" ]]; then
        grep -vE "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)" \
            "${dir}/.tmp/ports/scan_targets.txt" | \
            sort -u > "${dir}/.tmp/ports/scan_targets_filtered.txt"
        mv "${dir}/.tmp/ports/scan_targets_filtered.txt" "${dir}/.tmp/ports/scan_targets.txt"
    fi
    
    local target_count=$(count_lines "${dir}/.tmp/ports/scan_targets.txt")
    log_info "Prepared $target_count targets for scanning"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE PORT SCANNING (SHODAN)
# ═══════════════════════════════════════════════════════════════════════════════

portscan_passive() {
    if ! should_run_module "portscan_passive" "SCAN_PASSIVE"; then
        return 0
    fi
    
    start_subfunc "portscan_passive" "Running passive port scanning"
    
    if [[ ! -s "${dir}/.tmp/ports/scan_targets.txt" ]]; then
        log_warning "No targets for passive scanning"
        return 0
    fi
    
    # smap - Shodan-based passive scanning
    if command_exists smap; then
        log_info "Running smap (Shodan passive scan)..."
        smap -iL "${dir}/.tmp/ports/scan_targets.txt" \
            -oG "${dir}/ports/smap_results.gnmap" \
            2>> "$LOGFILE" || true
        
        # Parse smap results
        if [[ -s "${dir}/ports/smap_results.gnmap" ]]; then
            grep "Ports:" "${dir}/ports/smap_results.gnmap" | \
                sed 's/Ports:/\n/g' | \
                grep -oE '[0-9]+/open' | \
                cut -d/ -f1 | \
                sort -nu > "${dir}/ports/passive_ports.txt"
        fi
    fi
    
    # Shodan CLI (if API key available)
    if [[ -n "${SHODAN_API_KEY:-}" ]] && command_exists shodan; then
        log_info "Running Shodan queries..."
        
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            shodan host "$ip" >> "${dir}/ports/shodan_results.txt" 2>/dev/null || true
            sleep 1  # Rate limiting
        done < <(head -n 20 "${dir}/.tmp/ports/scan_targets.txt")  # Limit to first 20 IPs
    fi
    
    local passive_ports=$(count_lines "${dir}/ports/passive_ports.txt")
    end_subfunc "Passive scan found $passive_ports unique ports" "portscan_passive"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MASSCAN - FAST PORT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

portscan_masscan() {
    if ! should_run_module "portscan_masscan" "SCAN_MASSCAN"; then
        return 0
    fi
    
    start_subfunc "portscan_masscan" "Running masscan fast port discovery"
    
    if ! command_exists masscan; then
        log_warning "masscan not installed, trying naabu..."
        portscan_naabu
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/ports/scan_targets.txt" ]]; then
        log_warning "No targets for masscan"
        return 0
    fi
    
    local target_count=$(count_lines "${dir}/.tmp/ports/scan_targets.txt")
    log_info "Running masscan on $target_count targets..."
    
    # Determine ports to scan
    local ports
    if [[ "${SCAN_COMMON_ONLY:-false}" == "true" ]]; then
        ports="${MASSCAN_COMMON_PORTS:-21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443}"
    elif [[ "${DEEP:-false}" == "true" ]]; then
        ports="${MASSCAN_PORTS:-0-65535}"
    else
        ports="1-10000"
    fi
    
    # Run masscan
    # Note: masscan typically requires root privileges
    if [[ $EUID -eq 0 ]]; then
        masscan -iL "${dir}/.tmp/ports/scan_targets.txt" \
            -p "$ports" \
            --rate "${MASSCAN_RATE:-1000}" \
            -oG "${dir}/ports/masscan_results.gnmap" \
            -oJ "${dir}/ports/masscan_results.json" \
            2>> "$LOGFILE" || true
    else
        log_warning "masscan requires root privileges, attempting with current user..."
        masscan -iL "${dir}/.tmp/ports/scan_targets.txt" \
            -p "$ports" \
            --rate "${MASSCAN_RATE:-1000}" \
            -oG "${dir}/ports/masscan_results.gnmap" \
            -oJ "${dir}/ports/masscan_results.json" \
            2>> "$LOGFILE" || true
    fi
    
    # Parse masscan results
    if [[ -s "${dir}/ports/masscan_results.gnmap" ]]; then
        # Extract IP:Port combinations
        grep "Ports:" "${dir}/ports/masscan_results.gnmap" | \
            awk '{print $2 ":" $4}' | \
            sed 's|/open.*||' | \
            sort -u > "${dir}/ports/masscan_open_ports.txt"
        
        # Extract unique ports
        cut -d: -f2 "${dir}/ports/masscan_open_ports.txt" | \
            sort -nu > "${dir}/ports/masscan_unique_ports.txt"
        
        # Extract IPs with open ports
        cut -d: -f1 "${dir}/ports/masscan_open_ports.txt" | \
            sort -u > "${dir}/ports/masscan_live_hosts.txt"
    fi
    
    local open_ports=$(count_lines "${dir}/ports/masscan_open_ports.txt")
    end_subfunc "Masscan found $open_ports open port/host combinations" "portscan_masscan"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NAABU - ALTERNATIVE FAST PORT SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

portscan_naabu() {
    start_subfunc "portscan_naabu" "Running naabu port discovery"
    
    if ! command_exists naabu; then
        log_warning "naabu not installed, skipping"
        return 0
    fi
    
    if [[ ! -s "${dir}/.tmp/ports/scan_targets.txt" ]]; then
        log_warning "No targets for naabu"
        return 0
    fi
    
    local target_count=$(count_lines "${dir}/.tmp/ports/scan_targets.txt")
    log_info "Running naabu on $target_count targets..."
    
    # Determine ports
    local port_flag=""
    if [[ "${SCAN_COMMON_ONLY:-false}" == "true" ]]; then
        port_flag="-top-ports 100"
    elif [[ "${DEEP:-false}" == "true" ]]; then
        port_flag="-p - "  # All ports
    else
        port_flag="-top-ports 1000"
    fi
    
    naabu -l "${dir}/.tmp/ports/scan_targets.txt" \
        $port_flag \
        -rate "${NAABU_RATE:-1000}" \
        -silent \
        -o "${dir}/ports/naabu_results.txt" \
        -json \
        -output-json "${dir}/ports/naabu_results.json" \
        2>> "$LOGFILE" || true
    
    # Parse results
    if [[ -s "${dir}/ports/naabu_results.txt" ]]; then
        cat "${dir}/ports/naabu_results.txt" | sort -u > "${dir}/ports/naabu_open_ports.txt"
    fi
    
    local open_ports=$(count_lines "${dir}/ports/naabu_open_ports.txt")
    end_subfunc "Naabu found $open_ports open port/host combinations" "portscan_naabu"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NMAP - DEEP SERVICE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

portscan_nmap() {
    if ! should_run_module "portscan_nmap" "SCAN_NMAP"; then
        return 0
    fi
    
    start_subfunc "portscan_nmap" "Running nmap service detection"
    
    if ! command_exists nmap; then
        log_warning "nmap not installed, skipping service detection"
        return 0
    fi
    
    # Determine targets and ports for nmap
    local nmap_targets="${dir}/.tmp/ports/nmap_targets.txt"
    local nmap_ports=""
    
    # Use masscan/naabu results if available
    if [[ -s "${dir}/ports/masscan_live_hosts.txt" ]]; then
        cp "${dir}/ports/masscan_live_hosts.txt" "$nmap_targets"
        # Use discovered ports
        nmap_ports=$(cat "${dir}/ports/masscan_unique_ports.txt" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    elif [[ -s "${dir}/ports/naabu_open_ports.txt" ]]; then
        cut -d: -f1 "${dir}/ports/naabu_open_ports.txt" | sort -u > "$nmap_targets"
        nmap_ports=$(cut -d: -f2 "${dir}/ports/naabu_open_ports.txt" | sort -nu | tr '\n' ',' | sed 's/,$//')
    else
        # Use original targets with top ports
        cp "${dir}/.tmp/ports/scan_targets.txt" "$nmap_targets" 2>/dev/null || true
        nmap_ports=""
    fi
    
    if [[ ! -s "$nmap_targets" ]]; then
        log_warning "No targets for nmap"
        return 0
    fi
    
    local target_count=$(count_lines "$nmap_targets")
    
    # Limit targets for nmap (it's slower)
    local max_targets=50
    if [[ "${DEEP:-false}" == "true" ]]; then
        max_targets=200
    fi
    
    if [[ $target_count -gt $max_targets ]]; then
        log_warning "Limiting nmap to first $max_targets targets"
        head -n $max_targets "$nmap_targets" > "${nmap_targets}.limited"
        mv "${nmap_targets}.limited" "$nmap_targets"
    fi
    
    log_info "Running nmap on $(count_lines "$nmap_targets") targets..."
    
    # Build nmap command
    local nmap_cmd="nmap ${NMAP_DEFAULT_FLAGS:--sV -sC -Pn --open}"
    
    # Add ports if discovered
    if [[ -n "$nmap_ports" ]]; then
        nmap_cmd+=" -p $nmap_ports"
    elif [[ "${DEEP:-false}" == "true" ]]; then
        nmap_cmd+=" -p ${NMAP_FULL_PORTS:-1-65535}"
    else
        nmap_cmd+=" --top-ports ${NMAP_TOP_PORTS:-1000}"
    fi
    
    # Add scripts
    nmap_cmd+=" --script ${NMAP_SCRIPTS:-vulners,http-enum}"
    
    # Add timeout
    nmap_cmd+=" --max-retries 2 --host-timeout ${NMAP_TIMEOUT:-3600}s"
    
    # Output files
    nmap_cmd+=" -oA ${dir}/ports/nmap_results"
    
    # Target file
    nmap_cmd+=" -iL $nmap_targets"
    
    # Run nmap
    log_debug "Nmap command: $nmap_cmd"
    eval "$nmap_cmd" 2>> "$LOGFILE" || true
    
    # Parse nmap results
    if [[ -s "${dir}/ports/nmap_results.xml" ]]; then
        portscan_parse_nmap
    fi
    
    end_subfunc "Nmap service detection completed" "portscan_nmap"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARSE NMAP RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

portscan_parse_nmap() {
    log_info "Parsing nmap results..."
    
    # Use nmap-parse-output if available
    if [[ -f "${TOOLS_PATH}/ultimate-nmap-parser/ultimate-nmap-parser.sh" ]]; then
        bash "${TOOLS_PATH}/ultimate-nmap-parser/ultimate-nmap-parser.sh" \
            "${dir}/ports/nmap_results.xml" \
            -o "${dir}/ports/parsed" 2>> "$LOGFILE" || true
    fi
    
    # Extract services for further testing
    if [[ -s "${dir}/ports/nmap_results.gnmap" ]]; then
        # Web services
        grep -E "80/open|443/open|8080/open|8443/open|8000/open" "${dir}/ports/nmap_results.gnmap" | \
            awk '{print $2}' | sort -u > "${dir}/ports/web_servers.txt" || true
        
        # SSH services
        grep "22/open" "${dir}/ports/nmap_results.gnmap" | \
            awk '{print $2}' | sort -u > "${dir}/ports/ssh_servers.txt" || true
        
        # Database services
        grep -E "3306/open|5432/open|1433/open|27017/open|6379/open" "${dir}/ports/nmap_results.gnmap" | \
            awk '{print $2}' | sort -u > "${dir}/ports/database_servers.txt" || true
        
        # FTP services
        grep "21/open" "${dir}/ports/nmap_results.gnmap" | \
            awk '{print $2}' | sort -u > "${dir}/ports/ftp_servers.txt" || true
        
        # SMB services
        grep -E "445/open|139/open" "${dir}/ports/nmap_results.gnmap" | \
            awk '{print $2}' | sort -u > "${dir}/ports/smb_servers.txt" || true
    fi
    
    # nmapurls - extract URLs from nmap results
    if command_exists nmapurls && [[ -s "${dir}/ports/nmap_results.xml" ]]; then
        nmapurls -f "${dir}/ports/nmap_results.xml" \
            > "${dir}/ports/nmap_urls.txt" 2>> "$LOGFILE" || true
        
        # Add discovered URLs to webs
        if [[ -s "${dir}/ports/nmap_urls.txt" ]]; then
            cat "${dir}/ports/nmap_urls.txt" >> "${dir}/webs/webs.txt"
            sort -u "${dir}/webs/webs.txt" -o "${dir}/webs/webs.txt"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE PORT SCANNING RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

portscan_aggregate() {
    log_info "Aggregating port scanning results..."
    
    local summary="${dir}/ports/portscan_summary.txt"
    
    # Combine all open ports
    cat "${dir}/ports/"*_open_ports.txt "${dir}/ports/"*_unique_ports.txt 2>/dev/null | \
        sort -nu > "${dir}/ports/all_open_ports.txt" || true
    
    cat > "$summary" << EOF
Port Scanning Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Targets Scanned: $(count_lines "${dir}/.tmp/ports/scan_targets.txt")

Unique Open Ports: $(count_lines "${dir}/ports/all_open_ports.txt")

Port Distribution:
$(sort -nu "${dir}/ports/all_open_ports.txt" 2>/dev/null | head -20 | tr '\n' ', ' || echo "N/A")

Service Categories:
- Web Servers: $(count_lines "${dir}/ports/web_servers.txt")
- SSH Servers: $(count_lines "${dir}/ports/ssh_servers.txt")
- Database Servers: $(count_lines "${dir}/ports/database_servers.txt")
- FTP Servers: $(count_lines "${dir}/ports/ftp_servers.txt")
- SMB Servers: $(count_lines "${dir}/ports/smb_servers.txt")

Passive Scan (Shodan):
$(head -5 "${dir}/ports/shodan_results.txt" 2>/dev/null || echo "N/A")

Detailed results available in ${dir}/ports/
EOF
    
    log_success "Port scanning aggregation completed"
}
