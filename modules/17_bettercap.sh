#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 17: BETTERCAP NETWORK SECURITY TESTING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Comprehensive network security testing using Bettercap including:
#   - Network reconnaissance and host discovery
#   - ARP/DNS spoofing detection
#   - WiFi security assessment (if applicable)
#   - SSL/TLS analysis and MITM capability testing
#   - HTTP/HTTPS proxy analysis
#   - Credential sniffing detection
#   - Network traffic analysis
#   - BLE (Bluetooth Low Energy) device scanning
#   - HID attack detection
# 
# Note: Some features require root/sudo access
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# BETTERCAP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Default settings (can be overridden in neko.cfg)
BETTERCAP_ENABLED="${BETTERCAP_ENABLED:-true}"
BETTERCAP_INTERFACE="${BETTERCAP_INTERFACE:-eth0}"
BETTERCAP_API_PORT="${BETTERCAP_API_PORT:-8083}"
BETTERCAP_API_USER="${BETTERCAP_API_USER:-neko}"
BETTERCAP_API_PASS="${BETTERCAP_API_PASS:-$(openssl rand -hex 16 2>/dev/null || echo 'neko_default_pass')}"
BETTERCAP_CAPLETS_PATH="${BETTERCAP_CAPLETS_PATH:-/usr/share/bettercap/caplets}"
BETTERCAP_TIMEOUT="${BETTERCAP_TIMEOUT:-300}"
BETTERCAP_PASSIVE_ONLY="${BETTERCAP_PASSIVE_ONLY:-true}"  # Safety: only passive by default

# Feature toggles
BETTERCAP_NET_RECON="${BETTERCAP_NET_RECON:-true}"
BETTERCAP_SSL_STRIP="${BETTERCAP_SSL_STRIP:-false}"  # Intrusive, disabled by default
BETTERCAP_DNS_SPOOF="${BETTERCAP_DNS_SPOOF:-false}"  # Intrusive, disabled by default
BETTERCAP_ARP_SPOOF="${BETTERCAP_ARP_SPOOF:-false}"  # Intrusive, disabled by default
BETTERCAP_HTTP_PROXY="${BETTERCAP_HTTP_PROXY:-true}"
BETTERCAP_HTTPS_PROXY="${BETTERCAP_HTTPS_PROXY:-false}"
BETTERCAP_WIFI_SCAN="${BETTERCAP_WIFI_SCAN:-false}"  # Requires monitor mode
BETTERCAP_BLE_SCAN="${BETTERCAP_BLE_SCAN:-false}"
BETTERCAP_PACKET_CAPTURE="${BETTERCAP_PACKET_CAPTURE:-true}"
BETTERCAP_CREDENTIALS="${BETTERCAP_CREDENTIALS:-true}"

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_main() {
    log_phase "PHASE 17: BETTERCAP NETWORK SECURITY TESTING"
    
    if ! should_run_module "bettercap_main" "BETTERCAP_ENABLED"; then
        return 0
    fi
    
    start_func "bettercap_main" "Starting Bettercap Network Security Testing"
    
    # Check prerequisites
    if ! bettercap_check_prerequisites; then
        log_error "Bettercap prerequisites not met, skipping"
        return 1
    fi
    
    # Create output directories
    ensure_dir "${dir}/bettercap"
    ensure_dir "${dir}/bettercap/captures"
    ensure_dir "${dir}/bettercap/credentials"
    ensure_dir "${dir}/bettercap/hosts"
    ensure_dir "${dir}/bettercap/ssl"
    ensure_dir "${dir}/bettercap/reports"
    ensure_dir "${dir}/.tmp/bettercap"
    
    # Get target information from other modules
    bettercap_prepare_targets
    
    # Run bettercap modules
    bettercap_network_recon
    bettercap_host_discovery
    bettercap_service_discovery
    bettercap_ssl_analysis
    bettercap_http_analysis
    bettercap_credential_detection
    
    # Only run intrusive tests if explicitly enabled
    if [[ "${BETTERCAP_PASSIVE_ONLY}" != "true" ]]; then
        [[ "${BETTERCAP_ARP_SPOOF}" == "true" ]] && bettercap_arp_analysis
        [[ "${BETTERCAP_DNS_SPOOF}" == "true" ]] && bettercap_dns_analysis
        [[ "${BETTERCAP_SSL_STRIP}" == "true" ]] && bettercap_sslstrip_test
    fi
    
    # Optional modules
    [[ "${BETTERCAP_WIFI_SCAN}" == "true" ]] && bettercap_wifi_scan
    [[ "${BETTERCAP_BLE_SCAN}" == "true" ]] && bettercap_ble_scan
    [[ "${BETTERCAP_PACKET_CAPTURE}" == "true" ]] && bettercap_packet_analysis
    
    # Aggregate results
    bettercap_aggregate_results
    
    # Store findings in intelligence database
    bettercap_store_intel
    
    end_func "Bettercap network security testing completed" "bettercap_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREREQUISITES CHECK
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_check_prerequisites() {
    log_info "Checking Bettercap prerequisites..."
    
    # Check if bettercap is installed
    if ! command_exists bettercap; then
        log_error "Bettercap is not installed"
        log_info "Install with: apt install bettercap (Debian/Ubuntu)"
        log_info "Or: go install github.com/bettercap/bettercap@latest"
        return 1
    fi
    
    # Get bettercap version
    local version=$(bettercap -version 2>/dev/null | head -1 || echo "unknown")
    log_info "Bettercap version: $version"
    
    # Check for root/sudo (needed for many features)
    if [[ $EUID -ne 0 ]]; then
        log_warning "Not running as root. Some Bettercap features may be limited."
        log_warning "Consider running with sudo for full functionality."
    fi
    
    # Check network interface
    if ! ip link show "$BETTERCAP_INTERFACE" &>/dev/null; then
        log_warning "Interface $BETTERCAP_INTERFACE not found, trying to detect..."
        
        # Try to auto-detect interface
        BETTERCAP_INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}' || echo "eth0")
        
        if ! ip link show "$BETTERCAP_INTERFACE" &>/dev/null; then
            log_error "Could not detect network interface"
            return 1
        fi
        
        log_info "Auto-detected interface: $BETTERCAP_INTERFACE"
    fi
    
    # Check for libpcap
    if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
        log_warning "libpcap not found. Packet capture may not work."
    fi
    
    # Update caplets if available
    if command_exists bettercap; then
        log_info "Updating Bettercap caplets..."
        timeout 60 bettercap -eval "caplets.update; quit" 2>/dev/null || true
    fi
    
    log_success "Bettercap prerequisites check passed"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# TARGET PREPARATION
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_prepare_targets() {
    log_info "Preparing targets for Bettercap from other modules..."
    
    local targets_file="${dir}/.tmp/bettercap/targets.txt"
    
    # Collect IPs from resolved subdomains
    if [[ -s "${dir}/subdomains/resolved.txt" ]]; then
        # Extract IPs from resolved domains
        if command_exists dnsx; then
            dnsx -l "${dir}/subdomains/resolved.txt" -a -resp-only -silent \
                >> "$targets_file" 2>/dev/null || true
        fi
    fi
    
    # Collect from port scanning results
    if [[ -s "${dir}/ports/ips_live.txt" ]]; then
        cat "${dir}/ports/ips_live.txt" >> "$targets_file" 2>/dev/null || true
    fi
    
    # Collect from web hosts
    if [[ -s "${dir}/webs/webs.txt" ]]; then
        sed -E 's|https?://([^:/]+).*|\1|' "${dir}/webs/webs.txt" | \
            while read host; do
                # Resolve hostname to IP
                dig +short "$host" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true
            done >> "$targets_file" 2>/dev/null || true
    fi
    
    # Add primary target if it's an IP or resolve it
    if is_ip "$domain"; then
        echo "$domain" >> "$targets_file"
    else
        dig +short "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' >> "$targets_file" || true
    fi
    
    # Deduplicate and validate IPs
    if [[ -s "$targets_file" ]]; then
        sort -u "$targets_file" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > "${targets_file}.clean"
        mv "${targets_file}.clean" "$targets_file"
    fi
    
    local target_count=$(count_lines "$targets_file")
    log_info "Prepared $target_count IP targets for Bettercap"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_network_recon() {
    if [[ "${BETTERCAP_NET_RECON}" != "true" ]]; then
        return 0
    fi
    
    start_subfunc "bettercap_net_recon" "Running Bettercap Network Reconnaissance"
    
    local output_dir="${dir}/bettercap/hosts"
    local caplet_file="${dir}/.tmp/bettercap/net_recon.cap"
    
    # Create custom caplet for network recon
    cat > "$caplet_file" << 'EOF'
# Neko Bettercap Network Reconnaissance Caplet

# Set events stream
set events.stream.output /tmp/bettercap_events.json

# Enable network discovery
net.probe on

# Wait for discovery
sleep 30

# Get all discovered hosts
net.show

# Save session
session.save /tmp/bettercap_session.json

quit
EOF
    
    # Run bettercap with caplet
    local session_output="${output_dir}/session.json"
    local events_output="${output_dir}/events.json"
    
    if [[ $EUID -eq 0 ]]; then
        timeout "$BETTERCAP_TIMEOUT" bettercap -iface "$BETTERCAP_INTERFACE" \
            -caplet "$caplet_file" \
            -silent \
            2>> "$LOGFILE" || true
        
        # Move output files
        [[ -f "/tmp/bettercap_session.json" ]] && mv "/tmp/bettercap_session.json" "$session_output"
        [[ -f "/tmp/bettercap_events.json" ]] && mv "/tmp/bettercap_events.json" "$events_output"
    else
        # Run with sudo if available
        if command_exists sudo; then
            timeout "$BETTERCAP_TIMEOUT" sudo bettercap -iface "$BETTERCAP_INTERFACE" \
                -caplet "$caplet_file" \
                -silent \
                2>> "$LOGFILE" || true
            
            [[ -f "/tmp/bettercap_session.json" ]] && sudo mv "/tmp/bettercap_session.json" "$session_output"
            [[ -f "/tmp/bettercap_events.json" ]] && sudo mv "/tmp/bettercap_events.json" "$events_output"
        else
            log_warning "Need root privileges for network recon"
        fi
    fi
    
    # Parse discovered hosts
    if [[ -s "$session_output" ]]; then
        jq -r '.lan.hosts[] | "\(.ipv4) \(.mac) \(.hostname // "unknown") \(.vendor // "unknown")"' \
            "$session_output" 2>/dev/null > "${output_dir}/discovered_hosts.txt" || true
        
        local host_count=$(count_lines "${output_dir}/discovered_hosts.txt")
        log_success "Discovered $host_count hosts on the network"
    fi
    
    end_subfunc "Network reconnaissance completed" "bettercap_net_recon"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HOST DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_host_discovery() {
    start_subfunc "bettercap_host_discovery" "Running Host Discovery"
    
    local output_dir="${dir}/bettercap/hosts"
    local targets_file="${dir}/.tmp/bettercap/targets.txt"
    
    # Create discovery caplet
    local caplet_file="${dir}/.tmp/bettercap/host_discovery.cap"
    
    cat > "$caplet_file" << EOF
# Host Discovery Caplet
set net.probe.throttle 10
net.probe on
sleep 20
net.show
quit
EOF
    
    # Run targeted discovery on our targets
    if [[ -s "$targets_file" ]]; then
        local host_details="${output_dir}/host_details.json"
        
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            
            # Get host details using various methods
            local host_info="{\"ip\":\"$ip\","
            
            # MAC address (if on same network)
            local mac=$(arp -n "$ip" 2>/dev/null | awk '/ether/ {print $3}' || echo "unknown")
            host_info+="\"mac\":\"$mac\","
            
            # Hostname
            local hostname=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' || echo "unknown")
            host_info+="\"hostname\":\"$hostname\","
            
            # TTL (for OS fingerprinting)
            local ttl=$(ping -c 1 -W 2 "$ip" 2>/dev/null | grep -oE 'ttl=[0-9]+' | cut -d= -f2 || echo "0")
            host_info+="\"ttl\":$ttl,"
            
            # Estimate OS from TTL
            local os_guess="unknown"
            if [[ $ttl -ge 128 ]] && [[ $ttl -le 255 ]]; then
                os_guess="Windows"
            elif [[ $ttl -ge 64 ]] && [[ $ttl -lt 128 ]]; then
                os_guess="Linux/Unix"
            elif [[ $ttl -lt 64 ]] && [[ $ttl -gt 0 ]]; then
                os_guess="Network Device"
            fi
            host_info+="\"os_guess\":\"$os_guess\"}"
            
            echo "$host_info" >> "$host_details"
            
        done < "$targets_file"
        
        # Convert to valid JSON array
        if [[ -s "$host_details" ]]; then
            jq -s '.' "$host_details" > "${host_details}.tmp" && mv "${host_details}.tmp" "$host_details"
        fi
    fi
    
    end_subfunc "Host discovery completed" "bettercap_host_discovery"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_service_discovery() {
    start_subfunc "bettercap_service_discovery" "Running Service Discovery"
    
    local output_dir="${dir}/bettercap/hosts"
    local targets_file="${dir}/.tmp/bettercap/targets.txt"
    
    [[ ! -s "$targets_file" ]] && {
        log_warning "No targets for service discovery"
        return 0
    }
    
    local services_output="${output_dir}/services.json"
    
    # Use data from port scanning phase if available
    if [[ -d "${dir}/ports" ]]; then
        # Aggregate service information
        cat > "$services_output" << EOF
{
    "source": "port_scan_integration",
    "services": []
}
EOF
        
        # Parse nmap results if available
        for xml_file in "${dir}/ports/"*.xml; do
            [[ -f "$xml_file" ]] || continue
            
            # Extract service info using nmap XML
            if command_exists xmlstarlet; then
                xmlstarlet sel -t -m "//port[state/@state='open']" \
                    -o '{"ip":"' -v "../address[@addrtype='ipv4']/@addr" \
                    -o '","port":' -v "@portid" \
                    -o ',"protocol":"' -v "@protocol" \
                    -o '","service":"' -v "service/@name" \
                    -o '","version":"' -v "service/@version" \
                    -o '"}' -n "$xml_file" 2>/dev/null | \
                    grep -v '^$' >> "${output_dir}/services_parsed.jsonl" || true
            fi
        done
    fi
    
    end_subfunc "Service discovery completed" "bettercap_service_discovery"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL/TLS ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_ssl_analysis() {
    start_subfunc "bettercap_ssl_analysis" "Running SSL/TLS Analysis"
    
    local output_dir="${dir}/bettercap/ssl"
    local targets_file="${dir}/.tmp/bettercap/targets.txt"
    local web_targets="${dir}/webs/webs.txt"
    
    # Analyze SSL certificates and configurations
    local ssl_results="${output_dir}/ssl_analysis.json"
    local ssl_findings="${output_dir}/ssl_findings.txt"
    
    # Process HTTPS targets
    local https_targets=""
    if [[ -s "$web_targets" ]]; then
        https_targets=$(grep "^https://" "$web_targets" | head -100)
    fi
    
    if [[ -n "$https_targets" ]]; then
        echo "$https_targets" | while read url; do
            [[ -z "$url" ]] && continue
            
            local host=$(echo "$url" | sed -E 's|https://([^:/]+).*|\1|')
            local port=$(echo "$url" | grep -oE ':[0-9]+' | tr -d ':' || echo "443")
            
            log_debug "Analyzing SSL for: $host:$port"
            
            # Get SSL certificate info
            local cert_info=$(echo | timeout 10 openssl s_client -connect "${host}:${port}" \
                -servername "$host" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
            
            if [[ -n "$cert_info" ]]; then
                # Extract important fields
                local subject=$(echo "$cert_info" | grep "Subject:" | head -1 | sed 's/.*Subject: //')
                local issuer=$(echo "$cert_info" | grep "Issuer:" | head -1 | sed 's/.*Issuer: //')
                local valid_from=$(echo "$cert_info" | grep "Not Before:" | sed 's/.*Not Before: //')
                local valid_to=$(echo "$cert_info" | grep "Not After:" | sed 's/.*Not After: //')
                local sig_alg=$(echo "$cert_info" | grep "Signature Algorithm:" | head -1 | awk '{print $3}')
                
                # Check for issues
                local issues=()
                
                # Check expiration
                local exp_date=$(date -d "$valid_to" +%s 2>/dev/null || echo "0")
                local now=$(date +%s)
                local days_left=$(( (exp_date - now) / 86400 ))
                
                [[ $days_left -lt 0 ]] && issues+=("EXPIRED")
                [[ $days_left -lt 30 ]] && [[ $days_left -ge 0 ]] && issues+=("EXPIRING_SOON")
                
                # Check for weak signature algorithm
                echo "$sig_alg" | grep -qiE "sha1|md5" && issues+=("WEAK_SIGNATURE")
                
                # Check for self-signed
                [[ "$subject" == "$issuer" ]] && issues+=("SELF_SIGNED")
                
                # Write results
                cat >> "$ssl_results" << EOF
{
    "host": "$host",
    "port": $port,
    "subject": "$subject",
    "issuer": "$issuer",
    "valid_from": "$valid_from",
    "valid_to": "$valid_to",
    "days_until_expiry": $days_left,
    "signature_algorithm": "$sig_alg",
    "issues": $(printf '%s\n' "${issues[@]}" | jq -Rs 'split("\n") | map(select(length > 0))')
}
EOF
                
                # Record findings
                if [[ ${#issues[@]} -gt 0 ]]; then
                    echo "[$host:$port] SSL Issues: ${issues[*]}" >> "$ssl_findings"
                fi
            fi
            
            # Test for SSL vulnerabilities using testssl.sh if available
            if command_exists testssl.sh; then
                log_debug "Running testssl.sh on $host:$port"
                timeout 120 testssl.sh --quiet --json-pretty \
                    --outfile "${output_dir}/testssl_${host}_${port}.json" \
                    "${host}:${port}" 2>> "$LOGFILE" || true
            fi
            
        done
    fi
    
    # Use data from other scanning modules if available
    if [[ -s "${dir}/vulnerabilities/nuclei/ssl"* ]]; then
        cat "${dir}/vulnerabilities/nuclei/"*ssl* >> "$ssl_findings" 2>/dev/null || true
    fi
    
    local finding_count=$(count_lines "$ssl_findings")
    end_subfunc "SSL analysis completed. Found $finding_count potential issues" "bettercap_ssl_analysis"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_http_analysis() {
    if [[ "${BETTERCAP_HTTP_PROXY}" != "true" ]]; then
        return 0
    fi
    
    start_subfunc "bettercap_http_analysis" "Running HTTP Traffic Analysis"
    
    local output_dir="${dir}/bettercap/captures"
    local web_targets="${dir}/webs/webs.txt"
    
    [[ ! -s "$web_targets" ]] && {
        log_warning "No web targets for HTTP analysis"
        return 0
    }
    
    local http_findings="${output_dir}/http_analysis.json"
    
    # Analyze HTTP headers and cookies
    while read url; do
        [[ -z "$url" ]] && continue
        
        local host=$(echo "$url" | sed -E 's|https?://([^:/]+).*|\1|')
        
        # Get HTTP headers
        local headers=$(curl -sI -m 10 "$url" 2>/dev/null)
        
        if [[ -n "$headers" ]]; then
            local findings=()
            
            # Check security headers
            echo "$headers" | grep -qi "strict-transport-security" || findings+=("MISSING_HSTS")
            echo "$headers" | grep -qi "x-frame-options" || findings+=("MISSING_X_FRAME_OPTIONS")
            echo "$headers" | grep -qi "x-content-type-options" || findings+=("MISSING_X_CONTENT_TYPE")
            echo "$headers" | grep -qi "content-security-policy" || findings+=("MISSING_CSP")
            echo "$headers" | grep -qi "x-xss-protection" || findings+=("MISSING_XSS_PROTECTION")
            
            # Check for information disclosure
            echo "$headers" | grep -qiE "server:.*apache|nginx|iis|tomcat" && findings+=("SERVER_VERSION_DISCLOSED")
            echo "$headers" | grep -qiE "x-powered-by" && findings+=("TECHNOLOGY_DISCLOSED")
            
            # Check cookies
            local cookies=$(echo "$headers" | grep -i "set-cookie")
            if [[ -n "$cookies" ]]; then
                echo "$cookies" | grep -qvi "secure" && findings+=("COOKIE_MISSING_SECURE")
                echo "$cookies" | grep -qvi "httponly" && findings+=("COOKIE_MISSING_HTTPONLY")
                echo "$cookies" | grep -qvi "samesite" && findings+=("COOKIE_MISSING_SAMESITE")
            fi
            
            # Write findings
            if [[ ${#findings[@]} -gt 0 ]]; then
                cat >> "$http_findings" << EOF
{
    "url": "$url",
    "host": "$host",
    "findings": $(printf '%s\n' "${findings[@]}" | jq -Rs 'split("\n") | map(select(length > 0))'),
    "headers": $(echo "$headers" | jq -Rs .)
}
EOF
            fi
        fi
        
    done < <(head -100 "$web_targets")
    
    # Convert to JSON array
    if [[ -s "$http_findings" ]]; then
        jq -s '.' "$http_findings" > "${http_findings}.tmp" && mv "${http_findings}.tmp" "$http_findings"
    fi
    
    end_subfunc "HTTP analysis completed" "bettercap_http_analysis"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_credential_detection() {
    if [[ "${BETTERCAP_CREDENTIALS}" != "true" ]]; then
        return 0
    fi
    
    start_subfunc "bettercap_credential_detection" "Running Credential Detection"
    
    local output_dir="${dir}/bettercap/credentials"
    
    # Look for credentials in previously captured data
    local cred_findings="${output_dir}/potential_credentials.txt"
    
    # Check JS files for hardcoded credentials
    if [[ -d "${dir}/js" ]]; then
        log_info "Scanning JavaScript files for credentials..."
        
        grep -rhoE "(api[_-]?key|apikey|secret|password|passwd|token|auth|bearer)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]" \
            "${dir}/js/" 2>/dev/null >> "$cred_findings" || true
        
        grep -rhoE "[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@" \
            "${dir}/js/" 2>/dev/null >> "$cred_findings" || true
    fi
    
    # Check URLs for credentials
    if [[ -s "${dir}/urls/urls.txt" ]]; then
        log_info "Scanning URLs for embedded credentials..."
        
        grep -oE "https?://[^:]+:[^@]+@[^/]+" "${dir}/urls/urls.txt" 2>/dev/null >> "$cred_findings" || true
    fi
    
    # Check for default credentials on web interfaces
    if [[ -s "${dir}/webs/webs.txt" ]]; then
        log_info "Checking for default credential endpoints..."
        
        # Common admin paths
        local admin_paths=(
            "/admin"
            "/administrator"
            "/wp-admin"
            "/wp-login.php"
            "/login"
            "/signin"
            "/auth"
            "/panel"
            "/console"
            "/management"
        )
        
        while read url; do
            [[ -z "$url" ]] && continue
            
            for path in "${admin_paths[@]}"; do
                local full_url="${url}${path}"
                local status=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$full_url" 2>/dev/null)
                
                if [[ "$status" == "200" ]] || [[ "$status" == "401" ]] || [[ "$status" == "403" ]]; then
                    echo "[LOGIN_ENDPOINT] $full_url (status: $status)" >> "$cred_findings"
                fi
            done
            
        done < <(head -50 "${dir}/webs/webs.txt")
    fi
    
    # Deduplicate findings
    if [[ -s "$cred_findings" ]]; then
        sort -u "$cred_findings" -o "$cred_findings"
    fi
    
    local finding_count=$(count_lines "$cred_findings")
    end_subfunc "Credential detection completed. Found $finding_count potential findings" "bettercap_credential_detection"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARP ANALYSIS (Passive)
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_arp_analysis() {
    start_subfunc "bettercap_arp_analysis" "Running ARP Analysis"
    
    local output_dir="${dir}/bettercap/hosts"
    
    # Get current ARP table
    local arp_table="${output_dir}/arp_table.txt"
    arp -a > "$arp_table" 2>/dev/null || true
    
    # Check for ARP anomalies
    local anomalies="${output_dir}/arp_anomalies.txt"
    
    # Check for duplicate MACs (potential MITM)
    awk '{print $4}' "$arp_table" | sort | uniq -d | while read mac; do
        echo "[DUPLICATE_MAC] $mac - Potential ARP spoofing detected" >> "$anomalies"
        grep "$mac" "$arp_table" >> "$anomalies"
    done
    
    # Check for known suspicious MAC prefixes
    while IFS= read -r line; do
        local mac=$(echo "$line" | awk '{print $4}')
        
        # Check for common VM/emulator MACs
        if echo "$mac" | grep -qiE "^(00:0c:29|00:50:56|08:00:27|52:54:00|00:16:3e)"; then
            echo "[VM_DETECTED] $line" >> "$anomalies"
        fi
        
        # Check for broadcast/multicast
        if echo "$mac" | grep -qiE "^(ff:ff:ff|01:00:5e|33:33)"; then
            echo "[BROADCAST_MULTICAST] $line" >> "$anomalies"
        fi
        
    done < "$arp_table"
    
    end_subfunc "ARP analysis completed" "bettercap_arp_analysis"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS ANALYSIS (Passive)
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_dns_analysis() {
    start_subfunc "bettercap_dns_analysis" "Running DNS Analysis"
    
    local output_dir="${dir}/bettercap/hosts"
    local dns_analysis="${output_dir}/dns_analysis.json"
    
    # Analyze DNS for target domain
    if [[ -n "$domain" ]]; then
        log_info "Analyzing DNS for $domain..."
        
        # Get various DNS records
        local dns_info=""
        
        # A records
        local a_records=$(dig +short "$domain" A 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        
        # AAAA records
        local aaaa_records=$(dig +short "$domain" AAAA 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        
        # MX records
        local mx_records=$(dig +short "$domain" MX 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        
        # NS records
        local ns_records=$(dig +short "$domain" NS 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        
        # TXT records (for SPF, DKIM, etc.)
        local txt_records=$(dig +short "$domain" TXT 2>/dev/null | tr '\n' '|' | sed 's/|$//')
        
        # CAA records
        local caa_records=$(dig +short "$domain" CAA 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        
        # Check for DNS security issues
        local dns_issues=()
        
        # Check for DNSSEC
        local dnssec=$(dig +dnssec "$domain" 2>/dev/null | grep -c "RRSIG" || echo "0")
        [[ $dnssec -eq 0 ]] && dns_issues+=("NO_DNSSEC")
        
        # Check SPF
        echo "$txt_records" | grep -qi "v=spf1" || dns_issues+=("NO_SPF")
        
        # Check DMARC
        local dmarc=$(dig +short "_dmarc.$domain" TXT 2>/dev/null)
        [[ -z "$dmarc" ]] && dns_issues+=("NO_DMARC")
        
        # Write DNS analysis
        cat > "$dns_analysis" << EOF
{
    "domain": "$domain",
    "records": {
        "A": "$a_records",
        "AAAA": "$aaaa_records",
        "MX": "$mx_records",
        "NS": "$ns_records",
        "TXT": $(echo "$txt_records" | jq -Rs .),
        "CAA": "$caa_records",
        "DNSSEC": $dnssec
    },
    "issues": $(printf '%s\n' "${dns_issues[@]}" | jq -Rs 'split("\n") | map(select(length > 0))')
}
EOF
    fi
    
    end_subfunc "DNS analysis completed" "bettercap_dns_analysis"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIFI SCANNING (Optional)
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_wifi_scan() {
    start_subfunc "bettercap_wifi_scan" "Running WiFi Scan"
    
    local output_dir="${dir}/bettercap/hosts"
    
    # Check for wireless interface
    local wifi_interface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' | head -1)
    
    if [[ -z "$wifi_interface" ]]; then
        log_warning "No WiFi interface found"
        return 0
    fi
    
    log_info "Using WiFi interface: $wifi_interface"
    
    # Create WiFi scan caplet
    local caplet_file="${dir}/.tmp/bettercap/wifi_scan.cap"
    
    cat > "$caplet_file" << EOF
# WiFi Scan Caplet
set wifi.interface $wifi_interface
wifi.recon on
sleep 60
wifi.show
wifi.recon off
quit
EOF
    
    # Run WiFi scan (requires root)
    if [[ $EUID -eq 0 ]]; then
        timeout 120 bettercap -iface "$wifi_interface" \
            -caplet "$caplet_file" \
            -silent \
            > "${output_dir}/wifi_scan.txt" 2>> "$LOGFILE" || true
    else
        log_warning "WiFi scan requires root privileges"
    fi
    
    end_subfunc "WiFi scan completed" "bettercap_wifi_scan"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BLE SCANNING (Optional)
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_ble_scan() {
    start_subfunc "bettercap_ble_scan" "Running BLE Scan"
    
    local output_dir="${dir}/bettercap/hosts"
    
    # Check for Bluetooth adapter
    if ! hciconfig 2>/dev/null | grep -q "UP RUNNING"; then
        log_warning "No active Bluetooth adapter found"
        return 0
    fi
    
    # Create BLE scan caplet
    local caplet_file="${dir}/.tmp/bettercap/ble_scan.cap"
    
    cat > "$caplet_file" << 'EOF'
# BLE Scan Caplet
ble.recon on
sleep 30
ble.show
ble.recon off
quit
EOF
    
    # Run BLE scan
    if [[ $EUID -eq 0 ]]; then
        timeout 60 bettercap -caplet "$caplet_file" \
            -silent \
            > "${output_dir}/ble_scan.txt" 2>> "$LOGFILE" || true
    else
        log_warning "BLE scan requires root privileges"
    fi
    
    end_subfunc "BLE scan completed" "bettercap_ble_scan"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PACKET ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_packet_analysis() {
    start_subfunc "bettercap_packet_analysis" "Running Packet Analysis"
    
    local output_dir="${dir}/bettercap/captures"
    local pcap_file="${output_dir}/capture.pcap"
    
    # Capture packets briefly for analysis
    if [[ $EUID -eq 0 ]]; then
        log_info "Capturing packets for 30 seconds..."
        
        timeout 35 tcpdump -i "$BETTERCAP_INTERFACE" \
            -c 10000 \
            -w "$pcap_file" \
            'tcp or udp' \
            2>> "$LOGFILE" &
        
        local tcpdump_pid=$!
        sleep 30
        kill $tcpdump_pid 2>/dev/null || true
        wait $tcpdump_pid 2>/dev/null || true
        
        # Analyze captured packets
        if [[ -s "$pcap_file" ]]; then
            log_info "Analyzing captured packets..."
            
            # Get protocol statistics
            tcpdump -r "$pcap_file" -qnn 2>/dev/null | \
                awk '{print $3}' | \
                cut -d. -f1-4 | \
                sort | uniq -c | \
                sort -rn | head -50 > "${output_dir}/top_talkers.txt"
            
            # Extract HTTP requests
            tcpdump -r "$pcap_file" -A 2>/dev/null | \
                grep -oE "(GET|POST|PUT|DELETE|HEAD|OPTIONS) [^ ]+ HTTP" | \
                sort | uniq -c | sort -rn > "${output_dir}/http_requests.txt"
            
            # Look for potential credentials in clear text
            tcpdump -r "$pcap_file" -A 2>/dev/null | \
                grep -iE "(user|pass|login|auth|token|session|cookie)" | \
                head -100 > "${output_dir}/potential_credentials_traffic.txt"
        fi
    else
        log_warning "Packet capture requires root privileges"
    fi
    
    end_subfunc "Packet analysis completed" "bettercap_packet_analysis"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL STRIP TEST (Intrusive - disabled by default)
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_sslstrip_test() {
    log_warning "SSL Strip testing is intrusive and should only be used in authorized tests"
    
    start_subfunc "bettercap_sslstrip" "Testing SSL Strip Vulnerability"
    
    # This function only documents potential for SSL strip, does not perform attack
    local output_dir="${dir}/bettercap/ssl"
    local sslstrip_report="${output_dir}/sslstrip_potential.txt"
    
    # Check targets for HSTS
    if [[ -s "${dir}/webs/webs.txt" ]]; then
        while read url; do
            [[ -z "$url" ]] && continue
            [[ "$url" != https://* ]] && continue
            
            local headers=$(curl -sI -m 10 "$url" 2>/dev/null)
            
            if ! echo "$headers" | grep -qi "strict-transport-security"; then
                echo "[VULNERABLE] $url - No HSTS header, potentially vulnerable to SSL strip" >> "$sslstrip_report"
            fi
            
        done < <(head -100 "${dir}/webs/webs.txt")
    fi
    
    end_subfunc "SSL Strip potential assessment completed" "bettercap_sslstrip"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_aggregate_results() {
    log_info "Aggregating Bettercap results..."
    
    local report_file="${dir}/bettercap/reports/bettercap_report.json"
    local summary_file="${dir}/bettercap/reports/bettercap_summary.txt"
    
    # Create comprehensive JSON report
    cat > "$report_file" << EOF
{
    "scan_info": {
        "target": "$domain",
        "interface": "$BETTERCAP_INTERFACE",
        "timestamp": "$(date -Iseconds)",
        "passive_only": $BETTERCAP_PASSIVE_ONLY
    },
    "hosts_discovered": $(cat "${dir}/bettercap/hosts/discovered_hosts.txt" 2>/dev/null | wc -l),
    "ssl_issues": $(count_lines "${dir}/bettercap/ssl/ssl_findings.txt"),
    "http_issues": $(jq -s 'length' "${dir}/bettercap/captures/http_analysis.json" 2>/dev/null || echo 0),
    "credential_findings": $(count_lines "${dir}/bettercap/credentials/potential_credentials.txt"),
    "dns_issues": $(jq '.issues | length' "${dir}/bettercap/hosts/dns_analysis.json" 2>/dev/null || echo 0)
}
EOF
    
    # Create human-readable summary
    cat > "$summary_file" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    BETTERCAP NETWORK SECURITY REPORT
═══════════════════════════════════════════════════════════════════════════════

Target: $domain
Interface: $BETTERCAP_INTERFACE
Scan Time: $(date)
Mode: ${BETTERCAP_PASSIVE_ONLY:+Passive Only}${BETTERCAP_PASSIVE_ONLY:-Active}

───────────────────────────────────────────────────────────────────────────────
                           SUMMARY
───────────────────────────────────────────────────────────────────────────────

Hosts Discovered: $(count_lines "${dir}/bettercap/hosts/discovered_hosts.txt")
SSL Issues Found: $(count_lines "${dir}/bettercap/ssl/ssl_findings.txt")
HTTP Security Issues: $(jq -s 'length' "${dir}/bettercap/captures/http_analysis.json" 2>/dev/null || echo 0)
Potential Credentials: $(count_lines "${dir}/bettercap/credentials/potential_credentials.txt")

───────────────────────────────────────────────────────────────────────────────
                        SSL/TLS FINDINGS
───────────────────────────────────────────────────────────────────────────────

$(cat "${dir}/bettercap/ssl/ssl_findings.txt" 2>/dev/null | head -20 || echo "No SSL issues found")

───────────────────────────────────────────────────────────────────────────────
                        DNS ANALYSIS
───────────────────────────────────────────────────────────────────────────────

$(jq -r '.issues[]' "${dir}/bettercap/hosts/dns_analysis.json" 2>/dev/null | head -10 || echo "No DNS issues found")

───────────────────────────────────────────────────────────────────────────────
                      CREDENTIAL FINDINGS
───────────────────────────────────────────────────────────────────────────────

$(cat "${dir}/bettercap/credentials/potential_credentials.txt" 2>/dev/null | head -20 || echo "No potential credentials found")

───────────────────────────────────────────────────────────────────────────────

Full results available in: ${dir}/bettercap/
═══════════════════════════════════════════════════════════════════════════════
EOF
    
    log_success "Bettercap results aggregated"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STORE FINDINGS IN INTELLIGENCE DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

bettercap_store_intel() {
    log_info "Storing Bettercap findings in intelligence database..."
    
    if ! type -t intel_store &>/dev/null; then
        log_debug "Intelligence module not loaded, skipping"
        return 0
    fi
    
    # Store SSL findings
    if [[ -s "${dir}/bettercap/ssl/ssl_findings.txt" ]]; then
        while IFS= read -r finding; do
            [[ -z "$finding" ]] && continue
            intel_store "vulnerability" "$domain" "$finding" "bettercap_ssl" 70 "medium" "bettercap"
        done < "${dir}/bettercap/ssl/ssl_findings.txt"
    fi
    
    # Store DNS findings
    if [[ -s "${dir}/bettercap/hosts/dns_analysis.json" ]]; then
        jq -r '.issues[]' "${dir}/bettercap/hosts/dns_analysis.json" 2>/dev/null | while read issue; do
            [[ -z "$issue" ]] && continue
            intel_store "vulnerability" "$domain" "DNS: $issue" "bettercap_dns" 60 "low" "bettercap"
        done
    fi
    
    # Store credential findings
    if [[ -s "${dir}/bettercap/credentials/potential_credentials.txt" ]]; then
        intel_store "secret" "$domain" "Potential credentials discovered" "bettercap" 80 "high" "bettercap"
    fi
    
    # Store discovered hosts
    if [[ -s "${dir}/bettercap/hosts/discovered_hosts.txt" ]]; then
        while IFS= read -r host_line; do
            [[ -z "$host_line" ]] && continue
            local ip=$(echo "$host_line" | awk '{print $1}')
            intel_store "host" "$ip" "$host_line" "bettercap_discovery" 90 "info" "bettercap"
        done < "${dir}/bettercap/hosts/discovered_hosts.txt"
    fi
    
    log_success "Bettercap findings stored in intelligence database"
}
