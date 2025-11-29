#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: DNS ANALYSIS & ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Deep DNS analysis and record enumeration
# Tools: dnsrecon, dnsx, massdns, dig, hakip2host
# ═══════════════════════════════════════════════════════════════════════════════

dns_main() {
    log_phase "PHASE 2: DNS ANALYSIS & ENUMERATION"
    
    if ! should_run_module "dns_main" "DNS_ENABLED"; then
        return 0
    fi
    
    start_func "dns_main" "Starting DNS Analysis"
    
    ensure_dir "${dir}/dns"
    ensure_dir "${dir}/hosts"
    ensure_dir "${dir}/.tmp/dns"
    
    # Run DNS analysis functions
    dns_resolution
    dns_records
    dns_zone_transfer
    dns_reverse_lookup
    dns_aggregate
    
    end_func "DNS analysis completed. Results in ${dir}/dns/" "dns_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MASS DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

dns_resolution() {
    if ! should_run_module "dns_resolution" "DNS_RESOLUTION"; then
        return 0
    fi
    
    start_subfunc "dns_resolution" "Running mass DNS resolution"
    
    if [[ ! -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_warning "No subdomains to resolve"
        return 0
    fi
    
    local sub_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    log_info "Resolving $sub_count subdomains..."
    
    # DNSx with full record retrieval
    if command_exists dnsx; then
        log_info "Running dnsx for DNS resolution..."
        
        dnsx -l "${dir}/subdomains/subdomains.txt" \
            -r "${RESOLVERS_TRUSTED}" \
            -t "${DNSX_THREADS:-150}" \
            -retry 3 \
            -silent \
            -recon \
            -json \
            -o "${dir}/dns/dns_records.json" 2>> "$LOGFILE" || true
        
        # Extract IPs from DNS records
        if [[ -s "${dir}/dns/dns_records.json" ]]; then
            jq -r 'select(.host) | "\(.host) - \((.a // [])[])"' \
                "${dir}/dns/dns_records.json" 2>/dev/null | \
                grep -E ' - [0-9]+\.' | \
                sort -u > "${dir}/dns/subdomain_ips.txt" || true
            
            # Extract just IPs
            jq -r '.a[]? // empty' "${dir}/dns/dns_records.json" 2>/dev/null | \
                sort -u > "${dir}/hosts/ips.txt" || true
            
            # Extract CNAME records
            jq -r 'select(.cname) | "\(.host) -> \(.cname[])"' \
                "${dir}/dns/dns_records.json" 2>/dev/null | \
                sort -u > "${dir}/dns/cname_records.txt" || true
            
            # Extract MX records
            jq -r 'select(.mx) | "\(.host) -> \(.mx[])"' \
                "${dir}/dns/dns_records.json" 2>/dev/null | \
                sort -u > "${dir}/dns/mx_records.txt" || true
            
            # Extract NS records
            jq -r 'select(.ns) | "\(.host) -> \(.ns[])"' \
                "${dir}/dns/dns_records.json" 2>/dev/null | \
                sort -u > "${dir}/dns/ns_records.txt" || true
            
            # Extract TXT records
            jq -r 'select(.txt) | "\(.host) -> \(.txt[])"' \
                "${dir}/dns/dns_records.json" 2>/dev/null | \
                sort -u > "${dir}/dns/txt_records.txt" || true
        fi
    fi
    
    # Filter out internal/CDN IPs if enabled
    if [[ "${EXCLUDE_CDN:-true}" == "true" ]] && [[ -s "${dir}/hosts/ips.txt" ]]; then
        filter_cdn_ips
    fi
    
    local ip_count=$(count_lines "${dir}/hosts/ips.txt")
    end_subfunc "Resolved to $ip_count unique IPs" "dns_resolution"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FILTER CDN IPs
# ═══════════════════════════════════════════════════════════════════════════════

filter_cdn_ips() {
    log_info "Filtering CDN IPs..."
    
    if command_exists cdncheck && [[ -s "${dir}/hosts/ips.txt" ]]; then
        # Identify CDN IPs
        cdncheck -i "${dir}/hosts/ips.txt" -cdn \
            -o "${dir}/hosts/cdn_ips.txt" 2>> "$LOGFILE" || true
        
        # Get non-CDN IPs
        cdncheck -i "${dir}/hosts/ips.txt" -nc \
            -o "${dir}/hosts/non_cdn_ips.txt" 2>> "$LOGFILE" || true
        
        log_info "CDN IPs: $(count_lines "${dir}/hosts/cdn_ips.txt")"
        log_info "Non-CDN IPs: $(count_lines "${dir}/hosts/non_cdn_ips.txt")"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# FULL DNS RECORD ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

dns_records() {
    if ! should_run_module "dns_records" "DNS_RECORDS"; then
        return 0
    fi
    
    start_subfunc "dns_records" "Running full DNS record enumeration"
    
    # DNSRecon for comprehensive analysis
    if command_exists dnsrecon; then
        log_info "Running dnsrecon..."
        
        # Standard enumeration
        dnsrecon -d "$domain" -t std \
            -j "${dir}/dns/dnsrecon_std.json" 2>> "$LOGFILE" || true
        
        # SRV records
        dnsrecon -d "$domain" -t srv \
            -j "${dir}/dns/dnsrecon_srv.json" 2>> "$LOGFILE" || true
        
        # SOA records
        dnsrecon -d "$domain" -t soa \
            -j "${dir}/dns/dnsrecon_soa.json" 2>> "$LOGFILE" || true
    fi
    
    # Manual dig queries for additional records
    log_info "Running dig queries..."
    
    # Various record types
    local record_types=("A" "AAAA" "CNAME" "MX" "NS" "TXT" "SOA" "SRV" "CAA" "PTR")
    
    for rtype in "${record_types[@]}"; do
        dig "$domain" "$rtype" +noall +answer >> "${dir}/dns/dig_${rtype,,}.txt" 2>/dev/null || true
    done
    
    # SPF record (in TXT)
    grep -i "spf" "${dir}/dns/dig_txt.txt" > "${dir}/dns/spf_record.txt" 2>/dev/null || true
    
    # DMARC record
    dig "_dmarc.${domain}" TXT +short > "${dir}/dns/dmarc_record.txt" 2>/dev/null || true
    
    # DKIM selectors (common ones)
    local dkim_selectors=("default" "google" "k1" "s1" "s2" "selector1" "selector2")
    for selector in "${dkim_selectors[@]}"; do
        local result=$(dig "${selector}._domainkey.${domain}" TXT +short 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "${selector}: $result" >> "${dir}/dns/dkim_records.txt"
        fi
    done
    
    end_subfunc "DNS record enumeration completed" "dns_records"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ZONE TRANSFER CHECK
# ═══════════════════════════════════════════════════════════════════════════════

dns_zone_transfer() {
    if ! should_run_module "dns_zone_transfer" "DNS_ZONE_TRANSFER"; then
        return 0
    fi
    
    start_subfunc "dns_zone_transfer" "Checking for zone transfer vulnerabilities"
    
    local vulnerable=false
    
    # Get nameservers
    local nameservers=$(dig NS "$domain" +short 2>/dev/null | sed 's/\.$//')
    
    if [[ -z "$nameservers" ]]; then
        log_warning "No nameservers found for $domain"
        return 0
    fi
    
    echo "Zone Transfer Check for $domain" > "${dir}/dns/zone_transfer.txt"
    echo "=================================" >> "${dir}/dns/zone_transfer.txt"
    echo "" >> "${dir}/dns/zone_transfer.txt"
    
    # Try zone transfer on each nameserver
    for ns in $nameservers; do
        echo "Testing nameserver: $ns" >> "${dir}/dns/zone_transfer.txt"
        
        # Try AXFR
        local result=$(dig @"$ns" "$domain" AXFR +noall +answer 2>/dev/null)
        
        if [[ -n "$result" ]] && [[ $(echo "$result" | wc -l) -gt 2 ]]; then
            vulnerable=true
            echo "  [VULNERABLE] Zone transfer successful!" >> "${dir}/dns/zone_transfer.txt"
            echo "" >> "${dir}/dns/zone_transfer.txt"
            echo "$result" >> "${dir}/dns/zone_transfer.txt"
            echo "" >> "${dir}/dns/zone_transfer.txt"
            
            # Extract subdomains from zone transfer
            echo "$result" | awk '{print $1}' | sed 's/\.$//' | \
                grep -E "\.$domain$|^$domain$" | \
                sort -u >> "${dir}/subdomains/subdomains_zone_transfer.txt"
            
            log_success "Zone transfer vulnerability found on $ns!"
            notify "Zone transfer vulnerability found on $ns for $domain" "warning"
        else
            echo "  [SECURE] Zone transfer denied" >> "${dir}/dns/zone_transfer.txt"
        fi
        echo "" >> "${dir}/dns/zone_transfer.txt"
    done
    
    # DNSRecon zone transfer check
    if command_exists dnsrecon; then
        log_info "Running dnsrecon zone transfer check..."
        dnsrecon -d "$domain" -t axfr \
            -j "${dir}/dns/dnsrecon_axfr.json" 2>> "$LOGFILE" || true
    fi
    
    if [[ "$vulnerable" == "true" ]]; then
        end_subfunc "ZONE TRANSFER VULNERABILITY FOUND!" "dns_zone_transfer"
    else
        end_subfunc "No zone transfer vulnerabilities found" "dns_zone_transfer"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# REVERSE DNS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

dns_reverse_lookup() {
    if ! should_run_module "dns_reverse_lookup" "DNS_REVERSE"; then
        return 0
    fi
    
    start_subfunc "dns_reverse_lookup" "Running reverse DNS lookups"
    
    if [[ ! -s "${dir}/hosts/ips.txt" ]]; then
        log_warning "No IPs available for reverse lookup"
        return 0
    fi
    
    local ip_count=$(count_lines "${dir}/hosts/ips.txt")
    log_info "Running reverse DNS on $ip_count IPs..."
    
    # hakip2host for reverse lookups
    if command_exists hakip2host; then
        log_info "Running hakip2host..."
        cat "${dir}/hosts/ips.txt" | hakip2host 2>> "$LOGFILE" | \
            tee "${dir}/dns/reverse_dns.txt" | \
            awk '{print $3}' | \
            grep -E "\.$domain$|^$domain$" | \
            sort -u > "${dir}/.tmp/dns/reverse_subs.txt" || true
        
        # Add new subdomains from reverse DNS
        if [[ -s "${dir}/.tmp/dns/reverse_subs.txt" ]]; then
            cat "${dir}/.tmp/dns/reverse_subs.txt" >> "${dir}/subdomains/subdomains.txt"
            sort -u "${dir}/subdomains/subdomains.txt" -o "${dir}/subdomains/subdomains.txt"
        fi
    fi
    
    # Manual reverse DNS using dig
    log_info "Running dig PTR lookups..."
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        local ptr=$(dig -x "$ip" +short 2>/dev/null | head -1 | sed 's/\.$//')
        if [[ -n "$ptr" ]]; then
            echo "$ip -> $ptr" >> "${dir}/dns/reverse_dns_manual.txt"
        fi
    done < "${dir}/hosts/ips.txt"
    
    local reverse_count=$(count_lines "${dir}/dns/reverse_dns.txt")
    end_subfunc "Reverse DNS: $reverse_count results" "dns_reverse_lookup"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE DNS RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

dns_aggregate() {
    log_info "Aggregating DNS results..."
    
    # Create DNS summary
    local summary="${dir}/dns/dns_summary.txt"
    
    cat > "$summary" << EOF
DNS Analysis Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

EOF
    
    # Count various records
    echo "Record Counts:" >> "$summary"
    echo "─────────────────────────────────────────" >> "$summary"
    
    for rtype in A AAAA CNAME MX NS TXT SOA; do
        local rtype_lower=$(echo "$rtype" | tr '[:upper:]' '[:lower:]')
        if [[ -f "${dir}/dns/dig_${rtype_lower}.txt" ]]; then
            local count=$(grep -c "IN.*${rtype}" "${dir}/dns/dig_${rtype_lower}.txt" 2>/dev/null || echo "0")
            printf "%-10s: %s\n" "$rtype" "$count" >> "$summary"
        fi
    done
    
    echo "" >> "$summary"
    echo "IP Statistics:" >> "$summary"
    echo "─────────────────────────────────────────" >> "$summary"
    echo "Total IPs: $(count_lines "${dir}/hosts/ips.txt")" >> "$summary"
    [[ -f "${dir}/hosts/cdn_ips.txt" ]] && \
        echo "CDN IPs: $(count_lines "${dir}/hosts/cdn_ips.txt")" >> "$summary"
    [[ -f "${dir}/hosts/non_cdn_ips.txt" ]] && \
        echo "Non-CDN IPs: $(count_lines "${dir}/hosts/non_cdn_ips.txt")" >> "$summary"
    
    echo "" >> "$summary"
    echo "Security Records:" >> "$summary"
    echo "─────────────────────────────────────────" >> "$summary"
    
    [[ -s "${dir}/dns/spf_record.txt" ]] && echo "SPF: Present" >> "$summary" || echo "SPF: Missing" >> "$summary"
    [[ -s "${dir}/dns/dmarc_record.txt" ]] && echo "DMARC: Present" >> "$summary" || echo "DMARC: Missing" >> "$summary"
    [[ -s "${dir}/dns/dkim_records.txt" ]] && echo "DKIM: Present" >> "$summary" || echo "DKIM: Not found (common selectors)" >> "$summary"
    
    # Zone transfer status
    if grep -q "VULNERABLE" "${dir}/dns/zone_transfer.txt" 2>/dev/null; then
        echo "" >> "$summary"
        echo "⚠️  ZONE TRANSFER VULNERABILITY DETECTED!" >> "$summary"
    fi
    
    log_success "DNS aggregation completed"
}
