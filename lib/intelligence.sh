#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO CROSS-PHASE INTELLIGENCE ENGINE
# Advanced vulnerability correlation and intelligence gathering
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE STORAGE
# ═══════════════════════════════════════════════════════════════════════════════

declare -gA INTEL_DATA
declare -gA INTEL_CORRELATIONS
declare -gA VULN_CHAIN
declare -g INTEL_DB=""

# Intelligence categories
readonly INTEL_SUBDOMAIN="subdomain"
readonly INTEL_HOST="host"
readonly INTEL_URL="url"
readonly INTEL_TECH="technology"
readonly INTEL_VULN="vulnerability"
readonly INTEL_SECRET="secret"
readonly INTEL_PARAM="parameter"
readonly INTEL_ENDPOINT="endpoint"

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

intel_init() {
    local intel_dir="${1:-${dir}/.tmp/intel}"
    
    ensure_dir "$intel_dir"
    INTEL_DB="${intel_dir}/intelligence.db"
    
    # Initialize SQLite database for complex queries
    if command_exists sqlite3; then
        sqlite3 "$INTEL_DB" << 'SQL'
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    target TEXT NOT NULL,
    data TEXT,
    source TEXT,
    confidence INTEGER DEFAULT 50,
    severity TEXT,
    phase TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    correlated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id_1 INTEGER,
    finding_id_2 INTEGER,
    correlation_type TEXT,
    confidence INTEGER,
    description TEXT,
    FOREIGN KEY (finding_id_1) REFERENCES findings(id),
    FOREIGN KEY (finding_id_2) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT,
    step_order INTEGER,
    finding_id INTEGER,
    description TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
SQL
    fi
    
    log_debug "Intelligence engine initialized at $intel_dir"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

# Store intelligence finding
intel_store() {
    local category="$1"
    local target="$2"
    local data="$3"
    local source="${4:-unknown}"
    local confidence="${5:-50}"
    local severity="${6:-info}"
    local phase="${7:-unknown}"
    
    if command_exists sqlite3 && [[ -f "$INTEL_DB" ]]; then
        sqlite3 "$INTEL_DB" "INSERT INTO findings (category, target, data, source, confidence, severity, phase) VALUES ('$category', '$target', '$(echo "$data" | sed "s/'/''/g")', '$source', $confidence, '$severity', '$phase');"
    fi
    
    # In-memory storage for quick access
    local key="${category}:${target}"
    INTEL_DATA["$key"]="$data"
    
    log_debug "Intel stored: $category -> $target ($severity)"
}

# Bulk import from file
intel_import_file() {
    local file="$1"
    local category="$2"
    local source="$3"
    local phase="${4:-unknown}"
    
    if [[ ! -s "$file" ]]; then
        return 0
    fi
    
    local count=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        intel_store "$category" "$line" "" "$source" 50 "info" "$phase"
        ((count++))
    done < "$file"
    
    log_debug "Imported $count entries from $file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-PHASE INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

# Correlate findings across phases
intel_correlate() {
    log_info "Running cross-phase correlation analysis..."
    
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        log_warning "SQLite not available for correlation"
        return 0
    fi
    
    # Correlation 1: Subdomains with multiple vulnerabilities
    sqlite3 "$INTEL_DB" << 'SQL'
INSERT INTO correlations (finding_id_1, finding_id_2, correlation_type, confidence, description)
SELECT DISTINCT f1.id, f2.id, 'multi_vuln_host', 80,
    'Host has multiple vulnerabilities: ' || GROUP_CONCAT(f2.data)
FROM findings f1
JOIN findings f2 ON f1.target = f2.target
WHERE f1.category = 'host' 
AND f2.category = 'vulnerability'
GROUP BY f1.target
HAVING COUNT(f2.id) > 1;
SQL
    
    # Correlation 2: Technology + Known CVEs
    sqlite3 "$INTEL_DB" << 'SQL'
INSERT INTO correlations (finding_id_1, finding_id_2, correlation_type, confidence, description)
SELECT f1.id, f2.id, 'tech_vuln', 90,
    'Technology ' || f1.data || ' has known vulnerabilities'
FROM findings f1
JOIN findings f2 ON f1.target = f2.target
WHERE f1.category = 'technology'
AND f2.category = 'vulnerability'
AND f2.data LIKE '%' || f1.data || '%';
SQL
    
    # Correlation 3: Parameter patterns across URLs
    sqlite3 "$INTEL_DB" << 'SQL'
INSERT INTO correlations (finding_id_1, finding_id_2, correlation_type, confidence, description)
SELECT DISTINCT f1.id, f2.id, 'param_pattern', 70,
    'Similar parameter pattern found across hosts'
FROM findings f1
JOIN findings f2 ON f1.data = f2.data AND f1.target != f2.target
WHERE f1.category = 'parameter'
AND f2.category = 'parameter';
SQL
    
    # Correlation 4: Secrets found in multiple locations
    sqlite3 "$INTEL_DB" << 'SQL'
INSERT INTO correlations (finding_id_1, finding_id_2, correlation_type, confidence, description)
SELECT f1.id, f2.id, 'secret_reuse', 95,
    'Secret/credential reused across locations'
FROM findings f1
JOIN findings f2 ON f1.data = f2.data AND f1.target != f2.target
WHERE f1.category = 'secret'
AND f2.category = 'secret';
SQL
    
    local correlation_count=$(sqlite3 "$INTEL_DB" "SELECT COUNT(*) FROM correlations;")
    log_success "Found $correlation_count correlations"
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY CHAIN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

# Detect potential attack chains
intel_find_attack_chains() {
    log_info "Analyzing potential attack chains..."
    
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        return 0
    fi
    
    local chain_id=0
    
    # Chain Pattern 1: SSRF → Internal Service → RCE
    sqlite3 "$INTEL_DB" << SQL
INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'ssrf_rce_$((++chain_id))', 1, f1.id, 'SSRF vulnerability allows internal access'
FROM findings f1
WHERE f1.category = 'vulnerability' 
AND (f1.data LIKE '%ssrf%' OR f1.data LIKE '%SSRF%');

INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'ssrf_rce_$chain_id', 2, f2.id, 'Internal service discovered via SSRF'
FROM findings f1
JOIN findings f2 ON f1.target = f2.target
WHERE f1.category = 'vulnerability'
AND f1.data LIKE '%ssrf%'
AND f2.category = 'endpoint'
AND f2.data LIKE '%internal%';
SQL
    
    # Chain Pattern 2: XSS → Session Hijack → Account Takeover
    sqlite3 "$INTEL_DB" << SQL
INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'xss_ato_$((++chain_id))', 1, f1.id, 'XSS vulnerability found'
FROM findings f1
WHERE f1.category = 'vulnerability'
AND (f1.data LIKE '%xss%' OR f1.data LIKE '%XSS%' OR f1.data LIKE '%cross-site%');

INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'xss_ato_$chain_id', 2, f2.id, 'Session management weakness'
FROM findings f1
JOIN findings f2 ON f1.target = f2.target
WHERE f1.data LIKE '%xss%'
AND f2.category = 'vulnerability'
AND (f2.data LIKE '%session%' OR f2.data LIKE '%cookie%');
SQL
    
    # Chain Pattern 3: SQLi → Data Exfiltration
    sqlite3 "$INTEL_DB" << SQL
INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'sqli_exfil_$((++chain_id))', 1, f1.id, 'SQL Injection vulnerability'
FROM findings f1
WHERE f1.category = 'vulnerability'
AND (f1.data LIKE '%sqli%' OR f1.data LIKE '%sql injection%' OR f1.data LIKE '%SQLi%');
SQL
    
    # Chain Pattern 4: Open Redirect → Phishing → Credential Theft
    sqlite3 "$INTEL_DB" << SQL
INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'redirect_phish_$((++chain_id))', 1, f1.id, 'Open redirect vulnerability'
FROM findings f1
WHERE f1.category = 'vulnerability'
AND (f1.data LIKE '%redirect%' OR f1.data LIKE '%url_redirect%');

INSERT INTO attack_chains (chain_id, step_order, finding_id, description)
SELECT 'redirect_phish_$chain_id', 2, f2.id, 'Login/auth endpoint present'
FROM findings f1
JOIN findings f2 ON f1.target = f2.target
WHERE f1.data LIKE '%redirect%'
AND f2.category = 'endpoint'
AND (f2.data LIKE '%login%' OR f2.data LIKE '%auth%' OR f2.data LIKE '%signin%');
SQL
    
    local chain_count=$(sqlite3 "$INTEL_DB" "SELECT COUNT(DISTINCT chain_id) FROM attack_chains;")
    log_success "Identified $chain_count potential attack chains"
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE QUERIES
# ═══════════════════════════════════════════════════════════════════════════════

# Get high-value targets
intel_get_high_value_targets() {
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        return 0
    fi
    
    sqlite3 -header -column "$INTEL_DB" << 'SQL'
SELECT target, 
       COUNT(DISTINCT id) as finding_count,
       GROUP_CONCAT(DISTINCT category) as categories,
       MAX(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as has_critical,
       AVG(confidence) as avg_confidence
FROM findings
GROUP BY target
HAVING finding_count > 3
ORDER BY has_critical DESC, finding_count DESC
LIMIT 20;
SQL
}

# Get vulnerability summary by severity
intel_vuln_summary() {
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        return 0
    fi
    
    sqlite3 -header -column "$INTEL_DB" << 'SQL'
SELECT severity,
       COUNT(*) as count,
       GROUP_CONCAT(DISTINCT target) as affected_targets
FROM findings
WHERE category = 'vulnerability'
GROUP BY severity
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        WHEN 'low' THEN 4 
        ELSE 5 
    END;
SQL
}

# Get correlated findings
intel_get_correlations() {
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        return 0
    fi
    
    sqlite3 -header -column "$INTEL_DB" << 'SQL'
SELECT c.correlation_type,
       c.confidence,
       c.description,
       f1.target as target_1,
       f2.target as target_2
FROM correlations c
JOIN findings f1 ON c.finding_id_1 = f1.id
JOIN findings f2 ON c.finding_id_2 = f2.id
ORDER BY c.confidence DESC
LIMIT 50;
SQL
}

# Get attack chains
intel_get_attack_chains() {
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        return 0
    fi
    
    sqlite3 -header -column "$INTEL_DB" << 'SQL'
SELECT ac.chain_id,
       ac.step_order,
       ac.description,
       f.target,
       f.data,
       f.severity
FROM attack_chains ac
JOIN findings f ON ac.finding_id = f.id
ORDER BY ac.chain_id, ac.step_order;
SQL
}

# ═══════════════════════════════════════════════════════════════════════════════
# PATTERN RECOGNITION
# ═══════════════════════════════════════════════════════════════════════════════

# Detect common vulnerability patterns
intel_detect_patterns() {
    log_info "Detecting vulnerability patterns..."
    
    local patterns_found=0
    
    # Pattern: Admin panels exposed
    if grep -qiE "admin|dashboard|panel|manage" "${dir}/urls/urls.txt" 2>/dev/null; then
        intel_store "$INTEL_VULN" "$domain" "admin_panel_exposure" "pattern_detection" 70 "medium" "pattern"
        ((patterns_found++))
    fi
    
    # Pattern: Development/debug endpoints
    if grep -qiE "debug|dev|test|staging|phpinfo|elmah|trace" "${dir}/urls/urls.txt" 2>/dev/null; then
        intel_store "$INTEL_VULN" "$domain" "debug_endpoint_exposure" "pattern_detection" 80 "high" "pattern"
        ((patterns_found++))
    fi
    
    # Pattern: Backup files exposed
    if grep -qiE "\.bak|\.old|\.backup|\.zip|\.tar|\.sql" "${dir}/content/"*.txt 2>/dev/null; then
        intel_store "$INTEL_VULN" "$domain" "backup_file_exposure" "pattern_detection" 85 "high" "pattern"
        ((patterns_found++))
    fi
    
    # Pattern: API key patterns in JS
    if grep -qiE "api[_-]?key|apikey|secret[_-]?key|access[_-]?token" "${dir}/js/"*.txt 2>/dev/null; then
        intel_store "$INTEL_SECRET" "$domain" "api_key_exposure_js" "pattern_detection" 90 "critical" "pattern"
        ((patterns_found++))
    fi
    
    # Pattern: Internal IP addresses
    if grep -qoE '\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b' "${dir}/"**/*.txt 2>/dev/null; then
        intel_store "$INTEL_VULN" "$domain" "internal_ip_exposure" "pattern_detection" 75 "medium" "pattern"
        ((patterns_found++))
    fi
    
    # Pattern: Error messages with stack traces
    if grep -qiE "stack ?trace|exception|error at|line [0-9]+|\.php on line" "${dir}/"**/*.txt 2>/dev/null; then
        intel_store "$INTEL_VULN" "$domain" "verbose_error_messages" "pattern_detection" 65 "low" "pattern"
        ((patterns_found++))
    fi
    
    # Pattern: Default credentials in responses
    if grep -qiE "admin:admin|root:root|password:password|test:test" "${dir}/"**/*.txt 2>/dev/null; then
        intel_store "$INTEL_SECRET" "$domain" "default_credentials" "pattern_detection" 95 "critical" "pattern"
        ((patterns_found++))
    fi
    
    log_success "Detected $patterns_found vulnerability patterns"
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

# Generate intelligence report
intel_generate_report() {
    local output_file="${1:-${dir}/reports/intelligence_report.md}"
    
    ensure_dir "$(dirname "$output_file")"
    
    cat > "$output_file" << EOF
# Intelligence Analysis Report
**Target:** ${domain}
**Generated:** $(date)
**Analysis Type:** Cross-Phase Intelligence Correlation

---

## Executive Summary

$(intel_vuln_summary 2>/dev/null || echo "No vulnerability summary available")

---

## High-Value Targets

$(intel_get_high_value_targets 2>/dev/null || echo "No high-value targets identified")

---

## Vulnerability Correlations

$(intel_get_correlations 2>/dev/null || echo "No correlations found")

---

## Potential Attack Chains

$(intel_get_attack_chains 2>/dev/null || echo "No attack chains identified")

---

## Statistics

$(if command_exists sqlite3 && [[ -f "$INTEL_DB" ]]; then
    sqlite3 "$INTEL_DB" << 'SQL'
SELECT 'Total Findings' as metric, COUNT(*) as value FROM findings
UNION ALL
SELECT 'Unique Targets', COUNT(DISTINCT target) FROM findings
UNION ALL
SELECT 'Correlations Found', COUNT(*) FROM correlations
UNION ALL
SELECT 'Attack Chains', COUNT(DISTINCT chain_id) FROM attack_chains
UNION ALL
SELECT 'Critical Severity', COUNT(*) FROM findings WHERE severity = 'critical'
UNION ALL
SELECT 'High Severity', COUNT(*) FROM findings WHERE severity = 'high';
SQL
else
    echo "Statistics unavailable"
fi)

---

## Recommendations

Based on the analysis, prioritize the following:

1. **Critical Findings**: Address all critical severity vulnerabilities immediately
2. **Attack Chains**: Review and remediate identified attack chain entry points
3. **Correlated Vulnerabilities**: Address hosts with multiple vulnerabilities
4. **Exposed Secrets**: Rotate any discovered credentials/API keys

---

*Report generated by Neko Intelligence Engine v2.0*
EOF
    
    log_success "Intelligence report generated: $output_file"
}

# Export intelligence data as JSON
intel_export_json() {
    local output_file="${1:-${dir}/reports/intelligence.json}"
    
    if ! command_exists sqlite3 || [[ ! -f "$INTEL_DB" ]]; then
        echo "{}" > "$output_file"
        return 0
    fi
    
    sqlite3 "$INTEL_DB" << SQL > "$output_file"
SELECT json_object(
    'findings', (SELECT json_group_array(
        json_object(
            'id', id,
            'category', category,
            'target', target,
            'data', data,
            'source', source,
            'confidence', confidence,
            'severity', severity,
            'phase', phase,
            'timestamp', timestamp
        )
    ) FROM findings),
    'correlations', (SELECT json_group_array(
        json_object(
            'type', correlation_type,
            'confidence', confidence,
            'description', description
        )
    ) FROM correlations),
    'attack_chains', (SELECT json_group_array(
        json_object(
            'chain_id', chain_id,
            'step', step_order,
            'description', description
        )
    ) FROM attack_chains)
);
SQL
    
    log_success "Intelligence exported to $output_file"
}
