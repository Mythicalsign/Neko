#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 15: REPORT GENERATION & NOTIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Generate comprehensive scan reports
# Formats: HTML, Markdown, JSON, Executive Summary
# ═══════════════════════════════════════════════════════════════════════════════

report_main() {
    log_phase "PHASE 15: REPORT GENERATION"
    
    start_func "report_main" "Generating Scan Reports"
    
    ensure_dir "${dir}/reports"
    
    # Generate various report formats
    report_json
    report_markdown
    report_html
    report_executive_summary
    
    # Compress if enabled
    if [[ "${COMPRESS_OUTPUT:-false}" == "true" ]]; then
        compress_output "$dir"
    fi
    
    # Send notification
    report_notify
    
    end_func "Reports generated in ${dir}/reports/" "report_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# JSON REPORT
# ═══════════════════════════════════════════════════════════════════════════════

report_json() {
    if ! should_run_module "report_json" "REPORT_JSON"; then
        return 0
    fi
    
    start_subfunc "report_json" "Generating JSON report"
    
    local json_report="${dir}/reports/neko_report.json"
    
    # Build JSON report
    cat > "$json_report" << EOF
{
    "scan_info": {
        "target": "${domain}",
        "scan_date": "$(date -Iseconds)",
        "scan_mode": "${mode}",
        "neko_version": "${NEKO_VERSION}"
    },
    "statistics": {
        "subdomains": $(count_lines "${dir}/subdomains/subdomains.txt"),
        "live_hosts": $(count_lines "${dir}/webs/webs.txt"),
        "unique_ips": $(count_lines "${dir}/hosts/ips.txt"),
        "open_ports": $(count_lines "${dir}/ports/all_open_ports.txt"),
        "urls_discovered": $(count_lines "${dir}/urls/urls.txt"),
        "parameters_found": $(count_lines "${dir}/parameters/params_all.txt")
    },
    "vulnerabilities": {
        "nuclei_critical": $(count_lines "${dir}/vulnerabilities/nuclei/critical.txt"),
        "nuclei_high": $(count_lines "${dir}/vulnerabilities/nuclei/high.txt"),
        "nuclei_medium": $(count_lines "${dir}/vulnerabilities/nuclei/medium.txt"),
        "nuclei_low": $(count_lines "${dir}/vulnerabilities/nuclei/low.txt"),
        "confirmed_xss": $(count_lines "${dir}/xss/confirmed_xss.txt"),
        "crlf_injection": $(count_lines "${dir}/vulnerabilities/crlf/crlfuzz_results.txt"),
        "cors_misconfig": $(count_lines "${dir}/vulnerabilities/cors/nuclei_cors.txt"),
        "open_redirect": $(count_lines "${dir}/vulnerabilities/redirect/nuclei_redirect.txt"),
        "subdomain_takeover": $(count_lines "${dir}/takeover/vulnerable.txt")
    },
    "files": {
        "subdomains": "subdomains/subdomains.txt",
        "live_hosts": "webs/webs.txt",
        "urls": "urls/urls.txt",
        "nuclei_findings": "vulnerabilities/nuclei/findings.json",
        "xss_findings": "xss/confirmed_xss.txt"
    }
}
EOF
    
    end_subfunc "JSON report generated" "report_json"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MARKDOWN REPORT
# ═══════════════════════════════════════════════════════════════════════════════

report_markdown() {
    if ! should_run_module "report_markdown" "REPORT_MARKDOWN"; then
        return 0
    fi
    
    start_subfunc "report_markdown" "Generating Markdown report"
    
    local md_report="${dir}/reports/neko_report.md"
    
    cat > "$md_report" << EOF
# Neko Scan Report

## Target Information
- **Domain**: ${domain}
- **Scan Date**: $(date)
- **Scan Mode**: ${mode}
- **Neko Version**: ${NEKO_VERSION}

---

## Executive Summary

| Category | Count |
|----------|-------|
| Subdomains | $(count_lines "${dir}/subdomains/subdomains.txt") |
| Live Web Hosts | $(count_lines "${dir}/webs/webs.txt") |
| Unique IPs | $(count_lines "${dir}/hosts/ips.txt") |
| Open Ports | $(count_lines "${dir}/ports/all_open_ports.txt") |
| URLs Discovered | $(count_lines "${dir}/urls/urls.txt") |
| Parameters Found | $(count_lines "${dir}/parameters/params_all.txt") |

---

## Vulnerability Summary

### Critical Findings
| Severity | Count |
|----------|-------|
| Critical | $(count_lines "${dir}/vulnerabilities/nuclei/critical.txt") |
| High | $(count_lines "${dir}/vulnerabilities/nuclei/high.txt") |
| Medium | $(count_lines "${dir}/vulnerabilities/nuclei/medium.txt") |
| Low | $(count_lines "${dir}/vulnerabilities/nuclei/low.txt") |

### Specific Vulnerabilities
| Type | Count |
|------|-------|
| Confirmed XSS | $(count_lines "${dir}/xss/confirmed_xss.txt") |
| CRLF Injection | $(count_lines "${dir}/vulnerabilities/crlf/crlfuzz_results.txt") |
| CORS Misconfiguration | $(count_lines "${dir}/vulnerabilities/cors/nuclei_cors.txt") |
| Open Redirect | $(count_lines "${dir}/vulnerabilities/redirect/nuclei_redirect.txt") |
| Subdomain Takeover | $(count_lines "${dir}/takeover/vulnerable.txt") |

---

## Critical Vulnerabilities Detail

### Nuclei Critical Findings
\`\`\`
$(head -20 "${dir}/vulnerabilities/nuclei/critical.txt" 2>/dev/null || echo "None found")
\`\`\`

### Confirmed XSS Vulnerabilities
\`\`\`
$(head -20 "${dir}/xss/confirmed_xss.txt" 2>/dev/null || echo "None found")
\`\`\`

### Subdomain Takeover Vulnerabilities
\`\`\`
$(head -20 "${dir}/takeover/vulnerable.txt" 2>/dev/null || echo "None found")
\`\`\`

---

## Reconnaissance Details

### Subdomains (Top 50)
\`\`\`
$(head -50 "${dir}/subdomains/subdomains.txt" 2>/dev/null || echo "None found")
\`\`\`

### Live Web Hosts (Top 50)
\`\`\`
$(head -50 "${dir}/webs/webs.txt" 2>/dev/null || echo "None found")
\`\`\`

### Technologies Detected
\`\`\`
$(head -30 "${dir}/webs/technologies_quick.txt" 2>/dev/null || echo "None detected")
\`\`\`

---

## WAF/CDN Analysis

### WAF Detection
\`\`\`
$(cat "${dir}/webs/waf_summary.txt" 2>/dev/null || echo "No WAF analysis performed")
\`\`\`

### CDN Detection
\`\`\`
$(cat "${dir}/webs/cdn_summary.txt" 2>/dev/null || echo "No CDN analysis performed")
\`\`\`

---

## Port Scan Results

### Open Ports Summary
\`\`\`
$(head -30 "${dir}/ports/portscan_summary.txt" 2>/dev/null || echo "No port scan performed")
\`\`\`

---

## Content Discovery

### Interesting Paths Found
\`\`\`
$(head -30 "${dir}/content/found_paths.txt" 2>/dev/null || echo "No content discovery performed")
\`\`\`

### Forbidden Paths (Potential Bypass)
\`\`\`
$(head -20 "${dir}/content/forbidden.txt" 2>/dev/null || echo "None found")
\`\`\`

---

## OSINT Findings

### Emails Found
\`\`\`
$(head -20 "${dir}/osint/emails.txt" 2>/dev/null || echo "None found")
\`\`\`

### GitHub/GitLab Leaks
\`\`\`
$(head -20 "${dir}/osint/secrets/all_secrets.json" 2>/dev/null || echo "None found")
\`\`\`

---

## Recommendations

1. **Critical Vulnerabilities**: Address all critical and high severity findings immediately
2. **XSS Vulnerabilities**: Implement proper input validation and output encoding
3. **Security Headers**: Add missing security headers (HSTS, CSP, X-Frame-Options)
4. **Subdomain Takeover**: Remove or properly configure vulnerable subdomains
5. **Open Redirects**: Validate and whitelist redirect destinations
6. **WAF Bypass**: Review WAF rules for hosts without protection

---

## Files Generated

| File | Description |
|------|-------------|
| \`subdomains/subdomains.txt\` | All discovered subdomains |
| \`webs/webs.txt\` | Live web hosts |
| \`urls/urls.txt\` | All discovered URLs |
| \`vulnerabilities/nuclei/findings.json\` | Nuclei scan results |
| \`xss/confirmed_xss.txt\` | Confirmed XSS vulnerabilities |
| \`reports/neko_report.json\` | Machine-readable report |

---

*Report generated by Neko v${NEKO_VERSION}*
EOF
    
    end_subfunc "Markdown report generated" "report_markdown"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ═══════════════════════════════════════════════════════════════════════════════

report_html() {
    if ! should_run_module "report_html" "REPORT_HTML"; then
        return 0
    fi
    
    start_subfunc "report_html" "Generating HTML report"
    
    local html_report="${dir}/reports/neko_report.html"
    
    # Calculate vulnerability counts
    local vuln_critical=$(count_lines "${dir}/vulnerabilities/nuclei/critical.txt")
    local vuln_high=$(count_lines "${dir}/vulnerabilities/nuclei/high.txt")
    local vuln_medium=$(count_lines "${dir}/vulnerabilities/nuclei/medium.txt")
    local vuln_low=$(count_lines "${dir}/vulnerabilities/nuclei/low.txt")
    local total_vulns=$((vuln_critical + vuln_high + vuln_medium + vuln_low))
    
    cat > "$html_report" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Neko Scan Report</title>
    <style>
        :root {
            --primary: #6366f1;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #16a34a;
            --info: #0284c7;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        header {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            padding: 3rem 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            text-align: center;
        }
        header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        header p { opacity: 0.9; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border: 1px solid var(--border);
        }
        .stat-card h3 { color: #94a3b8; font-size: 0.875rem; margin-bottom: 0.5rem; }
        .stat-card .value { font-size: 2rem; font-weight: bold; }
        .vuln-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .vuln-card {
            padding: 1.5rem;
            border-radius: 0.75rem;
            text-align: center;
        }
        .vuln-card.critical { background: rgba(220, 38, 38, 0.2); border: 1px solid var(--critical); }
        .vuln-card.high { background: rgba(234, 88, 12, 0.2); border: 1px solid var(--high); }
        .vuln-card.medium { background: rgba(202, 138, 4, 0.2); border: 1px solid var(--medium); }
        .vuln-card.low { background: rgba(22, 163, 74, 0.2); border: 1px solid var(--low); }
        .vuln-card .count { font-size: 2.5rem; font-weight: bold; }
        .section {
            background: var(--card);
            padding: 1.5rem;
            border-radius: 0.75rem;
            border: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }
        .section h2 {
            color: var(--primary);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }
        pre {
            background: var(--bg);
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            font-size: 0.875rem;
            max-height: 400px;
            overflow-y: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { color: #94a3b8; font-weight: 600; }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-critical { background: var(--critical); }
        .badge-high { background: var(--high); }
        .badge-medium { background: var(--medium); }
        .badge-low { background: var(--low); }
        footer {
            text-align: center;
            padding: 2rem;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🐱 Neko Scan Report</h1>
EOF

    cat >> "$html_report" << EOF
            <p>Target: <strong>${domain}</strong> | Date: $(date) | Mode: ${mode}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Subdomains</h3>
                <div class="value">$(count_lines "${dir}/subdomains/subdomains.txt")</div>
            </div>
            <div class="stat-card">
                <h3>Live Hosts</h3>
                <div class="value">$(count_lines "${dir}/webs/webs.txt")</div>
            </div>
            <div class="stat-card">
                <h3>Unique IPs</h3>
                <div class="value">$(count_lines "${dir}/hosts/ips.txt")</div>
            </div>
            <div class="stat-card">
                <h3>Open Ports</h3>
                <div class="value">$(count_lines "${dir}/ports/all_open_ports.txt")</div>
            </div>
            <div class="stat-card">
                <h3>URLs Found</h3>
                <div class="value">$(count_lines "${dir}/urls/urls.txt")</div>
            </div>
            <div class="stat-card">
                <h3>Total Vulns</h3>
                <div class="value">${total_vulns}</div>
            </div>
        </div>

        <h2 style="margin-bottom: 1rem;">Vulnerability Summary</h2>
        <div class="vuln-grid">
            <div class="vuln-card critical">
                <div class="count">${vuln_critical}</div>
                <div>Critical</div>
            </div>
            <div class="vuln-card high">
                <div class="count">${vuln_high}</div>
                <div>High</div>
            </div>
            <div class="vuln-card medium">
                <div class="count">${vuln_medium}</div>
                <div>Medium</div>
            </div>
            <div class="vuln-card low">
                <div class="count">${vuln_low}</div>
                <div>Low</div>
            </div>
        </div>

        <div class="section">
            <h2>Critical Findings</h2>
            <pre>$(head -30 "${dir}/vulnerabilities/nuclei/critical.txt" 2>/dev/null || echo "No critical vulnerabilities found")</pre>
        </div>

        <div class="section">
            <h2>High Severity Findings</h2>
            <pre>$(head -30 "${dir}/vulnerabilities/nuclei/high.txt" 2>/dev/null || echo "No high severity vulnerabilities found")</pre>
        </div>

        <div class="section">
            <h2>Confirmed XSS Vulnerabilities</h2>
            <pre>$(head -20 "${dir}/xss/confirmed_xss.txt" 2>/dev/null || echo "No confirmed XSS vulnerabilities")</pre>
        </div>

        <div class="section">
            <h2>Subdomains (Sample)</h2>
            <pre>$(head -50 "${dir}/subdomains/subdomains.txt" 2>/dev/null || echo "No subdomains found")</pre>
        </div>

        <div class="section">
            <h2>Live Web Hosts (Sample)</h2>
            <pre>$(head -50 "${dir}/webs/webs.txt" 2>/dev/null || echo "No live hosts found")</pre>
        </div>

        <footer>
            <p>Generated by Neko v${NEKO_VERSION} | $(date)</p>
        </footer>
    </div>
</body>
</html>
EOF
    
    end_subfunc "HTML report generated" "report_html"
}

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTIVE SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

report_executive_summary() {
    if ! should_run_module "report_summary" "REPORT_SUMMARY"; then
        return 0
    fi
    
    start_subfunc "report_summary" "Generating executive summary"
    
    local summary="${dir}/reports/executive_summary.txt"
    
    # Calculate risk score
    local vuln_critical=$(count_lines "${dir}/vulnerabilities/nuclei/critical.txt")
    local vuln_high=$(count_lines "${dir}/vulnerabilities/nuclei/high.txt")
    local vuln_medium=$(count_lines "${dir}/vulnerabilities/nuclei/medium.txt")
    local xss_count=$(count_lines "${dir}/xss/confirmed_xss.txt")
    local takeover_count=$(count_lines "${dir}/takeover/vulnerable.txt")
    
    local risk_score=$((vuln_critical * 10 + vuln_high * 5 + vuln_medium * 2 + xss_count * 8 + takeover_count * 10))
    
    local risk_level="LOW"
    [[ $risk_score -gt 10 ]] && risk_level="MEDIUM"
    [[ $risk_score -gt 30 ]] && risk_level="HIGH"
    [[ $risk_score -gt 60 ]] && risk_level="CRITICAL"
    
    cat > "$summary" << EOF
═══════════════════════════════════════════════════════════════════════════════
                        NEKO SCAN - EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════════════════

TARGET: ${domain}
SCAN DATE: $(date)
SCAN MODE: ${mode}

───────────────────────────────────────────────────────────────────────────────
                              RISK ASSESSMENT
───────────────────────────────────────────────────────────────────────────────

OVERALL RISK LEVEL: ${risk_level}
RISK SCORE: ${risk_score}/100

───────────────────────────────────────────────────────────────────────────────
                            KEY METRICS
───────────────────────────────────────────────────────────────────────────────

Attack Surface:
  • Subdomains Discovered: $(count_lines "${dir}/subdomains/subdomains.txt")
  • Live Web Applications: $(count_lines "${dir}/webs/webs.txt")
  • Exposed IP Addresses: $(count_lines "${dir}/hosts/ips.txt")
  • Open Ports Found: $(count_lines "${dir}/ports/all_open_ports.txt")

Vulnerability Counts:
  • Critical: ${vuln_critical}
  • High: ${vuln_high}
  • Medium: ${vuln_medium}
  • Low: $(count_lines "${dir}/vulnerabilities/nuclei/low.txt")

High-Impact Findings:
  • Confirmed XSS: ${xss_count}
  • Subdomain Takeover: ${takeover_count}
  • CORS Misconfiguration: $(count_lines "${dir}/vulnerabilities/cors/nuclei_cors.txt")
  • Open Redirects: $(count_lines "${dir}/vulnerabilities/redirect/nuclei_redirect.txt")

───────────────────────────────────────────────────────────────────────────────
                         IMMEDIATE ACTIONS REQUIRED
───────────────────────────────────────────────────────────────────────────────
EOF

    if [[ $vuln_critical -gt 0 ]]; then
        echo "
⚠️  CRITICAL: ${vuln_critical} critical vulnerabilities require immediate attention!
   Review: vulnerabilities/nuclei/critical.txt" >> "$summary"
    fi
    
    if [[ $xss_count -gt 0 ]]; then
        echo "
⚠️  XSS: ${xss_count} confirmed cross-site scripting vulnerabilities!
   Review: xss/confirmed_xss.txt" >> "$summary"
    fi
    
    if [[ $takeover_count -gt 0 ]]; then
        echo "
⚠️  TAKEOVER: ${takeover_count} subdomains vulnerable to takeover!
   Review: takeover/vulnerable.txt" >> "$summary"
    fi
    
    cat >> "$summary" << EOF

───────────────────────────────────────────────────────────────────────────────
                            RECOMMENDATIONS
───────────────────────────────────────────────────────────────────────────────

1. Address all critical and high severity findings immediately
2. Implement proper input validation to prevent XSS attacks
3. Configure security headers on all web applications
4. Remove or properly configure unused subdomains
5. Review and restrict exposed services
6. Implement WAF protection where missing

───────────────────────────────────────────────────────────────────────────────
                         DETAILED REPORTS AVAILABLE
───────────────────────────────────────────────────────────────────────────────

• Full HTML Report: reports/neko_report.html
• Markdown Report: reports/neko_report.md
• JSON Export: reports/neko_report.json
• Nuclei Findings: vulnerabilities/nuclei/findings.json
• XSS POCs: xss/xss_poc_urls.txt

═══════════════════════════════════════════════════════════════════════════════
                    Generated by Neko v${NEKO_VERSION}
═══════════════════════════════════════════════════════════════════════════════
EOF
    
    end_subfunc "Executive summary generated" "report_summary"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

report_notify() {
    log_info "Sending scan completion notification..."
    
    local vuln_critical=$(count_lines "${dir}/vulnerabilities/nuclei/critical.txt")
    local vuln_high=$(count_lines "${dir}/vulnerabilities/nuclei/high.txt")
    local total_subs=$(count_lines "${dir}/subdomains/subdomains.txt")
    local total_webs=$(count_lines "${dir}/webs/webs.txt")
    
    local message="Neko scan completed for ${domain}
━━━━━━━━━━━━━━━━━━━━━
Subdomains: ${total_subs}
Live Hosts: ${total_webs}
Critical Vulns: ${vuln_critical}
High Vulns: ${vuln_high}
━━━━━━━━━━━━━━━━━━━━━
Results: ${dir}/reports/"
    
    notify "$message" "success"
    
    # ProjectDiscovery notify tool
    if [[ "${NOTIFICATION_ENABLED:-false}" == "true" ]] && command_exists notify; then
        echo "$message" | notify -silent -id "neko-scan" 2>/dev/null || true
    fi
}
