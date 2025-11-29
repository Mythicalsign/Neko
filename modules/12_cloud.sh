#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 12: CLOUD & INFRASTRUCTURE SECURITY
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Cloud-specific vulnerabilities
# Tools: S3Scanner, CloudHunter, cloud_enum
# ═══════════════════════════════════════════════════════════════════════════════

cloud_main() {
    log_phase "PHASE 12: CLOUD & INFRASTRUCTURE SECURITY"
    
    if ! should_run_module "cloud_main" "CLOUD_ENABLED"; then
        return 0
    fi
    
    start_func "cloud_main" "Starting Cloud Security Testing"
    
    ensure_dir "${dir}/cloud"
    ensure_dir "${dir}/.tmp/cloud"
    
    # Run cloud security functions
    cloud_s3_buckets
    cloud_azure_blobs
    cloud_gcp_buckets
    cloud_enum
    cloud_aggregate
    
    end_func "Cloud security testing completed. Results in ${dir}/cloud/" "cloud_main"
}

cloud_s3_buckets() {
    if ! should_run_module "cloud_s3" "CLOUD_S3"; then
        return 0
    fi
    
    start_subfunc "cloud_s3" "Scanning for S3 bucket misconfigurations"
    
    # Generate potential bucket names
    local company_name=$(echo "$domain" | sed 's/\..*//')
    
    cat > "${dir}/.tmp/cloud/bucket_names.txt" << EOF
${company_name}
${company_name}-backup
${company_name}-dev
${company_name}-prod
${company_name}-staging
${company_name}-assets
${company_name}-media
${company_name}-uploads
${company_name}-data
${company_name}-logs
${company_name}-static
${company_name}-files
${company_name}-cdn
${company_name}-public
${company_name}-private
backup-${company_name}
dev-${company_name}
prod-${company_name}
www-${company_name}
api-${company_name}
EOF
    
    # S3Scanner
    if command_exists s3scanner; then
        log_info "Running S3Scanner..."
        s3scanner scan -b "${dir}/.tmp/cloud/bucket_names.txt" \
            -o "${dir}/cloud/s3scanner_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    # CloudHunter
    if [[ -f "${TOOLS_PATH}/CloudHunter/cloudhunter.py" ]]; then
        log_info "Running CloudHunter..."
        run_python_tool "${TOOLS_PATH}/CloudHunter" \
            -k "$company_name" \
            -o "${dir}/cloud/cloudhunter_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    # nuclei cloud templates
    if command_exists nuclei && [[ -s "${dir}/subdomains/subdomains.txt" ]]; then
        log_info "Running nuclei cloud templates..."
        nuclei -l "${dir}/subdomains/subdomains.txt" \
            -tags cloud,aws,s3 \
            -c 10 \
            -silent \
            -o "${dir}/cloud/nuclei_cloud.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "S3 bucket scanning completed" "cloud_s3"
}

cloud_azure_blobs() {
    if ! should_run_module "cloud_azure" "CLOUD_AZURE"; then
        return 0
    fi
    
    start_subfunc "cloud_azure" "Scanning for Azure blob misconfigurations"
    
    local company_name=$(echo "$domain" | sed 's/\..*//')
    
    # Generate Azure storage account names
    cat > "${dir}/.tmp/cloud/azure_names.txt" << EOF
${company_name}
${company_name}storage
${company_name}blob
${company_name}data
${company_name}backup
${company_name}dev
${company_name}prod
EOF
    
    # Check Azure blob endpoints
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local endpoint="https://${name}.blob.core.windows.net"
        local status=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$endpoint" 2>/dev/null)
        if [[ "$status" != "000" ]] && [[ "$status" != "404" ]]; then
            echo "$endpoint - HTTP $status" >> "${dir}/cloud/azure_blobs.txt"
        fi
    done < "${dir}/.tmp/cloud/azure_names.txt"
    
    end_subfunc "Azure blob scanning completed" "cloud_azure"
}

cloud_gcp_buckets() {
    if ! should_run_module "cloud_gcp" "CLOUD_GCP"; then
        return 0
    fi
    
    start_subfunc "cloud_gcp" "Scanning for GCP bucket misconfigurations"
    
    local company_name=$(echo "$domain" | sed 's/\..*//')
    
    # Check GCP bucket endpoints
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local endpoint="https://storage.googleapis.com/${name}"
        local status=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$endpoint" 2>/dev/null)
        if [[ "$status" != "000" ]] && [[ "$status" != "404" ]]; then
            echo "$endpoint - HTTP $status" >> "${dir}/cloud/gcp_buckets.txt"
        fi
    done < "${dir}/.tmp/cloud/bucket_names.txt"
    
    end_subfunc "GCP bucket scanning completed" "cloud_gcp"
}

cloud_enum() {
    if ! should_run_module "cloud_enum" "CLOUD_ENUM"; then
        return 0
    fi
    
    start_subfunc "cloud_enum" "Running cloud service enumeration"
    
    # cloud_enum tool
    if command_exists cloud_enum; then
        log_info "Running cloud_enum..."
        local company_name=$(echo "$domain" | sed 's/\..*//')
        cloud_enum -k "$company_name" \
            -l "${dir}/cloud/cloud_enum_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "Cloud enumeration completed" "cloud_enum"
}

cloud_aggregate() {
    log_info "Aggregating cloud security results..."
    
    local summary="${dir}/cloud/cloud_summary.txt"
    
    cat > "$summary" << EOF
Cloud Security Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

S3 Bucket Findings:
$(cat "${dir}/cloud/s3scanner_results.txt" 2>/dev/null | head -20 || echo "None")

Azure Blob Findings:
$(cat "${dir}/cloud/azure_blobs.txt" 2>/dev/null || echo "None")

GCP Bucket Findings:
$(cat "${dir}/cloud/gcp_buckets.txt" 2>/dev/null || echo "None")

Nuclei Cloud Findings:
$(cat "${dir}/cloud/nuclei_cloud.txt" 2>/dev/null || echo "None")

Detailed results in ${dir}/cloud/
EOF
    
    log_success "Cloud aggregation completed"
}
