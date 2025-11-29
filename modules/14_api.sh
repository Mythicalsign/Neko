#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 14: API SECURITY TESTING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Modern API-focused testing
# Tools: nuclei, kiterunner, wfuzz, mitmproxy2swagger
# ═══════════════════════════════════════════════════════════════════════════════

api_main() {
    log_phase "PHASE 14: API SECURITY TESTING"
    
    if ! should_run_module "api_main" "API_ENABLED"; then
        return 0
    fi
    
    start_func "api_main" "Starting API Security Testing"
    
    ensure_dir "${dir}/api"
    ensure_dir "${dir}/.tmp/api"
    
    # Run API security functions
    api_swagger_discovery
    api_endpoint_discovery
    api_graphql_testing
    api_fuzzing
    api_aggregate
    
    end_func "API security testing completed. Results in ${dir}/api/" "api_main"
}

api_swagger_discovery() {
    if ! should_run_module "api_swagger" "API_SWAGGER"; then
        return 0
    fi
    
    start_subfunc "api_swagger" "Discovering Swagger/OpenAPI endpoints"
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        log_warning "No web hosts for API discovery"
        return 0
    fi
    
    # Common Swagger/OpenAPI paths
    local swagger_paths=(
        "/swagger.json"
        "/swagger/v1/swagger.json"
        "/swagger/v2/swagger.json"
        "/api/swagger.json"
        "/api-docs"
        "/api-docs.json"
        "/v1/api-docs"
        "/v2/api-docs"
        "/openapi.json"
        "/openapi.yaml"
        "/api/openapi.json"
        "/docs"
        "/redoc"
        "/swagger-ui.html"
        "/swagger-ui/"
        "/api/swagger-ui.html"
        "/.well-known/openapi.json"
    )
    
    log_info "Checking for Swagger/OpenAPI endpoints..."
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        for path in "${swagger_paths[@]}"; do
            local full_url="${url}${path}"
            local status=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$full_url" 2>/dev/null)
            
            if [[ "$status" == "200" ]]; then
                echo "$full_url" >> "${dir}/api/swagger_endpoints.txt"
            fi
        done
    done < <(head -n 50 "${dir}/webs/webs.txt")
    
    # Download discovered swagger specs
    if [[ -s "${dir}/api/swagger_endpoints.txt" ]]; then
        ensure_dir "${dir}/api/swagger_specs"
        while IFS= read -r swagger_url; do
            local safe_name=$(echo "$swagger_url" | md5sum | cut -d' ' -f1)
            curl -sL -m 30 "$swagger_url" > "${dir}/api/swagger_specs/${safe_name}.json" 2>/dev/null || true
        done < "${dir}/api/swagger_endpoints.txt"
    fi
    
    local swagger_count=$(count_lines "${dir}/api/swagger_endpoints.txt")
    end_subfunc "Found $swagger_count Swagger/OpenAPI endpoints" "api_swagger"
}

api_endpoint_discovery() {
    if ! should_run_module "api_endpoints" "API_ENDPOINTS"; then
        return 0
    fi
    
    start_subfunc "api_endpoints" "Discovering API endpoints"
    
    # kiterunner for API route discovery
    if command_exists kr && [[ -s "${dir}/webs/webs.txt" ]]; then
        log_info "Running kiterunner..."
        
        head -n 20 "${dir}/webs/webs.txt" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            kr scan "$url" \
                -w "${TOOLS_PATH}/wordlists/api-endpoints.txt" \
                -o "${dir}/api/kiterunner_results.txt" \
                2>> "$LOGFILE" || true
        done
    fi
    
    # Extract API-like URLs from discovered URLs
    if [[ -s "${dir}/urls/urls.txt" ]]; then
        grep -iE "/api/|/v[0-9]/|/graphql|/rest/|/json|/xml" "${dir}/urls/urls.txt" | \
            sort -u > "${dir}/api/api_urls.txt" 2>/dev/null || true
    fi
    
    # nuclei API templates
    if command_exists nuclei && [[ -s "${dir}/api/api_urls.txt" ]]; then
        log_info "Running nuclei API templates..."
        nuclei -l "${dir}/api/api_urls.txt" \
            -tags api \
            -c 10 \
            -silent \
            -o "${dir}/api/nuclei_api.txt" \
            2>> "$LOGFILE" || true
    fi
    
    end_subfunc "API endpoint discovery completed" "api_endpoints"
}

api_graphql_testing() {
    if ! should_run_module "api_graphql" "API_GRAPHQL"; then
        return 0
    fi
    
    start_subfunc "api_graphql" "Testing GraphQL endpoints"
    
    if [[ ! -s "${dir}/webs/webs.txt" ]]; then
        return 0
    fi
    
    # Common GraphQL paths
    local graphql_paths=(
        "/graphql"
        "/graphql/console"
        "/graphql/api"
        "/graphql/v1"
        "/api/graphql"
        "/v1/graphql"
        "/gql"
        "/query"
    )
    
    log_info "Checking for GraphQL endpoints..."
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        for path in "${graphql_paths[@]}"; do
            local full_url="${url}${path}"
            
            # Try introspection query
            local response=$(curl -sX POST \
                -H "Content-Type: application/json" \
                -d '{"query":"query{__typename}"}' \
                -m 10 \
                "$full_url" 2>/dev/null)
            
            if echo "$response" | grep -q "__typename\|data\|Query"; then
                echo "$full_url" >> "${dir}/api/graphql_endpoints.txt"
                
                # Try full introspection
                curl -sX POST \
                    -H "Content-Type: application/json" \
                    -d '{"query":"query{__schema{types{name,fields{name}}}}"}' \
                    -m 30 \
                    "$full_url" > "${dir}/api/graphql_schema_$(echo "$full_url" | md5sum | cut -d' ' -f1).json" 2>/dev/null || true
            fi
        done
    done < <(head -n 30 "${dir}/webs/webs.txt")
    
    # nuclei GraphQL templates
    if command_exists nuclei && [[ -s "${dir}/api/graphql_endpoints.txt" ]]; then
        nuclei -l "${dir}/api/graphql_endpoints.txt" \
            -tags graphql \
            -c 10 \
            -silent \
            -o "${dir}/api/nuclei_graphql.txt" \
            2>> "$LOGFILE" || true
    fi
    
    local graphql_count=$(count_lines "${dir}/api/graphql_endpoints.txt")
    end_subfunc "Found $graphql_count GraphQL endpoints" "api_graphql"
}

api_fuzzing() {
    start_subfunc "api_fuzzing" "Fuzzing API endpoints"
    
    if ! command_exists ffuf; then
        log_warning "ffuf not installed for API fuzzing"
        return 0
    fi
    
    if [[ ! -s "${dir}/api/api_urls.txt" ]]; then
        log_warning "No API URLs for fuzzing"
        return 0
    fi
    
    # Fuzz API endpoints with common params
    local api_params="id,user,username,email,password,token,api_key,key,secret,file,path,url,redirect,callback,next,return,continue"
    
    head -n 10 "${dir}/api/api_urls.txt" | while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        ffuf -u "${url}?FUZZ=test" \
            -w <(echo "$api_params" | tr ',' '\n') \
            -t 20 \
            -mc all \
            -fc 404 \
            -sf \
            >> "${dir}/api/api_fuzz_results.txt" 2>> "$LOGFILE" || true
    done
    
    end_subfunc "API fuzzing completed" "api_fuzzing"
}

api_aggregate() {
    log_info "Aggregating API security results..."
    
    local summary="${dir}/api/api_summary.txt"
    
    cat > "$summary" << EOF
API Security Testing Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Swagger/OpenAPI Endpoints: $(count_lines "${dir}/api/swagger_endpoints.txt")
$(cat "${dir}/api/swagger_endpoints.txt" 2>/dev/null | head -10 || echo "None")

GraphQL Endpoints: $(count_lines "${dir}/api/graphql_endpoints.txt")
$(cat "${dir}/api/graphql_endpoints.txt" 2>/dev/null || echo "None")

API URLs Discovered: $(count_lines "${dir}/api/api_urls.txt")

Nuclei API Findings:
$(cat "${dir}/api/nuclei_api.txt" 2>/dev/null | head -10 || echo "None")

Nuclei GraphQL Findings:
$(cat "${dir}/api/nuclei_graphql.txt" 2>/dev/null || echo "None")

Detailed results in ${dir}/api/
EOF
    
    log_success "API aggregation completed"
}
