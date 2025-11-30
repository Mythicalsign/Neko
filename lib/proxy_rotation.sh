#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO AUTOMATIC PROXY/TOR ROTATION SYSTEM
# Intelligent proxy management with Tor integration
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

declare -ga PROXY_LIST
declare -g CURRENT_PROXY=""
declare -g PROXY_INDEX=0
declare -g TOR_ENABLED=false
declare -g TOR_CONTROL_PORT=9051
declare -g TOR_SOCKS_PORT=9050
declare -g PROXY_ROTATION_INTERVAL=300  # seconds
declare -g PROXY_FAILURE_THRESHOLD=3
declare -g PROXY_CHECK_URL="https://api.ipify.org"

# Proxy health tracking
declare -gA PROXY_HEALTH
declare -gA PROXY_FAILURES

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

proxy_init() {
    local config_file="${1:-${SCRIPTPATH}/config/proxies.txt}"
    
    # Load proxies from file
    if [[ -f "$config_file" ]]; then
        while IFS= read -r proxy; do
            [[ -z "$proxy" ]] && continue
            [[ "$proxy" =~ ^# ]] && continue
            PROXY_LIST+=("$proxy")
        done < "$config_file"
    fi
    
    # Check for environment proxies
    [[ -n "${HTTP_PROXY:-}" ]] && PROXY_LIST+=("$HTTP_PROXY")
    [[ -n "${HTTPS_PROXY:-}" ]] && PROXY_LIST+=("$HTTPS_PROXY")
    
    # Initialize Tor if available
    tor_init
    
    log_info "Proxy system initialized with ${#PROXY_LIST[@]} proxies"
    [[ "$TOR_ENABLED" == "true" ]] && log_info "Tor integration enabled"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOR INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

tor_init() {
    # Check if Tor is installed and running
    if ! command_exists tor; then
        log_debug "Tor not installed"
        return 1
    fi
    
    # Check if Tor is running
    if pgrep -x "tor" > /dev/null; then
        TOR_ENABLED=true
        log_debug "Tor daemon detected"
    else
        # Try to start Tor
        if [[ -f "/etc/tor/torrc" ]]; then
            log_info "Attempting to start Tor..."
            tor --quiet &
            sleep 5
            if pgrep -x "tor" > /dev/null; then
                TOR_ENABLED=true
                log_success "Tor started successfully"
            fi
        fi
    fi
    
    if [[ "$TOR_ENABLED" == "true" ]]; then
        # Add Tor as a proxy option
        PROXY_LIST+=("socks5://127.0.0.1:${TOR_SOCKS_PORT}")
    fi
}

# Rotate Tor circuit (new identity)
tor_new_identity() {
    if [[ "$TOR_ENABLED" != "true" ]]; then
        return 1
    fi
    
    # Check for Tor control authentication
    local tor_auth="${TOR_CONTROL_PASSWORD:-}"
    
    if command_exists tor-ctrl; then
        tor-ctrl NEWNYM 2>/dev/null && log_debug "Tor circuit rotated" && return 0
    fi
    
    # Manual control port connection
    if [[ -n "$tor_auth" ]]; then
        (
            echo "AUTHENTICATE \"$tor_auth\""
            echo "SIGNAL NEWNYM"
            echo "QUIT"
        ) | nc -q 1 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null && log_debug "Tor circuit rotated"
    else
        # Try without authentication
        (
            echo "AUTHENTICATE"
            echo "SIGNAL NEWNYM"
            echo "QUIT"
        ) | nc -q 1 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null
    fi
    
    # Wait for new circuit
    sleep 5
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Get current proxy
proxy_get_current() {
    echo "${CURRENT_PROXY:-}"
}

# Set current proxy
proxy_set() {
    local proxy="$1"
    CURRENT_PROXY="$proxy"
    
    # Export for subprocesses
    if [[ "$proxy" == socks* ]]; then
        export ALL_PROXY="$proxy"
        export http_proxy=""
        export https_proxy=""
    else
        export http_proxy="$proxy"
        export https_proxy="$proxy"
        export HTTP_PROXY="$proxy"
        export HTTPS_PROXY="$proxy"
        export ALL_PROXY=""
    fi
    
    log_debug "Proxy set to: $proxy"
}

# Clear proxy settings
proxy_clear() {
    CURRENT_PROXY=""
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
    log_debug "Proxy cleared"
}

# Check proxy health
proxy_check() {
    local proxy="$1"
    local timeout="${2:-10}"
    
    local curl_opts="-s -m $timeout -o /dev/null -w '%{http_code}'"
    
    if [[ "$proxy" == socks* ]]; then
        curl_opts+=" --socks5-hostname ${proxy#socks*://}"
    else
        curl_opts+=" -x $proxy"
    fi
    
    local status=$(eval "curl $curl_opts '$PROXY_CHECK_URL'" 2>/dev/null)
    
    if [[ "$status" == "200" ]]; then
        PROXY_HEALTH["$proxy"]="healthy"
        PROXY_FAILURES["$proxy"]=0
        return 0
    else
        PROXY_HEALTH["$proxy"]="unhealthy"
        ((PROXY_FAILURES["$proxy"]++)) || PROXY_FAILURES["$proxy"]=1
        return 1
    fi
}

# Get proxy IP (for verification)
proxy_get_ip() {
    local proxy="${1:-$CURRENT_PROXY}"
    
    if [[ -z "$proxy" ]]; then
        curl -s "$PROXY_CHECK_URL" 2>/dev/null
    elif [[ "$proxy" == socks* ]]; then
        curl -s --socks5-hostname "${proxy#socks*://}" "$PROXY_CHECK_URL" 2>/dev/null
    else
        curl -s -x "$proxy" "$PROXY_CHECK_URL" 2>/dev/null
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY ROTATION
# ═══════════════════════════════════════════════════════════════════════════════

# Rotate to next proxy
proxy_rotate() {
    if [[ ${#PROXY_LIST[@]} -eq 0 ]]; then
        log_warning "No proxies available for rotation"
        return 1
    fi
    
    local max_attempts=${#PROXY_LIST[@]}
    local attempts=0
    
    while [[ $attempts -lt $max_attempts ]]; do
        PROXY_INDEX=$(( (PROXY_INDEX + 1) % ${#PROXY_LIST[@]} ))
        local next_proxy="${PROXY_LIST[$PROXY_INDEX]}"
        
        # Check if proxy is healthy
        if [[ "${PROXY_FAILURES[$next_proxy]:-0}" -lt "$PROXY_FAILURE_THRESHOLD" ]]; then
            if proxy_check "$next_proxy"; then
                proxy_set "$next_proxy"
                log_info "Rotated to proxy: $next_proxy (IP: $(proxy_get_ip))"
                return 0
            fi
        fi
        
        ((attempts++))
    done
    
    log_error "No healthy proxies available"
    return 1
}

# Smart rotation based on load and health
proxy_smart_rotate() {
    local reason="${1:-scheduled}"
    
    log_debug "Smart rotation triggered: $reason"
    
    # If using Tor, try to get new circuit first
    if [[ "$CURRENT_PROXY" == *":${TOR_SOCKS_PORT}"* ]]; then
        tor_new_identity
        local new_ip=$(proxy_get_ip)
        log_info "Tor new identity: $new_ip"
        return 0
    fi
    
    # Regular proxy rotation
    proxy_rotate
}

# Automatic rotation daemon
proxy_rotation_daemon() {
    local interval="${1:-$PROXY_ROTATION_INTERVAL}"
    
    log_info "Starting proxy rotation daemon (interval: ${interval}s)"
    
    while true; do
        sleep "$interval"
        proxy_smart_rotate "scheduled"
    done &
    
    echo "$!" > "${dir}/.tmp/proxy_daemon.pid"
}

# Stop rotation daemon
proxy_rotation_stop() {
    local pid_file="${dir}/.tmp/proxy_daemon.pid"
    if [[ -f "$pid_file" ]]; then
        kill "$(cat "$pid_file")" 2>/dev/null || true
        rm -f "$pid_file"
        log_debug "Proxy rotation daemon stopped"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY-AWARE EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

# Execute command with proxy
proxy_exec() {
    local cmd="$@"
    
    if [[ -z "$CURRENT_PROXY" ]]; then
        eval "$cmd"
        return $?
    fi
    
    local proxy_opt=""
    
    # Determine proxy option based on command
    if [[ "$cmd" == curl* ]]; then
        if [[ "$CURRENT_PROXY" == socks* ]]; then
            proxy_opt="--socks5-hostname ${CURRENT_PROXY#socks*://}"
        else
            proxy_opt="-x $CURRENT_PROXY"
        fi
        eval "${cmd/ curl / curl $proxy_opt }"
    elif [[ "$cmd" == wget* ]]; then
        eval "$cmd --proxy=on -e use_proxy=yes -e http_proxy=$CURRENT_PROXY -e https_proxy=$CURRENT_PROXY"
    else
        # Use environment variables for other commands
        eval "$cmd"
    fi
}

# Execute with retry on proxy failure
proxy_exec_retry() {
    local max_retries="${1:-3}"
    shift
    local cmd="$@"
    
    local retries=0
    local exit_code=1
    
    while [[ $retries -lt $max_retries ]]; do
        proxy_exec "$cmd"
        exit_code=$?
        
        if [[ $exit_code -eq 0 ]]; then
            return 0
        fi
        
        log_warning "Command failed with proxy, rotating and retrying..."
        proxy_smart_rotate "failure"
        ((retries++))
        sleep 2
    done
    
    return $exit_code
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL-SPECIFIC PROXY WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════

# Get proxy flags for common tools
proxy_flags_curl() {
    if [[ -z "$CURRENT_PROXY" ]]; then
        echo ""
    elif [[ "$CURRENT_PROXY" == socks* ]]; then
        echo "--socks5-hostname ${CURRENT_PROXY#socks*://}"
    else
        echo "-x $CURRENT_PROXY"
    fi
}

proxy_flags_httpx() {
    if [[ -n "$CURRENT_PROXY" ]]; then
        echo "-proxy $CURRENT_PROXY"
    fi
}

proxy_flags_nuclei() {
    if [[ -n "$CURRENT_PROXY" ]]; then
        echo "-proxy $CURRENT_PROXY"
    fi
}

proxy_flags_ffuf() {
    if [[ -n "$CURRENT_PROXY" ]]; then
        echo "-x $CURRENT_PROXY"
    fi
}

proxy_flags_sqlmap() {
    if [[ -n "$CURRENT_PROXY" ]]; then
        echo "--proxy=$CURRENT_PROXY"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY LIST MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Add proxy to list
proxy_add() {
    local proxy="$1"
    
    # Validate proxy format
    if [[ ! "$proxy" =~ ^(http|https|socks4|socks5)://[^:]+:[0-9]+$ ]]; then
        log_warning "Invalid proxy format: $proxy"
        return 1
    fi
    
    PROXY_LIST+=("$proxy")
    log_debug "Proxy added: $proxy"
}

# Remove proxy from list
proxy_remove() {
    local proxy="$1"
    local new_list=()
    
    for p in "${PROXY_LIST[@]}"; do
        [[ "$p" != "$proxy" ]] && new_list+=("$p")
    done
    
    PROXY_LIST=("${new_list[@]}")
    log_debug "Proxy removed: $proxy"
}

# Fetch and update proxy list from online sources
proxy_update_list() {
    log_info "Updating proxy list from online sources..."
    
    local temp_file="${dir}/.tmp/new_proxies.txt"
    
    # Fetch from multiple sources
    # Source 1: Free proxy list API
    curl -sL "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=elite" \
        >> "$temp_file" 2>/dev/null || true
    
    # Source 2: Another free proxy source
    curl -sL "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt" | head -50 \
        >> "$temp_file" 2>/dev/null || true
    
    # Add http:// prefix and validate
    local added=0
    while IFS= read -r proxy; do
        [[ -z "$proxy" ]] && continue
        [[ "$proxy" != http* ]] && proxy="http://$proxy"
        
        if proxy_check "$proxy" 5; then
            proxy_add "$proxy"
            ((added++))
        fi
    done < "$temp_file"
    
    rm -f "$temp_file"
    log_success "Added $added working proxies"
}

# Check all proxies health
proxy_health_check() {
    log_info "Checking health of ${#PROXY_LIST[@]} proxies..."
    
    local healthy=0
    local unhealthy=0
    
    for proxy in "${PROXY_LIST[@]}"; do
        if proxy_check "$proxy" 10; then
            ((healthy++))
        else
            ((unhealthy++))
        fi
    done
    
    log_info "Proxy health: $healthy healthy, $unhealthy unhealthy"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STATISTICS AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

proxy_stats() {
    cat << EOF
Proxy System Statistics:
═══════════════════════════════════════════════════════════════════════════════
  Total Proxies:     ${#PROXY_LIST[@]}
  Current Proxy:     ${CURRENT_PROXY:-none}
  Current IP:        $(proxy_get_ip)
  Tor Enabled:       $TOR_ENABLED
  Rotation Interval: ${PROXY_ROTATION_INTERVAL}s

Proxy Health:
EOF
    
    for proxy in "${PROXY_LIST[@]}"; do
        local health="${PROXY_HEALTH[$proxy]:-unknown}"
        local failures="${PROXY_FAILURES[$proxy]:-0}"
        local status_color="${health/healthy/${GREEN}healthy${RESET}}"
        status_color="${status_color/unhealthy/${RED}unhealthy${RESET}}"
        echo "  - $proxy: ${health} (failures: $failures)"
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

proxy_cleanup() {
    proxy_rotation_stop
    proxy_clear
    log_debug "Proxy system cleaned up"
}
