#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO DATA FLOW BUS
# Inter-tool communication and data sharing system
# Enables tools to share results and work in tandem
# Version: 2.0.0
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# DATA BUS CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

declare -g DATA_BUS_DIR=""
declare -g DATA_BUS_REGISTRY=""
declare -gA DATA_BUS_CHANNELS
declare -gA DATA_BUS_SUBSCRIBERS
declare -gA DATA_BUS_PRODUCERS
declare -gA DATA_BUS_CACHE

# Data types
readonly DATA_TYPE_SUBDOMAINS="subdomains"
readonly DATA_TYPE_HOSTS="hosts"
readonly DATA_TYPE_IPS="ips"
readonly DATA_TYPE_URLS="urls"
readonly DATA_TYPE_PARAMS="parameters"
readonly DATA_TYPE_VULNS="vulnerabilities"
readonly DATA_TYPE_SECRETS="secrets"
readonly DATA_TYPE_TECH="technologies"
readonly DATA_TYPE_PORTS="ports"
readonly DATA_TYPE_ENDPOINTS="endpoints"
readonly DATA_TYPE_GRAPHQL="graphql"
readonly DATA_TYPE_WEBSOCKETS="websockets"
readonly DATA_TYPE_JS_FILES="js_files"
readonly DATA_TYPE_CREDENTIALS="credentials"

# Channel definitions: [channel_name]="data_type:format:description"
declare -gA DATA_BUS_CHANNEL_DEFS=(
    ["subdomain_discovery"]="${DATA_TYPE_SUBDOMAINS}:txt:Discovered subdomains from all sources"
    ["resolved_hosts"]="${DATA_TYPE_HOSTS}:txt:DNS resolved hosts"
    ["live_hosts"]="${DATA_TYPE_HOSTS}:txt:HTTP probed live hosts"
    ["target_ips"]="${DATA_TYPE_IPS}:txt:Target IP addresses"
    ["open_ports"]="${DATA_TYPE_PORTS}:json:Discovered open ports"
    ["web_urls"]="${DATA_TYPE_URLS}:txt:Discovered web URLs"
    ["param_urls"]="${DATA_TYPE_PARAMS}:txt:URLs with parameters"
    ["js_endpoints"]="${DATA_TYPE_JS_FILES}:txt:JavaScript file URLs"
    ["api_endpoints"]="${DATA_TYPE_ENDPOINTS}:txt:API endpoints"
    ["graphql_endpoints"]="${DATA_TYPE_GRAPHQL}:txt:GraphQL endpoints"
    ["websocket_endpoints"]="${DATA_TYPE_WEBSOCKETS}:txt:WebSocket endpoints"
    ["technologies"]="${DATA_TYPE_TECH}:json:Detected technologies"
    ["vulnerabilities"]="${DATA_TYPE_VULNS}:json:Discovered vulnerabilities"
    ["secrets"]="${DATA_TYPE_SECRETS}:txt:Discovered secrets"
    ["credentials"]="${DATA_TYPE_CREDENTIALS}:json:Discovered credentials"
    ["xss_targets"]="${DATA_TYPE_PARAMS}:txt:Potential XSS targets"
    ["sqli_targets"]="${DATA_TYPE_PARAMS}:txt:Potential SQLi targets"
    ["ssrf_targets"]="${DATA_TYPE_PARAMS}:txt:Potential SSRF targets"
    ["lfi_targets"]="${DATA_TYPE_PARAMS}:txt:Potential LFI targets"
)

# Tool to channel mapping (what each tool produces and consumes)
declare -gA TOOL_PRODUCES=(
    ["subfinder"]="subdomain_discovery"
    ["amass"]="subdomain_discovery"
    ["assetfinder"]="subdomain_discovery"
    ["dnsx"]="resolved_hosts,target_ips"
    ["httpx"]="live_hosts,technologies"
    ["nmap"]="open_ports"
    ["masscan"]="open_ports"
    ["katana"]="web_urls,js_endpoints"
    ["gau"]="web_urls,param_urls"
    ["waybackurls"]="web_urls,param_urls"
    ["arjun"]="param_urls"
    ["nuclei"]="vulnerabilities"
    ["dalfox"]="vulnerabilities"
    ["sqlmap"]="vulnerabilities"
    ["bettercap"]="target_ips,credentials"
    ["gf"]="xss_targets,sqli_targets,ssrf_targets,lfi_targets"
    ["trufflehog"]="secrets"
    ["gitleaks"]="secrets"
)

declare -gA TOOL_CONSUMES=(
    ["dnsx"]="subdomain_discovery"
    ["httpx"]="resolved_hosts,subdomain_discovery"
    ["nmap"]="target_ips,resolved_hosts"
    ["masscan"]="target_ips"
    ["katana"]="live_hosts"
    ["nuclei"]="live_hosts,web_urls,param_urls"
    ["dalfox"]="xss_targets,param_urls"
    ["sqlmap"]="sqli_targets,param_urls"
    ["ffuf"]="live_hosts"
    ["arjun"]="live_hosts"
    ["bettercap"]="target_ips"
    ["gf"]="web_urls,param_urls"
)

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

data_bus_init() {
    local base_dir="${1:-${dir}/.data_bus}"
    DATA_BUS_DIR="$base_dir"
    DATA_BUS_REGISTRY="${DATA_BUS_DIR}/registry.json"
    
    ensure_dir "$DATA_BUS_DIR"
    ensure_dir "${DATA_BUS_DIR}/channels"
    ensure_dir "${DATA_BUS_DIR}/cache"
    ensure_dir "${DATA_BUS_DIR}/transforms"
    ensure_dir "${DATA_BUS_DIR}/events"
    
    # Initialize registry
    cat > "$DATA_BUS_REGISTRY" << EOF
{
    "initialized": "$(date -Iseconds)",
    "target": "${domain:-unknown}",
    "channels": {},
    "producers": {},
    "consumers": {},
    "statistics": {
        "total_messages": 0,
        "total_bytes": 0
    }
}
EOF
    
    # Initialize all channels
    for channel in "${!DATA_BUS_CHANNEL_DEFS[@]}"; do
        _data_bus_init_channel "$channel"
    done
    
    # Start event dispatcher
    _data_bus_start_dispatcher &
    
    log_debug "Data Bus initialized at $DATA_BUS_DIR"
}

_data_bus_init_channel() {
    local channel="$1"
    local def="${DATA_BUS_CHANNEL_DEFS[$channel]}"
    
    IFS=':' read -r data_type format description <<< "$def"
    
    local channel_dir="${DATA_BUS_DIR}/channels/${channel}"
    ensure_dir "$channel_dir"
    
    # Create channel metadata
    cat > "${channel_dir}/meta.json" << EOF
{
    "name": "$channel",
    "data_type": "$data_type",
    "format": "$format",
    "description": "$description",
    "created": "$(date -Iseconds)",
    "message_count": 0,
    "last_updated": null,
    "subscribers": [],
    "producers": []
}
EOF
    
    # Create data file
    touch "${channel_dir}/data.${format}"
    
    DATA_BUS_CHANNELS["$channel"]="$channel_dir"
    DATA_BUS_SUBSCRIBERS["$channel"]=""
    DATA_BUS_PRODUCERS["$channel"]=""
}

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLISH / SUBSCRIBE
# ═══════════════════════════════════════════════════════════════════════════════

# Publish data to a channel
data_bus_publish() {
    local channel="$1"
    local data="$2"
    local producer="${3:-unknown}"
    local append="${4:-true}"  # true to append, false to replace
    
    local channel_dir="${DATA_BUS_CHANNELS[$channel]}"
    
    if [[ -z "$channel_dir" ]] || [[ ! -d "$channel_dir" ]]; then
        log_error "Unknown channel: $channel"
        return 1
    fi
    
    local def="${DATA_BUS_CHANNEL_DEFS[$channel]}"
    IFS=':' read -r data_type format description <<< "$def"
    
    local data_file="${channel_dir}/data.${format}"
    local timestamp=$(date -Iseconds)
    
    # Validate and transform data if needed
    data=$(_data_bus_validate_and_transform "$data" "$data_type" "$format")
    
    # Write data
    if [[ "$append" == "true" ]]; then
        if [[ "$format" == "json" ]]; then
            # For JSON, merge with existing data
            if [[ -s "$data_file" ]]; then
                jq -s 'add' "$data_file" <(echo "$data") > "${data_file}.tmp" && mv "${data_file}.tmp" "$data_file"
            else
                echo "$data" > "$data_file"
            fi
        else
            # For text, append unique lines
            echo "$data" | while read line; do
                [[ -z "$line" ]] && continue
                grep -qxF "$line" "$data_file" 2>/dev/null || echo "$line" >> "$data_file"
            done
        fi
    else
        echo "$data" > "$data_file"
    fi
    
    # Update metadata
    jq --arg ts "$timestamp" --arg prod "$producer" '
        .last_updated = $ts |
        .message_count += 1 |
        .producers += [$prod] | .producers |= unique
    ' "${channel_dir}/meta.json" > "${channel_dir}/meta.json.tmp" && \
        mv "${channel_dir}/meta.json.tmp" "${channel_dir}/meta.json"
    
    # Notify subscribers
    _data_bus_notify_subscribers "$channel" "$producer" "$timestamp"
    
    # Update cache
    DATA_BUS_CACHE["${channel}_updated"]="$timestamp"
    
    log_debug "Published to $channel by $producer"
}

# Subscribe to a channel
data_bus_subscribe() {
    local channel="$1"
    local subscriber="$2"
    local callback="${3:-}"  # Optional callback function
    
    local channel_dir="${DATA_BUS_CHANNELS[$channel]}"
    
    if [[ -z "$channel_dir" ]]; then
        log_error "Unknown channel: $channel"
        return 1
    fi
    
    # Add subscriber to channel
    DATA_BUS_SUBSCRIBERS["$channel"]+=" $subscriber"
    
    # Update metadata
    jq --arg sub "$subscriber" '
        .subscribers += [$sub] | .subscribers |= unique
    ' "${channel_dir}/meta.json" > "${channel_dir}/meta.json.tmp" && \
        mv "${channel_dir}/meta.json.tmp" "${channel_dir}/meta.json"
    
    # Store callback if provided
    if [[ -n "$callback" ]]; then
        echo "$callback" > "${channel_dir}/callbacks/${subscriber}.sh"
    fi
    
    log_debug "$subscriber subscribed to $channel"
}

# Get data from a channel
data_bus_get() {
    local channel="$1"
    local format="${2:-raw}"  # raw, file_path, json, lines
    local filter="${3:-}"     # Optional filter/grep pattern
    
    local channel_dir="${DATA_BUS_CHANNELS[$channel]}"
    
    if [[ -z "$channel_dir" ]] || [[ ! -d "$channel_dir" ]]; then
        log_error "Unknown channel: $channel"
        return 1
    fi
    
    local def="${DATA_BUS_CHANNEL_DEFS[$channel]}"
    IFS=':' read -r data_type data_format description <<< "$def"
    
    local data_file="${channel_dir}/data.${data_format}"
    
    [[ ! -s "$data_file" ]] && return 0
    
    case "$format" in
        file_path)
            echo "$data_file"
            ;;
        json)
            if [[ "$data_format" == "json" ]]; then
                cat "$data_file"
            else
                # Convert text to JSON array
                jq -Rs 'split("\n") | map(select(length > 0))' "$data_file"
            fi
            ;;
        lines)
            if [[ -n "$filter" ]]; then
                grep -E "$filter" "$data_file" 2>/dev/null || true
            else
                cat "$data_file"
            fi
            ;;
        count)
            wc -l < "$data_file" | tr -d ' '
            ;;
        raw|*)
            if [[ -n "$filter" ]]; then
                grep -E "$filter" "$data_file" 2>/dev/null || true
            else
                cat "$data_file"
            fi
            ;;
    esac
}

# Get file path for a channel's data
data_bus_get_file() {
    local channel="$1"
    data_bus_get "$channel" "file_path"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

# Get input data for a tool from channels it consumes
data_bus_get_tool_input() {
    local tool="$1"
    local input_type="${2:-all}"  # all, primary, merged
    local output_file="${3:-}"    # Optional: write to file instead of stdout
    
    local consumes="${TOOL_CONSUMES[$tool]:-}"
    
    if [[ -z "$consumes" ]]; then
        log_debug "Tool $tool has no defined input channels"
        return 0
    fi
    
    local temp_file=$(mktemp)
    
    IFS=',' read -ra channels <<< "$consumes"
    
    for channel in "${channels[@]}"; do
        channel=$(echo "$channel" | tr -d ' ')
        
        local channel_data=$(data_bus_get "$channel" "lines")
        
        if [[ -n "$channel_data" ]]; then
            echo "$channel_data" >> "$temp_file"
        fi
    done
    
    # Deduplicate
    if [[ -s "$temp_file" ]]; then
        sort -u "$temp_file" -o "$temp_file"
        
        if [[ -n "$output_file" ]]; then
            mv "$temp_file" "$output_file"
            echo "$output_file"
        else
            cat "$temp_file"
            rm -f "$temp_file"
        fi
    else
        rm -f "$temp_file"
    fi
}

# Store tool output to appropriate channels
data_bus_store_tool_output() {
    local tool="$1"
    local output_file="$2"
    local output_type="${3:-}"  # Optional: specify which output type if tool produces multiple
    
    local produces="${TOOL_PRODUCES[$tool]:-}"
    
    if [[ -z "$produces" ]]; then
        log_debug "Tool $tool has no defined output channels"
        return 0
    fi
    
    if [[ ! -s "$output_file" ]]; then
        log_debug "No output to store for $tool"
        return 0
    fi
    
    IFS=',' read -ra channels <<< "$produces"
    
    for channel in "${channels[@]}"; do
        channel=$(echo "$channel" | tr -d ' ')
        
        # If output_type is specified, only publish to matching channel
        if [[ -n "$output_type" ]] && [[ "$channel" != *"$output_type"* ]]; then
            continue
        fi
        
        # Get channel data type to determine if transformation is needed
        local def="${DATA_BUS_CHANNEL_DEFS[$channel]}"
        IFS=':' read -r data_type format description <<< "$def"
        
        # Transform output if needed based on tool and channel
        local transformed_data=$(_data_bus_transform_tool_output "$tool" "$channel" "$output_file")
        
        if [[ -n "$transformed_data" ]]; then
            data_bus_publish "$channel" "$transformed_data" "$tool" "true"
        fi
    done
}

# Transform tool output for specific channel
_data_bus_transform_tool_output() {
    local tool="$1"
    local channel="$2"
    local output_file="$3"
    
    case "${tool}:${channel}" in
        "httpx:live_hosts")
            # Extract URLs from httpx JSON/text output
            if file "$output_file" | grep -q "JSON"; then
                jq -r '.url // .host' "$output_file" 2>/dev/null | sort -u
            else
                cat "$output_file" | awk '{print $1}' | sort -u
            fi
            ;;
        "httpx:technologies")
            # Extract technologies from httpx output
            if file "$output_file" | grep -q "JSON"; then
                jq -r '.tech[]?' "$output_file" 2>/dev/null | sort -u
            else
                grep -oE '\[.*\]' "$output_file" | tr -d '[]' | tr ',' '\n' | sort -u
            fi
            ;;
        "nmap:open_ports"|"masscan:open_ports")
            # Already handled by format
            cat "$output_file"
            ;;
        "katana:web_urls"|"gau:web_urls"|"waybackurls:web_urls")
            # Just URLs
            grep -oE 'https?://[^ "]+' "$output_file" | sort -u
            ;;
        "katana:js_endpoints")
            # Extract JS files
            grep -oE 'https?://[^ "]+\.js[^"]*' "$output_file" | sort -u
            ;;
        "gf:xss_targets"|"gf:sqli_targets"|"gf:ssrf_targets"|"gf:lfi_targets")
            # GF pattern output is already URLs
            cat "$output_file" | sort -u
            ;;
        *)
            # Default: return as-is
            cat "$output_file"
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA TRANSFORMATION
# ═══════════════════════════════════════════════════════════════════════════════

_data_bus_validate_and_transform() {
    local data="$1"
    local data_type="$2"
    local format="$3"
    
    case "$data_type" in
        "$DATA_TYPE_SUBDOMAINS"|"$DATA_TYPE_HOSTS")
            # Validate domain format
            echo "$data" | grep -oE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$' || echo "$data"
            ;;
        "$DATA_TYPE_IPS")
            # Validate IP format
            echo "$data" | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || echo "$data"
            ;;
        "$DATA_TYPE_URLS")
            # Validate URL format
            echo "$data" | grep -oE '^https?://[^ ]+$' || echo "$data"
            ;;
        *)
            echo "$data"
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# EVENT SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

_data_bus_notify_subscribers() {
    local channel="$1"
    local producer="$2"
    local timestamp="$3"
    
    local subscribers="${DATA_BUS_SUBSCRIBERS[$channel]}"
    
    [[ -z "$subscribers" ]] && return 0
    
    # Write event to event log
    local event_file="${DATA_BUS_DIR}/events/events.jsonl"
    cat >> "$event_file" << EOF
{"channel":"$channel","producer":"$producer","timestamp":"$timestamp","type":"publish"}
EOF
    
    # Trigger callbacks for subscribers
    local channel_dir="${DATA_BUS_CHANNELS[$channel]}"
    
    for subscriber in $subscribers; do
        local callback_file="${channel_dir}/callbacks/${subscriber}.sh"
        
        if [[ -f "$callback_file" ]]; then
            local callback=$(cat "$callback_file")
            # Execute callback in background
            (eval "$callback '$channel' '$producer' '$timestamp'" 2>/dev/null) &
        fi
    done
}

_data_bus_start_dispatcher() {
    local event_fifo="${DATA_BUS_DIR}/events/dispatcher.fifo"
    
    [[ -p "$event_fifo" ]] || mkfifo "$event_fifo"
    
    # Simple event dispatcher
    while [[ -d "$DATA_BUS_DIR" ]]; do
        if read -t 1 event < "$event_fifo" 2>/dev/null; then
            # Process event
            log_debug "Data Bus Event: $event"
        fi
        sleep 0.1
    done 2>/dev/null &
}

# ═══════════════════════════════════════════════════════════════════════════════
# CHANNEL OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Merge multiple channels into one
data_bus_merge_channels() {
    local target_channel="$1"
    shift
    local source_channels=("$@")
    
    local merged_data=""
    
    for channel in "${source_channels[@]}"; do
        local channel_data=$(data_bus_get "$channel" "lines")
        [[ -n "$channel_data" ]] && merged_data+="$channel_data"$'\n'
    done
    
    if [[ -n "$merged_data" ]]; then
        merged_data=$(echo "$merged_data" | sort -u)
        data_bus_publish "$target_channel" "$merged_data" "merge_operation" "false"
    fi
}

# Filter channel data
data_bus_filter() {
    local channel="$1"
    local filter_type="$2"  # include, exclude, regex
    local pattern="$3"
    
    local data=$(data_bus_get "$channel" "lines")
    
    case "$filter_type" in
        include)
            echo "$data" | grep -E "$pattern"
            ;;
        exclude)
            echo "$data" | grep -vE "$pattern"
            ;;
        regex)
            echo "$data" | grep -oE "$pattern"
            ;;
    esac
}

# Get channel statistics
data_bus_channel_stats() {
    local channel="$1"
    
    local channel_dir="${DATA_BUS_CHANNELS[$channel]}"
    
    if [[ -z "$channel_dir" ]] || [[ ! -d "$channel_dir" ]]; then
        echo "{}"
        return
    fi
    
    local def="${DATA_BUS_CHANNEL_DEFS[$channel]}"
    IFS=':' read -r data_type format description <<< "$def"
    
    local data_file="${channel_dir}/data.${format}"
    local line_count=0
    local byte_count=0
    
    if [[ -f "$data_file" ]]; then
        line_count=$(wc -l < "$data_file" | tr -d ' ')
        byte_count=$(wc -c < "$data_file" | tr -d ' ')
    fi
    
    cat "${channel_dir}/meta.json" | jq --argjson lines "$line_count" --argjson bytes "$byte_count" '
        . + {
            "current_lines": $lines,
            "current_bytes": $bytes
        }
    '
}

# ═══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL TOOL WRAPPERS WITH DATA BUS INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

# Run a tool with automatic data bus integration
data_bus_run_tool() {
    local tool="$1"
    shift
    local extra_args="$@"
    
    # Get input from data bus
    local input_file=$(mktemp)
    data_bus_get_tool_input "$tool" "all" "$input_file"
    
    if [[ ! -s "$input_file" ]]; then
        log_warning "No input data for $tool from data bus"
        rm -f "$input_file"
        return 0
    fi
    
    local input_count=$(wc -l < "$input_file" | tr -d ' ')
    log_info "Running $tool with $input_count targets from data bus"
    
    # Create output file
    local output_file=$(mktemp)
    
    # Run tool with input
    case "$tool" in
        httpx)
            httpx -l "$input_file" -o "$output_file" $extra_args 2>> "$LOGFILE" || true
            ;;
        nuclei)
            nuclei -l "$input_file" -o "$output_file" $extra_args 2>> "$LOGFILE" || true
            ;;
        dnsx)
            dnsx -l "$input_file" -o "$output_file" $extra_args 2>> "$LOGFILE" || true
            ;;
        katana)
            katana -list "$input_file" -o "$output_file" $extra_args 2>> "$LOGFILE" || true
            ;;
        dalfox)
            dalfox file "$input_file" -o "$output_file" $extra_args 2>> "$LOGFILE" || true
            ;;
        ffuf)
            # ffuf needs special handling - iterate over targets
            while read target; do
                [[ -z "$target" ]] && continue
                ffuf -u "${target}FUZZ" -o "${output_file}_$(echo "$target" | md5sum | cut -d' ' -f1).json" $extra_args 2>> "$LOGFILE" || true
            done < "$input_file"
            ;;
        *)
            # Generic handling
            "$tool" -l "$input_file" -o "$output_file" $extra_args 2>> "$LOGFILE" || true
            ;;
    esac
    
    # Store output in data bus
    if [[ -s "$output_file" ]]; then
        data_bus_store_tool_output "$tool" "$output_file"
    fi
    
    # Cleanup
    rm -f "$input_file" "$output_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA BUS STATISTICS
# ═══════════════════════════════════════════════════════════════════════════════

data_bus_stats() {
    cat << EOF
Data Bus Statistics
═══════════════════════════════════════════════════════════════════════════════

Channels:
EOF
    
    for channel in "${!DATA_BUS_CHANNELS[@]}"; do
        local stats=$(data_bus_channel_stats "$channel")
        local lines=$(echo "$stats" | jq -r '.current_lines // 0')
        local updated=$(echo "$stats" | jq -r '.last_updated // "never"')
        local producers=$(echo "$stats" | jq -r '.producers | join(", ") // "none"')
        
        printf "  %-25s: %6d lines | Updated: %s | Producers: %s\n" \
            "$channel" "$lines" "$updated" "$producers"
    done
    
    echo "═══════════════════════════════════════════════════════════════════════════════"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

data_bus_cleanup() {
    log_info "Cleaning up Data Bus..."
    
    # Remove dispatcher FIFO
    rm -f "${DATA_BUS_DIR}/events/dispatcher.fifo"
    
    # Generate final statistics
    data_bus_stats > "${DATA_BUS_DIR}/final_stats.txt"
    
    # Archive data bus state
    local archive_file="${dir}/reports/data_bus_state.json"
    
    cat > "$archive_file" << EOF
{
    "cleanup_time": "$(date -Iseconds)",
    "channels": {
EOF
    
    local first=true
    for channel in "${!DATA_BUS_CHANNELS[@]}"; do
        [[ "$first" == "true" ]] || echo "," >> "$archive_file"
        first=false
        
        local stats=$(data_bus_channel_stats "$channel")
        echo "        \"$channel\": $stats" >> "$archive_file"
    done
    
    echo "    }" >> "$archive_file"
    echo "}" >> "$archive_file"
    
    log_debug "Data Bus cleanup completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Shorthand for publishing subdomains
data_bus_add_subdomains() {
    local data="$1"
    local producer="${2:-manual}"
    data_bus_publish "subdomain_discovery" "$data" "$producer"
}

# Shorthand for getting all live hosts
data_bus_get_live_hosts() {
    data_bus_get "live_hosts" "lines"
}

# Shorthand for getting all URLs with parameters
data_bus_get_param_urls() {
    data_bus_get "param_urls" "lines"
}

# Shorthand for getting all IPs
data_bus_get_ips() {
    data_bus_get "target_ips" "lines"
}

# Shorthand for getting vulnerabilities
data_bus_get_vulns() {
    data_bus_get "vulnerabilities" "json"
}

# Export functions
export -f data_bus_publish data_bus_get data_bus_subscribe
export -f data_bus_get_tool_input data_bus_store_tool_output
export -f data_bus_run_tool
