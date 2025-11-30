#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO ADVANCED DISCORD NOTIFICATION SYSTEM
# Comprehensive Discord webhook integration with rate limiting and rich embeds
# Version: 2.2.0
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# DISCORD CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Discord Webhook URL (REQUIRED)
declare -g DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

# Discord Rate Limiting Configuration
# Discord allows 30 requests per 60 seconds per webhook
declare -g DISCORD_RATE_LIMIT_REQUESTS=25          # Stay under limit
declare -g DISCORD_RATE_LIMIT_WINDOW=60            # Window in seconds
declare -g DISCORD_MIN_REQUEST_INTERVAL=2          # Minimum seconds between requests
declare -g DISCORD_RETRY_ATTEMPTS=3                # Number of retry attempts
declare -g DISCORD_RETRY_DELAY=5                   # Base retry delay in seconds
declare -g DISCORD_QUEUE_ENABLED=true              # Enable message queue
declare -g DISCORD_QUEUE_BATCH_SIZE=5              # Messages to batch together
declare -g DISCORD_QUEUE_FLUSH_INTERVAL=10         # Seconds between queue flushes

# Message queue
declare -ga DISCORD_MESSAGE_QUEUE=()
declare -g DISCORD_QUEUE_LAST_FLUSH=0

# Rate limiting state
declare -ga DISCORD_REQUEST_TIMESTAMPS=()
declare -g DISCORD_REQUESTS_REMAINING=30
declare -g DISCORD_RATE_LIMIT_RESET=0
declare -g DISCORD_LAST_REQUEST_TIME=0

# Notification settings
declare -g DISCORD_NOTIFY_LEVEL="${DISCORD_NOTIFY_LEVEL:-INFO}"  # Minimum level to send
declare -g DISCORD_INCLUDE_TIMESTAMPS=true
declare -g DISCORD_MENTION_ROLE="${DISCORD_MENTION_ROLE:-}"      # Role ID to mention for critical
declare -g DISCORD_MENTION_USER="${DISCORD_MENTION_USER:-}"      # User ID to mention for critical
declare -g DISCORD_THREAD_ID="${DISCORD_THREAD_ID:-}"            # Thread ID for grouped messages

# Embed colors (Discord uses decimal colors)
declare -gA DISCORD_COLORS=(
    ["TRACE"]=8421504       # Gray
    ["DEBUG"]=5793266       # Cyan
    ["INFO"]=3447003        # Blue
    ["NOTICE"]=10181046     # Purple
    ["SUCCESS"]=5763719     # Green
    ["WARNING"]=16776960    # Yellow
    ["ERROR"]=15158332      # Red
    ["CRITICAL"]=15548997   # Dark Red
    ["ALERT"]=16753920      # Orange
    ["EMERGENCY"]=16711680  # Bright Red
    ["VULN_CRITICAL"]=16711680
    ["VULN_HIGH"]=15158332
    ["VULN_MEDIUM"]=16776960
    ["VULN_LOW"]=3447003
    ["VULN_INFO"]=8421504
    ["SCAN_START"]=5793266
    ["SCAN_END"]=5763719
    ["PHASE_START"]=10181046
    ["PHASE_END"]=3447003
)

# Emoji mappings
declare -gA DISCORD_EMOJIS=(
    ["TRACE"]="🔍"
    ["DEBUG"]="🐛"
    ["INFO"]="ℹ️"
    ["NOTICE"]="📢"
    ["SUCCESS"]="✅"
    ["WARNING"]="⚠️"
    ["ERROR"]="❌"
    ["CRITICAL"]="🚨"
    ["ALERT"]="🔔"
    ["EMERGENCY"]="🆘"
    ["SCAN_START"]="🚀"
    ["SCAN_END"]="🏁"
    ["PHASE_START"]="▶️"
    ["PHASE_END"]="✔️"
    ["VULN"]="🎯"
    ["SUBDOMAIN"]="🌐"
    ["URL"]="🔗"
    ["PORT"]="🔌"
    ["TOOL"]="🔧"
    ["TARGET"]="🎯"
    ["FINDING"]="💎"
    ["XSS"]="💉"
    ["SQLI"]="💾"
    ["SSRF"]="🔀"
    ["TAKEOVER"]="👑"
    ["CLOUD"]="☁️"
    ["API"]="📡"
    ["NETWORK"]="🌍"
)

# Statistics tracking
declare -gA DISCORD_STATS=(
    ["total_sent"]=0
    ["total_queued"]=0
    ["total_failed"]=0
    ["total_retried"]=0
    ["rate_limited"]=0
)

# ─────────────────────────────────────────────────────────────────────────────
# INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────

# Initialize Discord notification system
discord_init() {
    local webhook_url="${1:-$DISCORD_WEBHOOK_URL}"
    
    if [[ -z "$webhook_url" ]]; then
        neko_log "WARNING" "DISCORD" "Discord webhook URL not configured - notifications disabled"
        return 1
    fi
    
    DISCORD_WEBHOOK_URL="$webhook_url"
    DISCORD_QUEUE_LAST_FLUSH=$(date +%s)
    DISCORD_LAST_REQUEST_TIME=0
    DISCORD_REQUEST_TIMESTAMPS=()
    
    # Validate webhook URL format
    if ! [[ "$DISCORD_WEBHOOK_URL" =~ ^https://discord\.com/api/webhooks/[0-9]+/.+ ]]; then
        neko_log "ERROR" "DISCORD" "Invalid Discord webhook URL format"
        return 1
    fi
    
    neko_log "INFO" "DISCORD" "Discord notification system initialized"
    
    # Send initialization notification
    discord_send_embed \
        "Neko Scanner Started" \
        "Bug bounty automation scan initiated" \
        "SCAN_START" \
        "Target|${domain:-Unknown}" \
        "Mode|${mode:-recon}" \
        "Session|${NEKO_SESSION_ID:-unknown}" \
        "Hostname|$(hostname)"
    
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────────────────────────────────────

# Check if we can send a request (rate limiting)
_discord_can_send() {
    local current_time=$(date +%s)
    
    # Check minimum interval between requests
    local time_since_last=$((current_time - DISCORD_LAST_REQUEST_TIME))
    if [[ "$time_since_last" -lt "$DISCORD_MIN_REQUEST_INTERVAL" ]]; then
        return 1
    fi
    
    # Clean old timestamps outside the rate limit window
    local window_start=$((current_time - DISCORD_RATE_LIMIT_WINDOW))
    local new_timestamps=()
    for ts in "${DISCORD_REQUEST_TIMESTAMPS[@]}"; do
        if [[ "$ts" -gt "$window_start" ]]; then
            new_timestamps+=("$ts")
        fi
    done
    DISCORD_REQUEST_TIMESTAMPS=("${new_timestamps[@]}")
    
    # Check if we're within rate limits
    if [[ ${#DISCORD_REQUEST_TIMESTAMPS[@]} -ge $DISCORD_RATE_LIMIT_REQUESTS ]]; then
        ((DISCORD_STATS["rate_limited"]++)) || true
        neko_log "DEBUG" "DISCORD" "Rate limited - queuing message"
        return 1
    fi
    
    return 0
}

# Record a request for rate limiting
_discord_record_request() {
    local current_time=$(date +%s)
    DISCORD_REQUEST_TIMESTAMPS+=("$current_time")
    DISCORD_LAST_REQUEST_TIME=$current_time
}

# Wait for rate limit to reset
_discord_wait_for_rate_limit() {
    local current_time=$(date +%s)
    local wait_time=$((DISCORD_RATE_LIMIT_WINDOW - (current_time - ${DISCORD_REQUEST_TIMESTAMPS[0]:-0})))
    
    if [[ "$wait_time" -gt 0 ]]; then
        neko_log "DEBUG" "DISCORD" "Waiting ${wait_time}s for rate limit reset"
        sleep "$wait_time"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MESSAGE QUEUE SYSTEM
# ─────────────────────────────────────────────────────────────────────────────

# Add message to queue
_discord_queue_message() {
    local payload="$1"
    
    DISCORD_MESSAGE_QUEUE+=("$payload")
    ((DISCORD_STATS["total_queued"]++)) || true
    
    neko_log "DEBUG" "DISCORD" "Message queued (queue size: ${#DISCORD_MESSAGE_QUEUE[@]})"
    
    # Check if we should flush the queue
    local current_time=$(date +%s)
    local time_since_flush=$((current_time - DISCORD_QUEUE_LAST_FLUSH))
    
    if [[ ${#DISCORD_MESSAGE_QUEUE[@]} -ge $DISCORD_QUEUE_BATCH_SIZE ]] || \
       [[ "$time_since_flush" -ge $DISCORD_QUEUE_FLUSH_INTERVAL ]]; then
        _discord_flush_queue
    fi
}

# Flush message queue
_discord_flush_queue() {
    [[ ${#DISCORD_MESSAGE_QUEUE[@]} -eq 0 ]] && return 0
    
    neko_log "DEBUG" "DISCORD" "Flushing message queue (${#DISCORD_MESSAGE_QUEUE[@]} messages)"
    
    DISCORD_QUEUE_LAST_FLUSH=$(date +%s)
    
    # Process queued messages with rate limiting
    for payload in "${DISCORD_MESSAGE_QUEUE[@]}"; do
        # Wait if rate limited
        while ! _discord_can_send; do
            sleep "$DISCORD_MIN_REQUEST_INTERVAL"
        done
        
        _discord_send_raw "$payload"
    done
    
    # Clear the queue
    DISCORD_MESSAGE_QUEUE=()
}

# Force flush all queued messages (call at end of scan)
discord_flush_all() {
    if [[ ${#DISCORD_MESSAGE_QUEUE[@]} -gt 0 ]]; then
        neko_log "INFO" "DISCORD" "Force flushing ${#DISCORD_MESSAGE_QUEUE[@]} queued messages"
        _discord_flush_queue
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CORE SENDING FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Send raw JSON payload to Discord
_discord_send_raw() {
    local payload="$1"
    local attempt=0
    local success=false
    
    while [[ $attempt -lt $DISCORD_RETRY_ATTEMPTS ]] && [[ "$success" == "false" ]]; do
        ((attempt++))
        
        # Make the request
        local response
        local http_code
        
        response=$(curl -s -w "\n%{http_code}" \
            -H "Content-Type: application/json" \
            -X POST \
            -d "$payload" \
            "${DISCORD_WEBHOOK_URL}${DISCORD_THREAD_ID:+?thread_id=$DISCORD_THREAD_ID}" \
            2>/dev/null)
        
        http_code=$(echo "$response" | tail -n1)
        local body=$(echo "$response" | sed '$d')
        
        # Record the request
        _discord_record_request
        
        # Check response
        case "$http_code" in
            200|204)
                # Success
                ((DISCORD_STATS["total_sent"]++)) || true
                success=true
                neko_log "DEBUG" "DISCORD" "Message sent successfully"
                ;;
            429)
                # Rate limited by Discord
                ((DISCORD_STATS["rate_limited"]++)) || true
                local retry_after=$(echo "$body" | grep -o '"retry_after":[0-9.]*' | cut -d: -f2)
                retry_after=${retry_after:-5}
                neko_log "WARNING" "DISCORD" "Rate limited by Discord, waiting ${retry_after}s"
                sleep "$retry_after"
                ((DISCORD_STATS["total_retried"]++)) || true
                ;;
            400)
                # Bad request - log and don't retry
                neko_log "ERROR" "DISCORD" "Bad request to Discord API: $body"
                ((DISCORD_STATS["total_failed"]++)) || true
                break
                ;;
            401|403)
                # Auth error - webhook may be invalid
                neko_log "ERROR" "DISCORD" "Discord webhook authentication failed"
                ((DISCORD_STATS["total_failed"]++)) || true
                break
                ;;
            *)
                # Other error - retry with backoff
                local delay=$((DISCORD_RETRY_DELAY * attempt))
                neko_log "WARNING" "DISCORD" "Discord request failed (HTTP $http_code), retrying in ${delay}s"
                sleep "$delay"
                ((DISCORD_STATS["total_retried"]++)) || true
                ;;
        esac
    done
    
    if [[ "$success" == "false" ]]; then
        ((DISCORD_STATS["total_failed"]++)) || true
        neko_log "ERROR" "DISCORD" "Failed to send message after $attempt attempts"
        return 1
    fi
    
    return 0
}

# Send message (with queue support)
discord_send() {
    local payload="$1"
    
    if [[ -z "$DISCORD_WEBHOOK_URL" ]]; then
        return 1
    fi
    
    if [[ "${DISCORD_QUEUE_ENABLED}" == "true" ]]; then
        if _discord_can_send; then
            _discord_send_raw "$payload"
        else
            _discord_queue_message "$payload"
        fi
    else
        # Wait for rate limit if necessary
        while ! _discord_can_send; do
            sleep "$DISCORD_MIN_REQUEST_INTERVAL"
        done
        _discord_send_raw "$payload"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SIMPLE MESSAGE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Send a simple text message
discord_send_simple() {
    local message="$1"
    local mention="${2:-}"
    
    local content="$message"
    
    # Add mentions if specified
    if [[ -n "$mention" ]]; then
        content="$mention $content"
    fi
    
    local payload
    payload=$(cat << EOF
{
    "content": $(echo "$content" | jq -Rs .)
}
EOF
)
    
    discord_send "$payload"
}

# ─────────────────────────────────────────────────────────────────────────────
# EMBED MESSAGE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Build a Discord embed field JSON
_discord_build_field() {
    local name="$1"
    local value="$2"
    local inline="${3:-true}"
    
    printf '{"name": %s, "value": %s, "inline": %s}' \
        "$(echo "$name" | jq -Rs .)" \
        "$(echo "$value" | jq -Rs .)" \
        "$inline"
}

# Send an embed message
# Usage: discord_send_embed <title> <description> <type> [field1|value1] [field2|value2] ...
discord_send_embed() {
    local title="$1"
    local description="$2"
    local type="${3:-INFO}"
    shift 3
    local fields=("$@")
    
    local color="${DISCORD_COLORS[$type]:-3447003}"
    local emoji="${DISCORD_EMOJIS[$type]:-ℹ️}"
    local timestamp=""
    
    if [[ "${DISCORD_INCLUDE_TIMESTAMPS}" == "true" ]]; then
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    fi
    
    # Escape strings for JSON
    local escaped_title
    local escaped_desc
    local escaped_footer
    
    escaped_title=$(printf '%s' "${emoji} ${title}" | jq -Rs . 2>/dev/null || printf '"%s"' "${emoji} ${title}")
    escaped_desc=$(printf '%s' "$description" | jq -Rs . 2>/dev/null || printf '"%s"' "$description")
    escaped_footer=$(printf '%s' "Neko Bug Bounty Scanner • Session: ${NEKO_SESSION_ID:-unknown}" | jq -Rs . 2>/dev/null || printf '"%s"' "Neko Bug Bounty Scanner")
    
    # Build fields array
    local fields_json=""
    if [[ ${#fields[@]} -gt 0 ]]; then
        fields_json='"fields": ['
        local first=true
        for field in "${fields[@]}"; do
            local fname="${field%%|*}"
            local fvalue="${field#*|}"
            [[ "$first" == "true" ]] || fields_json+=","
            fields_json+=$(_discord_build_field "$fname" "$fvalue" "true")
            first=false
        done
        fields_json+='],'
    fi
    
    # Build payload using proper JSON construction
    local payload
    if [[ -n "$timestamp" ]]; then
        payload=$(printf '{"embeds": [{"title": %s, "description": %s, "color": %d, %s "footer": {"text": %s}, "timestamp": "%s"}]}' \
            "$escaped_title" "$escaped_desc" "$color" "$fields_json" "$escaped_footer" "$timestamp")
    else
        payload=$(printf '{"embeds": [{"title": %s, "description": %s, "color": %d, %s "footer": {"text": %s}}]}' \
            "$escaped_title" "$escaped_desc" "$color" "$fields_json" "$escaped_footer")
    fi
    
    discord_send "$payload"
}

# Send a rich embed with all options
discord_send_rich_embed() {
    local title="$1"
    local description="$2"
    local color="$3"
    local author_name="$4"
    local author_icon="$5"
    local thumbnail_url="$6"
    local image_url="$7"
    local footer_text="$8"
    shift 8
    local fields=("$@")
    
    local timestamp=""
    if [[ "${DISCORD_INCLUDE_TIMESTAMPS}" == "true" ]]; then
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    fi
    
    # Build fields array
    local fields_json=""
    if [[ ${#fields[@]} -gt 0 ]]; then
        fields_json='"fields": ['
        local first=true
        for field in "${fields[@]}"; do
            local fname="${field%%|*}"
            local fvalue="${field#*|}"
            local finline="true"
            # Check for inline flag
            if [[ "$fvalue" == *"|inline=false"* ]]; then
                finline="false"
                fvalue="${fvalue%|inline=false}"
            fi
            [[ "$first" == "true" ]] || fields_json+=","
            fields_json+=$(_discord_build_field "$fname" "$fvalue" "$finline")
            first=false
        done
        fields_json+='],'
    fi
    
    local payload
    payload=$(cat << EOF
{
    "embeds": [{
        "title": $(echo "$title" | jq -Rs .),
        "description": $(echo "$description" | jq -Rs .),
        "color": ${color:-3447003},
        ${author_name:+"\"author\": {\"name\": \"$author_name\"${author_icon:+, \"icon_url\": \"$author_icon\"}},"}
        ${thumbnail_url:+"\"thumbnail\": {\"url\": \"$thumbnail_url\"},"}
        ${image_url:+"\"image\": {\"url\": \"$image_url\"},"}
        ${fields_json}
        "footer": {
            "text": "${footer_text:-Neko Bug Bounty Scanner}"
        }
        ${timestamp:+,"timestamp": "$timestamp"}
    }]
}
EOF
)
    
    discord_send "$payload"
}

# ─────────────────────────────────────────────────────────────────────────────
# SPECIALIZED NOTIFICATION FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# Notify scan start
discord_notify_scan_start() {
    local target="$1"
    local mode="$2"
    local config_summary="$3"
    
    discord_send_embed \
        "Scan Started" \
        "A new bug bounty scan has been initiated." \
        "SCAN_START" \
        "Target|$target" \
        "Mode|$mode" \
        "Session|${NEKO_SESSION_ID:-unknown}" \
        "Started|$(date '+%Y-%m-%d %H:%M:%S')" \
        "Configuration|$config_summary"
}

# Notify scan completion
discord_notify_scan_complete() {
    local target="$1"
    local duration="$2"
    local subdomains="$3"
    local urls="$4"
    local vulns="$5"
    local errors="$6"
    
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    local duration_str="${hours}h ${minutes}m ${seconds}s"
    
    # Determine status color based on errors and findings
    local status_type="SUCCESS"
    local status_desc="Scan completed successfully!"
    
    if [[ "$errors" -gt 10 ]]; then
        status_type="WARNING"
        status_desc="Scan completed with some errors."
    fi
    
    if [[ "$vulns" -gt 0 ]]; then
        status_desc+=" **${vulns} vulnerabilities found!**"
    fi
    
    discord_send_embed \
        "Scan Completed" \
        "$status_desc" \
        "$status_type" \
        "Target|$target" \
        "Duration|$duration_str" \
        "Subdomains|$subdomains" \
        "URLs|$urls" \
        "Vulnerabilities|$vulns" \
        "Errors|$errors" \
        "Session|${NEKO_SESSION_ID:-unknown}"
}

# Notify phase start
discord_notify_phase_start() {
    local phase_number="$1"
    local phase_name="$2"
    local description="${3:-}"
    
    discord_send_embed \
        "Phase ${phase_number}: ${phase_name}" \
        "${description:-Starting phase execution...}" \
        "PHASE_START" \
        "Phase|${phase_number}" \
        "Name|${phase_name}" \
        "Status|🔄 In Progress"
}

# Notify phase completion
discord_notify_phase_complete() {
    local phase_number="$1"
    local phase_name="$2"
    local duration="$3"
    local findings="$4"
    local status="${5:-completed}"
    
    local status_type="PHASE_END"
    local emoji="✅"
    
    if [[ "$status" == "failed" ]]; then
        status_type="ERROR"
        emoji="❌"
    elif [[ "$status" == "skipped" ]]; then
        status_type="WARNING"
        emoji="⏭️"
    fi
    
    discord_send_embed \
        "Phase ${phase_number}: ${phase_name} Complete" \
        "Phase execution finished." \
        "$status_type" \
        "Phase|${phase_number}" \
        "Name|${phase_name}" \
        "Duration|${duration}s" \
        "Findings|${findings}" \
        "Status|${emoji} ${status^}"
}

# Notify tool execution
discord_notify_tool_run() {
    local tool_name="$1"
    local phase="$2"
    local status="$3"
    local duration="$4"
    local output_count="${5:-0}"
    
    local status_type="SUCCESS"
    local emoji="✅"
    
    case "$status" in
        failed)
            status_type="ERROR"
            emoji="❌"
            ;;
        timeout)
            status_type="WARNING"
            emoji="⏱️"
            ;;
        skipped)
            status_type="INFO"
            emoji="⏭️"
            ;;
    esac
    
    discord_send_embed \
        "Tool: ${tool_name}" \
        "Tool execution ${status}." \
        "$status_type" \
        "Tool|${tool_name}" \
        "Phase|${phase}" \
        "Status|${emoji} ${status^}" \
        "Duration|${duration}s" \
        "Output|${output_count} items"
}

# Notify vulnerability found (CRITICAL - always sends immediately)
discord_notify_vulnerability() {
    local severity="$1"
    local vuln_type="$2"
    local target="$3"
    local tool="$4"
    local details="$5"
    local poc="${6:-}"
    
    # Determine color based on severity
    local color_key="VULN_${severity^^}"
    local color="${DISCORD_COLORS[$color_key]:-3447003}"
    local emoji="${DISCORD_EMOJIS["VULN"]:-🎯}"
    
    # Add severity-specific emoji
    case "${severity,,}" in
        critical) emoji="🚨" ;;
        high) emoji="⚠️" ;;
        medium) emoji="🔶" ;;
        low) emoji="🔷" ;;
        info) emoji="ℹ️" ;;
    esac
    
    # Build description with PoC if available
    local description="A vulnerability has been discovered!"
    if [[ -n "$poc" ]]; then
        # Use printf to handle newlines properly
        description=$(printf "A vulnerability has been discovered!\n\n**Proof of Concept:**\n\`\`\`\n%s\n\`\`\`" "$poc")
    fi
    
    # Add mention for critical/high findings
    local mention_json=""
    if [[ "${severity,,}" == "critical" ]] || [[ "${severity,,}" == "high" ]]; then
        local mention_content=""
        [[ -n "$DISCORD_MENTION_ROLE" ]] && mention_content="<@&${DISCORD_MENTION_ROLE}>"
        [[ -n "$DISCORD_MENTION_USER" ]] && mention_content="${mention_content} <@${DISCORD_MENTION_USER}>"
        if [[ -n "$mention_content" ]]; then
            mention_json="\"content\": $(printf '%s' "$mention_content" | jq -Rs .),"
        fi
    fi
    
    # Escape all strings for JSON
    local escaped_title escaped_desc escaped_vuln_type escaped_tool escaped_target escaped_details escaped_footer
    escaped_title=$(printf '%s' "${emoji} ${severity^^} Vulnerability Found!" | jq -Rs .)
    escaped_desc=$(printf '%s' "$description" | jq -Rs .)
    escaped_vuln_type=$(printf '%s' "$vuln_type" | jq -Rs .)
    escaped_tool=$(printf '%s' "$tool" | jq -Rs .)
    escaped_target=$(printf '%s' "\`${target}\`" | jq -Rs .)
    escaped_details=$(printf '%s' "$details" | jq -Rs .)
    escaped_footer=$(printf '%s' "Neko Bug Bounty Scanner • Session: ${NEKO_SESSION_ID:-unknown}" | jq -Rs .)
    
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local payload
    payload=$(printf '{%s "embeds": [{"title": %s, "description": %s, "color": %d, "fields": [{"name": "Severity", "value": "%s", "inline": true}, {"name": "Type", "value": %s, "inline": true}, {"name": "Tool", "value": %s, "inline": true}, {"name": "Target", "value": %s, "inline": false}, {"name": "Details", "value": %s, "inline": false}], "footer": {"text": %s}, "timestamp": "%s"}]}' \
        "$mention_json" "$escaped_title" "$escaped_desc" "$color" "${severity^^}" \
        "$escaped_vuln_type" "$escaped_tool" "$escaped_target" "$escaped_details" \
        "$escaped_footer" "$timestamp")
    
    # For critical vulnerabilities, send immediately bypassing queue
    if [[ "${severity,,}" == "critical" ]] || [[ "${severity,,}" == "high" ]]; then
        while ! _discord_can_send; do
            sleep 1
        done
        _discord_send_raw "$payload"
    else
        discord_send "$payload"
    fi
}

# Notify subdomain discoveries (batched)
discord_notify_subdomains() {
    local count="$1"
    local sample="${2:-}"
    local source="${3:-multiple}"
    
    local description="Discovered **${count}** new subdomains."
    if [[ -n "$sample" ]]; then
        description+="\n\n**Sample:**\n\`\`\`\n${sample}\n\`\`\`"
    fi
    
    discord_send_embed \
        "Subdomains Discovered" \
        "$description" \
        "INFO" \
        "Count|${count}" \
        "Source|${source}" \
        "Target|${domain:-unknown}"
}

# Notify URL discoveries (batched)
discord_notify_urls() {
    local count="$1"
    local interesting="${2:-0}"
    local source="${3:-multiple}"
    
    discord_send_embed \
        "URLs Discovered" \
        "Found **${count}** URLs during crawling." \
        "INFO" \
        "Total URLs|${count}" \
        "Interesting|${interesting}" \
        "Source|${source}"
}

# Notify port scan results
discord_notify_ports() {
    local host="$1"
    local open_ports="$2"
    local services="${3:-}"
    
    local description="Open ports discovered on target."
    if [[ -n "$services" ]]; then
        description+="\n\n**Services:**\n\`\`\`\n${services}\n\`\`\`"
    fi
    
    discord_send_embed \
        "Open Ports Found" \
        "$description" \
        "INFO" \
        "Host|${host}" \
        "Open Ports|${open_ports}"
}

# Notify error
discord_notify_error() {
    local error_type="$1"
    local message="$2"
    local tool="${3:-system}"
    local recoverable="${4:-true}"
    
    local status_type="ERROR"
    if [[ "$recoverable" == "false" ]]; then
        status_type="CRITICAL"
    fi
    
    discord_send_embed \
        "Error Occurred" \
        "An error occurred during scanning." \
        "$status_type" \
        "Type|${error_type}" \
        "Tool|${tool}" \
        "Recoverable|${recoverable}" \
        "Message|${message}"
}

# Notify takeover potential
discord_notify_takeover() {
    local subdomain="$1"
    local service="$2"
    local confidence="${3:-medium}"
    local details="${4:-}"
    
    # Takeover findings are high priority
    local mention_json=""
    if [[ -n "$DISCORD_MENTION_ROLE" ]]; then
        mention_json="\"content\": \"<@&${DISCORD_MENTION_ROLE}>\","
    fi
    
    local color="${DISCORD_COLORS["VULN_HIGH"]:-15158332}"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Escape strings
    local escaped_subdomain escaped_service escaped_details
    escaped_subdomain=$(printf '%s' "\`${subdomain}\`" | jq -Rs .)
    escaped_service=$(printf '%s' "$service" | jq -Rs .)
    
    # Build fields
    local fields_json
    fields_json=$(printf '[{"name": "Subdomain", "value": %s, "inline": false}, {"name": "Service", "value": %s, "inline": true}, {"name": "Confidence", "value": "%s", "inline": true}' \
        "$escaped_subdomain" "$escaped_service" "${confidence^^}")
    
    if [[ -n "$details" ]]; then
        escaped_details=$(printf '%s' "$details" | jq -Rs .)
        fields_json+=", {\"name\": \"Details\", \"value\": ${escaped_details}, \"inline\": false}"
    fi
    fields_json+="]"
    
    local payload
    payload=$(printf '{%s "embeds": [{"title": "👑 Potential Subdomain Takeover!", "description": "A potential subdomain takeover vulnerability has been identified.", "color": %d, "fields": %s, "footer": {"text": "Neko Bug Bounty Scanner • Verify before reporting!"}, "timestamp": "%s"}]}' \
        "$mention_json" "$color" "$fields_json" "$timestamp")
    
    discord_send "$payload"
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY AND STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

# Send daily/session summary
discord_send_summary() {
    local target="$1"
    local duration="$2"
    local stats_json="$3"
    
    # Parse stats JSON
    local subdomains urls vulns_critical vulns_high vulns_medium vulns_low tools_run tools_failed errors
    subdomains=$(echo "$stats_json" | jq -r '.subdomains // 0' 2>/dev/null || echo "0")
    urls=$(echo "$stats_json" | jq -r '.urls // 0' 2>/dev/null || echo "0")
    vulns_critical=$(echo "$stats_json" | jq -r '.vulns_critical // 0' 2>/dev/null || echo "0")
    vulns_high=$(echo "$stats_json" | jq -r '.vulns_high // 0' 2>/dev/null || echo "0")
    vulns_medium=$(echo "$stats_json" | jq -r '.vulns_medium // 0' 2>/dev/null || echo "0")
    vulns_low=$(echo "$stats_json" | jq -r '.vulns_low // 0' 2>/dev/null || echo "0")
    tools_run=$(echo "$stats_json" | jq -r '.tools_run // 0' 2>/dev/null || echo "0")
    tools_failed=$(echo "$stats_json" | jq -r '.tools_failed // 0' 2>/dev/null || echo "0")
    errors=$(echo "$stats_json" | jq -r '.errors // 0' 2>/dev/null || echo "0")
    
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    
    local color="${DISCORD_COLORS["SUCCESS"]:-5763719}"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local escaped_target
    escaped_target=$(printf '%s' "\`${target}\`" | jq -Rs .)
    
    local escaped_footer
    escaped_footer=$(printf '%s' "Neko Bug Bounty Scanner • Session: ${NEKO_SESSION_ID:-unknown}" | jq -Rs .)
    
    # Build the payload with proper JSON
    local payload
    payload=$(printf '{"embeds": [{"title": "📊 Scan Summary Report", "description": "Complete summary of the bug bounty scan.", "color": %d, "fields": [{"name": "🎯 Target", "value": %s, "inline": false}, {"name": "⏱️ Duration", "value": "%dh %dm", "inline": true}, {"name": "🔧 Tools Run", "value": "%s", "inline": true}, {"name": "❌ Failed", "value": "%s", "inline": true}, {"name": "───────────", "value": "**Discovery Results**", "inline": false}, {"name": "🌐 Subdomains", "value": "%s", "inline": true}, {"name": "🔗 URLs", "value": "%s", "inline": true}, {"name": "⚠️ Errors", "value": "%s", "inline": true}, {"name": "───────────", "value": "**Vulnerability Summary**", "inline": false}, {"name": "🚨 Critical", "value": "%s", "inline": true}, {"name": "🔴 High", "value": "%s", "inline": true}, {"name": "🟠 Medium", "value": "%s", "inline": true}, {"name": "🟡 Low", "value": "%s", "inline": true}], "footer": {"text": %s}, "timestamp": "%s"}]}' \
        "$color" "$escaped_target" "$hours" "$minutes" "$tools_run" "$tools_failed" \
        "$subdomains" "$urls" "$errors" \
        "$vulns_critical" "$vulns_high" "$vulns_medium" "$vulns_low" \
        "$escaped_footer" "$timestamp")
    
    discord_send "$payload"
}

# Get Discord notification statistics
discord_get_stats() {
    printf '{"total_sent": %d, "total_queued": %d, "total_failed": %d, "total_retried": %d, "rate_limited": %d}' \
        "${DISCORD_STATS["total_sent"]}" \
        "${DISCORD_STATS["total_queued"]}" \
        "${DISCORD_STATS["total_failed"]}" \
        "${DISCORD_STATS["total_retried"]}" \
        "${DISCORD_STATS["rate_limited"]}"
}

# ─────────────────────────────────────────────────────────────────────────────
# FINALIZATION
# ─────────────────────────────────────────────────────────────────────────────

# Finalize Discord notifications (call at end of scan)
discord_finalize() {
    local summary_json="$1"
    
    # Flush any remaining queued messages
    discord_flush_all
    
    # Send notification stats
    local stats
    stats=$(discord_get_stats)
    
    neko_log "INFO" "DISCORD" "Discord notification stats: $stats"
    
    # Send final completion notification
    discord_send_embed \
        "Scan Session Ended" \
        "The bug bounty scan session has completed. All notifications have been sent." \
        "SCAN_END" \
        "Session|${NEKO_SESSION_ID:-unknown}" \
        "Messages Sent|${DISCORD_STATS["total_sent"]}" \
        "Messages Failed|${DISCORD_STATS["total_failed"]}" \
        "Rate Limited|${DISCORD_STATS["rate_limited"]}"
}

# ─────────────────────────────────────────────────────────────────────────────
# EXPORT FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

export -f discord_init discord_send discord_send_simple discord_send_embed
export -f discord_send_rich_embed discord_flush_all discord_finalize
export -f discord_notify_scan_start discord_notify_scan_complete
export -f discord_notify_phase_start discord_notify_phase_complete
export -f discord_notify_tool_run discord_notify_vulnerability
export -f discord_notify_subdomains discord_notify_urls discord_notify_ports
export -f discord_notify_error discord_notify_takeover discord_send_summary
export -f discord_get_stats
