#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO PLUGIN ARCHITECTURE
# Extensible plugin system for custom modules and integrations
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

declare -gA PLUGINS
declare -gA PLUGIN_HOOKS
declare -gA PLUGIN_METADATA
declare -g PLUGINS_DIR="${PLUGINS_DIR:-${SCRIPTPATH}/plugins}"
declare -g PLUGINS_CONFIG="${PLUGINS_CONFIG:-${SCRIPTPATH}/config/plugins.json}"

# Hook points
readonly HOOK_PRE_SCAN="pre_scan"
readonly HOOK_POST_SCAN="post_scan"
readonly HOOK_PRE_PHASE="pre_phase"
readonly HOOK_POST_PHASE="post_phase"
readonly HOOK_ON_FINDING="on_finding"
readonly HOOK_ON_ERROR="on_error"
readonly HOOK_ON_COMPLETE="on_complete"

# Plugin states
readonly PLUGIN_ACTIVE="active"
readonly PLUGIN_DISABLED="disabled"
readonly PLUGIN_ERROR="error"

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

plugin_init() {
    ensure_dir "$PLUGINS_DIR"
    ensure_dir "${PLUGINS_DIR}/custom"
    ensure_dir "${PLUGINS_DIR}/community"
    ensure_dir "${PLUGINS_DIR}/integrations"
    
    # Create default plugin config if not exists
    if [[ ! -f "$PLUGINS_CONFIG" ]]; then
        cat > "$PLUGINS_CONFIG" << 'EOF'
{
    "enabled_plugins": [],
    "disabled_plugins": [],
    "plugin_settings": {}
}
EOF
    fi
    
    # Initialize hook arrays
    PLUGIN_HOOKS[$HOOK_PRE_SCAN]=""
    PLUGIN_HOOKS[$HOOK_POST_SCAN]=""
    PLUGIN_HOOKS[$HOOK_PRE_PHASE]=""
    PLUGIN_HOOKS[$HOOK_POST_PHASE]=""
    PLUGIN_HOOKS[$HOOK_ON_FINDING]=""
    PLUGIN_HOOKS[$HOOK_ON_ERROR]=""
    PLUGIN_HOOKS[$HOOK_ON_COMPLETE]=""
    
    # Load plugins
    plugin_load_all
    
    log_debug "Plugin system initialized"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN LOADING
# ═══════════════════════════════════════════════════════════════════════════════

# Load a single plugin
plugin_load() {
    local plugin_path="$1"
    local plugin_name=$(basename "${plugin_path%.sh}")
    
    if [[ ! -f "$plugin_path" ]]; then
        log_warning "Plugin not found: $plugin_path"
        return 1
    fi
    
    # Check if plugin is disabled
    if jq -e ".disabled_plugins | index(\"$plugin_name\")" "$PLUGINS_CONFIG" > /dev/null 2>&1; then
        log_debug "Plugin disabled: $plugin_name"
        return 0
    fi
    
    # Load plugin
    if source "$plugin_path" 2>> "$LOGFILE"; then
        PLUGINS["$plugin_name"]="$plugin_path"
        
        # Extract metadata if available
        if type -t "${plugin_name}_metadata" &>/dev/null; then
            PLUGIN_METADATA["$plugin_name"]=$("${plugin_name}_metadata")
        fi
        
        # Initialize plugin if it has init function
        if type -t "${plugin_name}_init" &>/dev/null; then
            "${plugin_name}_init" || {
                log_warning "Plugin init failed: $plugin_name"
                return 1
            }
        fi
        
        log_debug "Plugin loaded: $plugin_name"
        return 0
    else
        log_error "Failed to load plugin: $plugin_name"
        return 1
    fi
}

# Load all plugins
plugin_load_all() {
    local plugin_count=0
    
    # Load plugins from all directories
    for plugin_dir in "$PLUGINS_DIR" "${PLUGINS_DIR}/custom" "${PLUGINS_DIR}/community" "${PLUGINS_DIR}/integrations"; do
        if [[ -d "$plugin_dir" ]]; then
            for plugin in "$plugin_dir"/*.sh; do
                [[ -f "$plugin" ]] || continue
                if plugin_load "$plugin"; then
                    ((plugin_count++))
                fi
            done
        fi
    done
    
    log_info "Loaded $plugin_count plugins"
}

# Unload a plugin
plugin_unload() {
    local plugin_name="$1"
    
    if [[ -z "${PLUGINS[$plugin_name]:-}" ]]; then
        return 0
    fi
    
    # Call cleanup if available
    if type -t "${plugin_name}_cleanup" &>/dev/null; then
        "${plugin_name}_cleanup"
    fi
    
    unset "PLUGINS[$plugin_name]"
    unset "PLUGIN_METADATA[$plugin_name]"
    
    log_debug "Plugin unloaded: $plugin_name"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HOOK MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Register a hook callback
plugin_register_hook() {
    local hook="$1"
    local callback="$2"
    local priority="${3:-50}"  # 0-100, higher = runs first
    
    if [[ -z "${PLUGIN_HOOKS[$hook]:-}" ]]; then
        PLUGIN_HOOKS["$hook"]="$priority:$callback"
    else
        PLUGIN_HOOKS["$hook"]="${PLUGIN_HOOKS[$hook]}|$priority:$callback"
    fi
    
    log_debug "Hook registered: $hook -> $callback (priority: $priority)"
}

# Execute hooks for a given hook point
plugin_run_hooks() {
    local hook="$1"
    shift
    local args=("$@")
    
    local callbacks="${PLUGIN_HOOKS[$hook]:-}"
    [[ -z "$callbacks" ]] && return 0
    
    # Sort callbacks by priority (descending)
    local sorted_callbacks=$(echo "$callbacks" | tr '|' '\n' | sort -t: -k1 -rn)
    
    while IFS=: read -r priority callback; do
        [[ -z "$callback" ]] && continue
        
        log_debug "Running hook: $hook -> $callback"
        
        if type -t "$callback" &>/dev/null; then
            "$callback" "${args[@]}" 2>> "$LOGFILE" || {
                log_warning "Hook callback failed: $callback"
            }
        fi
    done <<< "$sorted_callbacks"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN API
# ═══════════════════════════════════════════════════════════════════════════════

# Get plugin setting
plugin_get_setting() {
    local plugin_name="$1"
    local setting_key="$2"
    local default="${3:-}"
    
    local value=$(jq -r ".plugin_settings.\"$plugin_name\".\"$setting_key\" // \"$default\"" "$PLUGINS_CONFIG" 2>/dev/null)
    echo "${value:-$default}"
}

# Set plugin setting
plugin_set_setting() {
    local plugin_name="$1"
    local setting_key="$2"
    local value="$3"
    
    local tmp_file="${PLUGINS_CONFIG}.tmp"
    jq ".plugin_settings.\"$plugin_name\".\"$setting_key\" = \"$value\"" "$PLUGINS_CONFIG" > "$tmp_file" && \
        mv "$tmp_file" "$PLUGINS_CONFIG"
}

# Check if plugin is loaded
plugin_is_loaded() {
    local plugin_name="$1"
    [[ -n "${PLUGINS[$plugin_name]:-}" ]]
}

# Get plugin metadata
plugin_get_metadata() {
    local plugin_name="$1"
    echo "${PLUGIN_METADATA[$plugin_name]:-}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN MANAGEMENT COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

# List all plugins
plugin_list() {
    echo "Installed Plugins:"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    
    for plugin_name in "${!PLUGINS[@]}"; do
        local path="${PLUGINS[$plugin_name]}"
        local metadata="${PLUGIN_METADATA[$plugin_name]:-}"
        local version=$(echo "$metadata" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
        local description=$(echo "$metadata" | jq -r '.description // "No description"' 2>/dev/null || echo "No description")
        
        printf "  %-25s v%-8s %s\n" "$plugin_name" "$version" "$description"
    done
}

# Enable a plugin
plugin_enable() {
    local plugin_name="$1"
    
    local tmp_file="${PLUGINS_CONFIG}.tmp"
    jq "(.disabled_plugins | . - [\"$plugin_name\"]) | .enabled_plugins += [\"$plugin_name\"] | .enabled_plugins |= unique" \
        "$PLUGINS_CONFIG" > "$tmp_file" && mv "$tmp_file" "$PLUGINS_CONFIG"
    
    # Load the plugin if not already loaded
    plugin_load "${PLUGINS_DIR}/${plugin_name}.sh" 2>/dev/null || \
        plugin_load "${PLUGINS_DIR}/custom/${plugin_name}.sh" 2>/dev/null || \
        plugin_load "${PLUGINS_DIR}/community/${plugin_name}.sh"
    
    log_success "Plugin enabled: $plugin_name"
}

# Disable a plugin
plugin_disable() {
    local plugin_name="$1"
    
    local tmp_file="${PLUGINS_CONFIG}.tmp"
    jq "(.enabled_plugins | . - [\"$plugin_name\"]) | .disabled_plugins += [\"$plugin_name\"] | .disabled_plugins |= unique" \
        "$PLUGINS_CONFIG" > "$tmp_file" && mv "$tmp_file" "$PLUGINS_CONFIG"
    
    plugin_unload "$plugin_name"
    
    log_success "Plugin disabled: $plugin_name"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════

# Install plugin from URL
plugin_install() {
    local source="$1"
    local plugin_name="${2:-}"
    
    if [[ "$source" == http* ]]; then
        # Download from URL
        local tmp_file="/tmp/neko_plugin_$$.sh"
        
        if curl -sL "$source" -o "$tmp_file"; then
            [[ -z "$plugin_name" ]] && plugin_name=$(basename "${source%.sh}")
            local target="${PLUGINS_DIR}/community/${plugin_name}.sh"
            
            # Validate plugin structure
            if grep -q "^${plugin_name}_main()" "$tmp_file" || grep -q "^plugin_" "$tmp_file"; then
                mv "$tmp_file" "$target"
                chmod +x "$target"
                plugin_load "$target"
                log_success "Plugin installed: $plugin_name"
            else
                rm -f "$tmp_file"
                log_error "Invalid plugin structure"
                return 1
            fi
        else
            log_error "Failed to download plugin"
            return 1
        fi
        
    elif [[ -f "$source" ]]; then
        # Install from local file
        [[ -z "$plugin_name" ]] && plugin_name=$(basename "${source%.sh}")
        local target="${PLUGINS_DIR}/custom/${plugin_name}.sh"
        
        cp "$source" "$target"
        chmod +x "$target"
        plugin_load "$target"
        log_success "Plugin installed: $plugin_name"
    else
        log_error "Invalid plugin source: $source"
        return 1
    fi
}

# Uninstall plugin
plugin_uninstall() {
    local plugin_name="$1"
    
    plugin_unload "$plugin_name"
    
    for dir in "$PLUGINS_DIR" "${PLUGINS_DIR}/custom" "${PLUGINS_DIR}/community"; do
        local plugin_file="${dir}/${plugin_name}.sh"
        if [[ -f "$plugin_file" ]]; then
            rm -f "$plugin_file"
            log_success "Plugin uninstalled: $plugin_name"
            return 0
        fi
    done
    
    log_warning "Plugin not found: $plugin_name"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BUILT-IN HOOK TRIGGERS
# ═══════════════════════════════════════════════════════════════════════════════

# Called before scan starts
trigger_pre_scan() {
    plugin_run_hooks "$HOOK_PRE_SCAN" "$domain" "$mode"
}

# Called after scan completes
trigger_post_scan() {
    plugin_run_hooks "$HOOK_POST_SCAN" "$domain" "$dir"
}

# Called before each phase
trigger_pre_phase() {
    local phase_name="$1"
    plugin_run_hooks "$HOOK_PRE_PHASE" "$phase_name"
}

# Called after each phase
trigger_post_phase() {
    local phase_name="$1"
    local phase_result="$2"
    plugin_run_hooks "$HOOK_POST_PHASE" "$phase_name" "$phase_result"
}

# Called when a finding is discovered
trigger_on_finding() {
    local severity="$1"
    local finding_type="$2"
    local details="$3"
    plugin_run_hooks "$HOOK_ON_FINDING" "$severity" "$finding_type" "$details"
}

# Called on error
trigger_on_error() {
    local error_type="$1"
    local message="$2"
    plugin_run_hooks "$HOOK_ON_ERROR" "$error_type" "$message"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════

# Create plugin template
plugin_create_template() {
    local plugin_name="$1"
    local output_file="${PLUGINS_DIR}/custom/${plugin_name}.sh"
    
    cat > "$output_file" << 'TEMPLATE'
#!/usr/bin/env bash

# ═══════════════════════════════════════════════════════════════════════════════
# NEKO PLUGIN: {{PLUGIN_NAME}}
# Description: {{DESCRIPTION}}
# Author: {{AUTHOR}}
# Version: 1.0.0
# ═══════════════════════════════════════════════════════════════════════════════

# Plugin metadata
{{PLUGIN_NAME}}_metadata() {
    cat << 'EOF'
{
    "name": "{{PLUGIN_NAME}}",
    "version": "1.0.0",
    "author": "{{AUTHOR}}",
    "description": "{{DESCRIPTION}}",
    "hooks": ["pre_scan", "post_phase"],
    "dependencies": []
}
EOF
}

# Initialize plugin
{{PLUGIN_NAME}}_init() {
    log_debug "Initializing {{PLUGIN_NAME}} plugin"
    
    # Register hooks
    plugin_register_hook "$HOOK_PRE_SCAN" "{{PLUGIN_NAME}}_on_pre_scan" 50
    plugin_register_hook "$HOOK_POST_PHASE" "{{PLUGIN_NAME}}_on_post_phase" 50
    
    return 0
}

# Pre-scan hook
{{PLUGIN_NAME}}_on_pre_scan() {
    local domain="$1"
    local mode="$2"
    
    log_debug "{{PLUGIN_NAME}}: Pre-scan for $domain ($mode)"
}

# Post-phase hook
{{PLUGIN_NAME}}_on_post_phase() {
    local phase_name="$1"
    local result="$2"
    
    log_debug "{{PLUGIN_NAME}}: Phase $phase_name completed"
}

# Main function (can be called directly)
{{PLUGIN_NAME}}_main() {
    log_info "Running {{PLUGIN_NAME}} plugin"
    
    # Plugin logic here
}

# Cleanup function
{{PLUGIN_NAME}}_cleanup() {
    log_debug "Cleaning up {{PLUGIN_NAME}} plugin"
}
TEMPLATE

    sed -i "s/{{PLUGIN_NAME}}/$plugin_name/g" "$output_file"
    sed -i "s/{{DESCRIPTION}}/Custom plugin/g" "$output_file"
    sed -i "s/{{AUTHOR}}/Neko User/g" "$output_file"
    
    chmod +x "$output_file"
    log_success "Plugin template created: $output_file"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

plugin_cleanup() {
    for plugin_name in "${!PLUGINS[@]}"; do
        if type -t "${plugin_name}_cleanup" &>/dev/null; then
            "${plugin_name}_cleanup" 2>/dev/null || true
        fi
    done
    
    log_debug "Plugin cleanup completed"
}
