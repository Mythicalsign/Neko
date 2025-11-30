#!/usr/bin/env bash

#  ███╗   ██╗███████╗██╗  ██╗ ██████╗     ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     
#  ████╗  ██║██╔════╝██║ ██╔╝██╔═══██╗    ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     
#  ██╔██╗ ██║█████╗  █████╔╝ ██║   ██║    ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     
#  ██║╚██╗██║██╔══╝  ██╔═██╗ ██║   ██║    ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     
#  ██║ ╚████║███████╗██║  ██╗╚██████╔╝    ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
#  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
#
# Neko Installer - Bug Bounty Automation Framework
# Version: 1.0.0

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Paths
SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_PATH="${HOME}/Tools"
GO_PATH="${HOME}/go"
WORDLISTS_PATH="${TOOLS_PATH}/wordlists"

# Banner
banner() {
    echo -e "${MAGENTA}"
    echo "  ███╗   ██╗███████╗██╗  ██╗ ██████╗     ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     "
    echo "  ████╗  ██║██╔════╝██║ ██╔╝██╔═══██╗    ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     "
    echo "  ██╔██╗ ██║█████╗  █████╔╝ ██║   ██║    ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     "
    echo "  ██║╚██╗██║██╔══╝  ██╔═██╗ ██║   ██║    ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     "
    echo "  ██║ ╚████║███████╗██║  ██╗╚██████╔╝    ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗"
    echo "  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝"
    echo -e "${RESET}"
    echo -e "  ${CYAN}Bug Bounty Automation Framework Installer${RESET}"
    echo ""
}

log_info() { echo -e "${BLUE}[INFO]${RESET} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${RESET} $1"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. Some tools work better with regular user."
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VERSION=$DISTRIB_RELEASE
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        VERSION=$(sw_vers -productVersion)
    else
        OS="unknown"
    fi
    
    log_info "Detected OS: $OS $VERSION"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian|kali)
            sudo apt-get update
            sudo apt-get install -y \
                git curl wget jq python3 python3-pip python3-venv \
                build-essential libpcap-dev libssl-dev \
                nmap masscan nikto whois dnsutils \
                parallel sqlite3 tor netcat-openbsd bc \
                chromium-browser || sudo apt-get install -y chromium
            ;;
        fedora|centos|rhel)
            sudo dnf install -y \
                git curl wget jq python3 python3-pip \
                gcc make libpcap-devel openssl-devel \
                nmap masscan nikto whois bind-utils \
                parallel sqlite tor nc bc \
                chromium
            ;;
        arch|manjaro)
            sudo pacman -Sy --noconfirm \
                git curl wget jq python python-pip \
                base-devel libpcap openssl \
                nmap masscan nikto whois bind \
                chromium
            ;;
        macos)
            if ! command -v brew &>/dev/null; then
                log_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install git curl wget jq python3 \
                nmap masscan nikto whois bind \
                parallel sqlite tor netcat
            ;;
        *)
            log_warning "Unknown OS. Please install dependencies manually."
            ;;
    esac
    
    log_success "System dependencies installed"
}

# Install Go
install_golang() {
    if command -v go &>/dev/null; then
        local go_version=$(go version | grep -oE '[0-9]+\.[0-9]+')
        log_info "Go $go_version already installed"
        return 0
    fi
    
    log_info "Installing Go..."
    
    local GO_VERSION="1.21.5"
    local GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    
    if [[ "$OS" == "macos" ]]; then
        GO_TAR="go${GO_VERSION}.darwin-amd64.tar.gz"
    fi
    
    wget -q "https://golang.org/dl/${GO_TAR}" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add to PATH
    echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc
    
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    
    log_success "Go installed"
}

# Install Go tools
install_go_tools() {
    log_info "Installing Go-based tools..."
    
    local go_tools=(
        # Subdomain enumeration
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        
        # DNS tools
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/d3mondev/puredns/v2@latest"
        "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        "github.com/hakluke/hakip2host@latest"
        "github.com/pwnesia/dnstake@latest"
        
        # Web probing
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/tomnomnom/httprobe@latest"
        "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
        
        # URL discovery
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
        
        # Fuzzing
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/epi052/feroxbuster@latest"
        "github.com/OJ/gobuster/v3@latest"
        
        # Vulnerability scanning
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/Emoe/kxss@latest"
        "github.com/KathanP19/Gxss@latest"
        "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        
        # Parameter discovery
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/tomnomnom/unfurl@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/tomnomnom/anew@latest"
        
        # Port scanning
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/s0md3v/smap/cmd/smap@latest"
        
        # JS analysis
        "github.com/lc/subjs@latest"
        "github.com/BishopFox/jsluice/cmd/jsluice@latest"
        "github.com/denandz/sourcemapper@latest"
        
        # OSINT
        "github.com/gwen001/github-subdomains@latest"
        "github.com/gwen001/gitlab-subdomains@latest"
        "github.com/ferreiraklet/Jeeves@latest"
        
        # Secrets
        "github.com/trufflesecurity/trufflehog/v3@latest"
        "github.com/gitleaks/gitleaks/v8@latest"
        "github.com/MrEmpy/mantra@latest"
        
        # Cloud
        "github.com/sa7mon/S3Scanner@latest"
        
        # Subdomain takeover
        "github.com/haccer/subjack@latest"
        
        # Misc
        "github.com/projectdiscovery/notify/cmd/notify@latest"
        "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
        "github.com/Josue87/gotator@latest"
        "github.com/resyncgg/ripgen@latest"
        "github.com/trickest/dsieve@latest"
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        "github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@latest"
    )
    
    for tool in "${go_tools[@]}"; do
        local tool_name=$(basename "$tool" | cut -d@ -f1)
        log_info "Installing $tool_name..."
        go install "$tool" 2>/dev/null || log_warning "Failed to install $tool_name"
    done
    
    log_success "Go tools installed"
}

# Install Python tools
install_python_tools() {
    log_info "Installing Python-based tools..."
    
    # Create virtual environment for global tools
    python3 -m pip install --user --upgrade pip
    
    local pip_tools=(
        "wafw00f"
        "arjun"
        "paramspider"
        "sqlmap"
        "commix"
        "ghauri"
        "dirsearch"
        "dnsrecon"
        "theHarvester"
        "porch-pirate"
        "uro"
        "urless"
    )
    
    for tool in "${pip_tools[@]}"; do
        log_info "Installing $tool..."
        python3 -m pip install --user "$tool" 2>/dev/null || log_warning "Failed to install $tool"
    done
    
    log_success "Python tools installed"
}

# Install additional tools from GitHub
install_github_tools() {
    log_info "Installing tools from GitHub..."
    
    mkdir -p "$TOOLS_PATH"
    cd "$TOOLS_PATH"
    
    # CMSeeK
    if [[ ! -d "CMSeeK" ]]; then
        log_info "Installing CMSeeK..."
        git clone https://github.com/Tuhinshubhra/CMSeeK.git
        cd CMSeeK && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
        cd "$TOOLS_PATH"
    fi
    
    # Corsy
    if [[ ! -d "Corsy" ]]; then
        log_info "Installing Corsy..."
        git clone https://github.com/s0md3v/Corsy.git
        cd Corsy && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
        cd "$TOOLS_PATH"
    fi
    
    # Oralyzer
    if [[ ! -d "Oralyzer" ]]; then
        log_info "Installing Oralyzer..."
        git clone https://github.com/r0075h3ll/Oralyzer.git
        cd Oralyzer && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
        cd "$TOOLS_PATH"
    fi
    
    # Spoofy
    if [[ ! -d "Spoofy" ]]; then
        log_info "Installing Spoofy..."
        git clone https://github.com/MattKeeley/Spoofy.git
        cd Spoofy && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
        cd "$TOOLS_PATH"
    fi
    
    # SwaggerSpy
    if [[ ! -d "SwaggerSpy" ]]; then
        log_info "Installing SwaggerSpy..."
        git clone https://github.com/UndeadSec/SwaggerSpy.git
        cd SwaggerSpy && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
        cd "$TOOLS_PATH"
    fi
    
    # dorks_hunter
    if [[ ! -d "dorks_hunter" ]]; then
        log_info "Installing dorks_hunter..."
        git clone https://github.com/six2dez/dorks_hunter.git
        cd dorks_hunter && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
        cd "$TOOLS_PATH"
    fi
    
    # xnLinkFinder
    if ! command -v xnLinkFinder &>/dev/null; then
        log_info "Installing xnLinkFinder..."
        python3 -m pip install --user xnLinkFinder
    fi
    
    # ffufPostprocessing
    if [[ ! -d "ffufPostprocessing" ]]; then
        log_info "Installing ffufPostprocessing..."
        git clone https://github.com/Damian89/ffufPostprocessing.git
        cd ffufPostprocessing && go build -o ffufPostprocessing
        cd "$TOOLS_PATH"
    fi
    
    # gitdorks_go
    if [[ ! -d "gitdorks_go" ]]; then
        log_info "Installing gitdorks_go..."
        git clone https://github.com/damit5/gitdorks_go.git
    fi
    
    # nuclei-templates
    if [[ ! -d "${HOME}/nuclei-templates" ]]; then
        log_info "Installing nuclei templates..."
        nuclei -update-templates
    fi
    
    # GF patterns
    if [[ ! -d "${HOME}/.gf" ]]; then
        log_info "Installing GF patterns..."
        mkdir -p ~/.gf
        git clone https://github.com/tomnomnom/gf.git /tmp/gf
        cp /tmp/gf/examples/*.json ~/.gf/
        git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns
        cp /tmp/gf-patterns/*.json ~/.gf/
        rm -rf /tmp/gf /tmp/gf-patterns
    fi
    
    log_success "GitHub tools installed"
}

# Download wordlists
install_wordlists() {
    log_info "Downloading wordlists..."
    
    mkdir -p "$WORDLISTS_PATH"
    cd "$WORDLISTS_PATH"
    
    # Subdomain wordlists
    if [[ ! -f "subdomains.txt" ]]; then
        log_info "Downloading subdomain wordlists..."
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -O subdomains-top1million-5000.txt
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -O subdomains-top1million-110000.txt
        cat subdomains-top1million-5000.txt > subdomains.txt
    fi
    
    # Directory/file wordlists
    if [[ ! -f "fuzz.txt" ]]; then
        log_info "Downloading fuzzing wordlists..."
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -O common.txt
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" -O raft-large-directories.txt
        cat common.txt > fuzz.txt
    fi
    
    # LFI wordlist
    if [[ ! -f "lfi.txt" ]]; then
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" -O lfi.txt
    fi
    
    # Download resolvers
    if [[ ! -f "resolvers.txt" ]]; then
        log_info "Downloading DNS resolvers..."
        wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -O resolvers.txt
        wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" -O resolvers_trusted.txt
    fi
    
    log_success "Wordlists downloaded"
}

# Setup Neko
setup_neko() {
    log_info "Setting up Neko..."
    
    # Make scripts executable
    chmod +x "${SCRIPTPATH}/neko.sh"
    chmod +x "${SCRIPTPATH}/modules/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPTPATH}/lib/"*.sh 2>/dev/null || true
    
    # Create symlink
    if [[ ! -L "/usr/local/bin/neko" ]]; then
        sudo ln -sf "${SCRIPTPATH}/neko.sh" /usr/local/bin/neko || true
    fi
    
    # Update config with tools path
    sed -i "s|TOOLS_PATH=.*|TOOLS_PATH=\"${TOOLS_PATH}\"|" "${SCRIPTPATH}/neko.cfg" 2>/dev/null || true
    
    log_success "Neko setup completed"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    local missing=()
    local critical_tools=("subfinder" "httpx" "nuclei" "ffuf" "nmap" "dnsx" "katana")
    local v2_tools=("parallel" "sqlite3")
    
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warning "Missing critical tools: ${missing[*]}"
        log_warning "Some features may not work without these tools."
    else
        log_success "All critical tools installed!"
    fi
    
    # Check v2.0 dependencies
    local v2_missing=()
    for tool in "${v2_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            v2_missing+=("$tool")
        fi
    done
    
    if [[ ${#v2_missing[@]} -gt 0 ]]; then
        log_warning "Missing v2.0 tools: ${v2_missing[*]}"
        log_warning "Advanced features (parallel processing, intelligence) may be limited."
    else
        log_success "All v2.0 dependencies installed!"
    fi
}

# Main installation
main() {
    banner
    
    log_info "Starting Neko installation..."
    echo ""
    
    check_root
    detect_os
    
    echo ""
    echo -e "${CYAN}Installation Options:${RESET}"
    echo "  1) Full installation (recommended)"
    echo "  2) Go tools only"
    echo "  3) Python tools only"
    echo "  4) Update wordlists only"
    echo "  5) Verify installation"
    echo ""
    
    read -p "Select option [1-5]: " option
    
    case $option in
        1)
            install_dependencies
            install_golang
            install_go_tools
            install_python_tools
            install_github_tools
            install_wordlists
            setup_neko
            verify_installation
            ;;
        2)
            install_golang
            install_go_tools
            ;;
        3)
            install_python_tools
            ;;
        4)
            install_wordlists
            ;;
        5)
            verify_installation
            ;;
        *)
            log_error "Invalid option"
            exit 1
            ;;
    esac
    
    echo ""
    log_success "Installation completed!"
    echo ""
    echo -e "${GREEN}To start using Neko:${RESET}"
    echo "  source ~/.bashrc"
    echo "  neko -h"
    echo ""
    echo -e "${YELLOW}Don't forget to:${RESET}"
    echo "  1. Add your API keys to neko.cfg"
    echo "  2. Configure notification settings if needed"
    echo ""
}

main "$@"
