#!/bin/bash
# ============================================================================
# GLOBAL INTELLIGENCE SECURITY COMMAND CENTER
# TIER-0 NATIONAL SECURITY OPERATIONS CENTER
# CLASSIFICATION: TOP SECRET // NSOC // MULTI-AGENCY
# ============================================================================
# COMPREHENSIVE STARTUP SCRIPT
# Installs all opensource security tools and starts the complete system
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/gisc-backend"
FRONTEND_DIR="$SCRIPT_DIR/gisc-ui"
LOG_DIR="$SCRIPT_DIR/logs"
DATA_DIR="$SCRIPT_DIR/data"
CONFIG_DIR="$SCRIPT_DIR/config"

mkdir -p "$LOG_DIR" "$DATA_DIR" "$CONFIG_DIR"

print_banner() {
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "   ████████╗██╗   ██╗██████╗  █████╗ ███╗   ██╗████████╗██╗  ██╗ ██████╗ ███████╗"
    echo "   ╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██║  ██║██╔═══██╗██╔════╝"
    echo "      ██║    ╚████╔╝ ██████╔╝███████║██╔██╗ ██║   ██║   ███████║██║   ██║███████╗"
    echo "      ██║     ╚██╔╝  ██╔══██╗██╔══██║██║╚██╗██║   ██║   ██╔══██║██║   ██║╚════██║"
    echo "      ██║      ██║   ██║  ██║██║  ██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████║"
    echo "      ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
    echo "   CYBER INTELLIGENCE OPERATIONS SYSTEM"
    echo "   CLASSIFICATION: TOP SECRET // NSOC // MULTI-AGENCY"
    echo "============================================================================"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "Not running as root. Some security tools require root privileges."
        log_warn "Run with: sudo ./START_SYSTEM.sh full-install"
        return 1
    fi
    return 0
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        log_info "Detected OS: $OS $VERSION"
    else
        log_error "Cannot detect OS. This script supports Ubuntu/Debian."
        exit 1
    fi
}

# ============================================================================
# SYSTEM DEPENDENCIES
# ============================================================================

install_system_deps() {
    log_step "Installing system dependencies..."
    
    apt-get update -qq
    apt-get install -y -qq \
        build-essential \
        curl \
        wget \
        git \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        libpcap-dev \
        libnet1-dev \
        libyaml-dev \
        libjansson-dev \
        libmagic-dev \
        zlib1g-dev \
        libssl-dev \
        libpcre3-dev \
        liblz4-dev \
        libhwloc-dev \
        libluajit-5.1-dev \
        pkg-config \
        rustc \
        cargo \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        jq \
        tcpdump \
        tshark \
        nmap \
        netcat-openbsd \
        dnsutils \
        whois \
        traceroute \
        net-tools \
        iptables \
        ipset \
        sqlite3 \
        redis-server \
        nginx \
        2>/dev/null || true
    
    log_info "System dependencies installed"
}

install_nodejs() {
    log_step "Installing Node.js..."
    
    if command -v node &> /dev/null; then
        log_info "Node.js already installed: $(node --version)"
        return 0
    fi
    
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    log_info "Node.js installed: $(node --version)"
}

# ============================================================================
# SECURITY TOOLS INSTALLATION
# ============================================================================

install_suricata() {
    log_step "Installing Suricata IDS/IPS..."
    
    if command -v suricata &> /dev/null; then
        log_info "Suricata already installed: $(suricata --build-info | head -1)"
        return 0
    fi
    
    add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
    apt-get update -qq
    apt-get install -y suricata suricata-update
    
    mkdir -p /etc/suricata/rules
    mkdir -p /var/log/suricata
    
    suricata-update 2>/dev/null || true
    
    cat > /etc/suricata/suricata-gisc.yaml << 'SURICATA_CONFIG'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,8000,443"
    DNS_PORTS: "53"

default-log-dir: /var/log/suricata/

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
        - flow
        - netflow
        - stats

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

pcap:
  - interface: eth0

app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: yes
    dns:
      enabled: yes
    smtp:
      enabled: yes
    ssh:
      enabled: yes
    ftp:
      enabled: yes
SURICATA_CONFIG
    
    log_info "Suricata installed and configured"
}

install_zeek() {
    log_step "Installing Zeek Network Security Monitor..."
    
    if command -v zeek &> /dev/null; then
        log_info "Zeek already installed: $(zeek --version)"
        return 0
    fi
    
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list 2>/dev/null || true
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null 2>/dev/null || true
    apt-get update -qq 2>/dev/null || true
    apt-get install -y zeek 2>/dev/null || {
        log_warn "Zeek package not available, installing from source..."
        install_zeek_from_source
    }
    
    mkdir -p /opt/zeek/logs
    mkdir -p /opt/zeek/spool
    
    log_info "Zeek installed and configured"
}

install_zeek_from_source() {
    log_step "Building Zeek from source..."
    
    apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev libmaxminddb-dev
    
    cd /tmp
    wget -q https://download.zeek.org/zeek-6.0.0.tar.gz || {
        log_warn "Could not download Zeek source"
        return 1
    }
    tar xzf zeek-6.0.0.tar.gz
    cd zeek-6.0.0
    ./configure --prefix=/opt/zeek
    make -j$(nproc)
    make install
    
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
    ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
    
    cd "$SCRIPT_DIR"
    rm -rf /tmp/zeek-6.0.0*
}

install_snort() {
    log_step "Installing Snort IDS..."
    
    if command -v snort &> /dev/null; then
        log_info "Snort already installed: $(snort --version 2>&1 | head -1)"
        return 0
    fi
    
    apt-get install -y snort 2>/dev/null || {
        log_warn "Snort package not available, skipping..."
        return 0
    }
    
    mkdir -p /etc/snort/rules
    mkdir -p /var/log/snort
    
    log_info "Snort installed and configured"
}

install_arkime() {
    log_step "Installing Arkime (Full Packet Capture)..."
    
    if command -v capture &> /dev/null || [ -d /opt/arkime ]; then
        log_info "Arkime already installed"
        return 0
    fi
    
    cd /tmp
    ARKIME_VERSION="5.0.0"
    wget -q "https://s3.amazonaws.com/files.molo.ch/builds/ubuntu-22.04/arkime_${ARKIME_VERSION}-1_amd64.deb" 2>/dev/null || {
        log_warn "Could not download Arkime, skipping..."
        return 0
    }
    
    dpkg -i "arkime_${ARKIME_VERSION}-1_amd64.deb" 2>/dev/null || apt-get install -f -y
    
    mkdir -p /opt/arkime/raw
    mkdir -p /opt/arkime/logs
    
    cd "$SCRIPT_DIR"
    rm -f /tmp/arkime_*.deb
    
    log_info "Arkime installed"
}

install_elasticsearch() {
    log_step "Installing Elasticsearch/OpenSearch..."
    
    if systemctl is-active --quiet elasticsearch 2>/dev/null || systemctl is-active --quiet opensearch 2>/dev/null; then
        log_info "Elasticsearch/OpenSearch already running"
        return 0
    fi
    
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list 2>/dev/null || true
    apt-get update -qq 2>/dev/null || true
    apt-get install -y elasticsearch 2>/dev/null || {
        log_warn "Elasticsearch not available, installing OpenSearch..."
        install_opensearch
        return 0
    }
    
    cat > /etc/elasticsearch/elasticsearch.yml << 'ES_CONFIG'
cluster.name: gisc-cluster
node.name: gisc-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200
xpack.security.enabled: false
ES_CONFIG
    
    systemctl enable elasticsearch
    systemctl start elasticsearch
    
    log_info "Elasticsearch installed and started"
}

install_opensearch() {
    log_step "Installing OpenSearch..."
    
    cd /tmp
    wget -q https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.0/opensearch-2.11.0-linux-x64.tar.gz 2>/dev/null || {
        log_warn "Could not download OpenSearch, skipping..."
        return 0
    }
    
    tar xzf opensearch-2.11.0-linux-x64.tar.gz
    mv opensearch-2.11.0 /opt/opensearch
    
    useradd -r -s /bin/false opensearch 2>/dev/null || true
    chown -R opensearch:opensearch /opt/opensearch
    
    cat > /etc/systemd/system/opensearch.service << 'OPENSEARCH_SERVICE'
[Unit]
Description=OpenSearch
After=network.target

[Service]
Type=simple
User=opensearch
Group=opensearch
ExecStart=/opt/opensearch/bin/opensearch
Restart=on-failure
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
OPENSEARCH_SERVICE
    
    systemctl daemon-reload
    systemctl enable opensearch
    systemctl start opensearch
    
    cd "$SCRIPT_DIR"
    rm -rf /tmp/opensearch-*
    
    log_info "OpenSearch installed and started"
}

install_ntopng() {
    log_step "Installing ntopng (Network Traffic Monitor)..."
    
    if command -v ntopng &> /dev/null; then
        log_info "ntopng already installed"
        return 0
    fi
    
    apt-get install -y software-properties-common wget
    add-apt-repository -y universe 2>/dev/null || true
    wget -q https://packages.ntop.org/apt-stable/22.04/all/apt-ntop-stable.deb 2>/dev/null || {
        log_warn "Could not download ntop repository, trying apt..."
    }
    dpkg -i apt-ntop-stable.deb 2>/dev/null || true
    apt-get update -qq 2>/dev/null || true
    apt-get install -y ntopng nprobe 2>/dev/null || {
        log_warn "ntopng not available from ntop repo, trying default..."
        apt-get install -y ntopng 2>/dev/null || {
            log_warn "ntopng not available, skipping..."
            return 0
        }
    }
    
    mkdir -p /var/lib/ntopng
    
    cat > /etc/ntopng/ntopng.conf << 'NTOPNG_CONFIG'
-i=eth0
-w=3000
-m=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
--community
--disable-login=1
NTOPNG_CONFIG
    
    rm -f /tmp/apt-ntop-stable.deb
    
    log_info "ntopng installed and configured"
}

install_tor() {
    log_step "Installing Tor for Dark Web connectivity..."
    
    if command -v tor &> /dev/null; then
        log_info "Tor already installed"
        return 0
    fi
    
    apt-get install -y tor torsocks
    
    cat > /etc/tor/torrc.gisc << 'TOR_CONFIG'
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /var/lib/tor
Log notice file /var/log/tor/notices.log
TOR_CONFIG
    
    mkdir -p /var/log/tor
    chown debian-tor:debian-tor /var/log/tor
    
    log_info "Tor installed and configured"
}

# ============================================================================
# PYTHON AND NODE DEPENDENCIES
# ============================================================================

install_python_deps() {
    log_step "Installing Python dependencies..."
    
    cd "$BACKEND_DIR"
    
    if command -v poetry &> /dev/null; then
        log_info "Using Poetry for dependency management..."
        poetry install 2>/dev/null || {
            log_warn "Poetry lock failed, regenerating..."
            poetry lock --no-update 2>/dev/null || true
            poetry install 2>/dev/null || true
        }
    else
        log_info "Poetry not found, using pip with virtual environment..."
        
        # Create virtual environment if it doesn't exist
        if [ ! -d ".venv" ]; then
            log_info "Creating Python virtual environment..."
            python3 -m venv .venv
        fi
        
        # Activate and install dependencies
        source .venv/bin/activate
        pip install --quiet --upgrade pip
        
        pip install --quiet \
            fastapi[standard] \
            uvicorn[standard] \
            sqlalchemy \
            aiosqlite \
            python-multipart \
            pydantic-settings \
            psutil \
            httpx \
            aiohttp \
            beautifulsoup4 \
            lxml \
            dnspython \
            python-whois \
            pycryptodome \
            cryptography \
            requests \
            scapy \
            2>/dev/null || true
    fi
    
    log_info "Python dependencies installed"
}

install_node_deps() {
    log_step "Installing Node.js dependencies..."
    
    cd "$FRONTEND_DIR"
    
    if [ -f "package-lock.json" ]; then
        npm ci --silent 2>/dev/null || npm install --silent
    else
        npm install --silent
    fi
    
    log_info "Node.js dependencies installed"
}

# ============================================================================
# CONFIGURATION
# ============================================================================

configure_system() {
    log_step "Configuring system..."
    
    cat > "$CONFIG_DIR/gisc.conf" << 'GISC_CONFIG'
# GISC Configuration
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
FRONTEND_PORT=5173

# Security Tools
SURICATA_ENABLED=true
ZEEK_ENABLED=true
SNORT_ENABLED=false
ARKIME_ENABLED=true
ELASTICSEARCH_ENABLED=true
NTOPNG_ENABLED=true
TOR_ENABLED=true

# Network Interface
CAPTURE_INTERFACE=eth0

# Logging
LOG_LEVEL=INFO
LOG_DIR=/var/log/gisc
GISC_CONFIG
    
    mkdir -p /var/log/gisc
    
    log_info "System configured"
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

start_security_services() {
    log_step "Starting security services..."
    
    if command -v suricata &> /dev/null; then
        systemctl start suricata 2>/dev/null || suricata -c /etc/suricata/suricata.yaml -i eth0 -D 2>/dev/null || true
        log_info "Suricata started"
    fi
    
    if command -v zeek &> /dev/null || [ -x /opt/zeek/bin/zeek ]; then
        zeekctl deploy 2>/dev/null || /opt/zeek/bin/zeekctl deploy 2>/dev/null || true
        log_info "Zeek started"
    fi
    
    if systemctl is-enabled elasticsearch 2>/dev/null; then
        systemctl start elasticsearch 2>/dev/null || true
        log_info "Elasticsearch started"
    fi
    
    if systemctl is-enabled opensearch 2>/dev/null; then
        systemctl start opensearch 2>/dev/null || true
        log_info "OpenSearch started"
    fi
    
    if command -v ntopng &> /dev/null; then
        systemctl start ntopng 2>/dev/null || ntopng /etc/ntopng/ntopng.conf 2>/dev/null &
        log_info "ntopng started"
    fi
    
    if command -v tor &> /dev/null; then
        systemctl start tor 2>/dev/null || tor -f /etc/tor/torrc.gisc 2>/dev/null &
        log_info "Tor started"
    fi
    
    systemctl start redis-server 2>/dev/null || redis-server --daemonize yes 2>/dev/null || true
    
    log_info "Security services started"
}

stop_security_services() {
    log_step "Stopping security services..."
    
    systemctl stop suricata 2>/dev/null || pkill -f suricata 2>/dev/null || true
    zeekctl stop 2>/dev/null || /opt/zeek/bin/zeekctl stop 2>/dev/null || pkill -f zeek 2>/dev/null || true
    systemctl stop elasticsearch 2>/dev/null || true
    systemctl stop opensearch 2>/dev/null || pkill -f opensearch 2>/dev/null || true
    systemctl stop ntopng 2>/dev/null || pkill -f ntopng 2>/dev/null || true
    systemctl stop tor 2>/dev/null || pkill -f tor 2>/dev/null || true
    
    log_info "Security services stopped"
}

start_backend() {
    log_step "Starting backend API server..."
    
    cd "$BACKEND_DIR"
    
    # Create virtual environment if it doesn't exist and Poetry is not available
    if ! command -v poetry &> /dev/null; then
        if [ ! -d ".venv" ]; then
            log_info "Creating Python virtual environment..."
            python3 -m venv .venv
        fi
        
        log_info "Activating virtual environment and installing dependencies..."
        source .venv/bin/activate
        pip install --quiet --upgrade pip
        pip install --quiet \
            fastapi[standard] \
            uvicorn[standard] \
            sqlalchemy \
            aiosqlite \
            python-multipart \
            pydantic-settings \
            psutil \
            httpx \
            aiohttp \
            beautifulsoup4 \
            lxml \
            dnspython \
            python-whois \
            pycryptodome \
            cryptography \
            requests \
            scapy \
            2>/dev/null || true
        
        .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/backend.log" 2>&1 &
    else
        poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000 > "$LOG_DIR/backend.log" 2>&1 &
    fi
    BACKEND_PID=$!
    echo $BACKEND_PID > "$DATA_DIR/backend.pid"
    
    sleep 3
    
    curl -s -X POST http://localhost:8000/api/v1/seed > /dev/null 2>&1 || true
    
    log_info "Backend started (PID: $BACKEND_PID)"
}

start_frontend() {
    log_step "Starting frontend UI server..."
    
    cd "$FRONTEND_DIR"
    
    npm run dev -- --port 3000 --host 0.0.0.0 > "$LOG_DIR/frontend.log" 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > "$DATA_DIR/frontend.pid"
    
    log_info "Frontend started (PID: $FRONTEND_PID)"
}

stop_backend() {
    if [ -f "$DATA_DIR/backend.pid" ]; then
        kill $(cat "$DATA_DIR/backend.pid") 2>/dev/null || true
        rm -f "$DATA_DIR/backend.pid"
    fi
    pkill -f "uvicorn app.main:app" 2>/dev/null || true
    log_info "Backend stopped"
}

stop_frontend() {
    if [ -f "$DATA_DIR/frontend.pid" ]; then
        kill $(cat "$DATA_DIR/frontend.pid") 2>/dev/null || true
        rm -f "$DATA_DIR/frontend.pid"
    fi
    pkill -f "npm run dev" 2>/dev/null || true
    pkill -f "vite" 2>/dev/null || true
    log_info "Frontend stopped"
}

# ============================================================================
# STATUS CHECK
# ============================================================================

check_status() {
    echo ""
    echo -e "${CYAN}=== SYSTEM STATUS ===${NC}"
    echo ""
    
    local SECURITY_INSTALLED=false
    
    if command -v suricata &> /dev/null || command -v zeek &> /dev/null; then
        SECURITY_INSTALLED=true
        echo -e "${BLUE}Security Tools:${NC}"
        
        if pgrep -x suricata > /dev/null; then
            echo -e "  Suricata:      ${GREEN}RUNNING${NC}"
        elif command -v suricata &> /dev/null; then
            echo -e "  Suricata:      ${YELLOW}INSTALLED${NC} (not running)"
        fi
        
        if pgrep -x zeek > /dev/null || pgrep -f "zeek" > /dev/null; then
            echo -e "  Zeek:          ${GREEN}RUNNING${NC}"
        elif command -v zeek &> /dev/null; then
            echo -e "  Zeek:          ${YELLOW}INSTALLED${NC} (not running)"
        fi
        
        if curl -s http://localhost:9200 > /dev/null 2>&1; then
            echo -e "  Elasticsearch: ${GREEN}RUNNING${NC}"
        elif command -v elasticsearch &> /dev/null || [ -d /usr/share/elasticsearch ]; then
            echo -e "  Elasticsearch: ${YELLOW}INSTALLED${NC} (not running)"
        fi
        
        if pgrep -x ntopng > /dev/null; then
            echo -e "  ntopng:        ${GREEN}RUNNING${NC}"
        elif command -v ntopng &> /dev/null; then
            echo -e "  ntopng:        ${YELLOW}INSTALLED${NC} (not running)"
        fi
        
        if pgrep -x tor > /dev/null; then
            echo -e "  Tor:           ${GREEN}RUNNING${NC}"
        elif command -v tor &> /dev/null; then
            echo -e "  Tor:           ${YELLOW}INSTALLED${NC} (not running)"
        fi
        
        echo ""
    fi
    
    echo -e "${BLUE}Application:${NC}"
    
    if curl -s http://localhost:8000/healthz > /dev/null 2>&1; then
        echo -e "  Backend API:   ${GREEN}RUNNING${NC} (http://localhost:8000)"
    else
        echo -e "  Backend API:   ${RED}STOPPED${NC}"
    fi
    
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo -e "  Frontend UI:   ${GREEN}RUNNING${NC} (http://localhost:3000)"
    else
        echo -e "  Frontend UI:   ${RED}STOPPED${NC}"
    fi
    
    echo ""
}

# ============================================================================
# MAIN COMMANDS
# ============================================================================

print_banner

case "${1:-}" in
    "")
        log_step "TYRANTHOS - AUTOMATIC FULL SYSTEM STARTUP"
        log_step "Installing dependencies and starting system..."
        
        log_step "Installing libpcap for deep packet inspection..."
        sudo apt-get update -qq 2>/dev/null || true
        sudo apt-get install -y -qq libpcap-dev tcpdump netcat-openbsd 2>/dev/null || true
        
        install_python_deps
        install_node_deps
        
        log_step "Setting up packet capture capabilities..."
        sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || true
        
        PYTHON_VENV_PATH=$(cd "$BACKEND_DIR" && poetry env info -p 2>/dev/null)/bin/python3
        if [ -n "$PYTHON_VENV_PATH" ]; then
            REAL_PYTHON=$(readlink -f "$PYTHON_VENV_PATH" 2>/dev/null)
            if [ -n "$REAL_PYTHON" ] && [ -f "$REAL_PYTHON" ]; then
                log_step "Setting Python capabilities for Scapy packet capture..."
                sudo setcap cap_net_raw,cap_net_admin=eip "$REAL_PYTHON" 2>/dev/null || true
            fi
        fi
        
        start_backend
        start_frontend
        sleep 3
        check_status
        echo ""
        log_info "============================================"
        log_info "TYRANTHOS SYSTEM READY - 100% OPERATIONAL"
        log_info "============================================"
        log_info "Backend API:  http://localhost:8000"
        log_info "API Docs:     http://localhost:8000/docs"
        log_info "Frontend UI:  http://localhost:3000"
        log_info "============================================"
        log_info "Deep Packet Inspection: ENABLED (Scapy)"
        log_info "Real-time Attack Detection: ENABLED"
        log_info "Malicious Payload Analysis: ENABLED"
        log_info "============================================"
        log_info "Press Ctrl+C to stop"
        wait
        ;;
    
    run)
        log_step "TYRANTHOS - FULL SYSTEM INSTALLATION & STARTUP"
        
        install_python_deps
        install_node_deps
        
        sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || true
        
        start_backend
        start_frontend
        sleep 3
        check_status
        echo ""
        log_info "============================================"
        log_info "TYRANTHOS SYSTEM READY - 100% OPERATIONAL"
        log_info "============================================"
        log_info "Backend API:  http://localhost:8000"
        log_info "API Docs:     http://localhost:8000/docs"
        log_info "Frontend UI:  http://localhost:3000"
        log_info "============================================"
        log_info "Press Ctrl+C to stop"
        wait
        ;;
    
    run-full)
        log_step "FULL SYSTEM INSTALLATION (root mode)..."
        detect_os
        install_system_deps
        install_nodejs
        install_suricata
        install_zeek
        install_snort
        install_arkime
        install_elasticsearch
        install_ntopng
        install_tor
        install_python_deps
        install_node_deps
        configure_system
        
        log_step "Starting ALL services..."
        start_security_services
        start_backend
        start_frontend
        sleep 3
        check_status
        echo ""
        log_info "============================================"
        log_info "FULL SYSTEM READY - 100% OPERATIONAL"
        log_info "============================================"
        log_info "Backend API:  http://localhost:8000"
        log_info "API Docs:     http://localhost:8000/docs"
        log_info "Frontend UI:  http://localhost:3000"
        log_info "ntopng:       http://localhost:3001"
        log_info "Elasticsearch: http://localhost:9200"
        log_info "============================================"
        log_info "Press Ctrl+C to stop"
        wait
        ;;
    
    full-install)
        log_step "FULL INSTALLATION - Installing all components..."
        check_root || { log_error "Root privileges required for full installation"; exit 1; }
        detect_os
        install_system_deps
        install_nodejs
        install_suricata
        install_zeek
        install_snort
        install_arkime
        install_elasticsearch
        install_ntopng
        install_tor
        install_python_deps
        install_node_deps
        configure_system
        echo ""
        log_info "============================================"
        log_info "FULL INSTALLATION COMPLETE"
        log_info "============================================"
        log_info "Run: ./START_SYSTEM.sh start"
        ;;
    
    install)
        log_step "Installing application dependencies..."
        install_python_deps
        install_node_deps
        log_info "Dependencies installed. Run: ./START_SYSTEM.sh start"
        ;;
    
    install-security)
        log_step "Installing security tools only..."
        check_root || { log_error "Root privileges required"; exit 1; }
        detect_os
        install_system_deps
        install_suricata
        install_zeek
        install_snort
        install_arkime
        install_elasticsearch
        install_ntopng
        install_tor
        log_info "Security tools installed"
        ;;
    
    start)
        log_step "Starting GISC system..."
        start_security_services
        start_backend
        start_frontend
        sleep 2
        check_status
        echo ""
        log_info "============================================"
        log_info "SYSTEM STARTED"
        log_info "============================================"
        log_info "Backend API:  http://localhost:8000"
        log_info "API Docs:     http://localhost:8000/docs"
        log_info "Frontend UI:  http://localhost:3000"
        log_info "ntopng:       http://localhost:3001"
        log_info "============================================"
        log_info "Press Ctrl+C to stop or run: ./START_SYSTEM.sh stop"
        wait
        ;;
    
    start-app)
        log_step "Starting application only (no security services)..."
        start_backend
        start_frontend
        sleep 2
        echo ""
        log_info "Backend API:  http://localhost:8000"
        log_info "Frontend UI:  http://localhost:3000"
        wait
        ;;
    
    stop)
        log_step "Stopping GISC system..."
        stop_frontend
        stop_backend
        stop_security_services
        log_info "System stopped"
        ;;
    
    restart)
        log_step "Restarting GISC system..."
        $0 stop
        sleep 2
        $0 start
        ;;
    
    status)
        check_status
        ;;
    
    backend)
        log_step "Starting backend only..."
        start_backend
        wait
        ;;
    
    frontend)
        log_step "Starting frontend only..."
        start_frontend
        wait
        ;;
    
    build)
        log_step "Building production frontend..."
        cd "$FRONTEND_DIR"
        npm run build
        log_info "Frontend built in dist/ directory"
        ;;
    
    logs)
        log_step "Showing logs..."
        tail -f "$LOG_DIR"/*.log 2>/dev/null || {
            log_warn "No logs found. Showing system logs..."
            journalctl -f -u suricata -u elasticsearch -u ntopng -u tor 2>/dev/null || true
        }
        ;;
    
    help|*)
        echo "Usage: $0 {command}"
        echo ""
        echo "Installation Commands:"
        echo "  full-install    - Install ALL components (requires root)"
        echo "  install         - Install application dependencies only"
        echo "  install-security - Install security tools only (requires root)"
        echo ""
        echo "Runtime Commands:"
        echo "  start           - Start complete system (security + app)"
        echo "  start-app       - Start application only (backend + frontend)"
        echo "  stop            - Stop all services"
        echo "  restart         - Restart all services"
        echo "  status          - Show system status"
        echo ""
        echo "Individual Services:"
        echo "  backend         - Start backend API only"
        echo "  frontend        - Start frontend UI only"
        echo "  build           - Build production frontend"
        echo "  logs            - Show system logs"
        echo ""
        echo "Examples:"
        echo "  sudo ./START_SYSTEM.sh full-install  # First time setup"
        echo "  ./START_SYSTEM.sh start              # Start everything"
        echo "  ./START_SYSTEM.sh start-app          # Start without security tools"
        ;;
esac
