#!/bin/bash

# Teleport Installation Script for Ubuntu
# Supports Ubuntu 20.04, 22.04, and 24.04
# Run as root

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Teleport Installation for Ubuntu${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   echo -e "${YELLOW}    Try: sudo $0${NC}"
   exit 1
fi

# Check if Ubuntu
if [ ! -f /etc/os-release ]; then
    echo -e "${RED}[!] Cannot determine OS version${NC}"
    exit 1
fi

source /etc/os-release

if [[ "$ID" != "ubuntu" ]]; then
    echo -e "${RED}[!] This script is designed for Ubuntu${NC}"
    echo -e "${YELLOW}    Detected: $ID${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${GREEN}[+] Detected: $PRETTY_NAME${NC}"
echo ""

# Prompt for installation method
echo -e "${YELLOW}Select installation method:${NC}"
echo "  1) Install from Teleport APT repository (recommended)"
echo "  2) Download and install latest stable binary"
echo "  3) Install specific version from binary"
echo ""
read -p "Enter choice [1-3]: " INSTALL_METHOD

case $INSTALL_METHOD in
    1)
        echo -e "${GREEN}[+] Installing from APT repository${NC}"
        
        # Install dependencies
        echo -e "${YELLOW}[*] Installing dependencies...${NC}"
        apt-get update
        apt-get install -y curl gnupg2 ca-certificates
        
        # Add Teleport repository
        echo -e "${YELLOW}[*] Adding Teleport APT repository...${NC}"
        curl https://apt.releases.teleport.dev/gpg -o /usr/share/keyrings/teleport-archive-keyring.asc
        
        # Determine Ubuntu version codename
        CODENAME=$(lsb_release -cs)
        
        echo "deb [signed-by=/usr/share/keyrings/teleport-archive-keyring.asc] https://apt.releases.teleport.dev/${CODENAME} ${CODENAME} stable/v16" \
        | tee /etc/apt/sources.list.d/teleport.list > /dev/null
        
        # Update and install
        echo -e "${YELLOW}[*] Updating package lists...${NC}"
        apt-get update
        
        echo -e "${YELLOW}[*] Installing Teleport...${NC}"
        apt-get install -y teleport
        
        ;;
        
    2)
        echo -e "${GREEN}[+] Installing latest stable binary${NC}"
        
        # Detect architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)
                TELEPORT_ARCH="amd64"
                ;;
            aarch64)
                TELEPORT_ARCH="arm64"
                ;;
            armv7l)
                TELEPORT_ARCH="arm"
                ;;
            *)
                echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
                exit 1
                ;;
        esac
        
        echo -e "${YELLOW}[*] Detected architecture: $TELEPORT_ARCH${NC}"
        
        # Get latest version
        echo -e "${YELLOW}[*] Fetching latest Teleport version...${NC}"
        LATEST_VERSION=$(curl -s https://api.github.com/repos/gravitational/teleport/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        
        if [ -z "$LATEST_VERSION" ]; then
            echo -e "${RED}[!] Could not determine latest version${NC}"
            echo -e "${YELLOW}[*] Using fallback version: 16.4.0${NC}"
            LATEST_VERSION="16.4.0"
        fi
        
        echo -e "${GREEN}[+] Latest version: $LATEST_VERSION${NC}"
        
        # Download Teleport
        DOWNLOAD_URL="https://cdn.teleport.dev/teleport-v${LATEST_VERSION}-linux-${TELEPORT_ARCH}-bin.tar.gz"
        echo -e "${YELLOW}[*] Downloading from: $DOWNLOAD_URL${NC}"
        
        cd /tmp
        curl -LO "$DOWNLOAD_URL"
        
        # Extract
        echo -e "${YELLOW}[*] Extracting archive...${NC}"
        tar -xzf "teleport-v${LATEST_VERSION}-linux-${TELEPORT_ARCH}-bin.tar.gz"
        
        # Install binaries
        echo -e "${YELLOW}[*] Installing binaries...${NC}"
        cd teleport
        ./install
        
        # Clean up
        cd /tmp
        rm -rf teleport "teleport-v${LATEST_VERSION}-linux-${TELEPORT_ARCH}-bin.tar.gz"
        
        ;;
        
    3)
        echo -e "${GREEN}[+] Installing specific version${NC}"
        read -p "Enter Teleport version (e.g., 16.4.0): " SPECIFIC_VERSION
        
        # Detect architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)
                TELEPORT_ARCH="amd64"
                ;;
            aarch64)
                TELEPORT_ARCH="arm64"
                ;;
            armv7l)
                TELEPORT_ARCH="arm"
                ;;
            *)
                echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
                exit 1
                ;;
        esac
        
        # Download specific version
        DOWNLOAD_URL="https://cdn.teleport.dev/teleport-v${SPECIFIC_VERSION}-linux-${TELEPORT_ARCH}-bin.tar.gz"
        echo -e "${YELLOW}[*] Downloading from: $DOWNLOAD_URL${NC}"
        
        cd /tmp
        curl -LO "$DOWNLOAD_URL"
        
        # Extract
        echo -e "${YELLOW}[*] Extracting archive...${NC}"
        tar -xzf "teleport-v${SPECIFIC_VERSION}-linux-${TELEPORT_ARCH}-bin.tar.gz"
        
        # Install binaries
        echo -e "${YELLOW}[*] Installing binaries...${NC}"
        cd teleport
        ./install
        
        # Clean up
        cd /tmp
        rm -rf teleport "teleport-v${SPECIFIC_VERSION}-linux-${TELEPORT_ARCH}-bin.tar.gz"
        
        ;;
        
    *)
        echo -e "${RED}[!] Invalid choice${NC}"
        exit 1
        ;;
esac

# Verify installation
echo ""
echo -e "${YELLOW}[*] Verifying installation...${NC}"
if command -v teleport &> /dev/null; then
    echo -e "${GREEN}[+] Teleport installed successfully!${NC}"
    INSTALLED_VERSION=$(teleport version | head -n1)
    echo -e "${GREEN}[+] Version: $INSTALLED_VERSION${NC}"
else
    echo -e "${RED}[!] Teleport installation failed${NC}"
    exit 1
fi

# Check for other binaries
echo ""
echo -e "${YELLOW}[*] Checking installed binaries:${NC}"
for binary in teleport tsh tctl tbot; do
    if command -v $binary &> /dev/null; then
        echo -e "${GREEN}    [+] $binary - $(which $binary)${NC}"
    else
        echo -e "${YELLOW}    [!] $binary - not found${NC}"
    fi
done

# Create teleport user if doesn't exist
echo ""
echo -e "${YELLOW}[*] Setting up teleport user...${NC}"
if ! id "teleport" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin teleport
    echo -e "${GREEN}[+] Created teleport system user${NC}"
else
    echo -e "${GREEN}[+] Teleport user already exists${NC}"
fi

# Create necessary directories
echo -e "${YELLOW}[*] Creating directories...${NC}"
mkdir -p /var/lib/teleport
mkdir -p /var/log/teleport
mkdir -p /etc/teleport

chown -R teleport:teleport /var/lib/teleport
chown -R teleport:teleport /var/log/teleport
chmod 700 /var/lib/teleport
chmod 750 /var/log/teleport

echo -e "${GREEN}[+] Directories created${NC}"

# Ask if user wants to configure Teleport now
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}Installation complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

read -p "Would you like to generate a basic configuration now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[*] Generating basic configuration...${NC}"
    
    # Get hostname
    HOSTNAME=$(hostname -f)
    
    # Generate basic config
    cat > /etc/teleport.yaml << EOF
version: v3
teleport:
  nodename: ${HOSTNAME}
  data_dir: /var/lib/teleport
  log:
    output: stderr
    severity: INFO
    format:
      output: text

auth_service:
  enabled: yes
  listen_addr: 0.0.0.0:3025
  cluster_name: teleport-cluster
  
  authentication:
    type: local
    second_factor: optional

proxy_service:
  enabled: yes
  listen_addr: 0.0.0.0:3023
  web_listen_addr: 0.0.0.0:3080
  tunnel_listen_addr: 0.0.0.0:3024
  public_addr: ${HOSTNAME}:3080
  ssh_public_addr: ${HOSTNAME}:3022

ssh_service:
  enabled: yes
  listen_addr: 0.0.0.0:3022
EOF

    chmod 600 /etc/teleport.yaml
    chown root:root /etc/teleport.yaml
    
    echo -e "${GREEN}[+] Configuration created at /etc/teleport.yaml${NC}"
fi

# Create systemd service if doesn't exist
echo ""
echo -e "${YELLOW}[*] Setting up systemd service...${NC}"

if [ ! -f /etc/systemd/system/teleport.service ]; then
    cat > /etc/systemd/system/teleport.service << 'EOF'
[Unit]
Description=Teleport SSH Service
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5
ExecStart=/usr/local/bin/teleport start --config=/etc/teleport.yaml --pid-file=/run/teleport.pid
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/teleport.pid
LimitNOFILE=8192
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}[+] Systemd service created${NC}"
else
    echo -e "${GREEN}[+] Systemd service already exists${NC}"
fi

# Ask if user wants to start service
echo ""
read -p "Would you like to start Teleport now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[*] Starting Teleport service...${NC}"
    systemctl start teleport
    systemctl enable teleport
    
    sleep 2
    
    if systemctl is-active --quiet teleport; then
        echo -e "${GREEN}[+] Teleport service is running!${NC}"
    else
        echo -e "${RED}[!] Teleport service failed to start${NC}"
        echo -e "${YELLOW}[*] Check logs: journalctl -u teleport -n 50${NC}"
    fi
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Installation Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}Teleport Version:${NC} $(teleport version | head -n1)"
echo -e "${YELLOW}Configuration:${NC} /etc/teleport.yaml"
echo -e "${YELLOW}Data Directory:${NC} /var/lib/teleport"
echo -e "${YELLOW}Log Directory:${NC} /var/log/teleport"
echo ""
echo -e "${YELLOW}Service Commands:${NC}"
echo -e "  Start:   systemctl start teleport"
echo -e "  Stop:    systemctl stop teleport"
echo -e "  Status:  systemctl status teleport"
echo -e "  Logs:    journalctl -u teleport -f"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Review/edit config: nano /etc/teleport.yaml"
echo -e "  2. Configure firewall for ports: 3080, 3022, 3025, 3024"
echo -e "  3. Create admin user: tctl users add admin --roles=editor,access --logins=root"
echo -e "  4. Access web UI: https://$(hostname -I | awk '{print $1}'):3080"
echo ""
echo -e "${YELLOW}For CCDC:${NC}"
echo -e "  Run the hardening script after installation to secure Teleport"
echo ""
echo -e "${BLUE}========================================${NC}"
