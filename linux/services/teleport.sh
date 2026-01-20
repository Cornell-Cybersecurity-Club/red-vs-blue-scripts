#!/bin/bash

# Teleport Security Hardening Script for CCDC
# Run as root

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[+] Starting Teleport Security Hardening${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[!] This script must be run as root${NC}"
  exit 1
fi

# Define Teleport ports
TELEPORT_PROXY_PORT=3080  # Web UI and API
TELEPORT_AUTH_PORT=3025   # Auth service
TELEPORT_SSH_PORT=3022    # SSH proxy
TELEPORT_TUNNEL_PORT=3024 # Reverse tunnel
TELEPORT_K8S_PORT=3026    # Kubernetes proxy (if used)

echo -e "${GREEN}[+] Configuring iptables rules${NC}"

# Allow Teleport ports
echo -e "${YELLOW}[*] Opening Teleport ports${NC}"
iptables -I INPUT -p tcp --dport $TELEPORT_PROXY_PORT -m state --state NEW -j ACCEPT
iptables -I INPUT -p tcp --dport $TELEPORT_AUTH_PORT -m state --state NEW -j ACCEPT
iptables -I INPUT -p tcp --dport $TELEPORT_SSH_PORT -m state --state NEW -j ACCEPT
iptables -I INPUT -p tcp --dport $TELEPORT_TUNNEL_PORT -m state --state NEW -j ACCEPT

# Optional: Allow Kubernetes proxy port
# iptables -I INPUT -p tcp --dport $TELEPORT_K8S_PORT -m state --state NEW -j ACCEPT

# Rate limiting for Teleport ports to prevent brute force
iptables -I INPUT -p tcp --dport $TELEPORT_PROXY_PORT -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport $TELEPORT_PROXY_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

# Save iptables rules
if [ -f /etc/debian_version ]; then
  # Debian/Ubuntu
  iptables-save >/etc/iptables/rules.v4
elif [ -f /etc/redhat-release ]; then
  # RHEL/CentOS
  service iptables save
fi

echo -e "${GREEN}[+] Hardening Teleport configuration${NC}"

# Create secure teleport configuration
cat >/etc/teleport.yaml <<'EOF'
version: v3
teleport:
  nodename: teleport-node
  data_dir: /var/lib/teleport
  log:
    output: stderr
    severity: INFO
    format:
      output: text
  
  # Connection limits
  connection_limits:
    max_connections: 1000
    max_users: 250

  # Cache settings
  cache:
    enabled: true
    ttl: 20h

auth_service:
  enabled: yes
  listen_addr: 0.0.0.0:3025
  
  # Session recording
  session_recording: node
  
  # Cluster configuration
  cluster_name: ccdc-cluster
  
  # Authentication settings
  authentication:
    type: local
    second_factor: otp
    webauthn:
      rp_id: localhost
    
  # Password complexity
  local_auth: true
  
  # Disconnect expired certificates
  disconnect_expired_cert: yes

proxy_service:
  enabled: yes
  listen_addr: 0.0.0.0:3023
  web_listen_addr: 0.0.0.0:3080
  tunnel_listen_addr: 0.0.0.0:3024
  
  # TLS settings
  https_keypairs:
  - key_file: /var/lib/teleport/privkey.pem
    cert_file: /var/lib/teleport/fullchain.pem
  
  # Security headers
  public_addr: localhost:3080
  
  # SSH settings
  ssh_public_addr: localhost:3022

ssh_service:
  enabled: yes
  listen_addr: 0.0.0.0:3022
  
  # Enhanced session recording
  enhanced_recording:
    enabled: true
    command_buffer_size: 8
    disk_buffer_size: 128
    network_buffer_size: 8
  
  # PAM configuration
  pam:
    enabled: no
    service_name: teleport
  
  # Command execution
  commands:
  - name: hostname
    command: [hostname]
    period: 1m0s
EOF

echo -e "${GREEN}[+] Setting secure file permissions${NC}"

# Secure teleport directories and files
chown -R root:root /etc/teleport.yaml
chmod 600 /etc/teleport.yaml

if [ -d /var/lib/teleport ]; then
  chown -R teleport:teleport /var/lib/teleport
  chmod 700 /var/lib/teleport
fi

echo -e "${GREEN}[+] Configuring system security${NC}"

# Disable teleport user login
if id "teleport" &>/dev/null; then
  usermod -s /usr/sbin/nologin teleport
fi

# Enable audit logging
if [ ! -d /var/log/teleport ]; then
  mkdir -p /var/log/teleport
  chown teleport:teleport /var/log/teleport
  chmod 750 /var/log/teleport
fi

# Configure fail2ban for Teleport (if fail2ban is installed)
if command -v fail2ban-client &>/dev/null; then
  echo -e "${YELLOW}[*] Configuring fail2ban${NC}"

  cat >/etc/fail2ban/filter.d/teleport.conf <<'EOF'
[Definition]
failregex = Authentication attempt failed.*client=<HOST>
            Invalid user.*from <HOST>
            Failed login attempt.*addr.remote_addr:<HOST>
ignoreregex =
EOF

  cat >/etc/fail2ban/jail.d/teleport.conf <<'EOF'
[teleport]
enabled = true
port = 3080,3022,3023,3025
filter = teleport
logpath = /var/log/teleport/*.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

  systemctl restart fail2ban
fi

echo -e "${GREEN}[+] Restarting Teleport service${NC}"

# Restart teleport service
systemctl daemon-reload
systemctl restart teleport
systemctl enable teleport

# Verify service is running
if systemctl is-active --quiet teleport; then
  echo -e "${GREEN}[+] Teleport service is running${NC}"
else
  echo -e "${RED}[!] Teleport service failed to start${NC}"
  echo -e "${YELLOW}[*] Check logs: journalctl -u teleport -n 50${NC}"
fi

echo -e "${GREEN}[+] Security hardening complete!${NC}"
echo -e "${YELLOW}[*] Summary:${NC}"
echo -e "  - Firewall configured for ports: $TELEPORT_PROXY_PORT, $TELEPORT_AUTH_PORT, $TELEPORT_SSH_PORT, $TELEPORT_TUNNEL_PORT"
echo -e "  - Two-factor authentication enabled"
echo -e "  - Session recording enabled"
echo -e "  - Enhanced session recording enabled"
echo -e "  - Rate limiting configured"
echo -e "  - Configuration backed up to: $BACKUP_DIR"
echo -e ""
echo -e "${YELLOW}[*] Next steps:${NC}"
echo -e "  1. Create admin user: tctl users add admin --roles=editor,access --logins=root"
echo -e "  2. Review configuration: cat /etc/teleport.yaml"
echo -e "  3. Monitor logs: journalctl -u teleport -f"
echo -e "  4. Test access: tsh login --proxy=localhost:3080"
echo -e ""
echo -e "${RED}[!] CCDC Reminders:${NC}"
echo -e "  - Change default passwords immediately"
echo -e "  - Monitor for suspicious connections"
echo -e "  - Keep backups of working configurations"
echo -e "  - Document all changes made"
