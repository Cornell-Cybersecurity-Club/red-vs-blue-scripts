#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting firewall configuration..."

echo "Step 1: Resetting existing rules..."
{
  # Set default policies to ACCEPT to prevent lockout during flush
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  ip6tables -P INPUT ACCEPT
  ip6tables -P FORWARD ACCEPT
  ip6tables -P OUTPUT ACCEPT

  # Flush all rules
  iptables -F
  iptables -t nat -F
  iptables -t mangle -F
  iptables -t raw -F

  # Delete all custom chains
  iptables -X
  iptables -t nat -X
  iptables -t mangle -X
  iptables -t raw -X

  # Flush specific tables
  iptables -t filter -F INPUT
  iptables -t filter -F OUTPUT
  ip6tables -t filter -F INPUT
  ip6tables -t filter -F OUTPUT
} >/dev/null 2>>"$LOG_FILE"

echo "Step 2: Creating logging and defense chains..."
{
  # --- Create LOGGING chains ---
  # IPv4
  iptables -N SSH-INITIAL-LOG
  iptables -t mangle -N INVALID-LOG
  # IPv6
  ip6tables -N SSH-INITIAL-LOG
  ip6tables -t mangle -N INVALID-LOG

  # --- Setup SSH-INITIAL-LOG chain ---
  # IPv4
  iptables -A SSH-INITIAL-LOG -m limit --limit 4/sec -j LOG --log-prefix "IPTables-SSH-INITIAL: " --log-level 5
  iptables -A SSH-INITIAL-LOG -j RETURN
  # IPv6
  ip6tables -A SSH-INITIAL-LOG -m limit --limit 4/sec -j LOG --log-prefix "IP6Tables-SSH-INITIAL: " --log-level 5
  ip6tables -A SSH-INITIAL-LOG -j RETURN

  # --- Setup INVALID-LOG chain ---
  # IPv4
  iptables -t mangle -A INVALID-LOG -m limit --limit 5/sec -j LOG --log-prefix "IPTables-INVALID-LOG: " --log-level 4
  iptables -t mangle -A INVALID-LOG -j DROP
  # IPv6
  ip6tables -t mangle -A INVALID-LOG -m limit --limit 5/sec -j LOG --log-prefix "IP6Tables-INVALID-LOG: " --log-level 4
  ip6tables -t mangle -A INVALID-LOG -j DROP

  # --- Create Flood Protection Chains ---
  iptables -N ICMP-FLOOD
  ip6tables -N ICMP-FLOOD

  # --- Setup ICMP-FLOOD Chain ---
  # IPv4
  iptables -A ICMP-FLOOD -m recent --set --name ICMP-FLOOD --rsource
  iptables -A ICMP-FLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP-FLOOD --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "IPTables-ICMP-FLOOD: " --log-level 4
  iptables -A ICMP-FLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP-FLOOD --rsource --rttl -j DROP
  iptables -A ICMP-FLOOD -j ACCEPT
  # IPv6
  ip6tables -A ICMP-FLOOD -m recent --set --name ICMP-FLOOD --rsource
  ip6tables -A ICMP-FLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP-FLOOD --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "IPTables-ICMP-FLOOD: " --log-level 4
  ip6tables -A ICMP-FLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP-FLOOD --rsource --rttl
  ip6tables -A ICMP-FLOOD -j ACCEPT
} >/dev/null 2>>"$LOG_FILE"

echo "Step 3: Configuring pre-routing and invalid packet blocking..."
{
  # IPv4
  iptables -t mangle -I PREROUTING -m conntrack -p tcp ! --syn --ctstate NEW -j INVALID-LOG
  iptables -t mangle -I PREROUTING -m conntrack --ctstate INVALID -j INVALID-LOG
  # IPv6
  ip6tables -t mangle -I PREROUTING -m conntrack -p tcp ! --syn --ctstate NEW -j INVALID-LOG
  ip6tables -t mangle -I PREROUTING -m conntrack --ctstate INVALID -j INVALID-LOG
} >/dev/null 2>>"$LOG_FILE"

echo "Step 4: Applying Input rules..."
{
  # --- Loopback Anti-Spoofing ---
  iptables -A INPUT -s 127.0.0.1/8 ! -i lo -j DROP
  ip6tables -A INPUT -s ::1/128 ! -i lo -j DROP

  # --- SSH ---
  iptables -I INPUT -m conntrack -p tcp --dport 22 --ctstate NEW -j SSH-INITIAL-LOG
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  ip6tables -I INPUT -m conntrack -p tcp --dport 22 --ctstate NEW -j SSH-INITIAL-LOG
  ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT

  # --- Established/Related ---
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # --- Loopback Allow ---
  iptables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -i lo -j ACCEPT

  # --- ICMP IPv4 ---
  iptables -A INPUT -m conntrack -p icmp --icmp-type 3 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -m conntrack -p icmp --icmp-type 11 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -m conntrack -p icmp --icmp-type 12 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

  # --- ICMP IPv6 (Neighbor Discovery & Control) ---
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 1 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 3 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 4 -j ACCEPT
  # Echo (Flood protected)
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 128 -j ICMP-FLOOD
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 129 -j ICMP-FLOOD
  # Multicast & Discovery
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 130 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 131 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 132 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 143 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 141 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 142 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 148 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 149 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 151 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 152 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type 153 -j ACCEPT
} >/dev/null 2>>"$LOG_FILE"

echo "Step 5: Applying Output rules..."
{
  # --- SSH Output ---
  iptables -I OUTPUT -m conntrack -p tcp --dport 22 --ctstate NEW -j SSH-INITIAL-LOG
  iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
  ip6tables -I OUTPUT -m conntrack -p tcp --dport 22 --ctstate NEW -j SSH-INITIAL-LOG
  ip6tables -A OUTPUT -p tcp --sport 22 -j ACCEPT

  # --- DNS Output ---
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -p tcp --sport 53 -j ACCEPT
  ip6tables -A OUTPUT -p tcp --dport 53 -j ACCEPT
  ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT
  ip6tables -A OUTPUT -p tcp --sport 53 -j ACCEPT

  # --- Loopback Output ---
  iptables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT

  # --- Web Output ---
  iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
  iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
  iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT
  iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT
  ip6tables -A OUTPUT -p tcp --dport 443 -j ACCEPT
  ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT
  ip6tables -A OUTPUT -p tcp --sport 443 -j ACCEPT
  ip6tables -A OUTPUT -p tcp --sport 80 -j ACCEPT

  # --- ICMP Output ---
  iptables -A OUTPUT -m conntrack -p icmp --icmp-type 3 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack -p icmp --icmp-type 11 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack -p icmp --icmp-type 12 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 1 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 3 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 4 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 128 -j ICMP-FLOOD
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 129 -j ICMP-FLOOD
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 130 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 131 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 132 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 143 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 141 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 142 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 148 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 149 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 151 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 152 -j ACCEPT
  ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 153 -j ACCEPT
} >/dev/null 2>>"$LOG_FILE"

echo "Step 6: Setting default policies..."
{
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  ip6tables -P INPUT DROP
  ip6tables -P OUTPUT ACCEPT
  ip6tables -P FORWARD DROP
} >/dev/null 2>>"$LOG_FILE"

echo "Step 7: Configuring Docker (if detected)..."
{
  if command -v docker >/dev/null 2>&1; then
    iptables -N DOCKER-LOG
    iptables -I DOCKER-LOG -m limit --limit 3/sec -j LOG --log-prefix "IPTables-DOCKER-LOG:" --log-level 5
    iptables -A DOCKER-LOG -j RETURN
    iptables -I DOCKER-USER -o docker0 -j DOCKER-LOG
  fi
} >/dev/null 2>>"$LOG_FILE"

echo "Step 8: Saving rules to persistence file..."
{
  if [ -f "/etc/debian_version" ]; then
    iptables-save >/etc/iptables/rules.v4
    ip6tables-save >/etc/iptables/rules.v6
  else
    iptables-save >/etc/sysconfig/iptables
    ip6tables-save >/etc/sysconfig/iptables
  fi
} 2>>"$LOG_FILE"

CONFLICTING_SERVICES="firewalld ufw nftables shorewall"

# List of services that keep iptables rules persistent across reboots.
# We try to enable ALL of them; usually only one exists per distro.
IPTABLES_SERVICES="iptables iptables-persistent netfilter-persistent"

log_info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$1"; }

# ------------------------------------------------------------------------------
# 1. Disable UFW Command
# ------------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  log_info "Disabling UFW internal state..."
  ufw disable >/dev/null 2>&1
fi

# ------------------------------------------------------------------------------
# 2. Systemd Logic
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  log_info "Detected Init System: Systemd"

  # A. Disable Conflicts
  for service in $CONFLICTING_SERVICES; do
    if systemctl list-unit-files "$service.service" >/dev/null 2>&1; then
      log_info "Disabling conflicting service: $service"
      systemctl stop "$service" >/dev/null 2>&1
      systemctl disable "$service" >/dev/null 2>&1
      systemctl mask "$service" >/dev/null 2>&1
    fi
  done

  # B. Enable Iptables Persistence
  log_info "Enabling iptables persistence services..."
  for service in $IPTABLES_SERVICES; do
    if systemctl list-unit-files "$service.service" >/dev/null 2>&1; then
      log_info "  Enabling $service..."
      # Unmask first just in case it was hidden
      systemctl unmask "$service" >/dev/null 2>&1
      systemctl enable "$service" >/dev/null 2>&1
      systemctl start "$service" >/dev/null 2>&1
    fi
  done

# ------------------------------------------------------------------------------
# 3. OpenRC Logic (Alpine / Gentoo)
# ------------------------------------------------------------------------------
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  log_info "Detected Init System: OpenRC"

  # A. Disable Conflicts
  for service in $CONFLICTING_SERVICES; do
    if [ -x "/etc/init.d/$service" ]; then
      log_info "Disabling conflicting service: $service"
      rc-service "$service" stop >/dev/null 2>&1
      rc-update del "$service" boot >/dev/null 2>&1
      rc-update del "$service" default >/dev/null 2>&1
    fi
  done

  # B. Enable Iptables
  # Alpine typically uses 'iptables' and 'ip6tables' services to load rules on boot
  log_info "Enabling iptables persistence services..."
  for service in iptables ip6tables; do
    if [ -x "/etc/init.d/$service" ]; then
      log_info "  Enabling $service..."
      rc-update add "$service" default >/dev/null 2>&1
      rc-service "$service" start >/dev/null 2>&1
    fi
  done

# ------------------------------------------------------------------------------
# 4. SysVinit Fallback
# ------------------------------------------------------------------------------
elif [ -d /etc/init.d ]; then
  log_info "Detected Init System: SysVinit (Legacy)"

  # A. Disable Conflicts
  for service in $CONFLICTING_SERVICES; do
    if [ -x "/etc/init.d/$service" ]; then
      log_info "Disabling conflicting service: $service"
      "/etc/init.d/$service" stop >/dev/null 2>&1

      if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d -f "$service" remove >/dev/null 2>&1
      elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig "$service" off >/dev/null 2>&1
      fi
    fi
  done

  # B. Enable Iptables
  log_info "Enabling iptables persistence services..."
  for service in $IPTABLES_SERVICES; do
    if [ -x "/etc/init.d/$service" ]; then
      log_info "  Enabling $service..."
      if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d "$service" defaults >/dev/null 2>&1
      elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig "$service" on >/dev/null 2>&1
      fi
      "/etc/init.d/$service" start >/dev/null 2>&1
    fi
  done
fi

log_info "Finished. Iptables is now the primary firewall controller."

echo "Finished firewall configuration."
