#!/bin/sh

# ==============================================================================
# Script Name: net_inventory.sh
# Description: Scans a network for devices and open ports using nmap.
#              Parses the output into a readable inventory format.
#              Portable: Runs on sh, dash, ash, bash.
# Usage:       ./net_inventory.sh <CIDR_OR_IP>
# Example:     ./net_inventory.sh 192.168.1.0/24
# ==============================================================================

# 1. Helper Functions
log_err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$1" >&2; }
log_info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$1"; }

# 2. Dependency Check
if ! command -v nmap >/dev/null 2>&1; then
  log_err "This script requires 'nmap' to be installed."
  printf "Install it via: sudo apt install nmap (Debian/Ubuntu) or sudo yum install nmap (RHEL)\n"
  exit 1
fi

# 3. Input Validation
TARGET="$1"
if [ -z "$TARGET" ]; then
  log_err "No target provided."
  printf "Usage: %s <CIDR_Network>\n" "$0"
  printf "Example: %s 192.168.1.0/24\n" "$0"
  exit 1
fi

# 4. Execution
# -oG - : Outputs in "Grepable" format to stdout, which is easier to parse with awk.
# -F    : Fast mode (Scans top 100 ports). Remove -F if you want to scan top 1000.
# -T4   : Timing template (Faster scanning).
# --open: Only show open ports (hides closed/filtered).
log_info "Starting scan on network: $TARGET"
log_info "This may take a moment..."

printf "%-16s | %-25s | %s\n" "IP Address" "Hostname" "Open Ports"
printf "%s\n" "-------------------------------------------------------------------------------"

nmap -T4 -F --open -oG - "$TARGET" | awk '
    # Nmap Grepable Output format processing
    /Host:/ {
        # $2 is the IP address
        ip = $2
        
        # $3 is the hostname in format (name) or () if empty
        hostname = $3
        # Remove parentheses
        gsub(/[()]/, "", hostname)
        if (hostname == "") {
            hostname = "[Unknown]"
        }

        # Check if the line contains "Ports:"
        # The line looks like: Host: 1.2.3.4 () Ports: 22/open/tcp//ssh///, 80...
        if ($0 ~ /Ports:/) {
            # Everything after "Ports: " is the port list
            # We use match to find where "Ports: " starts
            match($0, /Ports: .*/)
            # Extract the substring starting at the match
            # "RLENGTH" is the length of the match. +7 skips "Ports: "
            raw_ports = substr($0, RSTART + 7, RLENGTH - 7)
            
            # Formatting the ports list for readability
            # Split by comma
            n = split(raw_ports, port_array, ",")
            final_ports = ""
            
            for (i = 1; i <= n; i++) {
                # Each item looks like: 22/open/tcp//ssh///
                # Split by forward slash "/"
                split(port_array[i], details, "/")
                
                # details[1] is port number, details[5] is service name
                p_num = details[1]
                p_svc = details[5]
                
                # Trim spaces
                gsub(/^[ \t]+|[ \t]+$/, "", p_num)
                
                # Build pretty string
                if (p_svc == "") {
                    p_svc = "unknown"
                }
                
                # Add comma if not the first item
                if (i > 1) {
                    final_ports = final_ports ", "
                }
                final_ports = final_ports p_num "/" p_svc
            }
        } else {
            final_ports = "No open ports found (or blocked)"
        }

        # Print formatted row using printf (Portable awk)
        printf "%-16s | %-25s | %s\n", ip, substr(hostname, 1, 25), final_ports
    }
'

log_info "Scan complete."
