#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting system hardening..."

echo "Step 1: Applying system configuration files..."
cat configs/sysctl.conf >/etc/sysctl.conf 2>>"$LOG_FILE"
cat configs/host.conf >/etc/host.conf 2>>"$LOG_FILE"

echo "Step 2: Configuring security limits and directories..."
mkdir -p /etc/security >/dev/null 2>>"$LOG_FILE"
mkdir -p /etc/modprobe.d >/dev/null 2>>"$LOG_FILE"
echo "* hard core 0" >/etc/security/limits.conf 2>>"$LOG_FILE"

echo "Step 3: Enabling kernel security features..."
# Note: Writing to /sys or /etc/kernel might fail if features aren't supported by the kernel.
# These errors will be captured in the log file.
{ echo "integrity" >/etc/kernel/security/lockdown; } 2>>"$LOG_FILE"
{ echo 1 >/sys/kernel/security/evm; } 2>>"$LOG_FILE"

echo "Step 4: Disabling unused features and USB storage..."
{ echo "" >/etc/updatedb.conf; } 2>>"$LOG_FILE"
{ echo "blacklist usb-storage" >>/etc/modprobe.d/blacklist.conf; } 2>>"$LOG_FILE"
{ echo "install usb-storage /bin/false" >/etc/modprobe.d/usb-storage.conf; } 2>>"$LOG_FILE"
# Clear securetty
{ echo >/etc/securetty; } 2>>"$LOG_FILE"

echo "Step 5: Restoring prelinked binaries..."
if command -v prelink >/dev/null 2>&1; then
  prelink -ua >/dev/null 2>>"$LOG_FILE"
fi

echo "Step 6: Reloading sysctl settings..."
# -e ignores unknown keys, -p loads from default file.
# Output suppressed to dev/null, errors to log.
sysctl -ep >/dev/null 2>>"$LOG_FILE"
sysctl -w net.ipv4.route.flush=1 >/dev/null 2>>"$LOG_FILE"
sysctl -w net.ipv6.route.flush=1 >/dev/null 2>>"$LOG_FILE"

echo "Finished system hardening."
