#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting auditd configuration..."

echo "Step 1: Creating audit directory..."
# Create directory. Stdout -> Null. Stderr -> Appended to log file.
mkdir -p /etc/audit >/dev/null 2>>"$LOG_FILE"

echo "Step 2: Copying configuration files..."
# Copy auditd.conf.
# Any error (file not found, or permission denied writing target) goes to log.
cat configs/auditd.conf >/etc/audit/auditd.conf 2>>"$LOG_FILE"

# Copy audit.rules.
cat configs/audit.rules >/etc/audit/audit.rules 2>>"$LOG_FILE"

echo "Step 3: Enabling auditd..."
# Check if auditctl exists silently
if command -v auditctl >/dev/null 2>&1; then
  # Enable audit system (-e 1). Stdout -> Null. Stderr -> Appended to log file.
  auditctl -e 1 >/dev/null 2>>"$LOG_FILE"
fi

echo "Finished auditd configuration."
