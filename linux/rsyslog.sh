#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting rsyslog configuration..."

echo "Step 1: Applying rsyslog configuration..."
# Apply configuration.
# Standard output goes to the target file.
# Standard error is appended to the log file.
cat configs/rsyslog.conf >/etc/rsyslog.conf 2>>"$LOG_FILE"

echo "Finished rsyslog configuration."
