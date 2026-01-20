#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting journald configuration..."

echo "Step 1: Applying journald settings..."
if [ -f /etc/systemd/journald.conf ]; then
  # Overwrite configuration.
  # Standard output goes to the file.
  # Standard error is appended to the log file.
  cat configs/journald.conf >/etc/systemd/journald.conf 2>>"$LOG_FILE"
fi

echo "Finished journald configuration."
