#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting AppArmor configuration..."

echo "Step 1: Creating PAM configuration..."
# Create directory. Stdout -> Null. Stderr -> Appended to log file.
mkdir -p /etc/pam.d >/dev/null 2>>"$LOG_FILE"

# Write configuration. Wrapped in { } to catch file permission errors in the log.
{ echo "session optional pam_apparmor.so order=user,group,default" >/etc/pam.d/apparmor; } 2>>"$LOG_FILE"

echo "Step 2: Enforcing AppArmor profiles..."
# Check if aa-enforce exists silently
if command -v aa-enforce >/dev/null 2>&1; then
  # Enforce profiles. Stdout -> Null. Stderr -> Appended to log file.
  aa-enforce /etc/apparmor.d/* >/dev/null 2>>"$LOG_FILE"
fi

echo "Finished AppArmor configuration."
