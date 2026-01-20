#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting system file cleanup..."

echo "Step 1: Removing insecure network configuration files..."
# Using find on / produces many "Permission denied" errors for proc/sys,
# so redirecting stderr (2>>) to the log is very important here.
find / -name ".rhosts" -exec rm -rf {} \; >/dev/null 2>>"$LOG_FILE"
find / -name "hosts.equiv" -exec rm -rf {} \; >/dev/null 2>>"$LOG_FILE"

echo "Step 2: Removing temporary and suspicious files..."
rm -f /usr/lib/svfs/*trash 2>>"$LOG_FILE"
rm -f /usr/lib/gvfs/*trash 2>>"$LOG_FILE"
rm -f /var/timemachine 2>>"$LOG_FILE"
rm -f /bin/ex1t 2>>"$LOG_FILE"
rm -f /var/oxygen.html 2>>"$LOG_FILE"

echo "Step 3: Removing access control deny files..."
rm -f /etc/at.deny 2>>"$LOG_FILE"
rm -f /etc/cron.deny 2>>"$LOG_FILE"

echo "Step 4: Removing potentially sensitive data files..."
find / -iname 'users.csv' -delete >/dev/null 2>>"$LOG_FILE"
find / -iname 'user.csv' -delete >/dev/null 2>>"$LOG_FILE"
find / -iname '*password.txt' -delete >/dev/null 2>>"$LOG_FILE"
find / -iname '*passwords.txt' -delete >/dev/null 2>>"$LOG_FILE"

echo "Finished system file cleanup."
