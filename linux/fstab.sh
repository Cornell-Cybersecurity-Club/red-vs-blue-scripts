#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting fstab configuration..."

echo "Step 1: Securing temporary filesystems in fstab..."
# We wrap the echo commands in a block.
# >> appends the output to /etc/fstab.
# 2>> redirects any errors (like permission denied or read-only filesystem) to the log file.
{
  echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0"
  echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
  echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0"
} >>/etc/fstab 2>>"$LOG_FILE"

echo "Finished fstab configuration."
