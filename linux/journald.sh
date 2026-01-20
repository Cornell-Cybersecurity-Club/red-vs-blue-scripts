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

SERVICE="systemd-journald"

# Helper to log status
log_info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$1"; }
log_warn() { printf "\033[0;33m[WARN]\033[0m %s\n" "$1"; }
log_err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$1" >&2; }

# ------------------------------------------------------------------------------
# 1. Systemd Logic
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  log_info "Detected Init System: Systemd"

  # 1. Enable on boot
  # Note: journald is usually a "static" service (socket activated).
  # Enabling it explicitly often returns a warning "The unit files have no installation config".
  # We attempt it, but silence errors because it's usually already active/static.
  log_info "Ensuring $SERVICE is active..."
  systemctl enable "$SERVICE" >/dev/null 2>&1

  # 2. Restart
  # Restarting journald applies changes made to /etc/systemd/journald.conf
  log_info "Restarting $SERVICE..."
  if systemctl restart "$SERVICE" >/dev/null 2>&1; then
    :
  else
    log_err "Failed to restart $SERVICE."
  fi

  # 3. Flush
  # If the storage setting changed (e.g., from 'auto' to 'persistent'),
  # this moves logs from memory to disk immediately.
  log_info "Flushing journal to disk..."
  if systemctl kill --kill-who=main --signal=SIGUSR1 "$SERVICE" >/dev/null 2>&1; then
    :
  else
    # Fallback to standard flush command
    journalctl --flush >/dev/null 2>&1
  fi

# ------------------------------------------------------------------------------
# 2. OpenRC Logic (Alpine / Gentoo)
# ------------------------------------------------------------------------------
elif command -v rc-service >/dev/null 2>&1; then
  log_info "Detected Init System: OpenRC"

  # Check if this is a weird hybrid setup where systemd-journald might exist
  if [ -x "/etc/init.d/systemd-journald" ]; then
    log_info "Restarting legacy/hybrid journald..."
    rc-service systemd-journald restart >/dev/null 2>&1
  else
    # Standard OpenRC behavior
    log_warn "Systemd-journald is specific to Systemd."
    log_warn "OpenRC systems usually use 'rsyslog' or 'syslog-ng'."
    log_warn "Skipping configuration."
  fi

else
  log_err "Could not detect Systemd or OpenRC."
fi

# ------------------------------------------------------------------------------
# 3. Final Verification (Systemd only)
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  if systemctl is-active --quiet "$SERVICE"; then
    log_info "Verification: $SERVICE is active and running."
  else
    log_err "Verification: $SERVICE is NOT active."
    exit 1
  fi
fi

log_info "Journald operation complete."
