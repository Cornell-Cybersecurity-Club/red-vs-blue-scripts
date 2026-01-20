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

SERVICE="rsyslog"

# Helper to log status
log_info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$1"; }
log_err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$1" >&2; }

# 0. Pre-flight check: Is rsyslog actually installed?
# We check for the daemon binary (rsyslogd) usually found in /usr/sbin/
if ! command -v rsyslogd >/dev/null 2>&1; then
  log_err "rsyslogd binary not found. Is rsyslog installed?"
  exit 1
fi

# ------------------------------------------------------------------------------
# 1. Systemd Logic
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  log_info "Detected Init System: Systemd"

  # 1. Enable on boot
  log_info "Enabling $SERVICE service..."
  if systemctl enable "$SERVICE" >/dev/null 2>&1; then
    :
  else
    log_err "Failed to enable $SERVICE (Systemd)."
  fi

  # 2. Restart
  log_info "Restarting $SERVICE..."
  if systemctl restart "$SERVICE" >/dev/null 2>&1; then
    :
  else
    log_err "Failed to restart $SERVICE via systemctl."
  fi

# ------------------------------------------------------------------------------
# 2. OpenRC Logic (Alpine / Gentoo)
# ------------------------------------------------------------------------------
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  log_info "Detected Init System: OpenRC"

  # 1. Enable on boot
  log_info "Adding $SERVICE to default runlevel..."
  if rc-update add "$SERVICE" default >/dev/null 2>&1; then
    :
  else
    log_err "Failed to add $SERVICE to runlevel (OpenRC)."
  fi

  # 2. Restart
  log_info "Restarting $SERVICE..."
  if rc-service "$SERVICE" restart >/dev/null 2>&1; then
    :
  else
    log_err "Failed to restart $SERVICE via rc-service."
  fi

# ------------------------------------------------------------------------------
# 3. SysVinit Fallback (Legacy)
# ------------------------------------------------------------------------------
elif [ -x "/etc/init.d/$SERVICE" ]; then
  log_info "Detected Init System: SysVinit (Legacy)"

  # Enable
  if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d "$SERVICE" defaults >/dev/null 2>&1
  elif command -v chkconfig >/dev/null 2>&1; then
    chkconfig "$SERVICE" on >/dev/null 2>&1
  fi

  # Restart
  "/etc/init.d/$SERVICE" restart >/dev/null 2>&1

else
  log_err "Could not detect Systemd or OpenRC configuration for rsyslog."
fi

# ------------------------------------------------------------------------------
# 4. Final Verification
# ------------------------------------------------------------------------------
# We check if the process is actually running using pgrep
sleep 1
if command -v pgrep >/dev/null 2>&1; then
  if pgrep -x "rsyslogd" >/dev/null; then
    log_info "Verification: rsyslogd is running."
  else
    log_err "Verification: rsyslogd process is NOT running."
    exit 1
  fi
fi

log_info "Rsyslog configuration complete."
echo "Finished rsyslog configuration."
