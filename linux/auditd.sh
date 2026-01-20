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

SERVICE="auditd"

# Helper to log status
log_info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$1"; }
log_err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$1" >&2; }

# ------------------------------------------------------------------------------
# 1. Systemd Logic
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  log_info "Detected Init System: Systemd"

  # 1. Enable on boot
  log_info "Enabling $SERVICE service..."
  if systemctl enable "$SERVICE" >/dev/null 2>&1; then
    : # Do nothing on success
  else
    log_err "Failed to enable $SERVICE (Systemd)."
  fi

  # 2. Restart / Reload
  # Note: auditd often refuses a hard 'restart' via systemctl.
  # We try 'reload' first (which reloads config), then fallback to 'restart'.
  log_info "Restarting/Reloading $SERVICE..."

  if systemctl is-active "$SERVICE" >/dev/null 2>&1; then
    # Try reload first (safer for auditd)
    if ! systemctl reload "$SERVICE" >/dev/null 2>&1; then
      # If reload fails, try hard restart
      systemctl restart "$SERVICE" >/dev/null 2>&1
    fi
  else
    # Not running, just start it
    systemctl start "$SERVICE" >/dev/null 2>&1
  fi

# ------------------------------------------------------------------------------
# 2. OpenRC Logic (Alpine / Gentoo)
# ------------------------------------------------------------------------------
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  log_info "Detected Init System: OpenRC"

  # 1. Enable on boot
  # We try 'default', if that fails (some setups use 'boot'), we warn.
  log_info "Adding $SERVICE to default runlevel..."
  if rc-update add "$SERVICE" default >/dev/null 2>&1; then
    :
  else
    log_err "Failed to add $SERVICE to runlevel (OpenRC)."
  fi

  # 2. Restart
  log_info "Restarting $SERVICE..."
  rc-service "$SERVICE" restart >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 3. SysVinit Fallback (Legacy)
# ------------------------------------------------------------------------------
elif [ -x "/etc/init.d/$SERVICE" ]; then
  log_info "Detected Init System: SysVinit (Legacy)"

  # Enable (Distro specific, simplistic attempt)
  if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d "$SERVICE" defaults >/dev/null 2>&1
  elif command -v chkconfig >/dev/null 2>&1; then
    chkconfig "$SERVICE" on >/dev/null 2>&1
  fi

  # Restart
  "/etc/init.d/$SERVICE" restart >/dev/null 2>&1

else
  log_err "Could not detect Systemd or OpenRC."
fi

# ------------------------------------------------------------------------------
# 4. Kernel Level Enforcement (Safety Net)
# ------------------------------------------------------------------------------
# Even if the service manager failed, we tell the kernel specifically to enable auditing.
if command -v auditctl >/dev/null 2>&1; then
  log_info "Enforcing audit enabled via auditctl..."
  # -e 1: Enable auditing
  auditctl -e 1 >/dev/null 2>&1
fi

log_info "Audit configuration complete."

echo "Finished auditd configuration."
