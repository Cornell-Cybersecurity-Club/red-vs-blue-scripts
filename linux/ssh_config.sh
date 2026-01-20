#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir -p /etc/ssh

ssh-keygen -A

cat configs/sshd_config >/etc/ssh/sshd_config

cat configs/authorized_keys >/home/cybear/.ssh/authorized_keys
chmod 600 /home/cybear/.ssh/authorized_keys

log_info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$1"; }
log_err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$1" >&2; }

# 1. Detect Service Name
# Debian/Ubuntu uses 'ssh', RHEL/CentOS/Alpine/Arch use 'sshd'
if [ -x "/etc/init.d/ssh" ] || [ -f "/usr/lib/systemd/system/ssh.service" ] || [ -f "/lib/systemd/system/ssh.service" ]; then
  SERVICE="ssh"
elif [ -x "/etc/init.d/sshd" ] || [ -f "/usr/lib/systemd/system/sshd.service" ] || [ -f "/lib/systemd/system/sshd.service" ]; then
  SERVICE="sshd"
else
  # Fallback/Guess based on command presence if service files are hidden
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
      SERVICE="ssh"
    else
      SERVICE="sshd"
    fi
  else
    # Default to sshd as it is more common upstream
    SERVICE="sshd"
  fi
fi

log_info "Detected SSH Service Name: $SERVICE"

# ------------------------------------------------------------------------------
# 2. Systemd Logic
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  log_info "Detected Init System: Systemd"

  # Unmask just in case it was explicitly disabled
  systemctl unmask "$SERVICE" >/dev/null 2>&1

  log_info "Enabling $SERVICE..."
  if systemctl enable "$SERVICE" >/dev/null 2>&1; then
    :
  else
    log_err "Failed to enable $SERVICE via systemctl."
  fi

  log_info "Starting $SERVICE..."
  systemctl start "$SERVICE" >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 3. OpenRC Logic (Alpine / Gentoo)
# ------------------------------------------------------------------------------
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  log_info "Detected Init System: OpenRC"

  log_info "Adding $SERVICE to default runlevel..."
  if rc-update add "$SERVICE" default >/dev/null 2>&1; then
    :
  else
    log_err "Failed to add $SERVICE to runlevel."
  fi

  log_info "Starting $SERVICE..."
  rc-service "$SERVICE" start >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 4. SysVinit Fallback
# ------------------------------------------------------------------------------
elif [ -x "/etc/init.d/$SERVICE" ]; then
  log_info "Detected Init System: SysVinit (Legacy)"

  log_info "Enabling $SERVICE..."
  if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d "$SERVICE" defaults >/dev/null 2>&1
  elif command -v chkconfig >/dev/null 2>&1; then
    chkconfig "$SERVICE" on >/dev/null 2>&1
  fi

  log_info "Starting $SERVICE..."
  "/etc/init.d/$SERVICE" start >/dev/null 2>&1

else
  log_err "Could not detect init system or SSH service file."
  exit 1
fi

log_info "SSH Server configuration complete."
