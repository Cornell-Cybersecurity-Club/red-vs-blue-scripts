#!/bin/sh

LOGFILE="error_log.txt"

# Preserve original stdout for progress messages
exec 3>&1

# Suppress all stdout, append all stderr to log
exec 1>/dev/null
exec 2>>"$LOGFILE"

progress() {
  printf '%s\n' "$1" >&3
}

progress "Starting account and PAM configuration..."

if [ "$(id -u || true)" -ne 0 ]; then
  progress "ERROR: Must be run as root"
  exit 1
fi

progress "Creating required configuration directories..."
mkdir -p /etc/pam.d /etc/security /etc/bash

progress "Installing system configuration files..."
cat configs/login.defs >/etc/login.defs
cat configs/common-password >/etc/pam.d/common-password
cat configs/common-auth >/etc/pam.d/common-auth
cat configs/common-account >/etc/pam.d/common-account
cat configs/pwquality.conf >/etc/security/pwquality.conf
cat configs/limits.conf >/etc/security/limits.conf
cat configs/sudo.conf >/etc/sudo.conf
cat configs/sudoers >/etc/sudoers
cat configs/bashrc >/etc/bash/bashrc
cat configs/etc_profile >/etc/profile
cat configs/.bashrc >/root/.bashrc

progress "Creating standard user accounts..."
while IFS= read -r user; do
  [ -n "$user" ] || continue

  useradd -m "$user"
  usermod -s /bin/bash "$user"
  usermod -rG adm "$user"
  usermod -rG sudo "$user"
  usermod -rG wheel "$user"
  chage -M 15 -m 6 -W 7 -I 5 "$user"

  cat configs/.bashrc >/home/"$user"/.bashrc
done <configs/users.txt

progress "Creating administrative accounts..."
while IFS= read -r admin; do
  [ -n "$admin" ] || continue

  useradd -m "$admin"
  usermod -s /bin/bash "$admin"
  usermod -aG adm "$admin"
  usermod -aG sudo "$admin"
  usermod -aG wheel "$admin"
  chage -M 15 -m 6 -W 7 -I 5 "$admin"

  cat configs/.bashrc >/home/"$admin"/.bashrc
done <configs/admins.txt

progress "Building whitelist..."
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONFIG_DIR="$SCRIPT_DIR/../configs"

WHITELIST_TMP="/tmp/wl_$$"
: >"$WHITELIST_TMP"

[ -f "$CONFIG_DIR/admins.txt" ] && cat "$CONFIG_DIR/admins.txt" >>"$WHITELIST_TMP"
[ -f "$CONFIG_DIR/users.txt" ] && cat "$CONFIG_DIR/users.txt" >>"$WHITELIST_TMP"
[ -f "$CONFIG_DIR/services.txt" ] && cat "$CONFIG_DIR/services.txt" >>"$WHITELIST_TMP"

freeze_target() {
  u="$1"

  passwd -l "$u"

  if command -v chage >/dev/null 2>&1; then
    chage -E 0 "$u"
  else
    usermod -e 1 "$u"
  fi

  if [ -f /sbin/nologin ]; then
    usermod -s /sbin/nologin "$u"
  else
    usermod -s /bin/false "$u"
  fi

  pkill -KILL -u "$u"
  killall -KILL -u "$u"

  home_dir=$(grep "^$u:" /etc/passwd | cut -d: -f6)
  if [ -d "$home_dir/.ssh" ]; then
    mv "$home_dir/.ssh" "$home_dir/.ssh_quarantined_$$"
  fi
}

progress "Auditing existing accounts..."
while IFS= read -r line; do
  USERNAME=$(printf '%s\n' "$line" | cut -d: -f1)
  UID_NUM=$(printf '%s\n' "$line" | cut -d: -f3)
  SHELL=$(printf '%s\n' "$line" | cut -d: -f7)

  # SAFETY: root and nobody
  [ "$UID_NUM" -eq 0 ] && continue
  [ "$UID_NUM" -eq 65534 ] && continue

  # SAFETY: infrastructure users
  case "$USERNAME" in
  sync | shutdown | halt | reboot | operator) continue ;;
  esac

  # SAFETY: whitelist
  grep -Fxq "$USERNAME" "$WHITELIST_TMP" && continue

  # Freeze normal users not whitelisted
  if [ "$UID_NUM" -ge 1000 ]; then
    freeze_target "$USERNAME"
    continue
  fi

  SHADOW_ENTRY=$(grep "^$USERNAME:" /etc/shadow 2>/dev/null | cut -d: -f2)
  HAS_PASSWORD="No"
  case "$SHADOW_ENTRY" in
  "" | !*) HAS_PASSWORD="No" ;;
  *) HAS_PASSWORD="YES" ;;
  esac

  HAS_SHELL="No"
  case "$SHELL" in
  */bash | */sh | */zsh | */dash | */ksh | */csh | */tcsh | */ash | */fish)
    HAS_SHELL="YES"
    ;;
  esac

  if [ "$HAS_SHELL" = "YES" ] || [ "$HAS_PASSWORD" = "YES" ]; then
    freeze_target "$USERNAME"
  fi
done </etc/passwd

rm -f "$WHITELIST_TMP"

progress "Account lockdown and configuration complete."
