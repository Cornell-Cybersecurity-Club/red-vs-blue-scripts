#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir -p /etc/pam.d
mkdir -p /etc/security
mkdir -p /etc/bash

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

while IFS= read -r user; do
  useradd -m "${user}"
  usermod -s /bin/bash "${user}"
  usermod -rG adm "${user}"
  usermod -rG sudo "${user}"
  usermod -rG wheel "${user}"
  chage -M 15 -m 6 -W 7 -I 5 "${user}"
  cat configs/.bashrc >/home/"${user}".bashrc
done <configs/users.txt

while IFS= read -r admin; do
  useradd -m "${admin}"
  usermod -s /bin/bash "${admin}"
  usermod -aG adm "${admin}"
  usermod -aG sudo "${admin}"
  usermod -aG wheel "${admin}"
  chage -M 15 -m 6 -W 7 -I 5 "${admin}"
  cat configs/.bashrc >/home/"${user}".bashrc
done <configs/admins.txt

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONFIG_DIR="$SCRIPT_DIR/../configs"

WHITELIST_TMP="/tmp/wl_$(date +%s)"
touch "$WHITELIST_TMP"

# Load Configs
if [ -f "$CONFIG_DIR/admins.txt" ]; then cat "$CONFIG_DIR/admins.txt" >>"$WHITELIST_TMP"; fi
if [ -f "$CONFIG_DIR/users.txt" ]; then cat "$CONFIG_DIR/users.txt" >>"$WHITELIST_TMP"; fi
if [ -f "$CONFIG_DIR/services.txt" ]; then cat "$CONFIG_DIR/services.txt" >>"$WHITELIST_TMP"; fi

freeze_target() {
  u="$1"
  passwd -l "$u" >/dev/null 2>&1

  if command -v chage >/dev/null 2>&1; then
    chage -E 0 "$u" >/dev/null 2>&1
  elif command -v usermod >/dev/null 2>&1; then
    usermod -e 1 "$u" >/dev/null 2>&1
  fi

  if [ -f /sbin/nologin ]; then
    usermod -s /sbin/nologin "$u" >/dev/null 2>&1
  else
    usermod -s /bin/false "$u" >/dev/null 2>&1
  fi

  pkill -KILL -u "$u" >/dev/null 2>&1
  killall -KILL -u "$u" >/dev/null 2>&1

  home_dir=$(grep "^$u:" /etc/passwd | cut -d: -f6)
  if [ -d "$home_dir/.ssh" ]; then
    mv "$home_dir/.ssh" "$home_dir/.ssh_quarantined_$(date +%s)" >/dev/null 2>&1
  fi
}

cat /etc/passwd | while read -r line; do
  USERNAME=$(echo "$line" | cut -d: -f1)
  UID_NUM=$(echo "$line" | cut -d: -f3)
  SHELL=$(echo "$line" | cut -d: -f7)

  # SAFETY 1: Root and Nobody
  if [ "$UID_NUM" -eq 0 ]; then continue; fi
  if [ "$UID_NUM" -eq 65534 ]; then continue; fi

  # SAFETY 2: OS Infrastructure Users
  # These often have binaries as shells (e.g., /bin/sync).
  # If they don't exist on your distro, this check is harmless.
  # If they DO exist, we must skip them to prevent OS breakage.
  case "$USERNAME" in
  sync | shutdown | halt | reboot | operator) continue ;;
  esac

  # SAFETY 3: Check Whitelist Files
  if grep -Fxq "$USERNAME" "$WHITELIST_TMP"; then
    continue
  fi

  # LOGIC: Freeze Normal Users (>=1000) not in whitelist
  if [ "$UID_NUM" -ge 1000 ]; then
    freeze_target "$USERNAME"
    continue
  fi

  # LOGIC: Check Camouflage (UID < 1000)
  SHADOW_ENTRY=$(grep "^$USERNAME:" /etc/shadow 2>/dev/null | cut -d: -f2)
  HAS_PASSWORD="No"
  if [ -n "$SHADOW_ENTRY" ]; then
    case "$SHADOW_ENTRY" in
    !* | *) HAS_PASSWORD="No" ;;
    *) HAS_PASSWORD="YES" ;;
    esac
  fi

  HAS_SHELL="No"
  # Matches any standard shell pattern
  case "$SHELL" in
  */bash | */sh | */zsh | */dash | */ksh | */csh | */tcsh | */ash | */fish)
    HAS_SHELL="YES"
    ;;
  esac

  # If it has a shell OR password, and wasn't skipped above -> Freeze
  if [ "$HAS_SHELL" = "YES" ] || [ "$HAS_PASSWORD" = "YES" ]; then
    freeze_target "$USERNAME"
  fi
done

rm -f "$WHITELIST_TMP"
