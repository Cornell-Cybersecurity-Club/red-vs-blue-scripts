#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

while IFS=: read -r user _ _ _ _ _ shell; do
  if [ "$user" = "root" ]; then
    continue
  fi

  case "$shell" in
  *sh)
    PASS=$(dd if=/dev/urandom bs=1 count=500 2>/dev/null | tr -dc 'A-Za-z0-9!@#$%^&*' | cut -c 1-14)

    echo "${user}:${PASS}" | chpasswd

    echo "PASSWORD CHANGED: ${user}:${PASS}"
    ;;
  *)
    continue
    ;;
  esac

done </etc/passwd

passwd -d root
passwd -l root
