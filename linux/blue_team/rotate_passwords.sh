#!/bin/sh

while IFS=: read -r user _ _ _ _ _ shell; do
  if [ "$user" = "root" ]; then
    continue
  fi

  case "$shell" in
  *sh)
    PASS=$(tr -dc 'a-zA-Z0-9' </dev/urandom | dd bs=1 count=14 2>/dev/null)

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
