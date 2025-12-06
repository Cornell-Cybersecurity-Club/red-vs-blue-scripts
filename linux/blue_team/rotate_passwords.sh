#!/bin/sh

while IFS= read -r user; do
  PASS=$(tr -dc '[:alnum:]' </dev/urandom | dd bs=1 count=14 2>/dev/null)
  echo "${user}":"${PASS}" | chpasswd
  echo "PASSWORD CHANGED: ${user}:${PASS}"
done <"$(grep -E "sh$" /etc/passwd | cut -d ":" -f 1)"

passwd -d root
passwd -l root
