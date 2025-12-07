#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

for dir in /home/* /root; do
  if [ -d "$dir" ]; then
    sshdir="$dir/.ssh"
    if [ -d "$sshdir" ]; then
      rm -rf "$sshdir"
    fi
  fi
done

command -v getent && getent passwd | cut -d: -f6 | sort -u | while read -r homedir; do
  if [ -n "$homedir" ] && [ -d "$homedir/.ssh" ]; then
    rm -rf "$homedir/.ssh"
  fi
done

rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*.pub

rm -f /etc/ssh/ssh_known_hosts
for dir in /home/* /root; do
  if [ -d "$dir" ]; then
    kh="$dir/.ssh/known_hosts"
    if [ -f "$kh" ]; then
      rm -f "$kh" "$kh.old"
    fi
  fi
done
