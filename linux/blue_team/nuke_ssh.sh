#!/bin/sh

for dir in /home/* /root; do
  if [ -d "$dir" ]; then
    sshdir="$dir/.ssh"
    if [ -d "$sshdir" ]; then
      rm -rf "$sshdir"
      echo "Deleted $sshdir"
    fi
  fi
done

if command -v getent >/dev/null 2>&1; then
  getent passwd | cut -d: -f6 | sort -u | while read -r homedir; do
    if [ -n "$homedir" ] && [ -d "$homedir/.ssh" ]; then
      rm -rf "$homedir/.ssh"
    fi
  done
fi

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
