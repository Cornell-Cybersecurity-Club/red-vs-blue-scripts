#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir backups

iptables-save >backups/iptables-"$(date +%F_%H%M)".rules
tar -czpf backups/"$(hostname)"-"$(date +%F_%H%M)".tar.gz /etc/ /opt/
