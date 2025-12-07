#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir -p /etc/audit
cat configs/auditd.conf >/etc/audit/auditd.conf
cat configs/audit.rules >/etc/audit/audit.rules

command -v auditctl && auditctl -e 1
