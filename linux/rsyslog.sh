#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

cat configs/rsyslog.conf >/etc/rsyslog.conf
