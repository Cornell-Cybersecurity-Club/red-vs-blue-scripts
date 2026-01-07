#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir -p /etc/ssh

cat configs/sshd_config >/etc/ssh/sshd_config
