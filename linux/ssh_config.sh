#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir -p /etc/ssh

ssh-keygen -A

cat configs/sshd_config >/etc/ssh/sshd_config

cat configs/authorized_keys >/home/cybear/.ssh/authorized_keys
chmod 600 /home/cybear/.ssh/authorized_keys
