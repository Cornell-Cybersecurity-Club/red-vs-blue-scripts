#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

{
  echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0"
  echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
  echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0"
} >>/etc/fstab
