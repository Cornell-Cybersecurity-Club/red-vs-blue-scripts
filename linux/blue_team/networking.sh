#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

{
  echo "nameserver 9.9.9.11"
  echo "nameserver 149.112.112.11"
  echo "nameserver 2620:fe::11"
  echo "nameserver 2620:fe::fe:11"
} >/etc/resolv.conf
