#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

cat configs/sysctl.conf >/etc/sysctl.conf
cat configs/host.conf >/etc/host.conf

mkdir -p /etc/security
mkdir -p /etc/modprobe.d

echo "* hard core 0" >/etc/security/limits.conf
echo "integrity" >/etc/kernel/security/lockdown
echo 1 >/sys/kernel/security/evm
echo "" >/etc/updatedb.conf
echo "blacklist usb-storage" >>/etc/modprobe.d/blacklist.conf
echo "install usb-storage /bin/false" >/etc/modprobe.d/usb-storage.conf
echo >/etc/securetty

command -v prelink >/dev/null 2>&1 && prelink -ua
sysctl -ep
