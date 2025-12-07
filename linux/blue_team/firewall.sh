#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

./iptables_script/iptables_UML/5-firewall-iptables.sh
