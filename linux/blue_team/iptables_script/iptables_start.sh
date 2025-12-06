#! /bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

./iptables_defaults.sh

read -n 1 -p "Continue?";

./iptables_UML/4-install-firewall.sh

read -n 1 -p "Continue?";

./iptables_UML/5-firewall-iptables.sh

