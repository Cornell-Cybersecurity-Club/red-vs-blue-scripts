#! /bin/bash

#check root
if [ "$EUID" -ne 0 ]
  then echo "need to run as root"
  exit
fi

if ! dpkg -s "iptables" &>/dev/null 
  then echo "iptables not installed"
  exit
fi

echo -e "differences in raw table: \033[31m"
iptables -t raw -L | diff --normal ./iptables_defaults/rawdefault -

echo -e "\033[0mdifferences in filter table:\033[31m"
iptables -t filter -L | diff --normal ./iptables_defaults/filterdefault -

echo -e "\033[0mdifferences in nat table:\033[31m"
iptables -t nat -L | diff --normal ./iptables_defaults/natdefault -

echo -e "\033[0mdifferences in mangle table:\033[31m"
iptables -t mangle -L | diff --normal ./iptables_defaults/mangledefault -

echo -e "\033[0mdifferences in security table:\033[31m"
iptables -t security -L  | diff --normal ./iptables_defaults/securitydefault -
echo -e "\033[0m"
