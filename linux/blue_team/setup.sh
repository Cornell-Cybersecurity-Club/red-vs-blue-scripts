#!/bin/sh

if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

./backup.sh
./fix_perms.sh
./auditd.sh
./users.sh
./kernel.sh
./fstab.sh
./apparmor.sh
./firewall.sh
./dconf.sh
./nuke_ssh.sh
./ssh.sh
./remove_bad_files.sh
