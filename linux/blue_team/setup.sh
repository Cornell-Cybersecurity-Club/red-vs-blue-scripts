#!/bin/sh

if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

./backup_create.sh
./permission_fix.sh
./users.sh
./password_rotate.sh
./networking.sh
./firewall.sh
./package_manager_reset.sh
./package_reinstall.sh
./package_install.sh
./ssh_remove_keys.sh
./ssh.sh
./auditd.sh
./kernel.sh
./fstab.sh
./file_cleaner.sh
./apparmor.sh
./dconf.sh
./misc.sh
