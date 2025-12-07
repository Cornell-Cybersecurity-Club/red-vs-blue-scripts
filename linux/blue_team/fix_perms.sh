#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

maybe_chmod() { [ -e "$2" ] && chmod "$1" "$2"; }
maybe_chown() { [ -e "$2" ] && chown "$1" "$2"; }

chmod 700 /root
chown root:root /root

chmod 700 /boot /usr/src /lib/modules /usr/lib/modules
maybe_chmod 600 /boot/grub/grub.cfg /boot/grub2/grub.cfg
maybe_chmod og-rwx /etc/grub.d/* /etc/grub2.d/*

chown root:adm /var/log || chown root:root /var/log
chmod 755 /var/log

chmod 1777 /tmp /var/tmp
chown root:root /var/tmp

maybe_chown root:root /etc/sudoers /etc/sudoers.d/*
maybe_chmod 440 /etc/sudoers /etc/sudoers.d/*

maybe_chown root:root /etc/shadow /etc/gshadow
maybe_chmod 600 /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group

maybe_chown root:root /etc/ssh/sshd_config
maybe_chmod 600 /etc/ssh/sshd_config

chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub

maybe_chown root:root /etc/crontab /etc/anacrontab
maybe_chmod 600 /etc/crontab
maybe_chmod 640 /etc/anacrontab
chmod 700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

maybe_chmod 644 /etc/login.defs /etc/securetty
maybe_chmod 600 /etc/security/pwquality.conf

chmod 644 /etc/services

while IFS= read -r user; do
  chown -R "${user}":"${user}" /home/"${user}"
  chmod 750 /home/"${user}"
done <"$(cat configs/users.txt configs/admins.txt)"
