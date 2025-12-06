#!/bin/sh
chattr -R -ia /
chown root:root /*

chown -R root:root /root/

chmod 600 /swapfile

chmod 700 /boot /usr/src
chmod 700 /lib/modules /usr/lib/modules
chmod 600 /boot/grub/grub.cfg /boot/grub2/grub.cfg
chmod og-rwx /etc/grub/grub.cfg /etc/grub2/grub.cfg

chown root:root -R /bin/
chmod u-s,g-s,755 /bin/*

chown root:root -R /var/log/
chgrp adm /var/log/syslog
chmod 0750 /var/log

chmod 1777 /tmp
chown root:root /var/tmp
chmod 1777 /var/tmp

chown root:root /etc/sudoers
chmod 640 /etc/sudoers

chown root:root /etc/login.defs
chmod 644 /etc/login.defs

chmod 644 /etc/passwd /etc/group
chown root:root /etc/shadow /etc/passwd /etc/group
chmod 755 /etc/security
chmod go-w /etc/security
chmod 600 /etc/security/pwquality.conf
chmod 600 /etc/shadow /etc/gshadow
chown -R root:root /etc/security

chown -R root:root /etc/*cron*
chmod -R 600 /etc/*cron*
chown -R root:root /var/spool/cron
chmod -R 600 /var/spool/cron
chown root:root /etc/anacrontab
chmod 640 /etc/anacrontab
chown root:root /etc/crontab
chmod 600 /etc/crontab
chown -R root:root /etc/cron.hourly
chmod 700 /etc/cron.hourly
chown -R root:root /etc/cron.daily
chmod 700 /etc/cron.daily
chown -R root:root /etc/cron.weekly
chmod 700 /etc/cron.weekly
chown -R root:root /etc/cron.monthly
chmod 700 /etc/cron.monthly
chown -R root:root /etc/cron.d
chmod 700 /etc/cron.d

chmod 644 /etc/services

while IFS= read -r user; do
  chown -R "${user}":"${user}" /home/"${user}"
  chmod 700 /home/"${user}"
done <"$(cat configs/users.txt configs/admins.txt)"
