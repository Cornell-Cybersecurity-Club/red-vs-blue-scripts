#!/bin/sh

create_backups() {
  cp -r /etc/ /bin/ /var/ backups/.
}

fix_perms() {
  chattr -R -ia /

  chmod 600 /etc/shadow /etc/gshadow /boot/grub/grub.cfg /boot/grub2/grub.cfg
  chmod 644 /etc/passwd /etc/group
  chown root:root /etc/shadow /etc/passwd /etc/group
  chown root:root -R /bin/ /var/log/
  chmod u-s,g-s,755 /bin/*
  chgrp adm /var/log/syslog
  chmod 0750 /var/log
  chmod og-rwx /etc/grub/grub.cfg /etc/grub2/grub.cfg

  chmod 600 /etc/security/pwquality.conf

  chown -R root:root /etc/*cron*
  chmod -R 600 /etc/*cron*
  chown -R root:root /var/spool/cron
  chmod -R 600 /var/spool/cron
  chmod 700 /boot /usr/src /lib/modules /usr/lib/modules

  chown root:root /etc/login.defs
  chmod 644 /etc/login.defs

  chown root:root /*
  chmod 600 /swapfile

  chown root:root /etc/sudoers
  chmod 640 /etc/sudoers
  chown root:root /tmp
  chmod 1777 /tmp
  chown root:root /var/tmp
  chmod 1777 /var/tmp
  chown -R root:root /etc/security
  chmod 755 /etc/security
  chmod go-w /etc/security
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
  # http://www.faqs.org/docs/securing/chap5sec40.html
  chmod 644 /etc/services
  chattr +i /etc/services

  chown -R root:root /root/

  while IFS= read -r user; do
    chown -R "${user}":"${user}" /home/"${user}"
    chmod 700 /home/"${user}"
  done <"$(cat configs/users.txt configs/admins.txt)"
}

setup_users() {
  cat configs/login.defs >/etc/login.defs
  cat configs/common-password >/etc/pam.d/common-password
  cat configs/common-auth >/etc/pam.d/common-auth
  cat configs/pwquality.conf >/etc/security/pwquality.conf
  cat configs/limits.conf >/etc/security/limits.conf
  cat configs/sudo.conf >/etc/sudo.conf

  while IFS= read -r user; do
    useradd "${user}"
    usermod -s /bin/bash "${user}"
    gpasswd -d "${user}" sudo
    gpasswd -d "${user}" adm
    gpasswd -d "${user}" wheel
    echo "Enter password for '${user}': "
    passwd "${user}"
    chage -M 15 -m 6 -W 7 -I 5 "${user}"
    echo "unalias -a" >>/home/"${user}"/.bashrc
  done <configs/users.txt

  while IFS= read -r admin; do
    useradd -G adm,sudo "${admin}"
    usermod -s /bin/bash "${admin}"
    echo "Enter admin password for '${admin}': "
    passwd "${admin}"
    chage -M 15 -m 6 -W 7 -I 5 "${admin}"
    echo "unalias -a" >>/home/"${admin}"/.bashrc
  done <configs/admins.txt

  while IFS= read -r user; do
    if ! cat configs/users.txt configs/admins.txt | grep -w "${user}"; then
      userdel -rf "${user}"
    fi

    if [ "$(id -u "${user}" || true)" -lt 1000 ] && [ "${user}" != "root" ]; then
      usermod -s /bin/false "${user}"
    fi
  done <"$(grep -E "sh$" /etc/passwd | cut -d ":" -f 1)"

  echo "unalias -a" >>/root/.bashrc

  userdel -f "$(awk -F':' '$3 == 0 { if (dup++) print } END { exit(dup > 1) }' /etc/passwd | cut -d ":" -f1 || true)"

  passwd -dl root
}

secure_kernel() {
  # TODO check more portable way of doing
  cat configs/systctl.conf >/etc/sysctl.conf
  sysctl -ep
  echo "integrity" >/etc/kernel/security/lockdown
  echo 1 >/sys/kernel/security/evm
  cat configs/host.conf >/etc/host.conf
}

secure_fstab() {
  {
    echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0"
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0"
  } >>/etc/fstab
}

secure_firewall() {
  command -v ufw | return

  echo "y" | ufw reset
  ufw enable
  ufw default deny incoming
  ufw default allow outgoing
  ufw logging high
  cat configs/ufw >/etc/default/ufw
}

setup_dconf() {
  dconf reset -f /

  while IFS= read -r user; do
    runuser -u "${user}" gsettings set org.gnome.desktop.privacy remember-recent-files false
    runuser -u "${user}" gsettings set org.gnome.desktop.media-handling automount false
    runuser -u "${user}" gsettings set org.gnome.desktop.media-handling automount-open false
    runuser -u "${user}" gsettings set org.gnome.desktop.search-providers disable-external true
    runuser -u "${user}" gsettings set org.gnome.desktop.session idle-delay 300
    runuser -u "${user}" gsettings set org.gnome.desktop.screensaver lock-enabled true
  done

  dconf update /
}

setup_apparmor() {
  aa-enforce /etc/apparmor.d/*
  echo "session optional pam_apparmor.so order=user,group,default" >/etc/pam.d/apparmor
}

setup_auditd() {
  auditctl -e 1
  cat configs/auditd.conf >/etc/audit/auditd.conf
  cat configs/audit.rules >/etc/audit/audit.rules
}

secure_display_manager() {
  cat configs/lightdm.conf >/etc/lightdm/lightdm.conf
  cat configs/lightdm-gtk-greeter.conf >/etc/lightdm/lightdm-gtk-greeter.conf
  cat configs/users.conf >/etc/lightdm/users.conf

  cat configs/custom.conf >/etc/gdm3/custom.conf
  cat configs/greeter.dconf-defaults >/etc/gdm3/greeter.docnf-defaults
  dconf update
}

misc() {
  prelink -ua
  find / -name ".rhosts" -exec rm -rf {} \;
  find / -name "hosts.equiv" -exec rm -rf {} \;
  # only root is allowed to login on tty1
  echo >/etc/securetty
  {
    echo "TMOUT=300"
    echo "readonly TMOUT"
    echo "export TMOUT"
  } >>/etc/profile
  echo "" >/etc/updatedb.conf
  echo "blacklist usb-storage" >>/etc/modprobe.d/blacklist.conf
  echo "install usb-storage /bin/false" >/etc/modprobe.d/usb-storage.conf
  rm -f /usr/lib/gvfs/gvfs-trash
  rm -f /usr/lib/svfs/*trash
  find / -iname '*password.txt' -delete
  find / -iname '*passwords.txt' -delete
  find /root -iname 'user*' -delete
  find / -iname 'users.csv' -delete
  find / -iname 'user.csv' -delete
  rm -f /usr/lib/gvfs/gvfs-trash
  rm -f /usr/lib/gvfs/*trash
  rm -f /var/timemachine
  rm -f /bin/ex1t
  rm -f /var/oxygen.html
}

harden_ssh() {
  SSH_CONFIG="/etc/ssh/sshd_config"

  # Apply hardening settings
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSH_CONFIG
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' $SSH_CONFIG
  sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSH_CONFIG
  sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' $SSH_CONFIG
  sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' $SSH_CONFIG
  sed -i 's/^#*Protocol.*/Protocol 2/' $SSH_CONFIG

  # Add additional settings if not present
  grep -q "^ClientAliveInterval" $SSH_CONFIG || echo "ClientAliveInterval 300" >>$SSH_CONFIG
  grep -q "^ClientAliveCountMax" $SSH_CONFIG || echo "ClientAliveCountMax 2" >>$SSH_CONFIG
  grep -q "^LoginGraceTime" $SSH_CONFIG || echo "LoginGraceTime 60" >>$SSH_CONFIG
}

check_os() {
  os=$(uname)

  if [ "${os}" = "Linux" ]; then
    if [ -f /etc/os-release ]; then
      . /etc/os-release
      if [ "${ID}" = "gentoo" ]; then
        echo "Script does not support gentoo"
        exit 1
      elif [ "${ID}" = "ubuntu" ]; then
        echo "Script does not support ubuntu"
        exit 1
      elif [ "${ID}" = "debian" ]; then
        echo "Script does not support debian"
        exit 1
      else
        echo "Distro not supported"
        exit 1
      fi
    fi
  fi
}

if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

create_backups
check_os
fix_perms
setup_users
setup_auditd
setup_apparmor
misc
