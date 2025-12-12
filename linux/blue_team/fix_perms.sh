#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

chattr -Ria /bin /etc /home /lib /opt /root /usr /var

IS_RHEL=0
if [ -f /etc/redhat-release ]; then
  IS_RHEL=1
fi

for dir in /dev /etc /home /media /mnt /opt /run /srv /usr /var /var/lib /var/spool /var/cache /usr/lib /usr/local; do
  if [ -d "$dir" ]; then
    chown root:root "$dir"
    chmod 755 "$dir"
  fi
done

if [ -f /etc/passwd ]; then
  while IFS=: read -r _ _ uid gid _ home _; do
    if [ "$uid" -ge 1000 ] 2>/dev/null; then
      case "$home" in
      /home/*)
        if [ -d "$home" ]; then
          chown "$uid:$gid" "$home"
          chmod 750 "$home"

          if [ -d "$home/.ssh" ]; then
            chown "$uid:$gid" "$home/.ssh"
            chmod 700 "$home/.ssh"

            if [ -f "$home/.ssh/authorized_keys" ]; then
              chown "$uid:$gid" "$home/.ssh/authorized_keys"
              chmod 600 "$home/.ssh/authorized_keys"
            fi
            if [ -f "$home/.ssh/config" ]; then
              chown "$uid:$gid" "$home/.ssh/config"
              chmod 644 "$home/.ssh/config"
            fi
            if [ -f "$home/.ssh/known_hosts" ]; then
              chown "$uid:$gid" "$home/.ssh/known_hosts"
              chmod 644 "$home/.ssh/known_hosts"
            fi

            find "$home/.ssh" -type f ! -name "*.pub" -exec chmod 600 {} \; 2>/dev/null
            find "$home/.ssh" -type f -exec chown "$uid:$gid" {} \; 2>/dev/null
          fi
        fi
        ;;
      esac
    fi
  done </etc/passwd
fi

if [ -d /var/log ]; then
  chown root:root /var/log
  chmod 755 /var/log
fi

if grep -q "^adm:" /etc/group; then
  for logfile in syslog auth.log kern.log dpkg.log mail.log user.log daemon.log; do
    if [ -f "/var/log/$logfile" ]; then
      chown root:adm "/var/log/$logfile"
      chmod 640 "/var/log/$logfile"
    fi
  done
  if [ -d /var/log/apache2 ]; then
    chown root:adm /var/log/apache2
    chmod 750 /var/log/apache2
  fi
  if [ -d /var/log/nginx ]; then
    chown root:adm /var/log/nginx
    chmod 750 /var/log/nginx
  fi
fi

if [ -f /var/log/wtmp ]; then
  chown root:utmp /var/log/wtmp 2>/dev/null || chown root:root /var/log/wtmp
  chmod 664 /var/log/wtmp
fi
if [ -f /var/log/btmp ]; then
  chown root:utmp /var/log/btmp 2>/dev/null || chown root:root /var/log/btmp
  chmod 660 /var/log/btmp
fi

if [ -f /etc/shadow ]; then
  if grep -q "^shadow:" /etc/group; then
    chown root:shadow /etc/shadow
    chmod 640 /etc/shadow
    [ -f /etc/gshadow ] && chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
  else
    chown root:root /etc/shadow
    chmod 000 /etc/shadow
    [ -f /etc/gshadow ] && chown root:root /etc/gshadow && chmod 000 /etc/gshadow
  fi
fi
if [ -f /etc/passwd ]; then
  chown root:root /etc/passwd
  chmod 644 /etc/passwd
fi
if [ -f /etc/group ]; then
  chown root:root /etc/group
  chmod 644 /etc/group
fi

if [ -d /var/spool/cron/crontabs ]; then
  if grep -q "^crontab:" /etc/group; then
    chown root:crontab /var/spool/cron/crontabs
    chmod 1730 /var/spool/cron/crontabs
  else
    chown root:root /var/spool/cron/crontabs
    chmod 1730 /var/spool/cron/crontabs
  fi
elif [ -d /var/spool/cron ]; then
  chown root:root /var/spool/cron
  chmod 700 /var/spool/cron
fi

for crondir in /etc/cron.*; do
  if [ -d "$crondir" ]; then
    chown root:root "$crondir"
    chmod 755 "$crondir"
  fi
done

if [ -d /var/mail ]; then
  chown root:mail /var/mail 2>/dev/null || chown root:root /var/mail
  chmod 2775 /var/mail
fi
if [ -d /var/spool/mail ]; then
  chown root:mail /var/spool/mail 2>/dev/null || chown root:root /var/spool/mail
  chmod 2775 /var/spool/mail
fi

if [ -d /boot ]; then
  chown root:root /boot
  if [ "$IS_RHEL" -eq 1 ]; then
    chmod 700 /boot
  else
    chmod 755 /boot
  fi

  for bfile in /boot/*; do
    if [ -f "$bfile" ]; then
      chmod 644 "$bfile"
      chown root:root "$bfile"
    fi
  done

  for grubdir in /boot/grub /boot/grub2; do
    if [ -d "$grubdir" ]; then
      chown root:root "$grubdir"
      if [ "$IS_RHEL" -eq 1 ]; then
        chmod 700 "$grubdir"
      else
        chmod 755 "$grubdir"
      fi
      find "$grubdir" -name "grub.cfg" -exec chmod 600 {} \; 2>/dev/null
    fi
  done
fi

if [ -d /lib/modules ]; then
  find /lib/modules -type d -exec chmod 755 {} \;
  find /lib/modules -type d -exec chown root:root {} \;
  find /lib/modules -type f -exec chmod 644 {} \;
  find /lib/modules -type f -exec chown root:root {} \;
fi

for libdir in /lib/security /lib64/security /usr/lib/security /usr/lib64/security; do
  if [ -d "$libdir" ]; then
    chown root:root "$libdir"
    chmod 755 "$libdir"
    find "$libdir" -name "*.so" -exec chmod 755 {} \;
  fi
done

if [ -f /etc/sudoers ]; then
  chmod 440 /etc/sudoers
  chown root:root /etc/sudoers
fi
if [ -d /etc/sudoers.d ]; then
  chmod 750 /etc/sudoers.d
  chown root:root /etc/sudoers.d
  find /etc/sudoers.d -type f -exec chmod 440 {} \;
fi

if [ -d /etc/ssh ]; then
  chown -R root:root /etc/ssh
  find /etc/ssh -name 'ssh_host_*key' -exec chmod 600 {} \;
  find /etc/ssh -name '*.pub' -exec chmod 644 {} \;
fi
for privsep in /var/empty /var/empty/sshd /run/sshd; do
  if [ -d "$privsep" ]; then
    chown root:root "$privsep"
    chmod 755 "$privsep"
  fi
done

for tmpdir in /tmp /var/tmp /dev/shm; do
  if [ -d "$tmpdir" ]; then
    chown root:root "$tmpdir"
    chmod 1777 "$tmpdir"
  fi
done

if [ -d /root ]; then
  chown root:root /root
  if [ "$IS_RHEL" -eq 1 ]; then
    chmod 550 /root
  else
    chmod 700 /root
  fi
fi

if command -v rpm >/dev/null 2>&1; then
  rpm -a --setperms --setugids >/dev/null 2>&1
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -R /boot /etc/pam.d /lib/modules /root /etc/ssh >/dev/null 2>&1
  fi
elif command -v apk >/dev/null 2>&1; then
  apk fix >/dev/null 2>&1
elif command -v dpkg >/dev/null 2>&1; then
  if [ -f /usr/lib/policykit-1/polkit-agent-helper-1 ]; then
    chmod 4755 /usr/lib/policykit-1/polkit-agent-helper-1
  fi
  if [ -f /usr/bin/pkexec ]; then
    chmod 4755 /usr/bin/pkexec
  fi
  if [ -f /usr/lib/sudo/sudoers.so ]; then
    chmod 644 /usr/lib/sudo/sudoers.so
  fi
fi
