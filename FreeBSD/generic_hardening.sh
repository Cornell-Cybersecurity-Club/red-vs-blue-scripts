#!/bin/sh

## Adapted from https://gist.github.com/jahil/4565d8dfa06254f0c11d 

# sendmail is an insecure service and should be disabled.
echo 'sendmail_enable="NO"' >> /etc/rc.conf

# The Internet Super Server (inetd) allows a number of simple Internet services to be enabled, including
# finger, ftp ssh, and telnetd.  Enabling these services may increase risk of security problems by
# increasing the exposure of your system.
echo 'inetd_enable="NO"' >> /etc/rc.conf

# Network File System allows a system to share directories and files with other computers over a network
# and should be disabled.
echo 'nfs_server_enable="NO"' >> /etc/rc.conf
echo 'nfs_client_enable="NO"' >> /etc/rc.conf

# Disable portmap if you are not running Network File Systems.
echo 'portmap_enable="NO"' >> /etc/rc.conf

# Disable computer system details from being added to /etc/motd on system reboot.
echo 'update_motd="NO"' >> /etc/rc.conf

# The /tmp directory should be cleared at startup to ensure that any malicious code that may have
# entered into the temp file is removed.
echo 'clear_tmp_enable="YES"' >> /etc/rc.conf

# The sysctl.conf file allows you to configure various aspects of a FreeBSD computer. This includes many
# advanced options of the TCP/IP stack and virtual memory system that can dramatically improve
# performance.
# Prevent users from seeing information about processes that are being run under another UID.
echo 'security.bsd.see_other_uids=0' >> /etc/sysctl.conf

# Disable users from having access to configuration files.
chmod o= /etc/fstab
chmod o= /etc/ftpusers
chmod o= /etc/group
chmod o= /etc/hosts
chmod o= /etc/hosts.allow
chmod o= /etc/hosts.equiv
chmod o= /etc/hosts.lpd
chmod o= /etc/inetd.conf
chmod o= /etc/login.access
chmod o= /etc/login.conf
chmod o= /etc/newsyslog.conf
chmod o= /etc/rc.conf
chmod o= /etc/ssh/sshd_config
chmod o= /etc/sysctl.conf
chmod o= /etc/syslog.conf
chmod o= /etc/ttys

# Enable root as the only account with the ability to schedule jobs.
echo "root" > /var/cron/allow
echo "root" > /var/at/at.allow
chmod o= /etc/crontab
chmod o= /usr/bin/crontab
chmod o= /usr/bin/at
chmod o= /usr/bin/atq
chmod o= /usr/bin/atrm
chmod o= /usr/bin/batch

# Secure the root directory contents to prevent viewing.
chmod 710 /root

# Disable user from having access to the system log file directory.
chmod o= /var/log
