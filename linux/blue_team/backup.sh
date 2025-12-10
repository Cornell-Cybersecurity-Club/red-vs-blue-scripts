#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Configuration
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)

mkdir -p "${BACKUP_DIR}"

command -v iptables-save >/dev/null 2>&1 &&
  iptables-save >"${BACKUP_DIR}/fw_iptables.rules" 2>/dev/null

command -v nft >/dev/null 2>&1 &&
  nft list ruleset >"${BACKUP_DIR}/fw_nftables.rules" 2>/dev/null

EXCLUDE_FILE="${BACKUP_DIR}/.exclude.tmp"
cat <<EOF >"${EXCLUDE_FILE}"
*.log
*.gz
*.tar
*.zip
*.7z
*.rar
*.iso
*.qcow2
*.vmdk
*.vdi
*.mp4
*.mp3
*.avi
*.mov
*.wav
*.swp
*.tmp
*.bak
*.old
*.1
*.2

/proc/*
/sys/*
/dev/*
/tmp/*
/run/*
/mnt/*
/media/*
/lost+found
/var/tmp
/var/cache
/usr/share/doc
/usr/share/man
/usr/share/info
/var/log/journal
/var/log/audit
core
core.*

.git
.svn
.terraform
.cache
__pycache__
node_modules
bower_components
*.pyc
*.class
*.o
*.obj
.sass-cache

.bash_history
.zsh_history
.lesshst
.viminfo
.mysql_history
.psql_history
.rediscli_history
known_hosts

client_body_temp
fastcgi_temp
proxy_temp
scgi_temp
uwsgi_temp
# PHP Sessions
sess_*
*.session

mysql-bin.*
relay-log.*
*.err
slow-query.log
slow.log
general.log
*.sock
*.pid
aria_log.*

pg_wal
pg_xlog
pg_stat_tmp
pg_replslot
pg_notify
pg_subtrans
pg_log
.s.PGSQL.*

/var/lib/containerd
/var/lib/docker
docker.sock
.docker

/var/ossec/logs/archives
/var/ossec/logs/alerts
/var/ossec/logs/firewall
/var/ossec/queue/diff
/var/ossec/var/run

*.retry
ansible_facts
galaxy_cache
cp
.ansible

/var/spool/postfix/active
/var/spool/postfix/hold
/var/spool/postfix/deferred
/var/spool/exim4/input
EOF

if command -v find >/dev/null 2>&1; then
  find /root /opt -type f -size +100M 2>/dev/null >>"${EXCLUDE_FILE}"
fi

DIRS_TO_BACKUP=""
CANDIDATES="/etc /opt /root /var/www /var/ossec /var/named /var/lib/bind /var/spool/cron /var/spool/anacron /var/lib/mysql /var/lib/pgsql /srv /usr/local"

for d in $CANDIDATES; do
  if [ -d "$d" ]; then
    DIRS_TO_BACKUP="$DIRS_TO_BACKUP $d"
  fi
done

if command -v zstd >/dev/null 2>&1; then
  COMPRESSOR="zstd -T0 -1"
  EXT="tar.zst"
elif command -v pigz >/dev/null 2>&1; then
  COMPRESSOR="pigz -p 0 --fast"
  EXT="tar.gz"
else
  COMPRESSOR="gzip -1"
  EXT="tar.gz"
fi

ARCHIVE_NAME="${HOSTNAME}-${TIMESTAMP}.${EXT}"

if [ -n "$DIRS_TO_BACKUP" ]; then
  tar -cf - -X "${EXCLUDE_FILE}" $DIRS_TO_BACKUP 2>/dev/null |
    $COMPRESSOR >"${BACKUP_DIR}/${ARCHIVE_NAME}"
fi

rm -f "${EXCLUDE_FILE}"
