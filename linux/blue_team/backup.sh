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
.cache
__pycache__
node_modules
bower_components
.git
.svn
.terraform
*.pyc
*.class
*.o
*.obj
/proc/*
/sys/*
/dev/*
/tmp/*
/run/*
/mnt/*
/media/*
/lost+found
/var/lib/docker
/var/cache
/var/tmp
/usr/share/doc
/usr/share/man
/usr/share/info
/etc/ld.so.cache
Thumbs.db
.DS_Store
core
core.*
sess_*
*.session
mysql-bin.*
relay-log.*
*.err
pg_stat_tmp
pg_replslot
pg_notify
pg_subtrans
EOF

DIRS_TO_BACKUP=""
CANDIDATES="/etc /var/www /var/spool/cron /var/spool/anacron /var/lib/mysql /var/lib/pgsql /srv"

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
