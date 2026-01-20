#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting system backup..."

# Configuration
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)

echo "Step 1: Preparing backup directory..."
mkdir -p "${BACKUP_DIR}" >/dev/null 2>>"$LOG_FILE"

echo "Step 2: Exporting firewall rules..."
{
  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save >"${BACKUP_DIR}/fw_iptables.rules"
  fi

  if command -v nft >/dev/null 2>&1; then
    nft list ruleset >"${BACKUP_DIR}/fw_nftables.rules"
  fi
} 2>>"$LOG_FILE"

echo "Step 3: Generating exclusion list..."
EXCLUDE_FILE="${BACKUP_DIR}/.exclude.tmp"

# Generate exclude file. Errors appended to log.
cat <<EOF >"${EXCLUDE_FILE}" 2>>"$LOG_FILE"
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

/var/lib/docker/overlay2
/var/lib/docker/containers
/var/lib/docker/image
/var/lib/docker/tmp
/var/lib/docker/fuse-overlayfs
/var/lib/containerd/io.containerd.content.v1.content
/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs
docker.sock
.docker

/var/lib/kubelet/pods
/var/lib/etcd/member/wal

/var/lib/jenkins/workspace
/var/lib/jenkins/builds
/var/lib/jenkins/caches
/var/lib/jenkins/analytics

/var/lib/teleport/log
/var/lib/teleport/proc

/var/lib/influxdb/data
/var/lib/influxdb/wal
/var/lib/elasticsearch/nodes
/var/lib/graylog-server/journal

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

# Append large files to exclude list
if command -v find >/dev/null 2>&1; then
  find /root /opt -type f -size +100M 2>>"$LOG_FILE" >>"${EXCLUDE_FILE}"
fi

echo "Step 4: Identifying directories to backup..."
DIRS_TO_BACKUP=""
CANDIDATES="/etc /opt /var/www /var/ossec /var/named /var/lib/bind /var/spool/cron /var/spool/anacron /var/lib/mysql /var/lib/pgsql /srv /usr/local /var/lib/jenkins /var/lib/gitea /var/lib/samba /var/lib/teleport /etc/kubernetes /var/lib/docker/swarm"

for d in $CANDIDATES; do
  if [ -d "$d" ]; then
    DIRS_TO_BACKUP="$DIRS_TO_BACKUP $d"
  fi
done

echo "Step 5: Compressing and archiving (This may take a while)..."
if command -v zstd >/dev/null 2>&1; then
  COMPRESSOR="zstd -T0 -1"
  EXT="tar.zst"
elif command -v pigz >/dev/null 2>&1; then
  COMPRESSOR="pigz --fast"
  EXT="tar.gz"
else
  COMPRESSOR="gzip -1"
  EXT="tar.gz"
fi

ARCHIVE_NAME="${HOSTNAME}-${TIMESTAMP}.${EXT}"

if [ -n "$DIRS_TO_BACKUP" ]; then
  # tar sends errors to log.
  # tar output (the archive stream) goes to the pipe.
  # compressor reads the pipe, writes to file, sends errors to log.
  tar -cf - -X "${EXCLUDE_FILE}" $DIRS_TO_BACKUP 2>>"$LOG_FILE" |
    $COMPRESSOR >"${BACKUP_DIR}/${ARCHIVE_NAME}" 2>>"$LOG_FILE"
fi

echo "Step 6: Cleaning up..."
rm -f "${EXCLUDE_FILE}" 2>>"$LOG_FILE"

echo "Finished system backup."
