#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <path_to_backup_file>" >&2
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: File '$BACKUP_FILE' not found." >&2
  exit 1
fi

case "$BACKUP_FILE" in
*.tar.zst)
  if command -v zstd >/dev/null 2>&1; then
    DECOMPRESS_CMD="zstd -dc"
  else
    echo "Error: Backup is zstd compressed but 'zstd' command not found." >&2
    exit 1
  fi
  ;;
*.tar.gz | *.tgz)
  DECOMPRESS_CMD="gzip -dc"
  ;;
*.tar)
  DECOMPRESS_CMD="cat"
  ;;
*)
  DECOMPRESS_CMD="gzip -dc"
  ;;
esac

$DECOMPRESS_CMD "$BACKUP_FILE" | tar -xf - -C / --numeric-owner --overwrite 2>/dev/null
