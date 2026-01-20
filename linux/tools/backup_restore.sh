#!/bin/sh

LOG_FILE="./error_log.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting system restore..."

echo "Step 1: Validating backup file..."
if [ "$#" -ne 1 ]; then
  echo "Usage Error: Missing argument. Usage: $0 <path_to_backup_file>" >>"$LOG_FILE"
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: File '$BACKUP_FILE' not found." >>"$LOG_FILE"
  exit 1
fi

echo "Step 2: Detecting compression format..."
case "$BACKUP_FILE" in
*.tar.zst)
  if command -v zstd >/dev/null 2>&1; then
    DECOMPRESS_CMD="zstd -dc"
  else
    echo "Error: Backup is zstd compressed but 'zstd' command not found." >>"$LOG_FILE"
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
  # Default fallback
  DECOMPRESS_CMD="gzip -dc"
  ;;
esac

echo "Step 3: Restoring files (This may take a while)..."
# We pipe the decompression to tar.
# Decompressor errors go to log.
# Tar errors go to log.
$DECOMPRESS_CMD "$BACKUP_FILE" 2>>"$LOG_FILE" |
  tar -xf - -C / --numeric-owner --overwrite 2>>"$LOG_FILE"

echo "Finished system restore."
