#!/bin/sh
printf "Enter the network prefix (e.g., 192.168.1): "
read -r INPUT_NET
NETWORK=${INPUT_NET%.}

if [ -z "$NETWORK" ]; then
  echo "Error: No network entered. Exiting."
  exit 1
fi

OUT_FILE="backups/inventory_${NETWORK}.csv"

echo "IP Address,MAC Address" >"$OUT_FILE"

i=1
while [ "$i" -le 254 ]; do
  target="$NETWORK.$i"
  ping -c 1 -W 1 "$target" >/dev/null 2>&1 &
  i=$((i + 1))
done

wait

if command -v arp >/dev/null 2>&1; then
  arp -n | grep "$NETWORK" | grep -v "incomplete" | awk '{print $1 "," $3}' >>"$OUT_FILE"
elif command -v ip >/dev/null 2>&1; then
  ip neigh show | grep "$NETWORK" | grep -v "FAILED" | awk '{print $1 "," $5}' >>"$OUT_FILE"
else
  echo "Error: Neither 'arp' nor 'ip' commands found. Cannot retrieve MAC addresses."
fi

echo "Done. Check $OUT_FILE for results."
