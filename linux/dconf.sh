#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if ! command -v gsettings >/dev/null 2>&1; then
  echo "Error: 'gsettings' not found. Is GNOME installed?"
  exit 1
fi

dconf reset -f /

while IFS=: read -r user _ uid _ _ home _; do
  if [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ] && [ -d "$home" ]; then
    runuser -u "${user}" -- dbus-launch gsettings set org.gnome.desktop.privacy remember-recent-files false
    runuser -u "${user}" -- dbus-launch gsettings set org.gnome.desktop.media-handling automount false
    runuser -u "${user}" -- dbus-launch gsettings set org.gnome.desktop.media-handling automount-open false
    runuser -u "${user}" -- dbus-launch gsettings set org.gnome.desktop.search-providers disable-external true
    runuser -u "${user}" -- dbus-launch gsettings set org.gnome.desktop.session idle-delay 300
    runuser -u "${user}" -- dbus-launch gsettings set org.gnome.desktop.screensaver lock-enabled true
  fi
done </etc/passwd

dconf update /
