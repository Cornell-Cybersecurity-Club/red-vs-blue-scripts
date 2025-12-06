#!/bin/sh

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
