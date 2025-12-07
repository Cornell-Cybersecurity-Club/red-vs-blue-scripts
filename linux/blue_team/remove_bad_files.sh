#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

find / -name ".rhosts" -exec rm -rf {} \;
find / -name "hosts.equiv" -exec rm -rf {} \;

rm -f /usr/lib/svfs/*trash
rm -f /usr/lib/gvfs/*trash
rm -f /var/timemachine
rm -f /bin/ex1t
rm -f /var/oxygen.html

find / -iname 'users.csv' -delete
find / -iname 'user.csv' -delete
find / -iname '*password.txt' -delete
find / -iname '*passwords.txt' -delete
