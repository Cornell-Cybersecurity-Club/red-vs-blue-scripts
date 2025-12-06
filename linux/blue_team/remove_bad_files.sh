#!/bin/sh

find / -name ".rhosts" -exec rm -rf {} \;
find / -name "hosts.equiv" -exec rm -rf {} \;

rm -f /usr/lib/svfs/*trash
rm -f /usr/lib/gvfs/*trash
find / -iname 'users.csv' -delete
find / -iname 'user.csv' -delete
