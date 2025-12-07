#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

mkdir -p /etc/pam.d
echo "session optional pam_apparmor.so order=user,group,default" >/etc/pam.d/apparmor
command -v aa-enforce && aa-enforce /etc/apparmor.d/*
