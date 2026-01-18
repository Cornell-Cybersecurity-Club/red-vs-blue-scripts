#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case "${ID_LIKE:-$ID}" in
  *debian* | *ubuntu* | *devuan* | *kali* | *raspbian* | *linuxmint* | *pop*)
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq

    dpkg --get-selections | grep -v deinstall | awk '{print $1}' |
      xargs apt-get install --reinstall -y -o Dpkg::Options::="--force-confmiss"

    apt-get upgrade -y
    apt-get dist-upgrade -y

    apt-get autoremove -y
    apt-get autoclean

    update-initramfs -u -k all
    ;;
  *rocky* | *rhel* | *fedora* | *centos* | *alma* | *ol* | *amzn* | *cloudlinux*)

    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    $PKG_MGR clean all
    $PKG_MGR makecache

    rpm -qa --qf '%{NAME}\n' | xargs $PKG_MGR reinstall -y

    $PKG_MGR upgrade -y

    $PKG_MGR autoremove -y
    $PKG_MGR clean all

    dracut -f
    ;;

  *alpine*)
    apk add --force-refresh alpine-keys

    apk update

    apk info -q | xargs apk fix --reinstall

    apk upgrade --available

    apk cache clean 2>/dev/null || rm -rf /var/cache/apk/*

    mkinitfs
    ;;
  *)
    echo "Unsupported distro."
    exit 1
    ;;
  esac
  echo "Finished package reinstall."
else
  exit 1
fi
