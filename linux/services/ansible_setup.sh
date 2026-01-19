#!/bin/sh

if [ "$(id -u || true)" -ne 0 ]; then
  echo "Script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  ID_MATCH="${ID_LIKE:-$ID}"

  case "$ID_MATCH" in
  *debian* | *ubuntu* | *devuan* | *kali* | *raspbian* | *linuxmint* | *pop*)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1

    apt-get install -y ansible
    ;;

  *rocky* | *rhel* | *fedora* | *centos* | *alma* | *ol* | *amzn* | *cloudlinux*)
    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    if ! grep -q "Amazon Linux" /etc/os-release; then
      $PKG_MGR install -y epel-release >/dev/null 2>&1
    fi

    $PKG_MGR install -y ansible
    ;;

  *alpine*)
    apk update

    apk add ansible
    ;;

  *suse* | *sles*)
    zypper refresh >/dev/null 2>&1

    zypper install -y ansible
    ;;

  *arch* | *manjaro*)
    pacman -Sy >/dev/null 2>&1

    pacman -S ansible
    ;;

  *)
    echo "Distro not supported."
    exit 1
    ;;
  esac
fi

echo "Finished installing ansible"

ssh-keygen -t ed25519
