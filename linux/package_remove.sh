#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case "${ID_LIKE:-$ID}" in
  *debian* | *ubuntu*)
    export DEBIAN_FRONTEND=noninteractive

    apt-get update

    apt-get purge -y \
      autofs \
      ftp \
      netcat \
      nis \
      rsh-client \
      talk \
      telnet
    ;;
  *rocky* | *rhel* | *fedora* | *centos* | *alma*)
    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    $PKG_MGR remove -y \
      autofs \
      ftp \
      netcat \
      nis \
      rsh-client \
      talk \
      telnet
    ;;
  *alpine*)
    apk update

    apk del \
      autofs \
      ftp \
      nis \
      rsh-client \
      talk \
      telnet
    ;;
  *)
    echo "Distro not supported."
    ;;
  esac

  echo "Finished installing packages."
fi
