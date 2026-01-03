#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case "${ID_LIKE:-$ID}" in
  *debian* | *ubuntu*)
    HELD=$(apt-mark showhold 2>/dev/null || true)

    if [ -n "$HELD" ]; then
      echo "$HELD" | xargs apt-mark unhold
    fi

    if [ -d /etc/apt/preferences.d ]; then
      rm -f /etc/apt/preferences.d/*
    fi

    if [ -f /etc/apt/preferences ]; then
      rm -f /etc/apt/preferences
    fi

    if [ -d /etc/apt/apt.conf.d ]; then
      find /etc/apt/apt.conf.d -type f ! -name '[0-1][0-9]*' ! -name '20*' -delete 2>/dev/null || true
    fi

    if [ -f /etc/apt/apt.conf ]; then
      rm -f /etc/apt/apt.conf
    fi

    apt-get clean

    apt-get update
    ;;
  *centos*)
    CENTOS_VERSION="${VERSION_ID%%.*}"

    if [ "$CENTOS_VERSION" -lt 8 ]; then
      echo "Error: CentOS 7 or earlier cannot be migrated to Rocky Linux."
      echo "Only CentOS 8+ is supported for migration."
      exit 1
    fi

    curl -O https://raw.githubusercontent.com/rocky-linux/rocky-tools/main/migrate2rocky/migrate2rocky.sh

    chmod +x migrate2rocky.sh

    echo "Running migration script..."
    ./migrate2rocky.sh -r

    rm -f migrate2rocky.sh
    ;;
  *rhel* | *fedora* | *centos* | *rocky* | *alma*)
    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    if $PKG_MGR versionlock list 2>/dev/null | grep -q .; then
      $PKG_MGR versionlock clear -y 2>/dev/null || true
    fi

    if [ -f /etc/dnf/dnf.conf ]; then
      sed -i '/^exclude=/d' /etc/dnf/dnf.conf
      sed -i '/^excludepkgs=/d' /etc/dnf/dnf.conf
    fi
    if [ -f /etc/yum.conf ]; then
      sed -i '/^exclude=/d' /etc/yum.conf
      sed -i '/^excludepkgs=/d' /etc/yum.conf
    fi

    for repo in /etc/yum.repos.d/*.repo; do
      [ -f "$repo" ] && sed -i 's/^enabled=0/enabled=1/' "$repo"
    done

    $PKG_MGR clean all

    $PKG_MGR makecache

    $PKG_MGR update
    ;;
  *alpine*)
    if [ -f /etc/apk/world ]; then
      sed -i 's/^!//' /etc/apk/world 2>/dev/null || true
    fi

    if [ -d /etc/apk/conf.d ]; then
      rm -f /etc/apk/conf.d/*
    fi

    apk cache clean 2>/dev/null || rm -rf /var/cache/apk/*

    apk update
    ;;
  *)
    echo "Unsupported distro."
    exit 1
    ;;
  esac
  echo "Package manager reset complete."
fi
