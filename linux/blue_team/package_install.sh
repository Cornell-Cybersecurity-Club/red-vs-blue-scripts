#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case "${ID_LIKE:-$ID}" in
  *debian* | *ubuntu*)
    apt-get update

    apt-get install -y \
      apparmor \
      apparmor-utils \
      auditd \
      chrootkit \
      coreutils \
      curl \
      debsums \
      git \
      gnupg \
      htop \
      iptables \
      iotop \
      libpam-pwquality \
      libpam-tmpdir \
      lsof \
      lynis \
      nano \
      needrestart \
      net-tools \
      nmap \
      openssh-server \
      openssl \
      pigz \
      rkhunter \
      sudo \
      tcpdump \
      unhide \
      unzip \
      vim \
      wget \
      zstd
    ;;
  *rocky* | *rhel* | *fedora* | *centos* | *alma*)
    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    $PKG_MGR install -y epel-release
    $PKG_MGR makecache

    $PKG_MGR install -y \
      audit \
      chrootkit \
      coreutils \
      curl \
      git \
      gnupg2 \
      htop \
      iptables \
      libpwquality \
      lsof \
      lynis \
      nano \
      net-tools \
      nmap \
      openssh-server \
      openssl \
      pigz \
      policycoreutils \
      rkhunter \
      setools-console \
      sudo \
      tcpdump \
      unhide \
      unzip \
      vim \
      wget \
      yum-utils \
      zstd
    ;;
  *alpine*)
    apk update

    apk add \
      audit \
      bash \
      busybox-extras \
      coreutils \
      curl \
      git \
      gnupg \
      htop \
      iptables \
      ip6tables \
      lsof \
      lynis \
      nano \
      net-tools \
      nmap \
      openssh \
      openssl \
      pigz \
      rkhunter \
      sudo \
      tcpdump \
      unzip \
      vim \
      wget \
      zstd
    ;;
  *)
    echo "Distro not supported."
    ;;
  esac

  echo "Finished installing packages."
fi
