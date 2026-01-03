#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case "${ID_LIKE:-$ID}" in
  *debian* | *ubuntu*)
    apt-get install -y \
      apparmor \
      apparmor-utils \
      auditd \
      chrootkit \
      curl \
      fail2ban \
      git \
      gnupg \
      htop \
      iptables \
      libpam-pwquality \
      lsof \
      nano \
      net-tools \
      nmap \
      pigz \
      rkhunter \
      tcpdump \
      unhide \
      vim \
      wget \
      zstd
    ;;
  *rocky*)
    dnf install -y epel-release

    dnf makecache

    dnf install -y \
      audit \
      chrootkit \
      curl \
      fail2ban \
      git \
      gnupg2 \
      htop \
      iptables \
      libpwquality \
      lsof \
      nano \
      net-tools \
      nmap \
      openssl \
      pigz \
      policycoreutils \
      rkhunter \
      tcpdump \
      unhide \
      vim \
      wget \
      zstd
    ;;
  *alpine*)
    apk update

    apk add \
      audit \
      curl \
      fail2ban \
      git \
      gnupg \
      htop \
      iptables \
      nano \
      net-tools \
      nmap \
      openssl \
      pigz \
      rsyslog \
      sysstat \
      tcpdump \
      vim \
      wget \
      zstd
    ;;
  *)
    FAMILY="$ID"
    ;;
  esac
fi
