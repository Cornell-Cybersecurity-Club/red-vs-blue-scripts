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
      tcpdump \
      nmap \
      net-tools \
      auditd \
      apparmor \
      apparmor-utils \
      iptabels \
      fail2ban \
      libpam-pwquality \
      htop \
      lsof \
      gnupg \
      curl \
      wget \
      git \
      vim \
      nano \
      zstd \
      pigz
    ;;
  *rocky*)
    dnf install -y epel-release

    dnf makecache

    dnf install -y \
      tcpdump \
      nmap \
      net-tools \
      fail2ban \
      audit \
      iptabels \
      policycoreutils \
      libpwquality \
      htop \
      lsof \
      openssl \
      gnupg2 \
      curl \
      wget \
      git \
      vim \
      nano \
      zstd \
      pigz
    ;;
  *alpine*)
    apk update

    apk add \
      tcpdump \
      nmap \
      net-tools \
      audit \
      fail2ban \
      sysstat \
      iptables \
      htop \
      openssl \
      rsyslog \
      gnupg \
      curl \
      wget \
      git \
      vim \
      nano \
      zstd \
      pigz
    ;;
  *)
    FAMILY="$ID"
    ;;
  esac
fi
