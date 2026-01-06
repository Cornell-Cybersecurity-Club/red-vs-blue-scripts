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
      apt \
      auditd \
      bash \
      busybox \
      chrootkit \
      coreutils \
      curl \
      dash \
      debsums \
      git \
      gnupg \
      htop \
      iotop \
      iptables \
      lib6c \
      libpam-modules \
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
      passwd \
      pigz \
      polkitd \
      rkhunter \
      sudo \
      tcpdump \
      unhide \
      unzip \
      util-linux \
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
      bash \
      busybox \
      chrootkit \
      coreutils \
      curl \
      dash \
      dpkg \
      git \
      glibc \
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
      passwd \
      pigz \
      policycoreutils \
      rkhunter \
      setools-console \
      sudo \
      tcpdump \
      unhide \
      unzip \
      util-linux \
      vim \
      wget \
      yum \
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
      ip6tables \
      iptables \
      lsof \
      lynis \
      nano \
      net-tools \
      nmap \
      openssh \
      openssl \
      passwd \
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
