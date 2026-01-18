#!/bin/sh

install_one_by_one() {
  INSTALL_CMD="$1"
  shift
  PACKAGES="$*"

  for pkg in $PACKAGES; do
    $INSTALL_CMD "$pkg" >/dev/null 2>&1
  done
}

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

    DEB_PKGS="apparmor apparmor-utils apt audispd-plugins auditd bash busybox chrootkit coreutils curl dash debsums git gnupg htop iotop iptables iptables-persistent libc6 libpam-modules libpam-pwquality libpam-tmpdir lsof lynis nano needrestart net-tools nmap openssh-server openssl passwd pigz polkitd rkhunter rsyslog sudo tcpdump unhide unzip util-linux vim wget zstd"

    install_one_by_one "apt-get install -y" $DEB_PKGS
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

    $PKG_MGR makecache >/dev/null 2>&1

    RHEL_PKGS="audit audit-libs bash busybox chrootkit coreutils curl dash dpkg git glibc gnupg2 htop iptables iptables-services libpwquality lsof lynis nano net-tools nmap openssh-server openssl passwd pigz policycoreutils rkhunter rsyslog setools-console sudo tcpdump unhide unzip util-linux vim wget yum-utils zstd"

    install_one_by_one "$PKG_MGR install -y" $RHEL_PKGS
    ;;

  *alpine*)
    apk update >/dev/null 2>&1

    ALPINE_PKGS="audit bash busybox-extras coreutils curl git gnupg htop ip6tables iptables lsof lynis nano net-tools nmap openssh openssl passwd pigz rkhunter rsyslog sudo tcpdump unzip vim wget zstd"

    install_one_by_one "apk add" $ALPINE_PKGS
    ;;

  *suse* | *sles*)
    zypper refresh >/dev/null 2>&1

    SUSE_PKGS="audit bash busybox coreutils curl git gpg2 htop iptables lsof lynis nano net-tools nmap openssh openssl pam passwd pigz rkhunter rsyslog sudo tcpdump unzip util-linux vim wget zstd"

    install_one_by_one "zypper install -y" $SUSE_PKGS
    ;;

  *arch* | *manjaro*)
    pacman -Sy >/dev/null 2>&1

    ARCH_PKGS="audit bash coreutils curl git gnupg htop iptables lsof lynis nano net-tools nmap openssh openssl pam pigz rkhunter rsyslog sudo tcpdump unzip util-linux vim wget zstd"

    install_one_by_one "pacman -S --noconfirm --needed" $ARCH_PKGS
    ;;

  *)
    echo "Distro not supported."
    exit 1
    ;;
  esac
fi

echo "Finished installing packages"
