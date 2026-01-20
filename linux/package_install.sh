#!/bin/sh

LOG_FILE="./error_log.txt"

# Function to install packages one by one
# Usage: install_one_by_one "install_command_with_flags" package_list
install_one_by_one() {
  INSTALL_CMD="$1"
  shift
  PACKAGES="$*"

  for pkg in $PACKAGES; do
    # Execute the install command.
    # Stdout -> Null (Silence).
    # Stderr -> Appended to log file.
    $INSTALL_CMD "$pkg" >/dev/null 2>>"$LOG_FILE"
  done
}

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

echo "Starting package installation..."

if [ -f /etc/os-release ]; then
  . /etc/os-release

  # Fallback to ID if ID_LIKE is empty
  ID_MATCH="${ID_LIKE:-$ID}"

  case "$ID_MATCH" in
  *debian* | *ubuntu* | *devuan* | *kali* | *raspbian* | *linuxmint* | *pop*)
    echo "Step 1: Detected Debian/Ubuntu-based system..."
    echo "Step 2: Updating package lists..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>>"$LOG_FILE"

    DEB_PKGS="apparmor apparmor-utils apt audispd-plugins auditd bash busybox ca-certificates chrootkit coreutils curl dash debsums git gnupg htop iotop iptables iptables-persistent libc6 libpam-modules libpam-pwquality libpam-tmpdir lsof lynis nano needrestart net-tools nmap openssh-server openssl passwd pigz polkitd rkhunter rsyslog sudo sysstat tcpdump unhide unzip util-linux vim wget zstd"

    echo "Step 3: Installing packages..."
    # -y: Answer yes
    # -q: Quiet
    install_one_by_one "apt-get install -y -q" $DEB_PKGS
    ;;

  *rocky* | *rhel* | *fedora* | *centos* | *alma* | *ol* | *amzn* | *cloudlinux*)
    echo "Step 1: Detected RHEL/CentOS-based system..."

    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    echo "Step 2: Preparing repositories..."
    if ! grep -q "Amazon Linux" /etc/os-release; then
      # -y: Answer yes
      $PKG_MGR install -y epel-release >/dev/null 2>>"$LOG_FILE"
    fi

    $PKG_MGR makecache >/dev/null 2>>"$LOG_FILE"

    RHEL_PKGS="audit audit-libs bash busybox ca-certificates chrootkit coreutils curl dash dpkg git glibc gnupg2 htop iptables iptables-services libpwquality lsof lynis nano net-tools nmap openssh-server openssl passwd pigz policycoreutils python3 rkhunter rsyslog setools-console sudo sysstat tcpdump unhide unzip util-linux vim wget yum-utils zstd"

    echo "Step 3: Installing packages..."
    # -y: Answer yes automatically
    install_one_by_one "$PKG_MGR install -y" $RHEL_PKGS
    ;;

  *alpine*)
    echo "Step 1: Detected Alpine Linux..."
    echo "Step 2: Updating package lists..."
    apk update >/dev/null 2>>"$LOG_FILE"

    ALPINE_PKGS="audit bash busybox-extras ca-certificates coreutils curl git gnupg htop ip6tables iptables lsof lynis nano net-tools nmap nmap-scripts openssh openssl passwd pigz python3 rkhunter rsyslog sudo sysstat tcpdump unzip vim wget zstd"

    echo "Step 3: Installing packages..."
    # apk add is generally non-interactive by default for known packages
    install_one_by_one "apk add" $ALPINE_PKGS
    ;;

  *suse* | *sles*)
    echo "Step 1: Detected SUSE Linux..."
    echo "Step 2: Refreshing repositories..."
    # --non-interactive: Don't ask questions
    zypper --non-interactive refresh >/dev/null 2>>"$LOG_FILE"

    SUSE_PKGS="audit bash busybox ca-certificates coreutils curl git gpg2 htop iptables lsof lynis nano net-tools nmap openssh openssl pam passwd pigz rkhunter rsyslog sudo sysstat tcpdump unzip util-linux vim wget zstd"

    echo "Step 3: Installing packages..."
    # -n: Non-interactive
    # -y: Yes
    install_one_by_one "zypper --non-interactive install -y" $SUSE_PKGS
    ;;

  *arch* | *manjaro*)
    echo "Step 1: Detected Arch Linux..."
    echo "Step 2: syncing package databases..."
    # --noconfirm: Do not ask for any confirmation
    pacman -Sy --noconfirm >/dev/null 2>>"$LOG_FILE"

    ARCH_PKGS="audit bash ca-certificates coreutils curl git gnupg htop iptables lsof lynis nano net-tools nmap openssh openssl pam pigz python rkhunter rsyslog sudo sysstat tcpdump unzip util-linux vim wget zstd"

    echo "Step 3: Installing packages..."
    # --noconfirm: Answer yes to all
    # --needed: Don't reinstall up-to-date packages
    install_one_by_one "pacman -S --noconfirm --needed" $ARCH_PKGS
    ;;

  *)
    echo "Error: Distro not supported."
    exit 1
    ;;
  esac
fi

echo "Finished installing packages."
