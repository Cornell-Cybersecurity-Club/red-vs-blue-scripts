#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case "${ID_LIKE:-$ID}" in
  *debian* | *ubuntu*)
    rm -f /etc/apt/apt.conf
    rm -rf /etc/apt/apt.conf.d/*
    rm -f /etc/apt/preferences
    rm -rf /etc/apt/preferences.d/*
    rm -rf /etc/apt/sources.list.d/*
    rm -f /etc/apt/auth.conf
    rm -rf /etc/apt/auth.conf.d/*
    rm -f /etc/apt/trusted.gpg
    rm -rf /etc/apt/trusted.gpg.d/*

    CODENAME=$(lsb_release -cs 2>/dev/null || echo "")

    if [ -z "$CODENAME" ]; then
      CODENAME=$VERSION_CODENAME
    fi

    if [ "$ID" = "ubuntu" ] || echo "$ID_LIKE" | grep -q "ubuntu"; then
      cat >/etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu $CODENAME main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $CODENAME-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $CODENAME-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu $CODENAME-security main restricted universe multiverse
EOF
    else
      cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian $CODENAME main contrib non-free
deb http://deb.debian.org/debian $CODENAME-updates main contrib non-free
deb http://security.debian.org/debian-security $CODENAME-security main contrib non-free
EOF
    fi

    rm -rf /var/cache/apt/archives/*
    rm -f /var/cache/apt/pkgcache.bin
    rm -f /var/cache/apt/srcpkgcache.bin
    rm -rf /var/lib/apt/lists/*

    rm -f /var/lib/apt/extended_states
    rm -rf /var/lib/apt/periodic/*

    HELD=$(apt-mark showhold 2>/dev/null || true)
    if [ -n "$HELD" ]; then
      echo "$HELD" | xargs apt-mark unhold
    fi

    apt-get update

    dpkg --get-selections | grep -v deinstall | awk '{print $1}' |
      xargs apt-get install --reinstall -y -o Dpkg::Options::="--force-confmiss"

    update-initramfs -u -k all
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
  *rocky*)
    if command -v dnf >/dev/null 2>&1; then
      PKG_MGR="dnf"
    else
      PKG_MGR="yum"
    fi

    rm -f /etc/yum.conf
    rm -f /etc/dnf/dnf.conf
    rm -rf /etc/yum.repos.d/*
    rm -rf /etc/dnf/plugins/*
    rm -rf /etc/yum/pluginconf.d/*
    rm -rf /etc/dnf/protected.d/*
    rm -rf /etc/yum/protected.d/*
    rm -rf /etc/yum/vars/*
    rm -rf /etc/dnf/vars/*

    cat >/etc/dnf/dnf.conf <<EOF
[main]
gpgcheck=1
installonly_limit=3
clean_requirements_on_remove=True
best=True
skip_if_unavailable=False
EOF

    cat >/etc/yum.repos.d/rocky.repo <<EOF
[baseos]
name=Rocky Linux \$releasever - BaseOS
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=\$basearch&repo=BaseOS-\$releasever
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial

[appstream]
name=Rocky Linux \$releasever - AppStream
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=\$basearch&repo=AppStream-\$releasever
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial

[extras]
name=Rocky Linux \$releasever - Extras
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=\$basearch&repo=extras-\$releasever
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial
EOF

    rm -rf /var/cache/yum/*
    rm -rf /var/cache/dnf/*
    rm -rf /var/lib/yum/*
    rm -rf /var/lib/dnf/*

    $PKG_MGR clean all
    $PKG_MGR makecache

    rpm -qa --qf '%{NAME}\n' | xargs $PKG_MGR reinstall -y

    dracut -f
    ;;
  *alpine*)

    rm -f /etc/apk/repositories
    rm -rf /etc/apk/keys/*
    rm -rf /etc/apk/protected_paths.d/*
    rm -rf /etc/apk/commit_hooks.d/*
    rm -f /etc/apk/world

    ALPINE_VERSION=$(cat /etc/alpine-release | cut -d. -f1,2)

    cat >/etc/apk/repositories <<EOF
https://dl-cdn.alpinelinux.org/alpine/v$ALPINE_VERSION/main
https://dl-cdn.alpinelinux.org/alpine/v$ALPINE_VERSION/community
EOF

    apk add --force-refresh alpine-keys

    rm -rf /var/cache/apk/*
    rm -rf /var/lib/apk/*

    apk update

    apk info -q | xargs apk fix --reinstall

    mkinitfs
    ;;
  *)
    FAMILY="$ID"
    ;;
  esac
fi
