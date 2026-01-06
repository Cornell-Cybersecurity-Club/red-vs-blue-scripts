#!/bin/sh
#!/bin/sh
if [ "$(id -u || true)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release

  case $ID in
  ubuntu | debian)
    apt-get install gnupg apt-transport-https

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

    apt-get update

    echo "Enter wazuh manager IP: "
    read -r WAZUH_MANAGER

    WAZUH_AGENT_NAME="$(uname -n)"

    export WAZUH_AGENT_NAME
    export WAZUH_MANAGER

    apt-get install wazuh-agent

    /var/ossec/bin/wazuh-control start
    ;;
  centos | rhel | fedora | almalinux)
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

    cat >/etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF

    echo "Enter wazuh manager IP: "
    read -r WAZUH_MANAGER

    WAZUH_AGENT_NAME="$(uname -n)"

    export WAZUH_AGENT_NAME
    export WAZUH_MANAGER

    dnf install wazuh-agent

    /var/ossec/bin/wazuh-control start
    ;;
  *)
    echo "Unsupported distribution: $ID"
    exit 1
    ;;
  esac
else
  echo "Error: /etc/os-release not found. System too old."
  exit 1
fi
