#!/bin/bash

if command -v apt-get; then
  apt-get install gnupg apt-transport-https

  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

  apt-get update

  apt-get -y install wazuh-manager filebeat

  curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.14/tpl/wazuh/filebeat/filebeat.yml

  filebeat keystore create

  echo admin | filebeat keystore add username --stdin --force
  echo admin | filebeat keystore add password --stdin --force

  curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/extensions/elasticsearch/7.x/wazuh-template.json
  chmod go+r /etc/filebeat/wazuh-template.json

  curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module
fi

if command -v dnf; then
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

  echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\npriority=1' | tee /etc/yum.repos.d/wazuh.repo

  dnf -y install wazuh-manager filebeat

  curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.14/tpl/wazuh/filebeat/filebeat.yml

  filebeat keystore create

  echo admin | filebeat keystore add username --stdin --force
  echo admin | filebeat keystore add password --stdin --force

  curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/extensions/elasticsearch/7.x/wazuh-template.json

  chmod go+r /etc/filebeat/wazuh-template.json

  curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module
fi
