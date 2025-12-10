#!/bin/bash

curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh

curl -sO https://packages.wazuh.com/4.14/config.yml

sed -i "s/ip:.*/ip: 127.0.0.1/g" config.yml

./wazuh_server_setup.sh --generate-config-files
./wazuh_server_setup.sh -a -i -o
