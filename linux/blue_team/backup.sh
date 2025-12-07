#!/bin/sh
iptables-save >backups/iptables-"$(date +%F_%H%M)".rules
tar -czpf backups/"$(hostname)"-"$(date +%F_%H%M)".tar.gz /etc/ /opt/
