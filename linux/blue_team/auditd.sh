#!/bin/sh

cat configs/auditd.conf >/etc/audit/auditd.conf
cat configs/audit.rules >/etc/audit/audit.rules

auditctl -e 1
