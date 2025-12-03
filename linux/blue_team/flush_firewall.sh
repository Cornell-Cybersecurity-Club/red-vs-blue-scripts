#!/bin/sh
iptables -F INPUT
iptables -F OUTPUT
iptables -F INPUT_ACCEPT
iptables -F INPUT_DROP
iptables -F OUTPUT_ACCEPT
iptables -F OUTPUT_DROP
iptables -F FORWARD_LOG
