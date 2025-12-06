#!/bin/sh
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -N INPUT_ACCEPT
iptables -N OUTPUT_ACCEPT

iptables -N INPUT_DROP
iptables -N OUTPUT_DROP

iptables -A INPUT_ACCEPT -j LOG --log-prefix "[INPUT_ACCEPT]"
iptables -A INPUT_ACCEPT -j ACCEPT

iptables -A OUTPUT_ACCEPT -j LOG --log-prefix "[OUTPUT_ACCEPT]"
iptables -A OUTPUT_ACCEPT -j ACCEPT

iptables -A OUTPUT_DROP -j LOG --log-prefix "[OUTPUT_DROP]"
iptables -A OUTPUT_DROP -j DROP

iptables -A INPUT_DROP -j LOG --log-prefix "[INPUT_DROP]"
iptables -A INPUT_DROP -j DROP
