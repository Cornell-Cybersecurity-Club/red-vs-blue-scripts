# Blocks all ports that are not used by k8s API server
# idk really where to run this...
# Also it's from Bing AI

# Run as root

# Clear existing rules
iptables -F
iptables -X

# Default behavior: Drop everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Accept loopback interface
iptables -A INPUT -i lo -j ACCEPT

# who knows???
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allows k8s ports:
# API server
iptables -A INPUT -p tcp --dport 6443 -j ACCEPT
# etcd
iptables -A INPUT -p tcp --dport 2379:2380 -j ACCEPT
# kubelet
iptables -A INPUT -p tcp --dport 10250 -j ACCEPT
# kube-scheduler
iptables -A INPUT -p tcp --dport 10259 -j ACCEPT
# kube-controller-manager
iptables -A INPUT -p tcp --dport 10257 -j ACCEPT

# Allows SSH (optional)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Saves rules
service iptables save

