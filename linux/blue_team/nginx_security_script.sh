#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

# Unblock http(s)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT

# Run as non root user
groupadd -r www-data
useradd www-data -r -g www-data -d /var/cache/nginx -s /sbin/nologin
usermod -g www-data -d /var/cache/nginx -s /sbin/nologin www-data
if [ "$(id -u www-data)" -eq 0 ]; then
  echo "\033[0;31mwww-data is root!\033[0m"
fi
sed -i '/user/cuser www-data;' /etc/nginx/nginx.conf

# Lock the nginx user acccount
passwd -l www-data > /dev/null

# Change nginx file ownership to root
chown -R root:root /etc/nginx
chmod 600 /etc/nginx/nginx.conf

# Remove write access to nginx files
chmod -R o-w /etc/nginx
chmod -R g-w /etc/nginx

# Set perms on PID file
chown root:root /run/nginx.pid
chmod 644 /run/nginx.pid

# List nginx listening ports
grep -ir "listen[^;]*;" /etc/nginx

# Disable server_tokens
sed -i '/server_tokens/cserver_tokens off;' /etc/nginx/nginx.conf

# Add http headers
touch /etc/nginx/conf.d/http_headers.conf
echo "add_header Content-Security-Policy \"default-src 'self';\" always;" >> /etc/nginx/conf.d/http_headers.conf
echo 'add_header X-Content-Type-Options "nosniff" always;' >> /etc/nginx/conf.d/http_headers.conf
echo 'add_header X-Frame-Options "SAMEORIGIN" always;' >> /etc/nginx/conf.d/http_headers.conf
echo 'add_header X-XSS-Protection "1; mode=block" always;' >> /etc/nginx/conf.d/http_headers.conf
echo "(Manual) Make sure to include http_headers.conf in the nginx config file"

# Gemini tells me this is how to disable core dumps
if ! grep -q "worker_rlimit_core" /etc/nginx/nginx.conf; then
  sed -i '1iworker_rlimit_core 0;' /etc/nginx/nginx.conf
fi