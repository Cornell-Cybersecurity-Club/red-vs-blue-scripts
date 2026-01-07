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

# Run apache as non root user
groupadd -r www-data
useradd www-data -r -g www-data -d /var/www -s /sbin/nologin
usermod -g www-data -d /var/www -s /sbin/nologin www-data
if [ "$(id -u www-data)" -eq 0 ]; then
  printf "\033[0;31mwww-data is root!\033[0m"
fi
sed -i '/APACHE_RUN_USER/cexport APACHE_RUN_USER=www-data' /etc/apache2/envvars
sed -i '/APACHE_RUN_GROUP/cexport APACHE_RUN_GROUP=www-data' /etc/apache2/envvars

# Lock the apache user acccount
passwd -l www-data > /dev/null

# Change apache file ownership to root
chown -R root:root /etc/apache2
chown -R root:root /var/www/html

# Remove write access to apache files
chmod -R o-w /etc/apache2
chmod -R g-w /etc/apache2

# Disable core dumps
sed -i '/CoreDumpDirectory/c#CoreDumpDirectory' /etc/apache2/apache2.conf

# Fix perms on config file
chmod 600 /etc/apache2/apache2.conf

# ServerTokens to Prod
sed -i '/^ServerTokens/cServerTokens Prod' /etc/apache2/conf-available/security.conf

# ServerSignature Off
sed -i '/^ServerSignature/cServerSignature Off' /etc/apache2/conf-available/security.conf

# Disable .htaccess overrides
sed -i 's/AllowOverride All/AllowOverride None/g' /etc/apache2/apache2.conf
sed -i 's/AllowOverride .*/AllowOverride None/g' /etc/apache2/apache2.conf

# List apache modules
ls -al /etc/apache2/mods-enabled

# Disable WebDAV, status, autoindex, UserDir, info
# I read some stuff about disabling CGI, not sure if it's safe to do in a script
a2dismod dav dav_fs dav_lock status autoindex userdir info 

# Install Modsecurity
apt-get install -y libapache2-mod-security2
a2enmod security2
sed -i '/SecRuleEngine/cSecRuleEngine On' /etc/modsecurity/modsecurity.conf

# Deny access to filesystem
echo "<Directory />" >> /etc/apache2/apache2.conf
echo "	AllowOverride None" >> /etc/apache2/apache2.conf
echo "	Require all denied" >> /etc/apache2/apache2.conf
echo "</Directory>" >> /etc/apache2/apache2.conf

# Disable HTTP TRACE
sed -i '/TraceEnable/cTraceEnable Off' /etc/apache2/conf-available/security.conf