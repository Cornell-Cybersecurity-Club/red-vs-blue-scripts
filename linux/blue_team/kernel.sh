cat configs/systctl.conf >/etc/sysctl.conf
echo "* hard core 0" >/etc/security/limits.conf
echo "integrity" >/etc/kernel/security/lockdown
echo 1 >/sys/kernel/security/evm
echo "" >/etc/updatedb.conf
echo "blacklist usb-storage" >>/etc/modprobe.d/blacklist.conf
echo "install usb-storage /bin/false" >/etc/modprobe.d/usb-storage.conf
echo "tty1" >/etc/securetty
echo "TMOUT=300" >>/etc/profile
echo "readonly TMOUT" >>/etc/profile
echo "export TMOUT" >>/etc/profile
prelink -ua
sysctl -ep
cat configs/host.conf >/etc/host.conf
