#!/bin/sh
cat configs/login.defs >/etc/login.defs
cat configs/common-password >/etc/pam.d/common-password
cat configs/common-auth >/etc/pam.d/common-auth
cat configs/common-account >/etc/pam.d/common-account
cat configs/pwquality.conf >/etc/security/pwquality.conf
cat configs/limits.conf >/etc/security/limits.conf
cat configs/sudo.conf >/etc/sudo.conf
cat configs/sudoers >/etc/sudoers
cat configs/bashrc >/etc/bash/bashrc

while IFS= read -r user; do
  useradd "${user}"
  usermod -s /bin/bash "${user}"
  gpasswd -d "${user}" sudo
  gpasswd -d "${user}" adm
  gpasswd -d "${user}" wheel
  echo "Enter password for '${user}': "
  passwd "${user}"
  chage -M 15 -m 6 -W 7 -I 5 "${user}"
  cat configs/.bashrc >/home/"${user}".bashrc
done <configs/users.txt

while IFS= read -r admin; do
  useradd -G adm,sudo "${admin}"
  usermod -s /bin/bash "${admin}"
  echo "Enter admin password for '${admin}': "
  passwd "${admin}"
  chage -M 15 -m 6 -W 7 -I 5 "${admin}"
  echo "unalias -a" >>/home/"${admin}"/.bashrc
done <configs/admins.txt

while IFS= read -r user; do
  if ! cat configs/users.txt configs/admins.txt | grep -w "${user}"; then
    userdel -rf "${user}"
  fi

  if [ "$(id -u "${user}" || true)" -lt 1000 ] && [ "${user}" != "root" ]; then
    usermod -s /bin/false "${user}"
  fi
done <"$(grep -E "sh$" /etc/passwd | cut -d ":" -f 1)"

echo "unalias -a" >>/root/.bashrc

userdel -f "$(awk -F':' '$3 == 0 { if (dup++) print } END { exit(dup > 1) }' /etc/passwd | cut -d ":" -f1 || true)"

passwd -dl root
