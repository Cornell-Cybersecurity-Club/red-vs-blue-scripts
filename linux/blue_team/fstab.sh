#!/bin/sh

{
  echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0"
  echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
  echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0"
} >>/etc/fstab
