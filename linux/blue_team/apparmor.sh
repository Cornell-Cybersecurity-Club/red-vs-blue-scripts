#!/bin/sh

aa-enforce /etc/apparmor.d/*
echo "session optional pam_apparmor.so order=user,group,default" >/etc/pam.d/apparmor
