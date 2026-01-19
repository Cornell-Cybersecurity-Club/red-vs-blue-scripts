@echo off

call :sub >results/inventory_info.txt
exit /b

:sub
::basic inventory
echo Hostname:
hostname
echo:
echo Ipconfig:
ipconfig /all
echo:
echo Operating System:
systeminfo | findstr OS

::check for listening ports
echo:
echo Listening Ports:
netstat -ano | findstr LIST | findstr /V ::1 | findstr /V 127.0.0.1

::users and groups
echo:
echo Users:
net user
echo:
echo Groups:
net localgroup
echo:
echo Administrator Users:
net localgroup "Administrators"
echo:
echo Remote Desktop Users:
net localgroup "Remote Desktop Users"
echo:
echo Remote Management Users:
net localgroup "Remote Management Users"

::looking for network shares
echo:
echo Network Shares:
net share