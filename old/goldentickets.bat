@echo off
:g
set rand=%RANDOM%
net user krbtgt PASSWORD!@#%rand% > NUL
net user krbtgt PASSWORD!@#%rand%
timeout /t 120 > NUL
cls
goto g
