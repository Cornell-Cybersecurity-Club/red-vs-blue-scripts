@echo off
:g
cls
netstat -ano | findstr STAB | findstr /v ::1 | findstr /v 127.0.0.1  
timeout /t 1 > NUL
goto g
