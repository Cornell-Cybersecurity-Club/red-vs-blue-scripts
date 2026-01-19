@echo off
:g
dir /S /B \Windows\system32 > new.txt
fc new.txt orig.txt
timeout /t 5 > NUL
cls
goto g
