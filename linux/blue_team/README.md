Hi! 

This directory contains Linux hardening scrits written in pure shell (`.sh`).  

TODO: Add instructions to run initial hardening master script

In no particular order, this is a list of initial hardening things to do other than running the startup scripts
- `sudo systemctl disable cron.service`
- `sudo systemctl stop cron.service`
  - If the above break scoring, re-enable cron and manually search for malicious cronjobs
