# Scripts
This directory contains various POSIX shell scripts to configure and secure Linux systems. The scripts are broken up into separate directories based on usage.

## Directories
### Current
The scripts in the current directory are made to be used on any machine during setup and then ideally not again.

### Backups
This is where backups created by `./tools/backup_create.sh` are stored.

### Configs
This is where the configuration files for each program is stored. It does not contain any scripts.

### Services
This is where scripts for configuring specific services are stored.

### Tools
This is where scripts that are meant to be run manually are stored. They may require user input or are just meant to be run periodically.

## Usage
- `tools/backup_create.sh` creates a timestamped backup of the entire system's configuration inside `backups`.

- `tools/backup_restore.sh` takes in a backup created by `tools/backup_create.sh` as input and restores all configurations on the system.

- `tools/password_rotate.sh` creates and sets a randomized password for every user on the system and prints each user and password to the screen in the format `user:password`.

- `tools/users.sh` deletes all users not defined in `configs/admins.txt` or `configs/users.txt` and creates the missing users if they do not already exist. It also adds each user to groups corresponding to the file they were defined in. Additionally this sets secure configurations for PAM, sudo, and bash.

- `setup.sh` runs through all generic scripts and secures the system regardless of distro.

