# General Folder Structure

```
├── scripts
│   ├── conf
│   │   ├── wc-member-client-v_.inf (or wc-dc-v_.inf)
│   │   ├── (GUID of client GPO or GUID of dc GPO)
│   │   ├── def-eg-settings.xml
│   │   ├── ossec_windows.conf
│   │   └── wc-auditpol-v_.csv
│   ├── results
│   │   ├── artifacts
│   │   │   └── (old GPO and sec template)
│   │   └── (outputs of scripts here)
│   ├── audit.ps1
|   ├── backup.ps1
|   ├── command_runbook.txt
│   ├── firewall.ps1
│   ├── Get-InjectedThread.ps1
│   ├── inventory.ps1
│   ├── logging.ps1
|   ├── PrivescCheck.ps1
│   ├── secure.ps1
│   ├── soaragent.ps1
│   ├── usermgmt.ps1
│   └── yara.bat
├── installers
│   ├── chromeinstall.exe
│   ├── MBSetup.exe
│   ├── netinstaller.exe
│   ├── notepadpp_installer.exe
│   ├── vc_redist.64.exe
│   ├── wazuhagent.msi
│   ├── wfcsetup.exe
│   └── wsinstall.exe
├── tools
│   ├── chainsaw
│   │   └── chainsaw_x86_64-pc-windows-msvc.exe
│   ├── pc
│   │   └── PingCastle.exe
│   ├── LGPO_30
│   │   └── LGPO.exe
│   ├── adalanche.exe
│   ├── hollows_hunter.exe
│   ├── floss.exe
│   └── sys
│       ├── ar
│       │   └── (autoruns)
│       ├── dll
│       │   └── (listdlls)
│       ├── pe
│       │   └── (proc explorer)
│       ├── pm
│       │   └── (proc mon)
│       ├── sc
│       │   └── (sigcheck)
│       ├── sm
│       │   └── (sysmon)
│       ├── stm
│       │   └── (streams)
│       ├── str
│       │   └── (strings)
│       └── tv
│           └── (tcpview)
└── zipped
    └── All zipped versions of files