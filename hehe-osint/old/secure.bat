@echo off

:: Import secpol file here
:: One secpol file for "domain policy" - not editing default domain policy but creating gpo to apply across domain 
    :: This file will also serve as local secpol file
    :: Will contain account and local policies
set /p choice="Is this a domain controller (Y or N)? "
if %choice%=="N" (
    secedit /configure /db %windir%\security\local.sdb /cfg conf/secpol.inf
    gpupdate /force
) else (
    echo:
    echo Skipping import of secpol file...
    echo: 
    echo Please use the Group Policy Management GUI to create a GPO and import the file into it. Make sure to do gpupdate /force after!
    timeout 5
)

:: Stopping "easy wins" for red team - following https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg

:: MiTM attacks
:: Countering poisoning via LLMNR/NBT-NS/MDNS - Turning off LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
:: Countering poisoning via LLMNR/NBT-NS/MDNS - Disabling NBT-NS via registry for all interfaces (might break something)
powershell -Command "& {$regkey = ""HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\""; Get-ChildItem $regkey | foreach { Set-ItemProperty -Path ""$regkey\$($_.pschildname)\"" -Name NetbiosOptions -Value 2 -Verbose} }"

:: MS08-068 (placeholder as it's for older systems)

:: CVE-2019-1040 - covered by LSASS protections (LmCompatibilityLevels)

:: Enable SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

:: CVE-2020-1472 - ZeroLogon (safe method) - apparently there are some security patches (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
:: For now, add netlogon registry key to deny vulnerable connections - watch for event IDs 5827 & 5828
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
:: Enable netlogon debug logging - %windir%\debug\netlogon.log
nltest /DBFlag:2080FFFF


:: Roasting of all varieties
:: ASREPRoast - Look for accounts with "Do not require kerberos authentication", limit perms for service accounts, detect by looking for event ID 4768 from service account
:: kerberoasting

:: CVE-2022-33679 - (placeholder b/c only mitigation I could find was patches, although there was a related regkey - AllowOldNt4Crypto)


:: Classic compromisation methods
:: MS17-010 - EternalBlue
:: (insert mitigation here)

:: MS14-025 - SYSVOL & GPP (placeholder b/c requires DC to be 2008 or 2012 and a patch - KB2962486) 
:: Don't set passwords via group policy ig

:: proxylogon, proxyshell (placeholder b/c no Exchange this year)


:: Mitigating some privesc methods
:: UAC - idk if these sync up w/secpol, oh well
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
:: Not sure if this should be set to 1 or 0
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
:: Remote UAC moment
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

:: CVE-2020-0796 (SMBGhost) - Affects Windows build versions 1903, 1909; patch at https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796
:: Workaround will only work on servers, clients would have to connect to malicious SMB server
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f

:: CVE-2021-36934 (HiveNightmare/SeriousSAM) - workaround (patch at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
icacls %windir%\system32\config\*.* /inheritance:e
:: delete vss shadow copies

:: RoguePotato and literally all the other potatoes and PrintSpoofer
:: bruh idk how to mitigate this, something about restricting service account privileges (https://assets.sentinelone.com/labs/rise-of-potatoes#page=1)

:: KrbRelayUp - literally a no fix exploit smh my head
:: Mitigations located at https://pyrochiliarch.com/2022/04/28/krbrelayup-mitigations/
:: Mitigations could break scoring/injects or might not be possible


:: Trying to block common things done after getting valid creds
:: bloodhound - dude idk

:: kerberoasting - https://www.netwrix.com/cracking_kerberos_tgs_tickets_using_kerberoasting.html
:: Events 4769 and 4770, look for use of RC4 encryption and large volume of requests
:: Reject auth requests not using Kerberos FAST
:: Disable insecure protocols (not sure abt this) - attribute msDs-SupportedEncryptionTypes set to 0x18
:: Response: quarantine and reset passwords

:: certipy - bruh idk, requires ADCS anyways

:: coercer.py - oof idk but might not be effective given SMB security settings


:: Known vulns that require valid creds
:: MS14-068
:: (Mitigations go here)

:: CVE-2019-0724, CVE-2019-0686 (privexchange) - placeholder b/c requires MS Exchange

:: CVE-2021-42287/CVE-2021-42278 (SamAccountName / nopac) - patching required; easy to exploit, kinda hard to detect
:: Limit users' abilities to join workstations to domain 

:: CVE-2021-1675 / CVE-2021-42278 (PrintNightmare)
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f

:: CVE-2022-26923 (Certifried) - placeholder b/c needs ADCS


:: Mitigating common things tried after getting local admin
:: Extracting creds from LSASS - LSASS Protections
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
:: Disable plain text passwords stored in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f 

:: Extracting creds from SAM, LSA - should be covered by above otherwise idk

:: dpapi extract - lol idl

:: Extract creds w/cert auth - placeholder b/c no ADCS, but still idk


:: Messing w/ACLs and permissions
:: dcsync

:: perms on groups, computers, users, gpos

:: CVE-2021-40469 - DNSadmins abuse
:: probs remove this from general script, specify in docs


:: Lateral movement attacks
:: Pass The Hash
:: https://www.netwrix.com/pass_the_hash_attack_explained.html

:: Pass The Ticket
:: https://www.netwrix.com/pass_the_ticket.html

:: overpass the hash
:: https://blog.netwrix.com/2022/10/04/overpass-the-hash-attacks/


:: Kerberos delegation
:: Unconstrained delegation

:: Contstrained delegation

:: Resource-based Constrained delegation (RBCD)


:: Trust relationships
:: Parent/child domain relations - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain?q=trust


:: Persistence
:: Golden Ticket - https://www.netwrix.com/how_golden_ticket_attack_works.html

:: Silver Ticket - https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html

:: Diamond Ticket??? Sapphire Ticket???


:: They got domain admin - rip bozo
:: ntds.dit extraction - https://www.netwrix.com/ntds_dit_security_active_directory.html



:: TODO: One secpol file for default domain controller policy (that contains user right assignments for DC's)

:: Done through secpol file
@REM :: Disable Guest user + rename
@REM net user Guest /active:no
@REM wmic useraccount where "name='Guest'" rename lettuce
@REM :: Rename Administrator
@REM wmic useraccount where "name='Administrator'" rename tomato

:: Create backup admin(s)
net user cucumber Passw0rd-123* /add
net localgroup Administrators cucumber /add

:: Most keys that exist in the SOFTWARE hive also exist under SOFTWARE\Wow6432Node but I am too lazy to add them


:: Stopping psexec with the power of svchost
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" /v Debugger /t REG_SZ /d "svchost.exe" /f

:: Securing RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f 
:: Disabling RDP (only if not needed)
::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
::reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fLogonDisabled /t REG_DWORD /d 1 /f



:: Ease of Access
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /t REG_DWORD /d 8 /f

:: Disable SMBv1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
:: Strengthen SMB
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f

:: UPnP
reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f

:: Limiting BITS transfer
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f

:: AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f

:: Caching logons
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 1

:: Remote Registry Path Denial
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f

:: Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, in HKCU, and Wow6432Node)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f

:: Removing exclusions in Defender
powershell -Command "& { Get-MpPreference | Select-Object -Property ExclusionExtension | ForEach-Object { if ($_.ExclusionExtension -ne $null) {Remove-MpPreference -ExclusionExtension $_.ExclusionExtension}}; Get-MpPreference | Select-Object -Property ExclusionPath | ForEach-Object {if ($_.ExclusionPath -ne $null) {Remove-MpPreference -ExclusionPath $_.ExclusionPath}}; Get-MpPreference | Select-Object -Property ExclusionProcess | ForEach-Object {if ($_.ExclusionProcess -ne $null) {Remove-MpPreference -ExclusionProcess $_.ExclusionProcess}} }"

:: Yeeting things
@REM net share admin$ /del
@REM net share c$ /del
@REM reg delete hklm\software\microsoft\windows\currentversion\runonce /f
@REM reg delete hklm\software\microsoft\windows\currentversion\run /f
@REM del /S "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
@REM del /S "C:\Users\LocalGuard\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f 
