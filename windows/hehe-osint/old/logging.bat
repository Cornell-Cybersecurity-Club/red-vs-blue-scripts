@echo off

:: Increasing log size
WevtUtil sl Application /ms:256000000
WevtUtil sl System /ms:256000000
WevtUtil sl Security /ms:1048576000
WevtUtil sl "Windows PowerShell" /ms:512000000
WevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:512000000

:: Audit policy 
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:disable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:disable

auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable
:: (applies to next line only) noisy if turned on, used to discover ad replication errors
auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable 
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable

:: (next line only) causes both 4740 and 4625 events to show up, which will also show the IP of application making request
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"User / Device Claims" /success:disable /failure:disable
auditpol /set /subcategory:"Group Membership" /success:enable /failure:disable
auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable
auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable
auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:disable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:disable /failure:enable
:: Windows Firewall (aka the Filtering stuff) is mad noisy, if want on go "Success and Failure" and "Success", respectively
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
:: Turn on "Success" if want to track starting/stopping services (very noisy)
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:disable
auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:disable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:disable
auditpol /set /subcategory:"Central Policy Staging" /success:disable /failure:disable

auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
:: Windows Firewall
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:disable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable /failure:disable
auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:disable

auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable
auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:disable
auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

:: Powershell logging
mkdir C:\scrips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d C:\scrips /f
:: Process Creation events (4688) include command line arguments
:: If Windows 7 or Server 2008: KB3004375
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

:: Sysmon mode
cd ../tools/sys/sm
sysmon64 -accepteula -i ../../../scripts/conf/sysmon.xml
WevtUtil sl "Microsoft-Windows-Sysmon/Operational" /ms:1048576000
cd ../../../scripts

set /p choice="Is this server a DNS server (Y or N)? "
:: Attempt to enable DNS logging if this is a DNS server 
:: %SYSTEMROOT%\System32\dns\dns.log
if %choice%=="Y" (
    dnscmd /config /loglevel 0x8000F301
    dnscmd /config /logfilemaxsize 0xC800000
)

:: DNS Client Logging
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true

set /p choice="Is this a domain controller (Y or N)? "
if %choice%=="Y" (
    echo Please use the Group Policy Management GUI to import the auditpol.csv file into the Advanced Audit Policy section of a GPO ^(ideally the same one as the secpol file^). Make sure to do gpupdate /force after!
) 
:: TODO: DHCP logging

:: RIP Wazuh configuration