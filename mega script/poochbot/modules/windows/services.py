import logging

from poochbot.utils import *

logger = logging.getLogger(__name__)

# auto, demand, disabled

servicelist = [
    ["WinDefend", "auto"],
    ["mpssvc", "auto"],
    ["EventLog", "auto"],
    ["WSearch", "auto"],
    ["wuauserv", "auto"],

    ["Sense", "demand"],

    ["BTAGService", "disabled"],
    ["bthserv", "disabled"],
    ["Browser", "disabled"],
    ["MapsBroker", "disabled"],
    ["lfsvc", "disabled"],
    ["SharedAccess", "disabled"],
    ["lltdsvc", "disabled"],
    ["MSiSCSI", "disabled"],
    ["NetTcpPortSharing", "disabled"],
    ["PNRPsvc", "disabled"],
    ["p2psvc", "disabled"],
    ["p2pimsvc", "disabled"],
    ["PNRPAutoReg", "disabled"],
    ["wercplsupport", "disabled"],
    ["RasAuto", "disabled"],
    ["SessionEnv", "disabled"],
    ["TermService", "disabled"],
    ["UmRdpService", "disabled"],
    ["RpcLocator", "disabled"],
    ["RemoteRegistry", "disabled"],
    ["RemoteAccess", "disabled"],
    ["LanmanServer", "disabled"], # ONLY IF NO SMB
    ["SSDPSRV", "disabled"],
    ["upnphost", "disabled"],
    ["WerSvc", "disabled"],
    ["Wecsvc", "disabled"],
    ["icssvc", "disabled"],
    ["WpnService", "disabled"],
    ["PushToInstall", "disabled"],
    ["WS-Management", "disabled"],
    ["XboxGipSvc", "disabled"],
    ["XblAuthManager", "disabled"],
    ["XblGameSave", "disabled"],
    ["XboxNetApiSvc", "disabled"],
    ["seclogon", "disabled"],
    ["IISADMIN", "disabled"], # ONLY IF NO IIS
    ["irmon", "disabled"],
    ["LxssManager", "disabled"],
    ["FTPSVC", "disabled"],
    ["sshd", "disabled"],
    ["simptcp", "disabled"],
    ["SNMP", "disabled"],
    ["sacsvr", "disabled"],
    ["WMSvc", "disabled"],
    ["WMPNetworkSvc", "disabled"],
    ["WinRM", "disabled"],
    ["W3SVC", "disabled"],
    ["tlntsvr", "disabled"],
]

def services() -> None:
    """Automatically configures the most common service settings"""

    for service in servicelist:
        try:
            setservice(service[0], service[1])
        except:
            logger.error(f"failed to set {service[0]} to {service[1]}")
    
def setservice(name: str, starttype: str):
    cmdshell(f"sc config {name} start= {starttype}")
