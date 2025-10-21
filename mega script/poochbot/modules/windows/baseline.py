import logging

import io
import os
import os.path

from poochbot.options import OPTIONS
from poochbot.utils import *

logger = logging.getLogger(__name__)

genbaselinedir = "./generated/baselines"
genreportdir = "./generated/reports"

def baseline() -> None:
    """Gives user difftables against good baselines for many different os related lists"""

    baselinedir = "./support/baselines/win10" if OPTIONS["OS"] == OperatingSystem.WINDOWS else "./support/baselines/server2022"
    servicesbaseline(baselinedir)
    tasksbaseline(baselinedir)
    firewallbaseline(baselinedir)

    accessbaseline(baselinedir, "file", "C:/")
    accessbaseline(baselinedir, "machineregaccess", "HKEY_LOCAL_MACHINE")
    accessbaseline(baselinedir, "userregaccess", "HKEY_CURRENT_USER")
    
    featuresbaseline(baselinedir)
    if OPTIONS["OS"] == OperatingSystem.WINDOWS_SERVER:
        serverfeaturesbaseline(baselinedir)

#region baseline functions

def servicesbaseline(baselinedir: str) -> None:
    headings = ("Name", "DisplayName", "StartMode", "State", "PathName")

    # formats raw data from services commandline query
    def format(unf: str) -> list[tuple[str]]:
        data = []
        for group in unf.split("\n\n\n\n"):
            if group.isspace():
                continue

            service_data = []
            for key in headings:
                for line in group.splitlines():
                    if line.startswith(key):
                        x = line.removeprefix(key + "=")

                        # ignore LUID for user specific services (so they match correctly)
                        if "_" in x and (key == "Name" or key == "DisplayName"):
                            x = x.split("_")[0] + "_XXXXX"

                        # default file paths to all lowercase (so they match correctly)
                        if key == "PathName":
                            if x.startswith("\""):
                                endind = x[1:].index("\"")
                                x = x[:endind].lower() + x[endind:]
                            else:
                                if " " in x:
                                    endind = x.index(" ")
                                    x = x[:endind].lower() + x[endind:]
                                else:
                                    x = x.lower()

                        service_data.append(x)
            if service_data:
                data.append(tuple(service_data))

        return data
    
    # ask to run
    if input("Run Services Baseline? (Y/n) ").lower() == "n":
        return

    rich.print("[bold]Running Services Baseline[/]")

    # get current services
    logger.info("Getting current services")
    servicedataraw = getdataifexists("services")
    if servicedataraw is None:
        servicedataraw = cmdshell("wmic service get * /format:list")
        savedata("services", servicedataraw)
    
    # get baseline services
    baselineservicedataraw = getbaselinedata("services", baselinedir)

    # format data
    servicedata = format(servicedataraw)
    baselineservicedata = format(baselineservicedataraw)

    # get difftable
    difftable = getdifftable(servicedata, baselineservicedata, headings)
    if input("Show diff-table? (Y/n) ").lower() == "y":
        rich.print(difftable)
    if input("Save diff-table? (Y/n) ").lower() == "y":
        savereport("services", difftable)

def tasksbaseline(baselinedir: str) -> None:
    headings = ("TaskName", "TaskPath", "State", "Description", "SecurityDescriptor")

    # formats raw data from tasks commandline query
    def format(unf: str) -> list[tuple[str]]:
        data = []
        for group in unf.split("\n\n"):
            if group.isspace():
                continue
            group_data = []
            for key in headings:
                for line in group.splitlines():
                    if line.startswith(key):
                        x = line.removeprefix(key).lstrip().removeprefix(": ")
                        if x.endswith("\\"):
                            x = x.removesuffix("\\") + "\\" + "\\"

                        group_data.append(x)
            if group_data:
                data.append(tuple(group_data))

        return data

    # ask to run
    if input("Run Tasks Baseline? (Y/n) ").lower() == "n":
        return

    rich.print("[bold]Running Tasks Baseline[/]")

    # get current tasks
    logger.info("Getting current tasks")
    taskdataraw = getdataifexists("tasks")
    if taskdataraw is None:
        taskdataraw = psshell("Get-ScheduledTask | Select * | Out-String -width 10000")
        savedata("tasks", taskdataraw)
    
    # get baseline tasks
    baselinetaskdataraw = getbaselinedata("tasks", baselinedir)

    # format data
    taskdata = format(taskdataraw)
    baselinetaskdata = format(baselinetaskdataraw)

    # get difftable
    difftable = getdifftable(taskdata, baselinetaskdata, headings)
    if input("Show diff-table? (Y/n) ").lower() == "y":
        rich.print(difftable)
    if input("Save diff-table? (Y/n) ").lower() == "y":
        savereport("tasks", difftable)

def firewallbaseline(baselinedir: str) -> None:
    headings = ("Name", "DisplayName", "DisplayGroup", "Description", "Enabled", "Profile", "Direction", "Action")

    # formats raw data from firewall commandline query
    def format(unf: str) -> list[tuple[str]]:
        data = []
        for group in unf.split("\n\n"):
            if group.isspace():
                continue
            group_data = []
            for key in headings:
                for line in group.splitlines():
                    if line.startswith(key):
                        x = line.removeprefix(key).lstrip().removeprefix(": ")
                        if x.endswith("\\"):
                            x = x.removesuffix("\\") + "\\" + "\\"

                        group_data.append(x)
            if group_data:
                data.append(tuple(group_data))

        return data

    # ask to run
    if input("Run Firewall Baseline? (Y/n) ").lower() == "n":
        return

    rich.print("[bold]Running Firewall Baseline[/]")

    # get current tasks
    logger.info("Getting current firewall rules")
    firewalldataraw = getdataifexists("firewall-rules")
    if firewalldataraw is None:
        firewalldataraw = psshell("Get-NetFirewallRule -all | Out-String -width 10000")
        savedata("firewall-rules", firewalldataraw)
    
    # get baseline tasks
    baselinefirewalldataraw = getbaselinedata("firewall-rules", baselinedir)

    # format data
    firewalldata = format(firewalldataraw)
    baselinefirewalldata = format(baselinefirewalldataraw)

    # get difftable
    difftable = getdifftable(firewalldata, baselinefirewalldata, headings)
    if input("Show diff-table? (Y/n) ").lower() == "y":
        rich.print(difftable)
    if input("Save diff-table? (Y/n) ").lower() == "y":
        savereport("firewall-rules", difftable)

def featuresbaseline(baselinedir: str) -> None:
    headings = ("FeatureName", "State")

    # formats raw data from features commandline query
    def format(unf: str) -> list[tuple[str]]:
        data = []
        for group in unf.split("\n\n"):
            if group.isspace():
                continue
            group_data = []
            for key in headings:
                for line in group.splitlines():
                    if line.startswith(key):
                        x = line.removeprefix(key).lstrip().removeprefix(": ")
                        if x.endswith("\\"):
                            x = x.removesuffix("\\") + "\\" + "\\"

                        group_data.append(x)
            if group_data:
                data.append(tuple(group_data))

        return data

    # ask to run
    if input("Run Features Baseline? (Y/n) ").lower() == "n":
        return

    rich.print("[bold]Running Features Baseline[/]")

    # get current features
    logger.info("Getting current features")
    featuredataraw = getdataifexists("optionalfeatures")
    if featuredataraw is None:
        featuredataraw = psshell("Get-WindowsOptionalFeature -Online")
        savedata("optionalfeatures", featuredataraw)
    
    # get baseline features
    baselinefeaturedataraw = getbaselinedata("optionalfeatures", baselinedir)

    # format data
    featuredata = format(featuredataraw)
    baselinefeaturedata = format(baselinefeaturedataraw)

    # get difftable
    difftable = getdifftable(featuredata, baselinefeaturedata, headings)
    if input("Show diff-table? (Y/n) ").lower() == "y":
        rich.print(difftable)
    if input("Save diff-table? (Y/n) ").lower() == "y":
        savereport("optionalfeatures", difftable)

def serverfeaturesbaseline(baselinedir: str) -> None:
    headings = ("Name", "Install State")

    # formats raw data from server features commandline query
    def format(unf: str) -> list[tuple[str]]:
        data = []
        for group in unf.split("\n\n"):
            if group.isspace():
                continue
            group_data = []
            for line in group.splitlines():
                if line.lstrip().startswith("["):
                    x = line.split()
                    group_data.append([x[-2], x[-1]])
            if group_data:
                data.append(tuple(group_data))

        return data

    # ask to run
    if input("Run Server Features Baseline? (Y/n) ").lower() == "n":
        return

    rich.print("[bold]Running Server Features Baseline[/]")

    # get current server features
    logger.info("Getting current server features")
    serverfeaturedataraw = getdataifexists("serverfeatures")
    if serverfeaturedataraw is None:
        serverfeaturedataraw = psshell("Get-WindowsOptionalFeature -Online")
        savedata("serverfeatures", serverfeaturedataraw)
    
    # get baseline server features
    baselineserverfeaturedataraw = getbaselinedata("serverfeatures", baselinedir)

    # format data
    serverfeaturedata = format(serverfeaturedataraw)
    baselineserverfeaturedata = format(baselineserverfeaturedataraw)

    # get difftable
    difftable = getdifftable(serverfeaturedata, baselineserverfeaturedata, headings)
    if input("Show diff-table? (Y/n) ").lower() == "y":
        rich.print(difftable)
    if input("Save diff-table? (Y/n) ").lower() == "y":
        savereport("serverfeatures", difftable)

def accessbaseline(baselinedir: str, accesstype: str, accessedname: str) -> None:
    headings = ("Path", "Read", "Write", "Deny")

    # formats raw data from access enum file
    def format(unf: str) -> list[tuple[str]]:
        data = []
        for group in unf.splitlines():
            if group.isspace() or group.startswith("\"Path\""):
                continue
            splitdata = group.split("\"")
            group_data = [splitdata[1], splitdata[3], splitdata[5], splitdata[7]]
            if group_data:
                data.append(tuple(group_data))

        return data

    # ask to run
    if input(f"Run Server {accesstype} Access Baseline? (Y/n) ").lower() == "n":
        return

    rich.print(f"[bold]Running {accesstype} Access Baseline[/]")

    # get current server features
    accessdataraw = askfilewithpath(f"Enter path of access enum export for [{accessedname}]: ")
    
    # get baseline server features
    baselineaccessdataraw = getbaselinedata(f"{accesstype}access", baselinedir)

    # format data
    accessdata = format(accessdataraw)
    baselineaccessdata = format(baselineaccessdataraw)

    # get difftable
    difftable = getchangedifftable(accessdata, baselineaccessdata, headings)
    if input("Show diff-table? (Y/n) ").lower() == "y":
        rich.print(difftable)
    if input("Save diff-table? (Y/n) ").lower() == "y":
        savereport(f"{accesstype}access", difftable)

#endregion

#region helpers

def getdataifexists(filename: str) -> str:
    filepath = f"{genbaselinedir}/{filename}.txt"

    if (os.path.exists(filepath)):
        if input(f"Use saved image data ({filepath})? (Y/n) ").lower() == "y":
            with open(filepath, "r") as f:
                return f.read()
        else:
            return None
    else:
        return None
    
def getbaselinedata(filename: str, baselinedir: str) -> str:
    filepath = f"{baselinedir}/{filename}.txt"

    with io.open(filepath, "r", encoding="utf-16-le") as f:
        return f.read()

def savedata(filename: str, writedata: str) -> None:
    filepath = f"{genbaselinedir}/{filename}.txt"

    with open(filepath, "w") as f:
        f.write(writedata)

def savereport(filename: str, writedata: rich.table.Table) -> None:
    filepath = f"{genreportdir}/{filename}.txt"

    with open(filepath, "w") as f:
        rich.print(writedata, file=f)

    logger.info(f"Diff-table saved at: {filepath}")

def askfilewithpath(question: str):
    filepath = input(question)

    while not (os.path.exists(filepath)):
        rich.print("path doesn't exist...")
        filepath = input(question)

    with open(filepath, "r", encoding="utf-16-le") as f:
        return f.read()

#endregion
