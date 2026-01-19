# Imports
import winrm
import re
import argparse
import os
import json

ALL_HOSTS = "/opt/passwordmanager/windows_starting_clients.txt"

# global FILE_PATH
# global SERVICE_NAME
# global PROCESS_NAME
# global RUN_KEY_LOCATION
# global SCHEDULED_TASK_NAME

global ARTIFACTS

# Fixes PyWinRM ipv6 issue (Shoutout illidian80 on github)
_original_build_url = winrm.Session._build_url
@staticmethod
def _patched_build_url(target, transport):
    # IPv6 pattern matching
    ipv6_match = re.match(
        r'(?i)^((?P<scheme>http[s]?)://)?(\[(?P<ipv6>[0-9a-f:]+)\])(:(?P<port>\d+))?(?P<path>(/)?(wsman)?)?',
        target
    )
    if ipv6_match:
        scheme = ipv6_match.group('scheme') or ('https' if transport == 'ssl' else 'http')
        host = '[' + ipv6_match.group('ipv6') + ']'
        port = ipv6_match.group('port') or ('5986' if transport == 'ssl' else '5985')
        path = ipv6_match.group('path') or 'wsman'
        return '{0}://{1}:{2}/{3}'.format(scheme, host, port, path.lstrip('/'))
    return _original_build_url(target, transport)
winrm.Session._build_url = _patched_build_url

# Establish WinRM Session
def create_session(host, username, password):
    try:
        # Wrap IPv6 addresses in brackets
        host_addr = f"[{host}]" if ':' in host and not host.startswith('[') else host
        session = winrm.Session(
            f'http://{host_addr}:5985/wsman',
            auth=(f"{username}", password),
            server_cert_validation='ignore',
            transport='ntlm'
        )
        return session
    except Exception as e:
        return None

# Gets all IPs from the password manager file
def get_ips():
    ignore_first_line = True
    WINDOWS_HOSTS = []
    with open(ALL_HOSTS, 'r') as ip_file:
        for line in ip_file:
            if ignore_first_line:
                ignore_first_line = False
                continue
            host = line.strip()
            WINDOWS_HOSTS.append(host)
    return WINDOWS_HOSTS

def parse_scheduled_task_output(output, file_path):
    tasks = output.split('\r\n\r\n')
    for task in tasks:
        if file_path in task:
            match = re.search(r'TaskName:\s+(.*)', task)
            if match:
                return match.group(1).strip()
    return None

def gather_information(session, host, file_paths):
    global ARTIFACTS
    ARTIFACTS[host] = {
        "File Paths": file_paths,
        "Process Name": set(),
        "Process ID": set(),
        "Service Name": set(),
        "Run Key Location": set(),
        "Scheduled Task Name": set()
    }

    if len(file_paths) != 0:
        for file_path in file_paths:
            ps_script = f'Test-Path -Path \'{file_path}\''
            output = session.run_cmd(f'powershell -c "{ps_script}"')
            if output.status_code == 0:
                # Process Information
                ps_script = 'get-process | where-object { $_.path -eq \'' + file_path + '\'} | select-object name, id, path | format-table -HideTableHeaders'
                output = session.run_cmd(f'powershell -c "{ps_script}"')
                output = output.std_out.decode().strip()
                if len(output) != 0:
                    tokens = output.split()
                    if len(tokens) >= 2:
                        ARTIFACTS[host]["Process Name"].add(tokens[0])
                        ARTIFACTS[host]["Process ID"].add(tokens[1])
                
                # Service Information
                ps_script = 'Get-CimInstance -ClassName win32_service | where-object { $_.PathName -eq \'' +  file_path + '\'} | select-object -ExpandProperty name'
                output = session.run_cmd(f'powershell -c "{ps_script}"')
                output = output.std_out.decode().strip()
                if len(output) != 0:
                    ARTIFACTS[host]["Service Name"].add(output.split("\r\n")[0])

                # Run Key Information
                ps_script = (
                    f'Get-ItemProperty -Path \'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\';'
                    f'Get-ItemProperty -Path \'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\';'
                    f'Get-ItemProperty -Path \'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\';'
                    f'Get-ItemProperty -Path \'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\''
                )
                output = session.run_cmd(f'powershell -c "{ps_script}"')
                tokens = output.std_out.decode().strip().split('\r\n')
                for token in tokens:
                    if file_path in token:
                        key_location = token.split(':')[0].strip()
                        ARTIFACTS[host]["Run Key Location"].add(key_location)
                        break

                # Scheduled Task Information
                ps_script = "schtasks /query /fo LIST /v"
                output = session.run_cmd(f"powershell -c {ps_script}")
                task_name = parse_scheduled_task_output(output.std_out.decode(), file_path)
                if task_name is not None:
                    ARTIFACTS[host]["Scheduled Task Name"].add(task_name)

    ARTIFACTS[host]["Process Name"] = list(ARTIFACTS[host]["Process Name"])
    ARTIFACTS[host]["Process ID"] = list(ARTIFACTS[host]["Process ID"])
    ARTIFACTS[host]["Service Name"] = list(ARTIFACTS[host]["Service Name"])
    ARTIFACTS[host]["Run Key Location"] = list(ARTIFACTS[host]["Run Key Location"])
    ARTIFACTS[host]["Scheduled Task Name"] = list(ARTIFACTS[host]["Scheduled Task Name"])

def contain(session, host):
    powershell_contain_command = ''
    # Remove Services
    for service_name in ARTIFACTS[host]["Service Name"]:
        service_name = service_name.strip()
        powershell_contain_command += f'Stop-Service -Name \'{service_name}\'; Disable-Service -Name \'{service_name}\'; sc.exe delete \'{service_name}\'; '

    # Remove Scheduled Tasks
    for task_name in ARTIFACTS[host]["Scheduled Task Name"]:
        task_name = task_name.strip()
        powershell_contain_command += f'Schtasks /Delete /TN \'{task_name}\' /F; '

    # Remove Run Keys
    for run_key in ARTIFACTS[host]["Run Key Location"]:
        run_key = run_key.strip()
        powershell_contain_command += f'Remove-ItemProperty -Path \'Registry::{run_key}\' -Name *;'

    # Remove Processes
    for process_id in ARTIFACTS[host]["Process ID"]:
        process_id = process_id.strip()
        powershell_contain_command += f'Stop-Process -Id {process_id} -Force; '

    # Remove File Path
    for file_path in ARTIFACTS[host]["File Paths"]:
        file_path = file_path.strip()
        powershell_contain_command += f'takeown /f \'{file_path}\'; Remove-Item -Path \'{file_path}\' -Force; '

    print(f"Running Contain Command: {powershell_contain_command} ... on {host}")
    output = session.run_cmd(f'powershell -c "{powershell_contain_command}"')
    if output.status_code == 0:
        print(f"Containment Successful on {host}")
    else:
        print(f"Containment Failed on {host}")
        print(f"Error: {output.std_err.decode().strip()}")


def format_artifacts():
    json_output = json.dumps(ARTIFACTS, indent=4)
    return json_output

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Containment Script')
    parser.add_argument('-u', required=True, help='Windows Domain Admin Username')
    parser.add_argument('-p', required=True, help='Windows Domain Admin Password')
    parser.add_argument('--file-path', required=True, help='File path to contain from remote hosts')
    args = parser.parse_args()
    
    # Define variables
    username = args.u
    password = args.p

    file_path = args.file_path
    if "," in file_path:
        file_path = file_path.split(",")
    else:
        file_path = [file_path]
    
    for i in range(len(file_path)):
        file_path[i] = file_path[i].strip()

    # Clear Terminal
    os.system('clear')

    # Gets all Windows IPs
    hosts = get_ips()

    global ARTIFACTS
    ARTIFACTS = {}

    # Runs commands against all hosts
    for host in hosts:
        ARTIFACTS[host] = {}
        session = create_session(host, username, password)
        if session is not None:
            gather_information(session, host, file_path)

    json_output = format_artifacts()
    print(json_output)

    contain_artifact = input("Remove Artifact? (Y/N): ")
    if contain_artifact.lower() == "y":
        for host in hosts:
            session = create_session(host, username, password)
            contain(session, host)
    else:
        pass

if __name__ == "__main__":
    main()