# IMPORTANT NEEDS TO BE ENABLED ON ALL BOXES!!!
#https://community.fortinet.com/t5/FortiSOAR-Knowledge-Base/Troubleshooting-Tip-Exchange-Microsoft-WinRM-Connector-Error/ta-p/324015

# Windows Reconnaissance Script to Fill Out Ansible Inventory
import os
import nmap
import winrm
import argparse
import paramiko
import socket
import re

# Global File Locations
#ANSIBLE_INVENTORY_FILE = '/Windows-Scripts/ansible/inventory/inventory.yml'
ANSIBLE_INVENTORY_FILE = '/Windows-Scripts/ansible/inventory/inventory.yml' # Used for testing without destroying actual inventory
IP_FILE = '/opt/passwordmanager/windows_starting_clients.txt'
TOPOLOGY_FILE = '/Windows-Scripts/topology.csv'

# Global Variables
global DOMAIN_CREDENTIALS
global LINUX_CREDENTIALS
global SCRIPTS_PATH
global PASSWORD_MANAGER_IP
global GRAFANA_IP
global LOCAL_IP
global HOST_INFO

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

# Scans the given subnet for hosts
def scan_all_hosts(subnet):
    global HOST_INFO
    nm = nmap.PortScanner()
    # param gets passed as comma separated, nmap wants spaces
    subnet = subnet.replace(',', ' ')
    # Use -6 flag for IPv6 scanning
    if ':' in subnet:
        nm.scan(hosts=subnet, arguments='-O -6 -p 22,3389,5985,5986')
    else:
        nm.scan(hosts=subnet, arguments='-O -p 22,3389,5985,5986')
    for host in [x for x in nm.all_hosts()]:
        lport = nm[host]['tcp'].keys()

        HOST_INFO[host] = {
            'OS': '',
            'OS_Version': '',
            'Username': None,
            'Password': None,
            'Hostname': None,
            'Services': set(),
        }

        for port in lport:
            if port == 22 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('SSH')
            elif port == 3389 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('RDP')
            elif port == 5985 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('WinRM_HTTP')
            elif port == 5986 and nm[host]['tcp'][port]['state'] == 'open':
                HOST_INFO[host]['Services'].add('WinRM_HTTPS')

        os_version = determine_os(nm, host)

        if os_version == "Windows" or ('WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services'] or 'RDP' in HOST_INFO[host]['Services']):
            HOST_INFO[host]['OS'] = 'Windows'
            print(f"Windows Host {host} detected:\n",end="")
        else:
            print(f"Unix Host {host} detected:\n",end="")
            HOST_INFO[host]['OS'] = os_version
            if GRAFANA_IP is None:
                find_grafana(host)

        if HOST_INFO[host]['Services'] == set():
            print("No Detected Remoting Services", end="")
        else:
            if 'SSH' in HOST_INFO[host]['Services'] or 'RDP' in HOST_INFO[host]['Services'] or 'WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services']:
                print("Detected Remoting Services: ", end="")
                for service in HOST_INFO[host]['Services']:
                    print(f"{service} ", end="")
    
        print("\n")
            
    return nm

def find_grafana(host):
    global GRAFANA_IP
    nm = nmap.PortScanner()
    if ":" in host:
        nm.scan(hosts=host, arguments='-6 -p 3000')
    else:
        nm.scan(hosts=host, arguments='-p 3000')
    if nm[host].has_tcp(3000) and nm[host]['tcp'][3000]['state'] == 'open':
        GRAFANA_IP = host
        print(f"Set as Grafana IP\n",end="")

# Attempts to gather additional information about Windows hosts
def gather_info(original_scan, subnet):
    global HOST_INFO
    command_output = {}
    
    for host in HOST_INFO.keys():
        if HOST_INFO[host]['OS'] == "Windows":
            if 'WinRM_HTTP' in HOST_INFO[host]['Services'] or 'WinRM_HTTPS' in HOST_INFO[host]['Services']:
                for i in range(len(DOMAIN_CREDENTIALS)):
                    username = DOMAIN_CREDENTIALS[i][0]
                    password = DOMAIN_CREDENTIALS[i][1]
                    try:
                        # Wrap IPv6 addresses in brackets
                        host_addr = f"[{host}]" if ':' in host and not host.startswith('[') else host
                        session = winrm.Session(
                            f'http://{host_addr}:5985/wsman',
                            auth=(f"{username}", password),
                            server_cert_validation='ignore',
                            transport='ntlm'
                        )
                        HOST_INFO[host]['Username'] = username
                        HOST_INFO[host]['Password'] = password
                        print(f"Windows Host {host}:")
                        print(f"Credentials Used: {username}:{password}")
                        detect_scored_services(session, host)
                        determine_windows_os_version(session, host)
                        log(IP_FILE, host)
                        continue
                    except Exception as e:
                        pass
                if HOST_INFO[host]['Username'] is None or HOST_INFO[host]['Password'] is None:
                    print(f"Windows Host {host} WinRM Authentication Failed, Running Port Scan:\n",end="")
                    port_scan_only(host, command_output)
            else:
                print(f"Windows Host {host} has WinRM Disabled, Running Port Scan:\n",end="")
                port_scan_only(host, command_output)
        elif LINUX_CREDENTIALS is not None and HOST_INFO[host]['OS'] == 'Linux' and PASSWORD_MANAGER_IP is None:
            for i in range(len(LINUX_CREDENTIALS)):
                username = LINUX_CREDENTIALS[i][0]
                password = LINUX_CREDENTIALS[i][1]
                # HOST_INFO[host]['Username'] = username
                # HOST_INFO[host]['Password'] = password
                print(f"Unix Host {host}:\n",end="")
                # port_scan_only(host, command_output)
                # if HOST_INFO[host]['OS'] == 'Linux' and PASSWORD_MANAGER_IP is None:
                determine_unix_os_version(host, username, password)
        services_str = ','.join(sorted(HOST_INFO[host]['Services'])) if HOST_INFO[host]['Services'] else 'None'
        os_version = HOST_INFO[host]['OS_Version']
        if os_version:
            os_version = re.sub(r'^(.*[0-9]).*$', r'\1', os_version)
        log(TOPOLOGY_FILE, f"{subnet},{host},{HOST_INFO[host]['Hostname']},{os_version},\"{services_str}\"")
    return command_output

# Determines scored service via WinRM
def detect_scored_services(session, ip_address):
    global HOST_INFO
    
    try:
        basic_query = session.run_cmd('hostname') #proves connection works
        if basic_query.status_code == 0:
            hostname = basic_query.std_out.decode().strip()
            HOST_INFO[ip_address]['Hostname'] = hostname
            print("Detected Potential Scored Services: ",end="")

        check_ftp = session.run_cmd('sc query ftpsvc')
        if check_ftp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":21"').std_out.decode() != '':
                print("FTP:21 ",end="")
                HOST_INFO[ip_address]['Services'].add('FTP')

        check_ssh = session.run_cmd('sc query sshd')
        if check_ssh.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":22"').std_out.decode() != '':
                print("SSH:22 ",end="")
                HOST_INFO[ip_address]['Services'].add('SSH')

        check_telnet = session.run_cmd('sc query telnet')
        if check_telnet.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":23"').std_out.decode() != '':
                print("Telnet:23 ",end="")
                HOST_INFO[ip_address]['Services'].add('Telnet')

        check_dns = session.run_cmd('sc query dns')
        if check_dns.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":53"').std_out.decode() != '':
                print("DNS:53 ",end="")
                HOST_INFO[ip_address]['Services'].add('DNS')

        check_dhcp = session.run_cmd('sc query dhcpserver')
        if check_dhcp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":67"').std_out.decode() != '':
                print("DHCP:67 ",end="")
                HOST_INFO[ip_address]['Services'].add('DHCP')

        check_http_iis = session.run_cmd('sc query w3svc')
        if check_http_iis.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() != '':
                print("HTTP_IIS:80 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTP')
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
                print("HTTPS_IIS:443 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTPS')
        check_http_nginx = session.run_cmd('sc query nginx')
        if check_http_nginx.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() != '':
                print("HTTP_Nginx:80 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTP')
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
                print("HTTPS_Nginx:443 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTPS')

        check_http_apache = session.run_cmd('sc query Apache2.4')
        if check_http_apache.status_code != 0:
            check_http_apache = session.run_cmd('sc query Apache24')
            if check_http_apache.status_code != 0:
                check_http_apache = session.run_cmd('sc query Apache')
        if check_http_apache.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":80"').std_out.decode() != '':
                print("HTTP_Apache:80 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTP')
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":443"').std_out.decode() != '':
                print("HTTPS_Apache:443 ",end="")
                HOST_INFO[ip_address]['Services'].add('HTTPS')

        check_ntp = session.run_cmd('sc query w32time')
        if check_ntp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":123"').std_out.decode() != '':
                print("NTP:123 ",end="")
                HOST_INFO[ip_address]['Services'].add('NTP')

        check_ldap = session.run_cmd('sc query ntds')
        if check_ldap.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":389"').std_out.decode() != '':
                print("LDAP:389 ", end="")
                HOST_INFO[ip_address]['Services'].add('LDAP')

        check_adfs = session.run_cmd('sc query adfssrv')
        if check_adfs.status_code == 0:
            print("ADFS ",end="")
            HOST_INFO[ip_address]['Services'].add('ADFS')

        check_ca = session.run_cmd('sc query certsvc')
        if check_ca.status_code == 0:
            print("CA ",end="")
            HOST_INFO[ip_address]['Services'].add('CA')

        check_smb = session.run_cmd('sc query lanmanserver')
        if check_smb.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":445"').std_out.decode() != '':
                print("SMB:445 ",end="")
                HOST_INFO[ip_address]['Services'].add('SMB')

        check_rdp = session.run_cmd('sc query termservice')
        if check_rdp.status_code == 0:
            if session.run_cmd('netstat -an | findstr /i "LISTENING" | findstr ":3389"').std_out.decode() != '':
                print("RDP:3389",end="")
                HOST_INFO[ip_address]['Services'].add('RDP')
        print("\n",end="")
    except Exception as e:
        print("Failed to create WinRM session\n\n",end="")
            

def determine_os(nm, host):
    # Check OS detection results
    os_match = nm[host].get('osmatch', [])
    if os_match:
        # Check all matches for Windows first (higher priority)
        for os_info in os_match:
            if 'Windows' in os_info.get('name', ''):
                return 'Windows'
        
        # If no Windows match found, check for Linux/Unix
        for os_info in os_match:
            if 'Linux' in os_info.get('name', ''):
                return 'Linux'
            
    return 'FreeBSD'  # Default to FreeBSD if no matches found

def determine_windows_os_version(session, ip_address):
    global HOST_INFO

    # Determines Windows OS Version
    check_os_type = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' InstallationType')
    check_os_version = session.run_cmd('powershell -c Get-ItemPropertyValue \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\' ProductName')
    if check_os_type.std_out.decode() != '' and check_os_version.std_out.decode() != '':
        print(f"Detected OS: {check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})\n",end="")
        HOST_INFO[ip_address]['OS_Version'] = f"{check_os_version.std_out.decode().strip()} ({check_os_type.std_out.decode().strip()})"
    else:
        if check_os_type.std_out.decode() == '':
            print("Could not determine OS Type\n",end="")
        else:
            print(f"Detected OS Type: {check_os_type.std_out.decode().strip()}",end="")
            HOST_INFO[ip_address]['OS_Version'] = f"{check_os_type.std_out.decode().strip()}"
        if check_os_version.std_out.decode() == '':
            print("Could not determine OS Version\n",end="")
        else:
            print(f"Detected OS Version: {check_os_version.std_out.decode().strip()}",end="")
            HOST_INFO[ip_address]['OS_Version'] += f" {check_os_version.std_out.decode().strip()}"
    print("")

def determine_unix_os_version(ip_address, username, password):
    global HOST_INFO

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(ip_address, username=username, password=password, timeout=10)
        stdin, stdout, stderr = ssh_client.exec_command('cat /etc/os-release | grep PRETTY_NAME | cut -d "=" -f2 | tr -d \'"\'')
        os_info = stdout.read().decode().strip()
        if os_info == '':
            stdin, stdout, stderr = ssh_client.exec_command('freebsd-version')
            os_info = "FreeBSD " + stdout.read().decode().strip()
        print(f"Credentials Used: {username}:{password}")
        print(f"Detected OS: {os_info}\n",end="")
        if "Ubuntu" in os_info:
            global PASSWORD_MANAGER_IP
            if PASSWORD_MANAGER_IP is None:
                PASSWORD_MANAGER_IP = ip_address
                print(f"Set as Password Manager IP\n",end="")
        if "FreeBSD" in os_info:
            print(f"Router Detected\n",end="")

        # Get Hostname
        stdin, stdout, stderr = ssh_client.exec_command('hostname')
        hostname = stdout.read().decode().strip()
        HOST_INFO[ip_address]['Hostname'] = hostname
        ssh_client.close()
    except Exception as e:
        print(f"Credentials Used: {username}:{password}")
        print(f"Failed to create SSH session.\n",end="")
    print("")

def log(file, content):
    with open(file, 'a') as log_file:
        log_file.write(content + '\n')

def port_scan_only(host, command_output):
    global HOST_INFO

    print("Detected Potential Scored Services: ",end="")
    try:
        ps = nmap.PortScanner()
        # Use -6 flag for IPv6 scanning
        if ':' in host:
            ps.scan(hosts=host, arguments='-sV -p 21,22,23,53,67,80,123,389,443,445,1500,3389,5985,5986 -6')
        else:
            ps.scan(hosts=host, arguments='-sV -p 21,22,23,53,67,80,123,389,443,445,1500,3389,5985,5986')
        port_dict = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            53: "DNS",
            67: "DHCP",
            80: "HTTP",
            123: "NTP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            1500: "ADFS",
            3389: "RDP",
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS"
        }
        lport = ps[host]['tcp'].keys()
        
        # Log open ports found
        for port in lport:
            port_state = ps[host]['tcp'][port]['state']
            if port_state == 'open':
                service = port_dict.get(port, f"Unknown ({port})")
                print(f"{service}:{port} ",end="")
                HOST_INFO[host]['Services'].add(service)
                if host not in command_output:
                    command_output[host] = f"Open ports: {port} ({service})"
                else:
                    command_output[host] += f", {port} ({service})"
        print("\n",end="")
    except Exception as e:
        print(f"Port scan failed: {str(e)}\n",end="")

def get_local_ip():
    global LOCAL_IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        LOCAL_IP = s.getsockname()[0]
        s.close()
    except Exception as e:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        LOCAL_IP = s.getsockname()[0]
        s.close()
        
# Adds information about Windows hosts to the Ansible inventory file
def add_to_ansible_inventory():
    global HOST_INFO

    print(f"Adding hosts to Ansible inventory file: {ANSIBLE_INVENTORY_FILE}\n")

    adfs_backup_password = os.urandom(12).hex()

    ansible_header_content = f"""---
all:
  children:
    windows:
      vars:
        ansible_connection: winrm
        ansible_winrm_server_cert_validation: ignore
        ansible_winrm_port: 5985
        ansible_winrm_transport: ntlm
        scripts_path: "{SCRIPTS_PATH}"
        scripts_ansible_location: "/Windows-Scripts"
        password_manager_ip: "{PASSWORD_MANAGER_IP if PASSWORD_MANAGER_IP is not None else ''}"{' #REPLACE' if PASSWORD_MANAGER_IP is None else ''}
        siem_IP: "{GRAFANA_IP if GRAFANA_IP is not None else ''}"{' #REPLACE' if GRAFANA_IP is None else ''}
        siem_name: "Grafana"
        adfs_backup_password: "{adfs_backup_password}"
        stabvest_ip: "{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}
        winrm_ip: "{LOCAL_IP if LOCAL_IP is not None else ''}"{' #REPLACE' if LOCAL_IP is None else ''}
      children:
        """

    for host in HOST_INFO.keys():
        server_type = "none"
        if 'ADFS' in HOST_INFO[host]['Services']:
            server_type = "adfs"
        elif 'SMB' in HOST_INFO[host]['Services'] and 'LDAP' in HOST_INFO[host]['Services']:
            server_type = "dc"
        elif 'CA' in HOST_INFO[host]['Services']:
            server_type = "ca"

        scored_services = HOST_INFO[host]['Services']
        scored_services.remove('WinRM_HTTP') if 'WinRM_HTTP' in scored_services else None
        scored_services.remove('WinRM_HTTPS') if 'WinRM_HTTPS' in scored_services else None
        scored_services.remove('RDP') if 'RDP' in scored_services else None
        scored_services.remove('SMB') if 'SMB' in scored_services else None
        scored_services.remove('SSH') if 'SSH' in scored_services else None
        scored_services.remove('FTP') if 'FTP' in scored_services else None
        scored_services.remove('Telnet') if 'Telnet' in scored_services else None
        scored_services.add('HTTP') if 'CA' in HOST_INFO[host]['Services'] else None
        scored_services.add('HTTPS') if 'ADFS' in HOST_INFO[host]['Services'] else None
        scored_services.remove('ADFS') if 'ADFS' in scored_services else None
        scored_services.remove('CA') if 'CA' in scored_services else None    
        
        scored_services = "io, ".join(scored_services)
        if scored_services != "":
            scored_services += "io"
        else:
            scored_services = "None"
        scored_services = scored_services.lower()

        is_win_server = 'Windows Server' in HOST_INFO[host]['OS_Version']
        is_server_core = "Server Core" in HOST_INFO[host]['OS_Version']

        
        if 'SMB' in HOST_INFO[host]['Services'] and 'LDAP' in HOST_INFO[host]['Services']:
            server_type = "dc"
        elif 'CA' in HOST_INFO[host]['Services']:
            server_type = "ca"

        if HOST_INFO[host]['OS'] == 'Windows':
            ansible_header_content += f"""win_{host.replace('.', '_').replace(':', '_')}:
          vars:
            ansible_user: "{HOST_INFO[host]['Username'] if HOST_INFO[host]['Username'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Username'] is None else ''}"
            ansible_password: "{HOST_INFO[host]['Password'] if HOST_INFO[host]['Password'] is not None else ''}{' #REPLACE' if HOST_INFO[host]['Password'] is None else ''}"
            scored_services: "{scored_services}"
            is_win_server: "{str(is_win_server).lower()}"
            is_server_core: "{str(is_server_core).lower()}"
            server_type: "{server_type}"
          hosts:
            {host}:
        """
    with open(ANSIBLE_INVENTORY_FILE, 'w') as inventory_file:
        inventory_file.write(ansible_header_content)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Windows Reconnaissance Script to Fill Out Ansible Inventory')
    parser.add_argument('-s4', required=True, help='Subnet(s) to scan for Windows hosts (e.g., 192.168.1.0/24)')
    parser.add_argument('-s6', required=False, help='IPv6 Subnet(s) to scan for Windows hosts (e.g., 2001:0db8::/32)')
    parser.add_argument('-c', required=True, help='Windows Domain Credentials in the format username:password,username:password')
    parser.add_argument('-lc', required=False, help='Linux Credentials in the format username:password,username:password')
    parser.add_argument('-sp', required=True, help='Scripts Path')
    args = parser.parse_args()

    # Clear Terminal
    os.system('clear')

    print("\n=======================================GENERAL SETUP=======================================\n\n")

    # Make sure IP file exists
    if not os.path.exists(IP_FILE):
        os.makedirs(os.path.dirname(IP_FILE), exist_ok=True)
        print(f"IP file created: {IP_FILE}")
    else:
        print(f"IP file found: {IP_FILE}")
    with open(IP_FILE, 'w') as ip_file:
        ip_file.write('[INI HEADER]' + '\n')

    # Make sure Topology CSV file exists
    if not os.path.exists(TOPOLOGY_FILE):
        os.makedirs(os.path.dirname(TOPOLOGY_FILE), exist_ok=True)
        print(f"Topology file created: {TOPOLOGY_FILE}")
    else:
        print(f"Topology file found: {TOPOLOGY_FILE}")
    with open(TOPOLOGY_FILE, 'w') as topology_file:
        topology_file.write('subnet,ip,hostname,os,services' + '\n')
    
    # Set global variables
    global DOMAIN_CREDENTIALS
    global LINUX_CREDENTIALS
    global PASSWORD_MANAGER_IP
    global GRAFANA_IP
    global SCRIPTS_PATH

    # Gathers Command Line Arguments
    SCRIPTS_PATH = args.sp
    subnet = args.s4
    ipv6_subnet = args.s6 if args.s6 is not None else None

    PASSWORD_MANAGER_IP = None
    GRAFANA_IP = None

    global HOST_INFO
    HOST_INFO = {}

    get_local_ip()

    print("\n\n======================================SUBNET SCANNING======================================\n\n")
    print(f"Scanning subnet: {subnet}")
    if ipv6_subnet is not None:
        print(f"Scanning IPv6 subnet: {ipv6_subnet}\n")

    # Gathers and Formats Credentials
    DOMAIN_CREDENTIALS = args.c.split(',')
    formatting_domain_creds = []
    for i in range(len(DOMAIN_CREDENTIALS)):
        DOMAIN_CREDENTIALS[i] = DOMAIN_CREDENTIALS[i].split(':')
        if len(DOMAIN_CREDENTIALS[i]) == 2:
            formatting_domain_creds.append(f"{DOMAIN_CREDENTIALS[i][0]}:{DOMAIN_CREDENTIALS[i][1]}")
    if formatting_domain_creds:
        cred_str = " | ".join(formatting_domain_creds)
        print(f"Using Windows Credentials | {cred_str}")

    LINUX_CREDENTIALS = args.lc.split(',') if args.lc is not None else None
    if LINUX_CREDENTIALS is not None:
        formatted_linux_creds = []
        for i in range(len(LINUX_CREDENTIALS)):
            LINUX_CREDENTIALS[i] = LINUX_CREDENTIALS[i].split(':')
            if len(LINUX_CREDENTIALS[i]) == 2:
                formatted_linux_creds.append(f"{LINUX_CREDENTIALS[i][0]}:{LINUX_CREDENTIALS[i][1]}")
        if formatted_linux_creds:
            cred_str = " | ".join(formatted_linux_creds)
            print(f"Using Linux Credentials | {cred_str}\n")

    original_ipv4_scan = scan_all_hosts(subnet)
    if ipv6_subnet is not None:
        original_ipv6_scan = scan_all_hosts(ipv6_subnet)
    print("\n============================DETECTING OS AND POTENTIAL SERVICES============================\n\n")
    gather_info(original_ipv4_scan, subnet)
    if ipv6_subnet is not None:
        gather_info(original_ipv6_scan, ipv6_subnet)
    print("\n==========================ADDING INFORMATION TO ANSIBLE INVENTORY==========================\n\n")
    add_to_ansible_inventory()
    print("\n==================================RECONNAISSANCE COMPLETE==================================\n\n")

if __name__ == "__main__":
    main()