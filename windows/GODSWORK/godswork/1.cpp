#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <ctime>
#include <sstream>
#include <thread>
#include <mutex>
#include <map>
#pragma comment(lib, "Psapi.lib")

// Optional SIEM endpoints (set to non-empty to enable rules)
static std::string GRAFANA_IP = "";
static std::string WAZUH_IP = "";
static std::string GRAYLOG_IP = "";

static std::string processNames[] = {
    "rpc.exe",
    "netlogon.exe",
    "msedge.exe",
    "chrome.exe",
    "git.exe",
    "firefox.exe",
    "winrm.exe",
    "dns.exe",
    "lsass.exe",
    "store.exe",
    "sshd.exe",
    "ftpsvc.exe",
    "smb.exe",
    "nginx.exe",
    "w3wp.exe",
    "httpd.exe",
    "krb5kdc.exe",
    "sqlservr.exe",
    "ccsclient.exe",
    "mstsc.exe",
    "rdpclip.exe",
    "vncserver.exe",
    "winvnc.exe",
    "dhcp.exe",
    "openvpn.exe",
    "vmms.exe",
    "smtpsvc.exe",
    "imap4.exe",
    "pop3svc.exe",
    "pandora.exe",
    "syslog.exe",
    "nfs.exe",
    "snmp.exe"
};

static std::string processServices[] = {
    "rpc,epmap",
    "kerberos,ldap,ldaps,ldapgc,ldapgcs,smb,rpc,epmap,w32time,dns",
    "http,https",
    "http,https",
    "ssh,https",
    "http,https",
    "winrm",
    "dns",
    "kerberos,ldap,ldaps,ldapgc,ldapgcs,smb,rpc,epmap",
    "https",
    "ssh,sftp",
    "ftp",
    "smb",
    "http,https",
    "http,https",
    "http,https",
    "kerberos",
    "mssql",
    "all",
    "rdp",
    "rdp",
    "vnc",
    "vnc",
    "dhcp",
    "openvpn",
    "hyperv",
    "smtp,smtps",
    "imap,imaps",
    "pop3,pop3s",
    "pandora",
    "syslog",
    "nfs",
    "snmp"
};

struct ServiceDef {
    std::string name;
    std::string protocol;
    std::string ports;
};

static ServiceDef serviceDefs[] = {
    {"icmp", "none", "none"},
    {"http", "tcp", "80"},
    {"https", "tcp", "443"},
    {"rdp", "both", "3389"},
    {"winrm", "tcp", "5985,5986"},
    {"ssh", "tcp", "22"},
    {"vnc", "both", "5900"},
    {"ldap", "both", "389"},
    {"ldaps", "tcp", "636"},
    {"ldapgc", "tcp", "3268"},
    {"ldapgcs", "tcp", "3269"},
    {"smb", "tcp", "445"},
    {"dhcp", "udp", "67,68"},
    {"ftp", "tcp", "20,21"},
    {"sftp", "tcp", "22"},
    {"openvpn", "udp", "1194"},
    {"hyperv", "tcp", "2179"},
    {"smtp", "tcp", "25"},
    {"smtps", "tcp", "465,587"},
    {"imap", "tcp", "143"},
    {"imaps", "tcp", "993"},
    {"pop3", "tcp", "110"},
    {"pop3s", "tcp", "995"},
    {"pandora", "tcp", "41121"},
    {"syslog", "udp", "514"},
    {"kerberos", "both", "88"},
    {"rpc", "tcp", "49152-65535"},
    {"epmap", "tcp", "135"},
    {"w32time", "udp", "123"},
    {"dns", "udp", "53"},
    {"ntp", "udp", "123"},
    {"nfs", "both", "2049"},
    {"snmp", "udp", "161,162"},
    {"mssql", "tcp", "1433"}
};

class Logger {
private:
    std::ofstream logFile;
    std::string getTimestamp() {
        std::time_t now = std::time(nullptr);
        std::tm localTime;
        localtime_s(&localTime, &now);
        char buffer[20];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &localTime);
        return std::string(buffer);
    }
public:
    Logger(const std::string& filename) {
        logFile.open(filename, std::ios::app);
        if (logFile.is_open()) {
            log("[INFO] Logging started.");
        }
    }
    ~Logger() {
        if (logFile.is_open()) {
            log("[INFO] Logging ended.");
            logFile.close();
        }
    }
    void log(const std::string& message) {
        if (logFile.is_open()) {
            logFile << "[" << getTimestamp() << "] " << message << std::endl;
        }
    }
};

bool executeNetshCommandThreadSafe(const std::string& command, Logger& logger, std::mutex& logMutex) {
    {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[INFO] Executing command: " + command);
    }
    int result = system(command.c_str());
    {
        std::lock_guard<std::mutex> lock(logMutex);
        if (result != 0) {
            logger.log("[ERROR] Command failed with code: " + std::to_string(result));
            return false;
        }
        else {
            logger.log("[INFO] Command executed successfully.");
        }
    }
    return true;
}

struct ProcessInfo {
    std::string name;
    DWORD pid;
    std::string executablePath;
};

std::string getExecutablePath(DWORD processID, Logger& logger, std::mutex& logMutex) {
    std::string exePath;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess != NULL) {
        char buffer[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, NULL, buffer, MAX_PATH)) {
            exePath = std::string(buffer);
        }
        else {
            std::lock_guard<std::mutex> lock(logMutex);
            logger.log("[ERROR] Failed to get executable path for PID: " + std::to_string(processID));
        }
        CloseHandle(hProcess);
    }
    else {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[ERROR] Failed to open process for PID: " + std::to_string(processID));
    }
    return exePath;
}

std::vector<ProcessInfo> getRunningProcesses(Logger& logger, std::mutex& logMutex) {
    std::vector<ProcessInfo> runningProcesses;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        logger.log("[ERROR] Failed to create process snapshot.");
        return runningProcesses;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &pe)) {
        do {
            ProcessInfo pInfo;
            pInfo.name = std::string(pe.szExeFile);
            pInfo.pid = pe.th32ProcessID;
            std::transform(pInfo.name.begin(), pInfo.name.end(), pInfo.name.begin(), ::tolower);
            pInfo.executablePath = getExecutablePath(pe.th32ProcessID, logger, logMutex);
            runningProcesses.push_back(pInfo);
        } while (Process32Next(snapshot, &pe));
    }
    else {
        logger.log("[ERROR] Process32First failed.");
    }
    CloseHandle(snapshot);
    {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[INFO] Process enumeration completed. Total processes found: " +
            std::to_string(runningProcesses.size()));
    }
    return runningProcesses;
}

std::vector<std::string> splitString(const std::string& input, char delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = 0;
    while ((end = input.find(delimiter, start)) != std::string::npos) {
        std::string token = input.substr(start, end - start);
        if (!token.empty()) {
            tokens.push_back(token);
        }
        start = end + 1;
    }
    std::string token = input.substr(start);
    if (!token.empty()) {
        tokens.push_back(token);
    }
    return tokens;
}

int main(int argc, char* argv[]) {
    Logger logger("firewallfucker.log");
    std::mutex logMutex;
    {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[INFO] Program started.");
    }
    executeNetshCommandThreadSafe("netsh advfirewall firewall delete rule name=all", logger, logMutex);
    executeNetshCommandThreadSafe("netsh advfirewall firewall add rule name=\"Allow_PSEXEC_SMB_IN\" dir=in action=allow protocol=TCP localport=445 remoteip=any", logger, logMutex);
    executeNetshCommandThreadSafe("netsh advfirewall firewall add rule name=\"Allow_RDP_IN\" dir=in action=allow protocol=TCP localport=3389 remoteip=any", logger, logMutex);
    std::string subnet = "any";
    if (argc > 1) {
        subnet = argv[1];
        {
            std::lock_guard<std::mutex> lock(logMutex);
            logger.log("[INFO] Subnet specified: " + subnet);
        }
    }
    else {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[INFO] No subnet argument provided; using 'any'.");
    }
    std::vector<ProcessInfo> runningProcesses = getRunningProcesses(logger, logMutex);
    std::set<std::string> servicesToAllow;
    bool allowAllCCSClient = false;
    std::string ccsClientPath;
    {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[INFO] Matching running processes against whitelist.");
    }
    for (size_t i = 0; i < sizeof(processNames) / sizeof(processNames[0]); ++i) {
        std::string whitelistProc = processNames[i];
        std::transform(whitelistProc.begin(), whitelistProc.end(), whitelistProc.begin(), ::tolower);
        for (const auto& proc : runningProcesses) {
            if (proc.name == whitelistProc) {
                {
                    std::lock_guard<std::mutex> lock(logMutex);
                    logger.log("[INFO] Whitelisted process running: " + proc.name +
                        " (PID: " + std::to_string(proc.pid) + ") " +
                        " Path: " + proc.executablePath);
                }
                std::vector<std::string> foundServices = splitString(processServices[i], ',');
                for (auto& svc : foundServices) {
                    svc.erase(std::remove_if(svc.begin(), svc.end(), ::isspace), svc.end());
                    if (svc == "all") {
                        if (whitelistProc == "ccsclient.exe") {
                            allowAllCCSClient = true;
                            ccsClientPath = proc.executablePath;
                            {
                                std::lock_guard<std::mutex> lock(logMutex);
                                logger.log("[INFO] CCSClient.exe detected. All inbound ports allowed. "
                                    "Executable Path: " + ccsClientPath);
                            }
                        }
                    }
                    else if (!svc.empty()) {
                        servicesToAllow.insert(svc);
                        {
                            std::lock_guard<std::mutex> lock(logMutex);
                            logger.log("[INFO] Service added to allow list: " + svc);
                        }
                    }
                }
            }
        }
    }
    std::map<std::string, std::string> processPathMap;
    for (const auto& proc : runningProcesses) {
        processPathMap[proc.name] = proc.executablePath;
    }
    std::map<std::string, ServiceDef> serviceMap;
    for (const auto& svc : serviceDefs) {
        serviceMap[svc.name] = svc;
    }

    for (const auto& serviceName : servicesToAllow) {
        auto it = serviceMap.find(serviceName);
        if (it == serviceMap.end()) {
            std::lock_guard<std::mutex> lock(logMutex);
            logger.log("[WARNING] No service definition found for: " + serviceName);
            continue;
        }
        const ServiceDef& svc = it->second;
        if (svc.protocol == "none") {
            executeNetshCommandThreadSafe("netsh adv f a r n=ICMP-IN dir=in act=allow prof=any remoteip=" + subnet + " prot=icmpv4:8,any", logger, logMutex);
            executeNetshCommandThreadSafe("netsh adv f a r n=ICMP-OUT dir=out act=allow prof=any remoteip=" + subnet + " prot=icmpv4:8,any", logger, logMutex);
            continue;
        }

        auto addTcpRules = [&]() {
            std::ostringstream inCmd;
            inCmd << "netsh advfirewall firewall add rule name=\"Allow_" << svc.name << "_TCP_IN\" dir=in action=allow protocol=TCP localport=" << svc.ports << " remoteip=" << subnet;
            executeNetshCommandThreadSafe(inCmd.str(), logger, logMutex);

            std::ostringstream outCmd;
            outCmd << "netsh advfirewall firewall add rule name=\"Allow_" << svc.name << "_TCP_OUT\" dir=out action=allow protocol=TCP remoteport=" << svc.ports << " remoteip=" << subnet;
            executeNetshCommandThreadSafe(outCmd.str(), logger, logMutex);
        };

        auto addUdpRules = [&]() {
            std::ostringstream inCmd;
            inCmd << "netsh advfirewall firewall add rule name=\"Allow_" << svc.name << "_UDP_IN\" dir=in action=allow protocol=UDP localport=" << svc.ports << " remoteip=" << subnet;
            executeNetshCommandThreadSafe(inCmd.str(), logger, logMutex);

            std::ostringstream outCmd;
            outCmd << "netsh advfirewall firewall add rule name=\"Allow_" << svc.name << "_UDP_OUT\" dir=out action=allow protocol=UDP remoteport=" << svc.ports << " remoteip=" << subnet;
            executeNetshCommandThreadSafe(outCmd.str(), logger, logMutex);
        };

        if (svc.protocol == "tcp") {
            addTcpRules();
        } else if (svc.protocol == "udp") {
            addUdpRules();
        } else if (svc.protocol == "both") {
            addTcpRules();
            addUdpRules();
        }
    }
    if (allowAllCCSClient && !ccsClientPath.empty()) {
        std::string escapedPath;
        escapedPath.reserve(ccsClientPath.size() * 2);
        for (char c : ccsClientPath) {
            if (c == '\\') {
                escapedPath += "\\\\";
            }
            else {
                escapedPath += c;
            }
        }
        {
            std::ostringstream oss;
            oss << "netsh advfirewall firewall add rule name=\"Allow_CCSClient_Inbound\""
                << " dir=in action=allow program=\"" << escapedPath << "\""
                << " remoteip=" << subnet << " enable=yes";
            executeNetshCommandThreadSafe(oss.str(), logger, logMutex);
        }
        {
            std::ostringstream oss;
            oss << "netsh advfirewall firewall add rule name=\"Allow_CCSClient_Outbound\""
                << " dir=out action=allow program=\"" << escapedPath << "\" enable=yes";
            executeNetshCommandThreadSafe(oss.str(), logger, logMutex);
        }
    }
    else if (allowAllCCSClient && ccsClientPath.empty()) {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[ERROR] CCSClient.exe was detected but no valid executable path was found.");
    }

    // SIEM outbound rules (if IPs provided)
    if (!GRAFANA_IP.empty()) {
        executeNetshCommandThreadSafe("netsh adv f a r n=Grafana-Client dir=out act=allow prof=any prot=tcp remoteip=" + GRAFANA_IP + " remoteport=3100", logger, logMutex);
        executeNetshCommandThreadSafe("netsh adv f a r n=Grafana-HTTP-Dashboard dir=out act=allow prof=any prot=tcp remoteip=" + GRAFANA_IP + " remoteport=3000", logger, logMutex);
    }
    if (!GRAYLOG_IP.empty()) {
        executeNetshCommandThreadSafe("netsh adv f a r n=Graylog-Client dir=out act=allow prof=any prot=tcp remoteip=" + GRAYLOG_IP + " remoteport=1468,5044,12201", logger, logMutex);
        executeNetshCommandThreadSafe("netsh adv f a r n=Graylog-HTTP-Dashboard dir=out act=allow prof=any prot=tcp remoteip=" + GRAYLOG_IP + " remoteport=443,9000", logger, logMutex);
    }
    if (!WAZUH_IP.empty()) {
        executeNetshCommandThreadSafe("netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteip=" + WAZUH_IP + " remoteport=1514", logger, logMutex);
        executeNetshCommandThreadSafe("netsh adv f a r n=Wazuh-HTTP-Dashboard dir=out act=allow prof=any prot=tcp remoteip=" + WAZUH_IP + " remoteport=80,443", logger, logMutex);
        executeNetshCommandThreadSafe("netsh adv f a r n=Wazuh-Agent-Enrollment dir=out act=allow prof=any prot=tcp remoteip=" + WAZUH_IP + " remoteport=1515", logger, logMutex);
    }
    {
        std::string wmiEnableCmd =
            "netsh advfirewall firewall set rule group=\"windows management instrumentation (wmi)\" new enable=yes";
        executeNetshCommandThreadSafe(wmiEnableCmd, logger, logMutex);
    }
    {
        std::string blockInboundCmd =
            "netsh advfirewall set allprofile firewallpolicy blockinbound,allowoutbound";
        executeNetshCommandThreadSafe(blockInboundCmd, logger, logMutex);
    }
    {
        std::lock_guard<std::mutex> lock(logMutex);
        logger.log("[INFO] Firewall rules configuration completed. Inbound is now default-block.");
    }
    return 0;
}
