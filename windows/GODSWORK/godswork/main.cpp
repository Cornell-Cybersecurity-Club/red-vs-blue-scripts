#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <lm.h>
#include <iostream>
#include <comdef.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <string>
#include <vector>
#include <iads.h>
#include <adshlp.h>
#include <adsiid.h>
#include <initguid.h>
#include <Winnetwk.h>
#include <thread>
#include <future>
#include <sstream>
#include <AclAPI.h>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <fstream>
#include <bcrypt.h>
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <mutex>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "ActiveDS.lib")
#pragma comment(lib, "ADSIid.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

// Forward declarations (needed for helpers declared early in this file)
static std::string WStringToString(const std::wstring& w);

static std::ofstream g_passFile;
static std::mutex g_passFileMutex;

static bool AppendPasswordChangeLine(const std::wstring& machine, const std::wstring& username, const std::wstring& newPassword)
{
    std::lock_guard<std::mutex> lock(g_passFileMutex);
    if (!g_passFile.is_open()) {
        return false;
    }
    // Store as UTF-8 to keep file readable.
    g_passFile << WStringToString(machine) << "\t" << WStringToString(username) << "\t" << WStringToString(newPassword) << "\n";
    g_passFile.flush();
    return true;
}

static bool BCryptRandomBytes(unsigned char* buf, size_t len)
{
    if (!buf || len == 0) return false;
    NTSTATUS status = BCryptGenRandom(nullptr, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0);
}

static std::wstring GenerateStrongPassword(size_t length)
{
    // Keep this command-line/PsExec friendly: avoid quotes, spaces, and shell metacharacters.
    static const std::wstring kUpper = L"ABCDEFGHJKLMNPQRSTUVWXYZ";
    static const std::wstring kLower = L"abcdefghijkmnopqrstuvwxyz";
    static const std::wstring kDigits = L"23456789";
    static const std::wstring kSpecial = L"@#$*-_+=?";
    static const std::wstring kAll = kUpper + kLower + kDigits + kSpecial;

    if (length < 12) length = 12;

    std::vector<wchar_t> chars;
    chars.reserve(length);

    auto pick = [](const std::wstring& alphabet) -> wchar_t {
        unsigned char b = 0;
        if (!BCryptRandomBytes(&b, 1)) {
            // Fallback (very unlikely): deterministic, but avoids crashing.
            return alphabet[0];
        }
        return alphabet[b % alphabet.size()];
    };

    // Ensure complexity.
    chars.push_back(pick(kUpper));
    chars.push_back(pick(kLower));
    chars.push_back(pick(kDigits));
    chars.push_back(pick(kSpecial));

    while (chars.size() < length) {
        chars.push_back(pick(kAll));
    }

    // Shuffle.
    for (size_t i = chars.size() - 1; i > 0; --i) {
        unsigned char b = 0;
        if (!BCryptRandomBytes(&b, 1)) {
            break;
        }
        size_t j = b % (i + 1);
        std::swap(chars[i], chars[j]);
    }

    return std::wstring(chars.begin(), chars.end());
}

// --------------------
// Helper functions for string conversion
// --------------------
static std::wstring StringToWString(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &wstr[0], sizeNeeded);
    return wstr;
}

static std::string WStringToString(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &str[0], sizeNeeded, NULL, NULL);
    return str;
}

// --------------------
// Helper functions for IPv4 manipulation
// --------------------
static uint32_t IPv4ToUint32(const std::string& ip) {
    uint32_t a, b, c, d;
    if (sscanf_s(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        throw std::runtime_error("Invalid IP address format: " + ip);
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static std::string Uint32ToIPv4(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
        std::to_string((ip >> 16) & 0xFF) + "." +
        std::to_string((ip >> 8) & 0xFF) + "." +
        std::to_string(ip & 0xFF);
}

// --------------------
// Given a subnet in CIDR notation (e.g. L"192.168.1.0/24"), generate a vector
// of IP addresses (as wstrings) to attempt authentication against.
// --------------------
static std::vector<std::wstring> GetMachinesFromSubnet(const std::wstring& subnet) {
    std::vector<std::wstring> machines;
    std::string subnetStr = WStringToString(subnet);
    size_t pos = subnetStr.find('/');
    std::string ipPart;
    int maskBits;
    if (pos != std::string::npos) {
        ipPart = subnetStr.substr(0, pos);
        maskBits = std::stoi(subnetStr.substr(pos + 1));
    }
    else {
        ipPart = subnetStr;
        maskBits = 32;
    }
    uint32_t baseIP = IPv4ToUint32(ipPart);
    if (maskBits < 0 || maskBits > 32) {
        throw std::runtime_error("Invalid mask bits in subnet: " + subnetStr);
    }
    uint32_t netmask = (maskBits == 0) ? 0 : (0xFFFFFFFF << (32 - maskBits));
    uint32_t networkIP = baseIP & netmask;
    uint32_t broadcastIP = networkIP | (~netmask);
    uint32_t startIP, endIP;
    // For subnets with more than two addresses, skip the network and broadcast addresses.
    if (broadcastIP - networkIP > 1) {
        startIP = networkIP + 1;
        endIP = broadcastIP - 1;
    }
    else {
        startIP = networkIP;
        endIP = broadcastIP;
    }
    for (uint32_t ip = startIP; ip <= endIP; ip++) {
        std::string ipStr = Uint32ToIPv4(ip);
        machines.push_back(StringToWString(ipStr));
    }
    return machines;
}

bool PingHost(const std::wstring& machine, DWORD timeoutMs = 1000) {
    std::string ipStr = WStringToString(machine);
    IN_ADDR addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1)
        return false;

    HANDLE hIcmp = ::IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
        return false;

    char sendData[] = "data";
    const int sendSize = sizeof(sendData);
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sendSize;
    std::vector<char> replyBuffer(replySize);
    DWORD ret = ::IcmpSendEcho(hIcmp, addr.s_addr, sendData, sendSize, NULL,
        replyBuffer.data(), replySize, timeoutMs);

    ::IcmpCloseHandle(hIcmp);
    return (ret != 0);
}

LONG SetRemoteRegistryDword(
    const std::wstring& machine,
    const std::wstring& regKeyPath,
    const std::wstring& valueName,
    DWORD valueData
)
{
    std::wstring machinePath = L"\\\\" + machine;
    HKEY hRemoteRoot = NULL;
    LONG lRet = RegConnectRegistryW(machinePath.c_str(), HKEY_LOCAL_MACHINE, &hRemoteRoot);
    if (lRet != ERROR_SUCCESS) {
        return lRet;
    }
    HKEY hSubKey = NULL;
    lRet = RegCreateKeyExW(
        hRemoteRoot,
        regKeyPath.c_str(),
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        NULL,
        &hSubKey,
        NULL
    );
    if (lRet == ERROR_SUCCESS) {
        lRet = RegSetValueExW(
            hSubKey,
            valueName.c_str(),
            0,
            REG_DWORD,
            (BYTE*)&valueData,
            sizeof(valueData)
        );
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hRemoteRoot);
    return lRet;
}

bool LaunchLocalProcess(const std::wstring& commandLine, bool waitForCompletion = true)
{
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdBuf(commandLine.begin(), commandLine.end());
    cmdBuf.push_back(L'\0');

    BOOL result = CreateProcessW(
        NULL,
        cmdBuf.data(),
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );
    if (!result) {
        std::wcerr << L"[ERROR] CreateProcess failed for: "
            << commandLine << L" (GLE=" << GetLastError() << L")\n";
        return false;
    }

    if (waitForCompletion)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            std::wcout << L"[INFO] Process exited with code: " << exitCode << std::endl;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return (exitCode == 0);
    }
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
}

bool AddDefenderExclusionForCurrentFolder()
{
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
        std::wcerr << L"[ERROR] GetModuleFileNameW failed. (GLE=" << GetLastError() << L")\n";
        return false;
    }
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\/");
    std::wstring folderPath = (pos != std::wstring::npos) ? fullPath.substr(0, pos) : fullPath;
    std::wstring cmd = L"powershell.exe -Command \"Add-MpPreference -ExclusionPath '";
    cmd += folderPath;
    cmd += L"'\"";
    std::wcout << L"[INFO] Adding Windows Defender exclusion for folder: " << folderPath << std::endl;
    return LaunchLocalProcess(cmd);
}

LONG SetLocalRegistryDword(const std::wstring& keyPath, const std::wstring& valueName, DWORD data) {
    HKEY hKey = NULL;
    LONG ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        keyPath.c_str(),
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        NULL,
        &hKey,
        NULL);
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] RegCreateKeyExW failed for key: " << keyPath << L" (error " << ret << L")\n";
        return ret;
    }
    ret = RegSetValueExW(hKey,
        valueName.c_str(),
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&data),
        sizeof(DWORD));
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] RegSetValueExW failed for " << keyPath << L"\\" << valueName << L" (error " << ret << L")\n";
    }
    RegCloseKey(hKey);
    return ret;
}

LONG DeleteLocalRegistryValue(const std::wstring& keyPath, const std::wstring& valueName) {
    HKEY hKey = NULL;
    LONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        keyPath.c_str(),
        0,
        KEY_SET_VALUE,
        &hKey);
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] RegOpenKeyExW failed for key: " << keyPath << L" (error " << ret << L")\n";
        return ret;
    }
    ret = RegDeleteValueW(hKey, valueName.c_str());
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] RegDeleteValueW failed for " << keyPath << L"\\" << valueName << L" (error " << ret << L")\n";
    }
    RegCloseKey(hKey);
    return ret;
}

struct RegEntry {
    std::wstring keyPath;
    std::wstring valueName;
    DWORD        data;
    bool         isDelete;
};

void ApplyLocalRegistrySettings()
{
    std::wcout << L"[INFO] Applying local registry hardening settings...\n";
    std::vector<RegEntry> entries = {
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"NoLmHash", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel", 5, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential", 0, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"LocalAccountTokenFilterPolicy", 0, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe", L"AuditLevel", 8, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SpyNetReporting", 2, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SubmitSamplesConsent", 3, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"DisableBlockAtFirstSeen", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpCloudBlockLevel", 6, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableBehaviorMonitoring", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableIOAVProtection", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"ServiceKeepAlive", 1, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"CheckForSignaturesBeforeRunningScan", 1, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableHeuristics", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableArchiveScanning", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection", L"ForceDefenderPassiveMode", 0, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-TCP", L"UserAuthentication", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"AllowTSConnections", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", 0, false},
        {L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"FullSecureChannelProtection", 1, false},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers", L"RegisterSpoolerRemoteRpcEndPoint", 2, false},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", L"NoWarningNoElevationOnInstall", 0, true},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", L"UpdatePromptSettings", 0, true},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", L"RestrictDriverInstallationToAdministrators", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Services\\LDAP", L"LDAPClientIntegrity", 2, false},
        {L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", L"LDAPServerIntegrity", 2, false},
        {L"Software\\Policies\\Microsoft\\Windows\\BITS", L"EnableBITSMaxBandwidth", 0, false},
        {L"Software\\Policies\\Microsoft\\Windows\\BITS", L"MaxDownloadTime", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorAdmin", 2, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorUser", 0, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"PromptOnSecureDesktop", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableInstallerDetection", 1, false},
    };
    for (const auto& entry : entries) {
        LONG ret = 0;
        if (entry.isDelete) {
            ret = DeleteLocalRegistryValue(entry.keyPath, entry.valueName);
            if (ret == ERROR_SUCCESS) {
                std::wcout << L"[OK] Deleted " << entry.keyPath << L"\\" << entry.valueName << std::endl;
            }
        }
        else {
            ret = SetLocalRegistryDword(entry.keyPath, entry.valueName, entry.data);
            if (ret == ERROR_SUCCESS) {
                std::wcout << L"[OK] Set " << entry.keyPath << L"\\" << entry.valueName << L" to " << entry.data << std::endl;
            }
        }
    }
    std::wcout << L"[INFO] Local registry hardening complete.\n";
}

LONG DeleteRemoteRegistryValue(const std::wstring& machine, const std::wstring& keyPath, const std::wstring& valueName) {
    std::wstring machinePath = L"\\\\" + machine;
    HKEY hRemoteRoot = nullptr;
    LONG lRet = RegConnectRegistryW(machinePath.c_str(), HKEY_LOCAL_MACHINE, &hRemoteRoot);
    if (lRet != ERROR_SUCCESS) {
        return lRet;
    }
    HKEY hSubKey = nullptr;
    lRet = RegOpenKeyExW(hRemoteRoot, keyPath.c_str(), 0, KEY_SET_VALUE, &hSubKey);
    if (lRet == ERROR_SUCCESS && hSubKey) {
        lRet = RegDeleteValueW(hSubKey, valueName.c_str());
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hRemoteRoot);
    return lRet;
}

struct RemoteRegEntry {
    std::wstring keyPath;
    std::wstring valueName;
    DWORD        data;
    bool         isDelete;
};

std::wstring ApplyRemoteRegistryHardeningSettings(const std::wstring& machine)
{
    std::wstringstream ss;
    ss << L"[INFO] Applying remote registry hardening settings on " << machine << L"\n";
    std::vector<RemoteRegEntry> entries = {
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"NoLmHash", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel", 5, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential", 0, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe", L"AuditLevel", 8, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SpyNetReporting", 2, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SubmitSamplesConsent", 3, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"DisableBlockAtFirstSeen", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpCloudBlockLevel", 6, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableBehaviorMonitoring", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableIOAVProtection", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"ServiceKeepAlive", 1, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"CheckForSignaturesBeforeRunningScan", 1, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableHeuristics", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableArchiveScanning", 0, false},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection", L"ForceDefenderPassiveMode", 0, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-TCP", L"UserAuthentication", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"AllowTSConnections", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", 0, false},
        {L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"FullSecureChannelProtection", 1, false},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers", L"RegisterSpoolerRemoteRpcEndPoint", 2, false},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", L"NoWarningNoElevationOnInstall", 0, true},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", L"UpdatePromptSettings", 0, true},
        {L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", L"RestrictDriverInstallationToAdministrators", 1, false},
        {L"SYSTEM\\CurrentControlSet\\Services\\LDAP", L"LDAPClientIntegrity", 2, false},
        {L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", L"LDAPServerIntegrity", 2, false},
        {L"Software\\Policies\\Microsoft\\Windows\\BITS", L"EnableBITSMaxBandwidth", 0, false},
        {L"Software\\Policies\\Microsoft\\Windows\\BITS", L"MaxDownloadTime", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorAdmin", 2, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorUser", 0, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"PromptOnSecureDesktop", 1, false},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableInstallerDetection", 1, false},
    };
    for (const auto& entry : entries) {
        LONG ret = 0;
        if (entry.isDelete) {
            ret = DeleteRemoteRegistryValue(machine, entry.keyPath, entry.valueName);
            if (ret == ERROR_SUCCESS) {
                ss << L"    [OK] Deleted " << entry.keyPath << L"\\" << entry.valueName << L"\n";
            }
            else {
                ss << L"    [ERROR] Deleting " << entry.keyPath << L"\\" << entry.valueName << L" (code " << ret << L")\n";
            }
        }
        else {
            ret = SetRemoteRegistryDword(machine, entry.keyPath, entry.valueName, entry.data);
            if (ret == ERROR_SUCCESS) {
                ss << L"    [OK] Set " << entry.keyPath << L"\\" << entry.valueName << L" to " << entry.data << L"\n";
            }
            else {
                ss << L"    [ERROR] Setting " << entry.keyPath << L"\\" << entry.valueName << L" (code " << ret << L")\n";
            }
        }
    }
    ss << L"[INFO] Remote registry hardening settings complete on " << machine << L"\n";
    return ss.str();
}


static bool HmacSha256_BCrypt(
    const unsigned char* key,
    size_t keyLen,
    const unsigned char* data,
    size_t dataLen,
    std::vector<unsigned char>& digestOut
)
{
    digestOut.clear();
    digestOut.resize(32);
    BCRYPT_ALG_HANDLE  hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    PBYTE pbHashObj = nullptr;
    DWORD cbHashObj = 0;
    NTSTATUS status = 0;
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    if (status != 0) goto cleanup;
    {
        DWORD cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObj, sizeof(DWORD), &cbData, 0);
        if (status != 0) goto cleanup;
    }
    pbHashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObj);
    if (!pbHashObj) {
        status = STATUS_NO_MEMORY;
        goto cleanup;
    }
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObj,
        cbHashObj,
        (PUCHAR)key,
        (ULONG)keyLen,
        0
    );
    if (status != 0) goto cleanup;
    status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0);
    if (status != 0) goto cleanup;
    status = BCryptFinishHash(hHash, digestOut.data(), (ULONG)digestOut.size(), 0);
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbHashObj) HeapFree(GetProcessHeap(), 0, pbHashObj);
    return (status == 0);
}

static bool AesCbcEncrypt_BCrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& plaintext,
    std::vector<unsigned char>& ciphertext
)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    PBYTE pbKeyObj = nullptr;
    DWORD cbKeyObj = 0;
    DWORD cbData = 0;
    DWORD cbCipherText = (DWORD)plaintext.size();
    NTSTATUS status = 0;
    ciphertext.clear();
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) goto cleanup;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != 0) goto cleanup;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0);
    if (status != 0) goto cleanup;
    pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
    if (!pbKeyObj) {
        status = STATUS_NO_MEMORY;
        goto cleanup;
    }
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (status != 0) goto cleanup;
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
        nullptr, (PUCHAR)iv.data(), (ULONG)iv.size(),
        nullptr, 0, &cbCipherText, 0);
    if (status != 0) goto cleanup;
    ciphertext.resize(cbCipherText);
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
        nullptr, (PUCHAR)iv.data(), (ULONG)iv.size(),
        ciphertext.data(), (ULONG)ciphertext.size(), &cbData, 0);
    if (status != 0) goto cleanup;
    ciphertext.resize(cbData);
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObj) HeapFree(GetProcessHeap(), 0, pbKeyObj);
    return (status == 0);
}

static std::string ResolveDNSNameToIP(const std::wstring& machineW)
{
    std::string machine = WStringToString(machineW);
    static bool s_winsockInitialized = false;
    if (!s_winsockInitialized) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
            s_winsockInitialized = true;
        }
    }
    if (!s_winsockInitialized) {
        return machine;
    }
    addrinfo* result = nullptr;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int ret = getaddrinfo(machine.c_str(), nullptr, &hints, &result);
    if (ret != 0 || !result) {
        return machine;
    }
    SOCKADDR_IN* addr = reinterpret_cast<SOCKADDR_IN*>(result->ai_addr);
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ipStr, INET_ADDRSTRLEN);
    freeaddrinfo(result);
    return std::string(ipStr);
}

std::wstring ConvertDomainNameToDN(const std::wstring& domain)
{
    std::wstring dn;
    size_t start = 0, end;
    while ((end = domain.find(L'.', start)) != std::wstring::npos) {
        dn += L"DC=" + domain.substr(start, end - start) + L",";
        start = end + 1;
    }
    dn += L"DC=" + domain.substr(start);
    return dn;
}

bool ForceDaclReadOnly(PSECURITY_DESCRIPTOR pSD)
{
    if (!pSD) return false;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    PACL pDacl = nullptr;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
        return false;
    }
    if (!bDaclPresent || !pDacl) {
        return false;
    }
    ACL_SIZE_INFORMATION aclSizeInfo = { 0 };
    if (!GetAclInformation(pDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
        return false;
    }
    for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
        LPVOID pAce = nullptr;
        if (GetAce(pDacl, i, &pAce)) {
            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(pAce);
            if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* allowedAce = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pAce);
                allowedAce->Mask = FILE_GENERIC_READ | SYNCHRONIZE;
            }
        }
    }
    return true;
}

std::wstring HardenSMB(const std::wstring& machine)
{
    std::wstringstream ss;
    ss << L"[INFO] Hardening SMB on machine: " << machine << L"\n";
    struct RegValue {
        std::wstring keyPath;
        std::wstring valueName;
        DWORD        data;
    };
    std::vector<RegValue> regs = {
        {L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",       L"SMB1",                    0},
        {L"SYSTEM\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters", L"RequireSecuritySignature",1},
        {L"SYSTEM\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters", L"EnableSecuritySignature", 1},
        {L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",      L"RequireSecuritySignature",1},
        {L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",      L"EnableSecuritySignature", 1},
    };
    for (auto& rv : regs) {
        LONG ret = SetRemoteRegistryDword(machine, rv.keyPath, rv.valueName, rv.data);
        if (ret == ERROR_SUCCESS) {
            ss << L"    [OK] " << rv.keyPath << L"\\" << rv.valueName
                << L" set to " << rv.data << L"\n";
        }
        else {
            ss << L"    [ERROR] Failed to set " << rv.keyPath << L"\\"
                << rv.valueName << L" (code " << ret << L")\n";
        }
    }
    std::vector<std::wstring> exemptShares = {
        L"NETLOGON", L"SYSVOL", L"ADMIN$", L"C$", L"IPC$",
        L"AdminUIContentPayload", L"EasySetupPayload", L"SCCMContentLib$",
        L"SMS_CPSC$", L"SMS_DP$", L"SMS_OCM_DATACACHE", L"SMS_SITE",
        L"SMS_SUIAgent", L"SMS_WWW", L"SMSPKGC$", L"SMSSIG$"
    };
    LPBYTE pBuf = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    NET_API_STATUS nStatus;
    std::wstring serverName = L"\\\\" + machine;
    do {
        pBuf = nullptr;
        nStatus = NetShareEnum(
            (LPWSTR)serverName.c_str(),
            502,
            &pBuf,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );
        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf) {
            PSHARE_INFO_502 pShareInfo = (PSHARE_INFO_502)pBuf;
            for (DWORD i = 0; i < entriesRead; ++i) {
                std::wstring shareName = pShareInfo[i].shi502_netname ? pShareInfo[i].shi502_netname : L"";
                auto it = std::find_if(
                    exemptShares.begin(),
                    exemptShares.end(),
                    [&](const std::wstring& s) {
                        return (_wcsicmp(s.c_str(), shareName.c_str()) == 0);
                    }
                );
                bool isExempt = (it != exemptShares.end());
                if (isExempt) {
                    ss << L"    [EXEMPT] " << shareName << L" share.\n";
                }
                else {
                    ss << L"    [HARDEN] " << shareName << L" share => forcing READ ONLY.\n";
                    if (ForceDaclReadOnly(pShareInfo[i].shi502_security_descriptor)) {
                        DWORD parmErr = 0;
                        NET_API_STATUS st = NetShareSetInfo(
                            (LPWSTR)serverName.c_str(),
                            (LPWSTR)shareName.c_str(),
                            502,
                            (LPBYTE)&pShareInfo[i],
                            &parmErr
                        );
                        if (st == NERR_Success) {
                            ss << L"        [OK] " << shareName << L" ACL updated.\n";
                        }
                        else {
                            ss << L"        [ERROR] NetShareSetInfo failed for "
                                << shareName << L" (code=" << st << L").\n";
                        }
                    }
                    else {
                        ss << L"        [ERROR] Could not make "
                            << shareName << L" read-only (DACL manipulation error).\n";
                    }
                }
            }
            NetApiBufferFree(pBuf);
        }
        else if (nStatus != ERROR_MORE_DATA && nStatus != NERR_Success) {
            ss << L"[ERROR] NetShareEnum failed on " << machine
                << L" (code=" << nStatus << L").\n";
        }
    } while (nStatus == ERROR_MORE_DATA);
    ss << L"[INFO] SMB hardening complete on " << machine << L"\n\n";
    return ss.str();
}

// ====================
// Modified: ProcessMachineHarden (removed psExec call)
// ====================
std::wstring ProcessMachineHarden(const std::wstring& machine, const std::wstring& workingPassword, const std::wstring& subnet)
{
    std::wstringstream ss;
    ss << L"\n[INFO] Processing machine for firewall/registry hardening: " << machine << std::endl;
    std::wstring uncPath = L"\\\\" + machine + L"\\IPC$";
    NETRESOURCEW nr;
    ZeroMemory(&nr, sizeof(nr));
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpLocalName = NULL;
    nr.lpRemoteName = (LPWSTR)uncPath.c_str();
    nr.lpProvider = NULL;
    DWORD wnetRet = WNetAddConnection2W(&nr, workingPassword.c_str(), L"Administrator", 0);
    if (wnetRet != NO_ERROR && wnetRet != ERROR_SESSION_CREDENTIAL_CONFLICT) {
        ss << L"[ERROR] WNetAddConnection2 failed for " << uncPath
            << L". Error code: " << wnetRet << std::endl;
        ss << L"[WARNING] Skipping firewall/registry hardening on " << machine
            << L" due to IPC$ connection failure." << std::endl;
        return ss.str();
    }
    auto smbFuture = std::async(std::launch::async, HardenSMB, machine);
    auto regFuture = std::async(std::launch::async, ApplyRemoteRegistryHardeningSettings, machine);
    ss << smbFuture.get();
    ss << regFuture.get();
    // NOTE: psExec call has been removed here. It will be run later using the new dynamic admin password.
    WNetCancelConnection2W(uncPath.c_str(), 0, TRUE);
    return ss.str();
}

struct MachinePasswordChangeResult {
    std::wstring log;
    std::wstring adminNewPassword; // The newly generated password for the Administrator account
};

MachinePasswordChangeResult ProcessMachineChangePasswords(const std::wstring& machine, const std::wstring& workingPassword)
{
    MachinePasswordChangeResult result;
    std::wstringstream ss;
    ss << L"\n[INFO] Changing local user passwords on machine: " << machine << std::endl;
    std::wstring uncPath = L"\\\\" + machine + L"\\IPC$";
    NETRESOURCEW nr;
    ZeroMemory(&nr, sizeof(nr));
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpLocalName = NULL;
    nr.lpRemoteName = (LPWSTR)uncPath.c_str();
    nr.lpProvider = NULL;
    DWORD wnetRet = WNetAddConnection2W(&nr, workingPassword.c_str(), L"Administrator", 0);
    if (wnetRet != NO_ERROR && wnetRet != ERROR_SESSION_CREDENTIAL_CONFLICT) {
        ss << L"[ERROR] WNetAddConnection2 failed for " << uncPath
            << L". Error code: " << wnetRet << std::endl;
        ss << L"[WARNING] Skipping local password changes on " << machine
            << L" due to IPC$ connection failure." << std::endl;
        result.log = ss.str();
        return result;
    }
    std::wstring serverName = L"\\\\" + machine;

    // Check if machine is a Domain Controller. If so, skip user modification to avoid changing domain users.
    LPSERVER_INFO_101 pInfo = NULL;
    NET_API_STATUS nStatusInfo = NetServerGetInfo((LPWSTR)serverName.c_str(), 101, (LPBYTE*)&pInfo);
    if (nStatusInfo == NERR_Success && pInfo != NULL) {
        bool isDC = (pInfo->sv101_type & SV_TYPE_DOMAIN_CTRL) || (pInfo->sv101_type & SV_TYPE_DOMAIN_BAKCTRL);
        NetApiBufferFree(pInfo);
        if (isDC) {
            ss << L"[INFO] Machine " << machine << L" is a Domain Controller. Skipping local user enumeration (which would be Domain Users) to prevent domain-wide password changes." << std::endl;
            WNetCancelConnection2W(uncPath.c_str(), 0, TRUE);
            result.log = ss.str();
            return result;
        }
    }
    else {
        ss << L"[WARNING] NetServerGetInfo failed (status=" << nStatusInfo << L"). Assuming not a DC." << std::endl;
    }

    LPUSER_INFO_0 pUser0 = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS nStatus = NetUserEnum(
        (LPWSTR)serverName.c_str(),
        0,
        FILTER_NORMAL_ACCOUNT,
        (LPBYTE*)&pUser0,
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        &dwResumeHandle
    );
    std::wstring adminNewPassword; // To capture new Administrator password
    if (nStatus == NERR_Success && pUser0 != NULL) {
        ss << L"[INFO] Found " << dwEntriesRead
            << L" local user(s) on " << machine << std::endl;
        for (DWORD i = 0; i < dwEntriesRead; i++) {
            std::wstring username = pUser0[i].usri0_name;

            // Skip a few special/built-in accounts that often break things when rotated.
            if (_wcsicmp(username.c_str(), L"Guest") == 0 ||
                _wcsicmp(username.c_str(), L"DefaultAccount") == 0 ||
                _wcsicmp(username.c_str(), L"WDAGUtilityAccount") == 0)
            {
                ss << L"[INFO] Skipping password change for special account: " << username << std::endl;
                continue;
            }

            // Check RID to identify built-in Administrator (RID 500) and Guest (RID 501).
            bool isBuiltInAdmin = false;
            {
                LPUSER_INFO_4 pUser4 = nullptr;
                NET_API_STATUS stInfo = NetUserGetInfo((LPWSTR)serverName.c_str(), (LPWSTR)username.c_str(), 4, (LPBYTE*)&pUser4);
                if (stInfo == NERR_Success && pUser4) {
                    DWORD rid = 0;
                    if (pUser4->usri4_user_sid && IsValidSid(pUser4->usri4_user_sid)) {
                        PUCHAR pCount = GetSidSubAuthorityCount(pUser4->usri4_user_sid);
                        if (pCount && *pCount > 0) {
                            rid = *GetSidSubAuthority(pUser4->usri4_user_sid, (*pCount) - 1);
                        }
                    }
                    if (rid == 500) {
                        isBuiltInAdmin = true;
                    }
                    if (rid == 501) {
                        NetApiBufferFree(pUser4);
                        ss << L"[INFO] Skipping password change for built-in Guest (RID 501): " << username << std::endl;
                        continue;
                    }
                    NetApiBufferFree(pUser4);
                }
            }

            std::wstring newPassword = GenerateStrongPassword(20);
            USER_INFO_1003 ui1003{};
            ui1003.usri1003_password = (LPWSTR)newPassword.c_str();
            DWORD parmErr = 0;
            NET_API_STATUS st = NetUserSetInfo((LPWSTR)serverName.c_str(), (LPWSTR)username.c_str(), 1003, (LPBYTE)&ui1003, &parmErr);
            if (st == NERR_Success) {
                ss << L"[OK] Changed password for local user: " << username << std::endl;
                (void)AppendPasswordChangeLine(machine, username, newPassword);
                if (isBuiltInAdmin || _wcsicmp(username.c_str(), L"Administrator") == 0) {
                    adminNewPassword = newPassword;
                }
            }
            else {
                ss << L"[ERROR] Failed to change password for local user: " << username
                    << L" (status=" << st << L", parmErr=" << parmErr << L")" << std::endl;
            }
        }
        NetApiBufferFree(pUser0);
    }
    else {
        ss << L"[ERROR] NetUserEnum failed for machine "
            << machine << L". Error: " << nStatus << std::endl;
    }
    WNetCancelConnection2W(uncPath.c_str(), 0, TRUE);
    result.log = ss.str();
    result.adminNewPassword = adminNewPassword;
    return result;
}

std::wstring RunPsExecWithNewPassword(const std::wstring& machine, const std::wstring& adminPassword, const std::wstring& subnet)
{
    std::wstringstream ss;
    // 1) Run the process-based firewall helper (1.exe) on the remote host
    std::wstring psExecCmd =
        L"psexec.exe \\\\" + machine +
        L" -u .\\Administrator -p \"" + adminPassword +
        L"\" -h -accepteula -c 1.exe " + subnet;
    ss << L"[INFO] Running PsExec command for 1.exe (not waiting for completion): " << psExecCmd << std::endl;
    if (!LaunchLocalProcess(psExecCmd, false)) {
        ss << L"[ERROR] Failed to run PsExec 1.exe command on " << machine << std::endl;
    }

    // 2) Also run the big hardening script whoo.ps1 on the remote host.
    // We expose it via this machine's administrative share so every
    // target can execute a single shared copy.
    wchar_t exePath[MAX_PATH] = { 0 };
    std::wstring scriptUNC;
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) != 0) {
        std::wstring exeFullPath(exePath);
        size_t pos = exeFullPath.find_last_of(L"\\/");
        std::wstring exeDir = (pos != std::wstring::npos) ? exeFullPath.substr(0, pos) : exeFullPath;
        std::wstring localScriptPath = exeDir + L"\\whoo.ps1";
        DWORD attrs = GetFileAttributesW(localScriptPath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            // Build a UNC path via the admin share, e.g. \\HOST\C$\path\whoo.ps1
            wchar_t computerName[MAX_PATH] = { 0 };
            DWORD nameLen = MAX_PATH;
            if (GetComputerNameW(computerName, &nameLen)) {
                if (localScriptPath.size() > 2 && localScriptPath[1] == L':') {
                    wchar_t driveLetter = localScriptPath[0];
                    std::wstring rest = localScriptPath.substr(2); // after "C:"
                    if (!rest.empty() && (rest[0] == L'/' || rest[0] == L'\\')) {
                        rest = rest.substr(1);
                    }
                    scriptUNC = L"\\\\";
                    scriptUNC += computerName;
                    scriptUNC += L"\\";
                    scriptUNC += driveLetter;
                    scriptUNC += L"$\\";
                    scriptUNC += rest;
                }
                else {
                    // Non-drive path (e.g. already UNC) – use as-is
                    scriptUNC = localScriptPath;
                }
            }
        }
    }

    if (!scriptUNC.empty()) {
        std::wstring psExecWhooCmd =
            L"psexec.exe \\\\" + machine +
            L" -u .\\Administrator -p \"" + adminPassword +
            L"\" -h -accepteula powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"" + scriptUNC + L"\"";
        ss << L"[INFO] Running PsExec command for whoo.ps1 (not waiting for completion): "
            << psExecWhooCmd << std::endl;
        if (!LaunchLocalProcess(psExecWhooCmd, false)) {
            ss << L"[ERROR] Failed to run PsExec whoo.ps1 command on " << machine << std::endl;
        }
    }
    else {
        ss << L"[WARNING] whoo.ps1 not found next to this executable; skipping remote whoo.ps1 run on "
           << machine << std::endl;
    }

    return ss.str();
}

std::wstring ProcessADUserChangePassword(const std::wstring& userDN)
{
    HRESULT hrCo = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    std::wstringstream ss;
    ss << L"\n[INFO] Processing AD user: " << userDN << std::endl;
    // Password generation removed
    ss << L"[INFO] Skipping password change for AD user" << std::endl;
    CoUninitialize();
    return ss.str();
}

// Helper to locate Chocolatey executable, either via PATH or
// the default C:\ProgramData\chocolatey\bin location.
static bool GetChocolateyExePath(std::wstring& outPath)
{
    wchar_t foundPath[MAX_PATH] = { 0 };
    DWORD len = SearchPathW(nullptr, L"choco.exe", nullptr, MAX_PATH, foundPath, nullptr);
    if (len > 0 && len < MAX_PATH) {
        outPath.assign(foundPath);
        return true;
    }

    std::wstring chocoRoot = L"C:\\ProgramData\\chocolatey";
    std::wstring chocoPath = chocoRoot + L"\\bin\\choco.exe";
    DWORD chocoExeAttrs = GetFileAttributesW(chocoPath.c_str());
    if (chocoExeAttrs != INVALID_FILE_ATTRIBUTES) {
        outPath = chocoPath;
        return true;
    }

    return false;
}

bool InstallChocolatey()
{
    std::wcout << L"[INFO] Checking if Chocolatey is installed...\n";

    std::wstring chocoPath;
    if (GetChocolateyExePath(chocoPath)) {
        std::wcout << L"[INFO] Chocolatey is available at: " << chocoPath << L"\n";
        return true;
    }

    // If Chocolatey is not present, try to run a local install script
    // located next to the executable (e.g. choco-install.ps1), similar to
    // how other tooling scripts like whoo.ps1 are invoked.
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) != 0) {
        std::wstring exeFullPath(exePath);
        size_t pos = exeFullPath.find_last_of(L"\\/");
        std::wstring exeDir = (pos != std::wstring::npos) ? exeFullPath.substr(0, pos) : exeFullPath;
        std::wstring scriptPath = exeDir + L"\\choco-install.ps1";
        DWORD scriptAttrs = GetFileAttributesW(scriptPath.c_str());
        if (scriptAttrs != INVALID_FILE_ATTRIBUTES) {
            std::wcout << L"[INFO] Chocolatey not detected; attempting install via script: "
                << scriptPath << L"\n";
            std::wstring psCmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"";
            psCmd += scriptPath;
            psCmd += L"\"";
            if (!LaunchLocalProcess(psCmd, true)) {
                std::wcerr << L"[ERROR] choco-install.ps1 execution failed.\n";
            }
            else {
                // Re-check for Chocolatey after running the script
                if (GetChocolateyExePath(chocoPath)) {
                    std::wcout << L"[INFO] Chocolatey appears to be installed after running script at: "
                        << chocoPath << L"\n";
                    return true;
                }
                std::wcerr << L"[WARNING] choco-install.ps1 completed but choco.exe is still not found.\n";
            }
        }
    }

    // Final warning if Chocolatey is still not available
    std::wcerr << L"[WARNING] Chocolatey was not found (neither in PATH nor at "
                << chocoPath << L").\n";
    std::wcerr << L"          Place a choco-install.ps1 script next to this exe,\n";
    std::wcerr << L"          or install Chocolatey manually, if you want automatic\n";
    std::wcerr << L"          MinGW/nmap installation.\n";
    return false;
}

bool InstallMinGW()
{
    std::wcout << L"[INFO] Checking if MinGW is installed via Chocolatey...\n";
	
    // Resolve path to choco.exe
    std::wstring chocoPath;
    if (!GetChocolateyExePath(chocoPath)) {
        std::wcerr << L"[ERROR] Chocolatey is not available; cannot manage MinGW via choco.\n";
        return false;
    }
    
    // Check if mingw is already installed
    std::wstring checkCmd = L"cmd.exe /c \"\"" + chocoPath + L"\" list --local-only mingw | findstr mingw >nul && exit /b 0 || exit /b 1\"";
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };
    
    std::vector<wchar_t> cmdBuf(checkCmd.begin(), checkCmd.end());
    cmdBuf.push_back(L'\0');
    
    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        if (exitCode == 0) {
            std::wcout << L"[INFO] MinGW is already installed.\n";
            return true;
        }
    }
    
    std::wcout << L"[INFO] Installing MinGW via Chocolatey (this may take several minutes)...\n";
    std::wstring installCmd = L"cmd.exe /c \"\"" + chocoPath + L"\" install mingw -y\"";
    
    if (!LaunchLocalProcess(installCmd, true)) {
        std::wcerr << L"[ERROR] Failed to install MinGW.\n";
        return false;
    }
    
    std::wcout << L"[INFO] MinGW installed successfully.\n";
    return true;
}

bool InstallNmap()
{
    std::wcout << L"[INFO] Checking if nmap is installed via Chocolatey...\n";
	
    // Resolve path to choco.exe
    std::wstring chocoPath;
    if (!GetChocolateyExePath(chocoPath)) {
        std::wcerr << L"[ERROR] Chocolatey is not available; cannot manage nmap via choco.\n";
        return false;
    }
    
    // Check if nmap is already installed
    std::wstring checkCmd = L"cmd.exe /c \"\"" + chocoPath + L"\" list --local-only nmap | findstr nmap >nul && exit /b 0 || exit /b 1\"";
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };
    
    std::vector<wchar_t> cmdBuf(checkCmd.begin(), checkCmd.end());
    cmdBuf.push_back(L'\0');
    
    if (CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        if (exitCode == 0) {
            std::wcout << L"[INFO] nmap is already installed.\n";
            return true;
        }
    }
    
    std::wcout << L"[INFO] Installing nmap via Chocolatey (this may take several minutes)...\n";
    std::wstring installCmd = L"cmd.exe /c \"\"" + chocoPath + L"\" install nmap -y\"";
    
    if (!LaunchLocalProcess(installCmd, true)) {
        std::wcerr << L"[ERROR] Failed to install nmap.\n";
        return false;
    }
    
    std::wcout << L"[INFO] nmap installed successfully.\n";
    return true;
}

static std::ofstream g_logFile;

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3) {
        std::wcerr << L"Usage: " << argv[0] << L" <LocalAdminPassword> <subnet>\n";
        return 1;
    }
    std::wcout << L"[INFO] To apply firewall rules to other win boxes, enable these services: "
               << L"Server (LanmanServer), Workstation (LanmanWorkstation), "
               << L"Remote Registry (RemoteRegistry).\n";
    std::wstring currentLocalAdminPassword = argv[1];
    std::wstring subnet = argv[2];

    // Install Chocolatey and MinGW for compilation tools
    std::wcout << L"[INFO] Ensuring build tools are installed...\n";
    if (!InstallChocolatey()) {
        std::wcerr << L"[WARNING] Chocolatey installation failed. Continuing anyway...\n";
    } else {
        if (!InstallMinGW()) {
            std::wcerr << L"[WARNING] MinGW installation failed. Continuing anyway...\n";
        }
        if (!InstallNmap()) {
            std::wcerr << L"[WARNING] nmap installation failed. Continuing anyway...\n";
        }
    }

    // Run whoo.ps1 locally (on this host) if present next to the executable,
    // regardless of whether Chocolatey/MinGW/nmap succeeded.
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) != 0) {
        std::wstring exeFullPath(exePath);
        size_t pos = exeFullPath.find_last_of(L"\\/");
        std::wstring exeDir = (pos != std::wstring::npos) ? exeFullPath.substr(0, pos) : exeFullPath;
        std::wstring localWhoo = exeDir + L"\\whoo.ps1";
        DWORD whooAttrs = GetFileAttributesW(localWhoo.c_str());
        if (whooAttrs != INVALID_FILE_ATTRIBUTES) {
            std::wcout << L"[INFO] Running local whoo.ps1 hardening script...\n";
            std::wstring psCmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"";
            psCmd += localWhoo;
            psCmd += L"\"";
            if (!LaunchLocalProcess(psCmd, true)) {
                std::wcerr << L"[WARNING] Failed to run local whoo.ps1. Continuing...\n";
            }
        } else {
            std::wcout << L"[INFO] whoo.ps1 not found next to this executable; skipping local whoo run.\n";
        }
    }

    // Find nmap executable (Chocolatey installs to Program Files)
    std::wstring nmapExe = L"C:\\Program Files (x86)\\Nmap\\nmap.exe";
    DWORD nmapAttribs = GetFileAttributesW(nmapExe.c_str());
    
    if (nmapAttribs == INVALID_FILE_ATTRIBUTES) {
        // Try 64-bit Program Files location
        nmapExe = L"C:\\Program Files\\Nmap\\nmap.exe";
        nmapAttribs = GetFileAttributesW(nmapExe.c_str());
    }
    
    if (nmapAttribs != INVALID_FILE_ATTRIBUTES) {
        // Launch nmap vulnerability scan in a new window
        std::wcout << L"[INFO] Launching nmap vulnerability scan in separate window...\n";
        std::wstring nmapCmd = L"cmd.exe /k \"\"" + nmapExe + L"\" -sV --script vulners -vvv " + subnet + L" && echo. && echo Scan complete. Press any key to close... && pause > nul\"";
        
        STARTUPINFOW nmapSi = { 0 };
        nmapSi.cb = sizeof(nmapSi);
        nmapSi.dwFlags = STARTF_USESHOWWINDOW;
        nmapSi.wShowWindow = SW_SHOW;
        PROCESS_INFORMATION nmapPi = { 0 };
        
        std::vector<wchar_t> nmapCmdBuf(nmapCmd.begin(), nmapCmd.end());
        nmapCmdBuf.push_back(L'\0');
        
        BOOL nmapResult = CreateProcessW(
            NULL,
            nmapCmdBuf.data(),
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &nmapSi,
            &nmapPi
        );
        
        if (nmapResult) {
            CloseHandle(nmapPi.hThread);
            CloseHandle(nmapPi.hProcess);
            std::wcout << L"[OK] nmap vulnerability scan launched in new window on subnet " << subnet << L"\n";
        } else {
            DWORD error = GetLastError();
            std::wcerr << L"[WARNING] Failed to launch nmap scan (Error " << error << L").\n";
        }
    } else {
        std::wcerr << L"[WARNING] nmap executable not found. Skipping vulnerability scan.\n";
        std::wcerr << L"[INFO] Please ensure nmap is installed and try again.\n";
    }

    if (!AddDefenderExclusionForCurrentFolder()) {
        std::wcerr << L"[WARNING] Failed to add Windows Defender exclusion for current folder.\n";
    }
    ApplyLocalRegistrySettings();
    g_logFile.open("password_log.txt", std::ios::out | std::ios::app);
    if (!g_logFile.is_open()) {
        std::wcerr << L"[ERROR] Could not open password_log.txt for writing.\n";
        return 1;
    }
    g_passFile.open("pass.txt", std::ios::out | std::ios::app);
    if (!g_passFile.is_open()) {
        std::wcerr << L"[ERROR] Could not open pass.txt for writing.\n";
        return 1;
    }
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        std::wcerr << L"[ERROR] CoInitialize failed. HRESULT=0x"
            << std::hex << hr << std::dec << std::endl;
        return 1;
    }
    // Get domain information for AD user changes
    std::wstring dn;
    PDOMAIN_CONTROLLER_INFO pDCInfo = NULL;
    if (DsGetDcName(NULL, NULL, NULL, NULL, 0, &pDCInfo) == ERROR_SUCCESS) {
        std::wstring domainName = pDCInfo->DomainName ? pDCInfo->DomainName : L"";
        dn = ConvertDomainNameToDN(domainName);
        NetApiBufferFree(pDCInfo);
    }
    else {
        std::wcerr << L"[WARNING] DsGetDcName failed; AD user changes may not work.\n";
    }

    // Use the provided subnet (instead of querying AD) to get a list of devices.
    std::vector<std::wstring> machines = GetMachinesFromSubnet(subnet);
    std::wcout << L"[INFO] Found " << machines.size()
        << L" devices in subnet " << subnet << L".\n";

    // Use multithreaded pings to quickly filter out non-responsive IPs.
    std::vector<std::future<bool>> pingFutures;
    for (auto& machine : machines) {
        pingFutures.push_back(std::async(std::launch::async, PingHost, machine, 1000));
    }
    std::vector<std::wstring> validMachines;
    for (size_t i = 0; i < machines.size(); i++) {
        if (pingFutures[i].get()) {
            validMachines.push_back(machines[i]);
            std::wcout << L"[Info] Machine " << machines[i] << L" responded to ping.\n";
        }
        else {
        }
    }
    std::wcout << L"[INFO] " << validMachines.size() << L" machines responded to ping.\n";

    // Harden each valid machine (psExec not run here)
    std::vector<std::future<std::wstring>> hardenFutures;
    for (auto& machine : validMachines) {
        hardenFutures.push_back(std::async(std::launch::async,
            ProcessMachineHarden, machine, currentLocalAdminPassword, subnet));
    }
    std::wstringstream hardenLogs;
    for (auto& f : hardenFutures) {
        try {
            hardenLogs << f.get();
        }
        catch (const std::exception& e) {
            hardenLogs << L"[ERROR] Exception in machine hardening thread: "
                << StringToWString(e.what()) << L"\n";
        }
        catch (...) {
            hardenLogs << L"[ERROR] Unknown exception in machine hardening thread.\n";
        }
    }
    std::wcout << hardenLogs.str();
    g_logFile << "[MACHINE HARDENING]\n" << WStringToString(hardenLogs.str()) << "\n";
    std::wcout << L"[INFO] Hardening complete on all machines. Proceeding to change local user passwords.\n";

    std::vector<std::future<MachinePasswordChangeResult>> localPwdFutures;
    for (auto& machine : validMachines) {
        localPwdFutures.push_back(std::async(std::launch::async,
            ProcessMachineChangePasswords, machine, currentLocalAdminPassword));
    }
    std::wstringstream localPwdLogs;
    std::vector<MachinePasswordChangeResult> localPwdResults;
    for (auto& f : localPwdFutures) {
        try {
            localPwdResults.push_back(f.get());
            localPwdLogs << localPwdResults.back().log;
        }
        catch (const std::exception& e) {
            localPwdLogs << L"[ERROR] Exception in local password change thread: "
                << StringToWString(e.what()) << L"\n";
        }
        catch (...) {
            localPwdLogs << L"[ERROR] Unknown exception in local password change thread.\n";
        }
    }
    std::wcout << localPwdLogs.str();
    g_logFile << "[MACHINE PASSWORD CHANGES]\n" << WStringToString(localPwdLogs.str()) << "\n";

    std::wcout << L"[INFO] Running psExec commands with new Administrator passwords...\n";
    std::vector<std::future<std::wstring>> psExecFutures;
    std::wstringstream psExecLogs;
    for (size_t i = 0; i < validMachines.size(); i++) {
        const std::wstring& machine = validMachines[i];
        std::wstring adminPassword = localPwdResults[i].adminNewPassword;
        if (adminPassword.empty()) {
            // Password rotation is currently disabled; fall back to the operator-supplied password.
            adminPassword = currentLocalAdminPassword;
            psExecLogs << L"[WARNING] No new Administrator password for machine: " << machine
                << L". Using provided working password for PsExec.\n";
        }
        if (!adminPassword.empty()) {
            psExecFutures.push_back(std::async(std::launch::async,
                RunPsExecWithNewPassword, machine, adminPassword, subnet));
        }
        else {
            psExecLogs << L"[ERROR] No password available for PsExec for machine: " << machine << L"\n";
        }
    }
    for (auto& f : psExecFutures) {
        try {
            psExecLogs << f.get();
        }
        catch (const std::exception& e) {
            psExecLogs << L"[ERROR] Exception in psExec thread: "
                << StringToWString(e.what()) << L"\n";
        }
        catch (...) {
            psExecLogs << L"[ERROR] Unknown exception in psExec thread.\n";
        }
    }
    std::wcout << psExecLogs.str();
    g_logFile << "[MACHINE PSEXEC COMMANDS]\n" << WStringToString(psExecLogs.str()) << "\n";

    // Process AD user changes (if domain info was successfully obtained)
    if (!dn.empty()) {
        std::wstring ldapPath = L"LDAP://CN=Users," + dn;
        std::wcout << L"[INFO] Enumerating AD users in " << ldapPath << L" ..." << std::endl;
        IDirectorySearch* pUserSearch = NULL;
        hr = ADsOpenObject(
            ldapPath.c_str(),
            NULL,
            NULL,
            ADS_SECURE_AUTHENTICATION,
            IID_IDirectorySearch,
            (void**)&pUserSearch
        );
        if (FAILED(hr) || !pUserSearch) {
            std::wcerr << L"[ERROR] ADsOpenObject for user search failed. HRESULT=0x"
                << std::hex << hr << std::endl;
            CoUninitialize();
            return 1;
        }
        ADS_SEARCHPREF_INFO searchPref;
        searchPref.dwSearchPref = ADS_SEARCHPREF_SIZE_LIMIT;
        searchPref.vValue.dwType = ADSTYPE_INTEGER;
        searchPref.vValue.Integer = 0;
        pUserSearch->SetSearchPreference(&searchPref, 1);
        LPWSTR userAttrs[] = { const_cast<LPWSTR>(L"distinguishedName") };
        ADS_SEARCH_HANDLE hUserSearch = NULL;
        const wchar_t* userFilter = L"(objectClass=user)";
        hr = pUserSearch->ExecuteSearch(
            const_cast<LPWSTR>(userFilter),
            userAttrs,
            1,
            &hUserSearch
        );
        if (FAILED(hr) || !hUserSearch) {
            std::wcerr << L"[ERROR] ExecuteSearch for users failed. HRESULT=0x"
                << std::hex << hr << std::endl;
            pUserSearch->Release();
            CoUninitialize();
            return 1;
        }
        std::vector<std::wstring> adUserDNs;
        while (pUserSearch->GetNextRow(hUserSearch) != S_ADS_NOMORE_ROWS) {
            ADS_SEARCH_COLUMN col;
            if (SUCCEEDED(pUserSearch->GetColumn(hUserSearch, userAttrs[0], &col))) {
                std::wstring userDN = col.pADsValues->CaseIgnoreString;
                adUserDNs.push_back(userDN);
                pUserSearch->FreeColumn(&col);
            }
        }
        pUserSearch->CloseSearchHandle(hUserSearch);
        pUserSearch->Release();
        std::wcout << L"[INFO] Found " << adUserDNs.size()
            << L" AD users. Processing domain password changes..." << std::endl;
        std::vector<std::future<std::wstring>> adFutures;
        for (const auto& userDN : adUserDNs) {
            adFutures.push_back(std::async(std::launch::async,
                ProcessADUserChangePassword, userDN));
        }
        std::wstringstream adLogs;
        for (auto& f : adFutures) {
            try {
                adLogs << f.get();
            }
            catch (const std::exception& e) {
                adLogs << L"[ERROR] Exception in AD user thread: "
                    << StringToWString(e.what()) << L"\n";
            }
            catch (...) {
                adLogs << L"[ERROR] Unknown exception in AD user thread.\n";
            }
        }
        std::wcout << adLogs.str();
        g_logFile << "[AD USER PASSWORD CHANGES]\n" << WStringToString(adLogs.str()) << "\n";
    }
    else {
        std::wcout << L"[WARNING] Skipping AD user password changes because domain info is unavailable.\n";
    }
    g_logFile.close();
    g_passFile.close();
    CoUninitialize();
    return 0;
}
