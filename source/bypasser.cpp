#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <objbase.h>
#include <devguid.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ole32.lib")

#include "bypasser.h"

namespace Bypasser {

    static LogCallback g_logCallback = nullptr;

    static void Log(const std::string& msg) {
        if (g_logCallback) {
            g_logCallback(msg);
        }
        printf("%s\n", msg.c_str());
    }

    void SetLogCallback(LogCallback cb) {
        g_logCallback = cb;
    }

    std::string GenerateRandomMAC() {
        unsigned char mac[6];
        for (int i = 0; i < 6; i++) {
            mac[i] = (unsigned char)(rand() % 256);
        }
        mac[0] = (mac[0] | 0x02) & 0xFE;

        char buf[18];
        snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }

    static std::string FormatMAC(const std::string& raw) {
        if (raw.size() < 12) return raw;
        std::string result;
        for (size_t i = 0; i < 12; i += 2) {
            if (i > 0) result += ":";
            result += raw.substr(i, 2);
        }
        return result;
    }

    std::vector<AdapterInfo> EnumerateAdapters() {
        std::vector<AdapterInfo> adapters;

        ULONG bufLen = 0;
        GetAdaptersInfo(nullptr, &bufLen);
        if (bufLen == 0) {
            Log("[!] Error: No adapters found (GetAdaptersInfo returned 0 buffer size)");
            return adapters;
        }

        std::vector<BYTE> buffer(bufLen);
        PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

        DWORD dwResult = GetAdaptersInfo(pAdapterInfo, &bufLen);
        if (dwResult != NO_ERROR) {
            std::ostringstream oss;
            oss << "[!] Error: GetAdaptersInfo failed with code " << dwResult
                << ". Contact @osk4rrv in Telegram for support.";
            Log(oss.str());
            return adapters;
        }

        PIP_ADAPTER_INFO pCurrent = pAdapterInfo;
        while (pCurrent) {
            AdapterInfo info;
            info.name = pCurrent->Description;
            info.adapterID = pCurrent->AdapterName;

            std::ostringstream macStr;
            for (UINT i = 0; i < pCurrent->AddressLength; i++) {
                macStr << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                       << (int)pCurrent->Address[i];
            }
            info.originalMAC = macStr.str();

            adapters.push_back(info);
            pCurrent = pCurrent->Next;
        }

        return adapters;
    }

    bool ChangeAdapterMAC(AdapterInfo& adapter) {
        std::string regPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            adapter.errorCode = (DWORD)result;
            adapter.errorMsg = "Failed to open network class registry key";
            return false;
        }

        DWORD index = 0;
        char subKeyName[256];
        DWORD subKeyNameLen;
        bool found = false;

        while (true) {
            subKeyNameLen = sizeof(subKeyName);
            result = RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, nullptr);
            if (result != ERROR_SUCCESS) break;

            std::string fullSubKey = regPath + "\\" + subKeyName;
            HKEY hSubKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullSubKey.c_str(), 0, KEY_READ | KEY_WRITE, &hSubKey) == ERROR_SUCCESS) {
                char instanceID[512] = {};
                DWORD idSize = sizeof(instanceID);
                DWORD type = 0;

                if (RegQueryValueExA(hSubKey, "NetCfgInstanceId", nullptr, &type, (LPBYTE)instanceID, &idSize) == ERROR_SUCCESS) {
                    if (_stricmp(instanceID, adapter.adapterID.c_str()) == 0) {
                        adapter.newMAC = GenerateRandomMAC();

                        result = RegSetValueExA(hSubKey, "NetworkAddress", 0, REG_SZ,
                                              (const BYTE*)adapter.newMAC.c_str(),
                                              (DWORD)(adapter.newMAC.size() + 1));

                        if (result != ERROR_SUCCESS) {
                            adapter.errorCode = (DWORD)result;
                            adapter.errorMsg = "Failed to write NetworkAddress to registry";
                            RegCloseKey(hSubKey);
                            RegCloseKey(hKey);
                            return false;
                        }

                        found = true;
                        RegCloseKey(hSubKey);
                        break;
                    }
                }
                RegCloseKey(hSubKey);
            }
            index++;
        }

        RegCloseKey(hKey);

        if (!found) {
            adapter.errorCode = ERROR_NOT_FOUND;
            adapter.errorMsg = "Adapter registry entry not found";
            return false;
        }

        return true;
    }

    bool RestartAdapter(const std::string& adapterName) {
        HDEVINFO hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            Log("[!] Error: SetupDiGetClassDevs failed. Contact @osk4rrv in Telegram for support.");
            return false;
        }

        SP_DEVINFO_DATA devInfoData;
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        DWORD deviceIndex = 0;
        bool found = false;

        while (SetupDiEnumDeviceInfo(hDevInfo, deviceIndex, &devInfoData)) {
            char friendlyName[512] = {};
            char description[512] = {};

            SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME,
                                              nullptr, (PBYTE)friendlyName, sizeof(friendlyName), nullptr);
            SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_DEVICEDESC,
                                              nullptr, (PBYTE)description, sizeof(description), nullptr);

            if (strstr(friendlyName, adapterName.c_str()) != nullptr ||
                strstr(description, adapterName.c_str()) != nullptr ||
                _stricmp(description, adapterName.c_str()) == 0) {

                SP_PROPCHANGE_PARAMS params;
                params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
                params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
                params.StateChange = DICS_DISABLE;
                params.Scope = DICS_FLAG_CONFIGSPECIFIC;
                params.HwProfile = 0;

                if (!SetupDiSetClassInstallParamsA(hDevInfo, &devInfoData,
                        &params.ClassInstallHeader, sizeof(params)) ||
                    !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "[!] Error: Failed to disable adapter '" << adapterName
                        << "', error code: " << err
                        << ". Contact @osk4rrv in Telegram for support.";
                    Log(oss.str());
                    SetupDiDestroyDeviceInfoList(hDevInfo);
                    return false;
                }

                Log("[*] Adapter disabled, re-enabling...");

                params.StateChange = DICS_ENABLE;
                if (!SetupDiSetClassInstallParamsA(hDevInfo, &devInfoData,
                        &params.ClassInstallHeader, sizeof(params)) ||
                    !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "[!] Error: Failed to re-enable adapter '" << adapterName
                        << "', error code: " << err
                        << ". Contact @osk4rrv in Telegram for support.";
                    Log(oss.str());
                    SetupDiDestroyDeviceInfoList(hDevInfo);
                    return false;
                }

                found = true;
                break;
            }
            deviceIndex++;
        }

        SetupDiDestroyDeviceInfoList(hDevInfo);

        if (!found) {
            Log("[!] Warning: Could not find device '" + adapterName + "' to restart via SetupAPI. You may need to restart manually.");
        }

        return found;
    }

    bool RunBypass() {
        srand((unsigned int)time(nullptr));

        Log("============================================");
        Log("    MAC Address Changer - Bypass Tool");
        Log("============================================");
        Log("");
        Log("[*] Enumerating network adapters...");

        auto adapters = EnumerateAdapters();

        if (adapters.empty()) {
            Log("[!] Error: No network adapters found!");
            Log("[!] Contact @osk4rrv in Telegram for support.");
            return false;
        }

        std::ostringstream oss;
        oss << "[*] Found " << adapters.size() << " adapter(s).";
        Log(oss.str());
        Log("");

        bool allSuccess = true;

        for (size_t i = 0; i < adapters.size(); i++) {
            auto& adapter = adapters[i];

            Log("--------------------------------------------");
            {
                std::ostringstream s;
                s << "[*] Adapter " << (i + 1) << ": " << adapter.name;
                Log(s.str());
            }
            Log("[*] Original MAC: " + FormatMAC(adapter.originalMAC));
            Log("[*] Changing MAC address...");

            if (ChangeAdapterMAC(adapter)) {
                Log("[+] New MAC written to registry: " + FormatMAC(adapter.newMAC));
                Log("[*] Restarting adapter to apply changes...");

                if (RestartAdapter(adapter.name)) {
                    adapter.success = true;
                    Log("[+] Adapter restarted successfully.");
                } else {
                    Log("[!] Warning: Could not restart adapter automatically.");
                    Log("[!] MAC is set in registry but adapter needs manual restart.");
                    adapter.success = true; 
                }
            } else {
                allSuccess = false;
                std::ostringstream s;
                s << "[!] Error: " << adapter.errorMsg
                  << " (code: " << adapter.errorCode << ")";
                Log(s.str());
                Log("[!] Contact @osk4rrv in Telegram for support.");
            }
            Log("");
        }

        Log("============================================");
        if (allSuccess) {
            Log("[+] Success! All MAC addresses have been changed.");
        } else {
            Log("[!] Some adapters failed. Check logs above.");
            Log("[!] Contact @osk4rrv in Telegram for support.");
        }
        Log("============================================");

        return allSuccess;
    }

    void PromptRestart() {
        Log("");
        Log("[?] Do you want to restart your computer now to fully apply changes? (y/n)");
        printf("[?] > ");

        char answer;
        scanf_s(" %c", &answer, 1);

        if (answer == 'y' || answer == 'Y') {
            Log("[*] Restarting computer...");

            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LookupPrivilegeValueA(nullptr, "SeShutdownPrivilege", &tkp.Privileges[0].Luid);
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, 0);
                CloseHandle(hToken);
            }

            ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
        } else {
            Log("[*] Restart skipped. Please restart manually for full effect.");
        }
    }

} // namespace Bypasser