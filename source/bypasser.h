#pragma once
#include <string>
#include <vector>
#include <functional>

namespace Bypasser {

    struct AdapterInfo {
        std::string name;
        std::string adapterID;
        std::string originalMAC;
        std::string newMAC;
        bool success = false;
        std::string errorMsg;
        DWORD errorCode = 0;
    };

    using LogCallback = std::function<void(const std::string&)>;
    void SetLogCallback(LogCallback cb);
    std::string GenerateRandomMAC();
    std::vector<AdapterInfo> EnumerateAdapters();
    bool ChangeAdapterMAC(AdapterInfo& adapter);
    bool RestartAdapter(const std::string& adapterName);
    bool RunBypass();
    void PromptRestart();

} // namespace Bypasser