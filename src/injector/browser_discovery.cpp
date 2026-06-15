// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "browser_discovery.hpp"
#include <algorithm>
#include <map>

#pragma comment(lib, "version.lib")

namespace Injector {

    namespace {
        const std::map<std::wstring, std::pair<std::wstring, std::string>> g_browserMap = {
            {L"chrome", {L"chrome.exe", "Chrome"}},
            {L"chrome-beta", {L"chrome.exe", "Chrome Beta"}},
            {L"edge", {L"msedge.exe", "Edge"}},
            {L"brave", {L"brave.exe", "Brave"}},
            {L"avast", {L"AvastBrowser.exe", "Avast"}}
        };

        // Convert NT-style registry paths to standard HKEY + subpath
        // NT paths start with "\Registry\Machine\" -> HKEY_LOCAL_MACHINE
        struct RegistryPath {
            HKEY root;
            std::wstring subKey;
        };

        RegistryPath ParseNtRegPath(const std::wstring& ntPath) {
            RegistryPath result{};
            std::wstring lower = ntPath;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            const std::wstring machinePrefix = L"\\registry\\machine\\";
            if (lower.find(machinePrefix) == 0) {
                result.root = HKEY_LOCAL_MACHINE;
                result.subKey = ntPath.substr(machinePrefix.length());
            }
            return result;
        }
    }

    std::vector<BrowserInfo> BrowserDiscovery::FindAll() {
        std::vector<BrowserInfo> results;
        for (const auto& [type, info] : g_browserMap) {
            auto path = ResolvePath(type, info.first);
            if (!path.empty()) {
                results.push_back({type, info.first, path, info.second, GetFileVersion(path)});
            }
        }
        return results;
    }

    std::optional<BrowserInfo> BrowserDiscovery::FindSpecific(const std::wstring& type) {
        std::wstring lowerType = type;
        std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::towlower);

        auto it = g_browserMap.find(lowerType);
        if (it == g_browserMap.end()) return std::nullopt;

        auto path = ResolvePath(lowerType, it->second.first);
        if (path.empty()) return std::nullopt;

        return BrowserInfo{lowerType, it->second.first, path, it->second.second, GetFileVersion(path)};
    }

    static bool ValidatePathForBrowser(const std::wstring& path, const std::wstring& browserType) {
        std::wstring lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (browserType == L"chrome") {
            return lowerPath.find(L"\\google\\chrome\\") != std::wstring::npos &&
                   lowerPath.find(L"\\google\\chrome beta\\") == std::wstring::npos;
        } else if (browserType == L"chrome-beta") {
            return lowerPath.find(L"\\google\\chrome beta\\") != std::wstring::npos;
        }
        return true;
    }

    std::wstring BrowserDiscovery::ResolvePath(const std::wstring& browserType, const std::wstring& exeName) {
        if (browserType != L"chrome" && browserType != L"chrome-beta") {
            const std::wstring appPaths[] = {
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName,
                L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName
            };

            for (const auto& regPath : appPaths) {
                auto path = QueryRegistry(regPath);
                if (!path.empty() && std::filesystem::exists(path)) {
                    return path;
                }
            }
        }

        std::vector<std::pair<std::wstring, std::wstring>> altRegistry;

        if (browserType == L"chrome") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome\\shell\\open\\command", L""}
            };
        } else if (browserType == L"chrome-beta") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome Beta", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome Beta\\shell\\open\\command", L""}
            };
        } else if (browserType == L"edge") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Microsoft Edge\\shell\\open\\command", L""}
            };
        } else if (browserType == L"brave") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brave-Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BraveSoftware Brave-Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Brave\\shell\\open\\command", L""}
            };
        } else if (browserType == L"avast") {
            altRegistry = {
                {L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Avast Secure Browser", L"InstallLocation"},
                {L"\\Registry\\Machine\\SOFTWARE\\Clients\\StartMenuInternet\\Avast Secure Browser\\shell\\open\\command", L""}
            };
        }

        for (const auto& [regKey, valueName] : altRegistry) {
            auto result = QueryRegistryValue(regKey, valueName);
            if (!result.empty()) {
                std::wstring fullPath;
                if (valueName == L"InstallLocation") {
                    fullPath = result + L"\\" + exeName;
                } else {
                    size_t start = (result[0] == L'"') ? 1 : 0;
                    size_t end = result.find(L'"', start);
                    if (end == std::wstring::npos) end = result.find(L' ', start);
                    if (end == std::wstring::npos) end = result.length();
                    fullPath = result.substr(start, end - start);
                }
                if (std::filesystem::exists(fullPath) && ValidatePathForBrowser(fullPath, browserType)) {
                    return fullPath;
                }
            }
        }

        return L"";
    }

    std::wstring BrowserDiscovery::QueryRegistryValue(const std::wstring& keyPath, const std::wstring& valueName) {
        auto parsed = ParseNtRegPath(keyPath);
        if (!parsed.root) return L"";

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(parsed.root, parsed.subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return L"";

        wchar_t data[4096] = {};
        DWORD dataSize = sizeof(data);
        DWORD type = 0;

        LONG status = RegQueryValueExW(hKey, valueName.empty() ? nullptr : valueName.c_str(),
                                       nullptr, &type, reinterpret_cast<LPBYTE>(data), &dataSize);
        RegCloseKey(hKey);

        if (status != ERROR_SUCCESS) return L"";
        if (type != REG_SZ && type != REG_EXPAND_SZ) return L"";

        std::wstring path(data);
        while (!path.empty() && path.back() == L'\0') path.pop_back();
        if (path.empty()) return L"";

        if (type == REG_EXPAND_SZ) {
            std::vector<wchar_t> expanded(MAX_PATH * 2);
            DWORD size = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), static_cast<DWORD>(expanded.size()));
            if (size > 0 && size <= expanded.size()) {
                path = std::wstring(expanded.data());
            }
        }

        return path;
    }

    std::wstring BrowserDiscovery::QueryRegistry(const std::wstring& keyPath) {
        // QueryRegistry reads the default value (empty value name)
        return QueryRegistryValue(keyPath, L"");
    }

    std::string BrowserDiscovery::GetFileVersion(const std::wstring& filePath) {
        DWORD dummy = 0;
        DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
        if (size == 0) return "";

        std::vector<BYTE> buffer(size);
        if (!GetFileVersionInfoW(filePath.c_str(), 0, size, buffer.data())) return "";

        VS_FIXEDFILEINFO* fileInfo = nullptr;
        UINT len = 0;
        if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &len)) return "";
        if (len == 0 || fileInfo == nullptr) return "";

        return std::to_string(HIWORD(fileInfo->dwFileVersionMS)) + "." +
               std::to_string(LOWORD(fileInfo->dwFileVersionMS)) + "." +
               std::to_string(HIWORD(fileInfo->dwFileVersionLS)) + "." +
               std::to_string(LOWORD(fileInfo->dwFileVersionLS));
    }

}
