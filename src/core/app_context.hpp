// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <Shlobj.h>
#include <shellapi.h>
#include <string>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")

// Application context utilities for path resolution, environment queries,
// and standard Windows integration. Used during startup initialization.

namespace Core {
namespace AppContext {

    // Get the user's local application data folder
    inline std::wstring GetLocalAppDataPath() {
        PWSTR path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
            std::wstring result(path);
            CoTaskMemFree(path);
            return result;
        }
        return L"";
    }

    // Get the common program files directory
    inline std::wstring GetProgramDataPath() {
        PWSTR path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path))) {
            std::wstring result(path);
            CoTaskMemFree(path);
            return result;
        }
        return L"";
    }

    // Check if the current user has administrator privileges
    inline bool IsRunningElevated() {
        BOOL elevated = FALSE;
        HANDLE token = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elev{};
            DWORD size = sizeof(elev);
            if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size)) {
                elevated = elev.TokenIsElevated;
            }
            CloseHandle(token);
        }
        return elevated != FALSE;
    }

    // Get the system's Windows directory
    inline std::wstring GetWindowsDirectory() {
        wchar_t buf[MAX_PATH] = {};
        ::GetWindowsDirectoryW(buf, MAX_PATH);
        return buf;
    }

    // Retrieve the current system locale name
    inline std::wstring GetSystemLocaleName() {
        wchar_t locale[LOCALE_NAME_MAX_LENGTH] = {};
        GetSystemDefaultLocaleName(locale, LOCALE_NAME_MAX_LENGTH);
        return locale;
    }

    // Query the number of monitors attached
    inline int GetDisplayCount() {
        return GetSystemMetrics(SM_CMONITORS);
    }

    // Get the current desktop DPI scaling
    inline UINT GetDesktopDpi() {
        HDC hdc = GetDC(nullptr);
        UINT dpi = hdc ? GetDeviceCaps(hdc, LOGPIXELSX) : 96;
        if (hdc) ReleaseDC(nullptr, hdc);
        return dpi;
    }

    // Retrieve the computer name
    inline std::wstring GetMachineName() {
        wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        GetComputerNameW(name, &size);
        return name;
    }

    // Retrieve the current user name
    inline std::wstring GetCurrentUserName() {
        wchar_t name[256] = {};
        DWORD size = 256;
        GetUserNameW(name, &size);
        return name;
    }

    // Initialize COM for the current thread (STA)
    inline bool InitializeCom() {
        return SUCCEEDED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED));
    }

    // Uninitialize COM
    inline void UninitializeCom() {
        CoUninitialize();
    }

} // namespace AppContext
} // namespace Core
