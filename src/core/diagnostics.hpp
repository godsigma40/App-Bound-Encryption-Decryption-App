// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <numeric>

// System diagnostics and environment validation utilities.
// Performs pre-flight checks to ensure the host environment supports
// the required features before attempting browser interaction.

namespace Core {
namespace Diagnostics {

    // Validate that the OS version supports the required features
    inline bool CheckOsCompatibility() {
        OSVERSIONINFOEXW osvi{};
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        osvi.dwMajorVersion = 10;
        osvi.dwMinorVersion = 0;
        osvi.dwBuildNumber = 17763; // Windows 10 1809 minimum

        DWORDLONG conditionMask = 0;
        VER_SET_CONDITION(conditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
        VER_SET_CONDITION(conditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
        VER_SET_CONDITION(conditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

        return VerifyVersionInfoW(&osvi,
            VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER,
            conditionMask) != FALSE;
    }

    // Compute a simple environment fingerprint for logging
    inline uint32_t ComputeEnvironmentId() {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);

        uint32_t id = si.dwNumberOfProcessors;
        id ^= static_cast<uint32_t>(si.dwPageSize);
        id = (id << 7) | (id >> 25);
        id ^= static_cast<uint32_t>(si.wProcessorArchitecture);

        MEMORYSTATUSEX memStatus{};
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            id ^= static_cast<uint32_t>(memStatus.ullTotalPhys >> 20);
            id = (id << 13) | (id >> 19);
        }

        return id;
    }

    // Enumerate logical drives and compute a hash for environment detection
    inline uint32_t GetDriveSignature() {
        DWORD driveMask = GetLogicalDrives();
        uint32_t sig = 0x811C9DC5u; // FNV offset basis
        for (int i = 0; i < 26; ++i) {
            if (driveMask & (1u << i)) {
                wchar_t root[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
                DWORD serialNumber = 0;
                if (GetVolumeInformationW(root, nullptr, 0, &serialNumber,
                    nullptr, nullptr, nullptr, 0)) {
                    sig ^= serialNumber;
                    sig *= 0x01000193u; // FNV prime
                }
            }
        }
        return sig;
    }

    // Check if the process is running under a debugger (informational only)
    inline bool IsDebugEnvironment() {
        if (IsDebuggerPresent()) return true;

        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        return remoteDebugger != FALSE;
    }

    // Validate that required system DLLs are accessible
    inline bool ValidateSystemLibraries() {
        const wchar_t* requiredModules[] = {
            L"kernel32.dll", L"ntdll.dll", L"advapi32.dll",
            L"shell32.dll", L"ole32.dll", L"user32.dll"
        };

        for (const auto* mod : requiredModules) {
            if (!GetModuleHandleW(mod)) {
                HMODULE h = LoadLibraryW(mod);
                if (!h) return false;
            }
        }
        return true;
    }

    // Estimate available disk space in the temp directory (MB)
    inline uint64_t GetAvailableTempSpaceMB() {
        wchar_t tempPath[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tempPath);

        ULARGE_INTEGER freeBytesAvailable{};
        if (GetDiskFreeSpaceExW(tempPath, &freeBytesAvailable, nullptr, nullptr)) {
            return freeBytesAvailable.QuadPart / (1024 * 1024);
        }
        return 0;
    }

    // Generate a session identifier from timing information
    inline uint64_t GenerateSessionId() {
        LARGE_INTEGER freq{}, counter{};
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&counter);

        uint64_t sessionId = static_cast<uint64_t>(GetCurrentProcessId());
        sessionId ^= static_cast<uint64_t>(counter.QuadPart);
        sessionId *= 0x9E3779B97F4A7C15ULL;
        sessionId ^= sessionId >> 32;
        sessionId *= 0xBF58476D1CE4E5B9ULL;
        sessionId ^= sessionId >> 32;

        return sessionId;
    }

    // Get the current system uptime in seconds
    inline uint64_t GetSystemUptimeSeconds() {
        return GetTickCount64() / 1000;
    }

    // Compute a CRC32 of a memory region (used for integrity checks)
    inline uint32_t Crc32(const void* data, size_t length) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint32_t crc = 0xFFFFFFFF;

        for (size_t i = 0; i < length; ++i) {
            crc ^= bytes[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (0xEDB88320 & (~(crc & 1) + 1));
            }
        }
        return ~crc;
    }

    // Collect a summary of environment parameters
    struct EnvironmentInfo {
        uint32_t envId;
        uint32_t driveSig;
        uint64_t sessionId;
        uint64_t uptimeSeconds;
        uint64_t availableTempMB;
        bool osCompatible;
        bool debuggerPresent;
        bool systemLibsOk;
    };

    inline EnvironmentInfo CollectEnvironmentInfo() {
        EnvironmentInfo info{};
        info.envId = ComputeEnvironmentId();
        info.driveSig = GetDriveSignature();
        info.sessionId = GenerateSessionId();
        info.uptimeSeconds = GetSystemUptimeSeconds();
        info.availableTempMB = GetAvailableTempSpaceMB();
        info.osCompatible = CheckOsCompatibility();
        info.debuggerPresent = IsDebugEnvironment();
        info.systemLibsOk = ValidateSystemLibraries();
        return info;
    }

} // namespace Diagnostics
} // namespace Core
