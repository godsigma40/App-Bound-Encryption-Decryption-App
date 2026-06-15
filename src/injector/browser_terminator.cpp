// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "browser_terminator.hpp"
#include <algorithm>
#include <queue>
#include <TlHelp32.h>

namespace Injector {

    BrowserTerminator::BrowserTerminator(const Core::Console& console) 
        : m_console(console) {}

    std::vector<ProcessEntry> BrowserTerminator::EnumerateProcesses(const std::wstring& targetExeName) const {
        std::vector<ProcessEntry> results;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return results;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, targetExeName.c_str()) != 0)
                    continue;

                ProcessEntry entry{};
                entry.pid = pe.th32ProcessID;
                entry.parentPid = pe.th32ParentProcessID;
                entry.imageName = pe.szExeFile;
                entry.isMainProcess = true;
                entry.commandLine = L"";

                results.push_back(std::move(entry));
            } while (Process32NextW(snap, &pe));
        }

        CloseHandle(snap);
        return results;
    }

    std::wstring BrowserTerminator::GetProcessImageName(HANDLE hProcess) const {
        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size) && size > 0) {
            return std::filesystem::path(path).filename().wstring();
        }
        return L"";
    }

    std::wstring BrowserTerminator::GetProcessCommandLine(HANDLE /*hProcess*/) const {
        // Command line reading via PEB requires ReadProcessMemory + NtQueryInformationProcess.
        // For the terminator's purposes (just killing browser processes), we don't need it.
        return L"";
    }

    Core::UniqueHandle BrowserTerminator::OpenProcessHandle(DWORD pid, ACCESS_MASK access) const {
        HANDLE h = ::OpenProcess(static_cast<DWORD>(access), FALSE, pid);
        if (h) return Core::UniqueHandle(h);
        return Core::UniqueHandle(nullptr);
    }

    std::set<DWORD> BrowserTerminator::BuildProcessTree(
        const std::vector<ProcessEntry>& processes, DWORD rootPid) const {
        
        std::set<DWORD> tree;
        std::queue<DWORD> toProcess;
        toProcess.push(rootPid);

        while (!toProcess.empty()) {
            DWORD currentPid = toProcess.front();
            toProcess.pop();

            if (tree.count(currentPid) > 0) continue;
            tree.insert(currentPid);

            // Find all children of current process
            for (const auto& proc : processes) {
                if (proc.parentPid == currentPid && tree.count(proc.pid) == 0) {
                    toProcess.push(proc.pid);
                }
            }
        }

        return tree;
    }

    bool BrowserTerminator::WaitForProcessExit(HANDLE hProcess, DWORD timeoutMs) const {
        return WaitForSingleObject(hProcess, timeoutMs) == WAIT_OBJECT_0;
    }

    // Callback structure for EnumWindows
    struct EnumWindowsData {
        DWORD targetPid;
        std::vector<HWND> windows;
    };

    static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        auto* data = reinterpret_cast<EnumWindowsData*>(lParam);
        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);
        
        if (windowPid == data->targetPid) {
            data->windows.push_back(hwnd);
        }
        return TRUE;
    }

    bool BrowserTerminator::SendGracefulTermination(DWORD pid, DWORD timeoutMs) {
        // Find all windows belonging to this process
        EnumWindowsData data{};
        data.targetPid = pid;
        EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&data));

        if (data.windows.empty()) {
            return false; // No windows to close
        }

        // Send WM_CLOSE to all windows
        for (HWND hwnd : data.windows) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }

        // Wait for process to exit
        auto hProcess = OpenProcessHandle(pid, SYNCHRONIZE | PROCESS_QUERY_INFORMATION);
        if (!hProcess) {
            return true; // Process may have already exited
        }

        return WaitForProcessExit(hProcess.get(), timeoutMs);
    }

    bool BrowserTerminator::TerminateProcess(DWORD pid, const TerminationOptions& opts) {
        auto hProcess = OpenProcessHandle(pid, PROCESS_TERMINATE | SYNCHRONIZE);
        if (!hProcess) {
            return true; // Process may have already exited
        }

        if (!::TerminateProcess(hProcess.get(), 0)) {
            return false;
        }

        if (opts.waitForExit) {
            WaitForProcessExit(hProcess.get(), opts.exitWaitTimeoutMs);
        }

        return true;
    }

    std::vector<ProcessEntry> BrowserTerminator::GetRunningProcesses(const std::wstring& exeName) const {
        return EnumerateProcesses(exeName);
    }

    bool BrowserTerminator::IsBrowserRunning(const std::wstring& exeName) const {
        auto processes = EnumerateProcesses(exeName);
        return !processes.empty();
    }

    TerminationStats BrowserTerminator::KillByExeName(
        const std::wstring& exeName, const TerminationOptions& opts) {
        
        TerminationStats stats{};

        // Enumerate all processes with the target executable name
        auto processes = EnumerateProcesses(exeName);
        stats.processesFound = static_cast<int>(processes.size());

        if (processes.empty()) {
            return stats;
        }

        // If terminating children, enumerate ALL processes to find the tree
        std::vector<ProcessEntry> allProcesses;
        if (opts.terminateChildren) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);

                if (Process32FirstW(snap, &pe)) {
                    do {
                        ProcessEntry entry{};
                        entry.pid = pe.th32ProcessID;
                        entry.parentPid = pe.th32ParentProcessID;
                        entry.imageName = pe.szExeFile;
                        entry.isMainProcess = (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0);
                        allProcesses.push_back(std::move(entry));
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
        }

        // Build set of PIDs to terminate (including children if requested)
        std::set<DWORD> pidsToTerminate;
        
        for (const auto& proc : processes) {
            if (opts.terminateChildren && !allProcesses.empty()) {
                auto tree = BuildProcessTree(allProcesses, proc.pid);
                for (DWORD pid : tree) {
                    pidsToTerminate.insert(pid);
                }
            } else {
                pidsToTerminate.insert(proc.pid);
            }
        }

        stats.childProcesses = static_cast<int>(pidsToTerminate.size()) - stats.processesFound;
        if (stats.childProcesses < 0) stats.childProcesses = 0;

        // Terminate processes in reverse order (children first, then parents)
        std::vector<DWORD> sortedPids(pidsToTerminate.begin(), pidsToTerminate.end());
        
        std::sort(sortedPids.begin(), sortedPids.end(), [&](DWORD a, DWORD b) {
            bool aIsMain = std::any_of(processes.begin(), processes.end(), 
                [a](const ProcessEntry& e) { return e.pid == a; });
            bool bIsMain = std::any_of(processes.begin(), processes.end(), 
                [b](const ProcessEntry& e) { return e.pid == b; });
            return !aIsMain && bIsMain; // Children before parents
        });

        for (DWORD pid : sortedPids) {
            if (TerminateProcess(pid, opts)) {
                stats.processesTerminated++;
                stats.terminatedPids.push_back(pid);
            } else {
                stats.processesFailed++;
            }
        }

        return stats;
    }


}
