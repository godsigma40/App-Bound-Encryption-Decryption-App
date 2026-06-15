// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include "version.hpp"

namespace Core {

    namespace detail {
        // Compile-time FNV-1a for key generation
        constexpr uint64_t fnv1a_64(const char* str, size_t len) {
            uint64_t hash = 14695981039346656037ULL;
            for (size_t i = 0; i < len; ++i) {
                hash ^= static_cast<uint64_t>(str[i]);
                hash *= 1099511628211ULL;
            }
            return hash;
        }

        constexpr uint64_t BUILD_KEY = fnv1a_64(__DATE__, 11) ^ fnv1a_64(Core::BUILD_TAG, 7);

        constexpr uint8_t key_byte(size_t pos, uint64_t seed) {
            uint64_t mixed = seed ^ (pos * 0x9E3779B97F4A7C15ULL);
            mixed ^= mixed >> 33;
            mixed *= 0xFF51AFD7ED558CCDULL;
            mixed ^= mixed >> 33;
            return static_cast<uint8_t>(mixed);
        }

        // Wide string support
        constexpr uint16_t key_byte_w(size_t pos, uint64_t seed) {
            return static_cast<uint16_t>(key_byte(pos, seed));
        }
    }

    template<size_t N>
    class ObfuscatedString {
    public:
        constexpr ObfuscatedString(const char (&str)[N], uint64_t seed) : m_seed(seed) {
            for (size_t i = 0; i < N; ++i) {
                m_data[i] = str[i] ^ detail::key_byte(i, seed);
            }
        }

        const char* c_str() const {
            thread_local char buffer[N];
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = m_data[i] ^ detail::key_byte(i, m_seed);
            }
            return buffer;
        }

        void decrypt_to(char* buffer) const {
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = m_data[i] ^ detail::key_byte(i, m_seed);
            }
        }

        constexpr size_t size() const { return N - 1; }

    private:
        std::array<char, N> m_data{};
        uint64_t m_seed;
    };

    template<size_t N>
    class ObfuscatedWString {
    public:
        constexpr ObfuscatedWString(const wchar_t (&str)[N], uint64_t seed) : m_seed(seed) {
            for (size_t i = 0; i < N; ++i) {
                m_data[i] = str[i] ^ detail::key_byte_w(i, seed);
            }
        }

        const wchar_t* c_str() const {
            thread_local wchar_t buffer[N];
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = m_data[i] ^ detail::key_byte_w(i, m_seed);
            }
            return buffer;
        }

        constexpr size_t size() const { return N - 1; }

    private:
        std::array<wchar_t, N> m_data{};
        uint64_t m_seed;
    };

    template<size_t N>
    constexpr auto make_obfuscated(const char (&str)[N], uint64_t line_seed) {
        return ObfuscatedString<N>(str, detail::BUILD_KEY ^ line_seed);
    }

    template<size_t N>
    constexpr auto make_obfuscated_w(const wchar_t (&str)[N], uint64_t line_seed) {
        return ObfuscatedWString<N>(str, detail::BUILD_KEY ^ line_seed);
    }
}

#define OBF(str) (::Core::make_obfuscated(str, __LINE__ * 0x85EBCA77C2B2AE63ULL).c_str())
#define WOBF(str) (::Core::make_obfuscated_w(str, __LINE__ * 0x85EBCA77C2B2AE63ULL).c_str())
