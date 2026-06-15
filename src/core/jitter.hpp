// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <cstdint>
#include <random>

namespace Core {

    // Thread-safe jittered sleep utility for timing-based evasion.
    // Adds configurable randomness to delay durations so that
    // execution timing is non-deterministic across runs.

    class Jitter {
    public:
        // Sleep for a base duration +/- a random percentage.
        // jitterPercent: 0-100, controls the range of randomness.
        //   e.g. base=100, jitterPercent=50 -> sleeps between 50..150 ms
        static void Sleep(DWORD baseMs, DWORD jitterPercent = 30) {
            if (baseMs == 0) return;
            DWORD actual = Apply(baseMs, jitterPercent);
            ::Sleep(actual);
        }

        // Sleep for a random duration within [minMs, maxMs].
        static void SleepRange(DWORD minMs, DWORD maxMs) {
            if (minMs >= maxMs) { ::Sleep(minMs); return; }
            std::uniform_int_distribution<DWORD> dist(minMs, maxMs);
            ::Sleep(dist(GetRng()));
        }

        // Apply jitter to a value and return it (no sleep).
        static DWORD Apply(DWORD baseMs, DWORD jitterPercent = 30) {
            if (baseMs == 0 || jitterPercent == 0) return baseMs;
            if (jitterPercent > 100) jitterPercent = 100;

            DWORD range = (baseMs * jitterPercent) / 100;
            if (range == 0) return baseMs;

            std::uniform_int_distribution<DWORD> dist(0, range * 2);
            DWORD offset = dist(GetRng());

            // result = base - range + offset  =>  [base - range, base + range]
            DWORD result = baseMs - range + offset;
            return result > 0 ? result : 1;
        }

    private:
        static std::mt19937& GetRng() {
            thread_local std::mt19937 rng(SeedFromSystem());
            return rng;
        }

        static uint32_t SeedFromSystem() {
            LARGE_INTEGER counter{};
            QueryPerformanceCounter(&counter);
            uint32_t seed = static_cast<uint32_t>(counter.LowPart);
            seed ^= GetCurrentProcessId();
            seed ^= GetCurrentThreadId();
            seed ^= GetTickCount();
            // Mix bits
            seed ^= seed >> 16;
            seed *= 0x45D9F3B;
            seed ^= seed >> 16;
            return seed;
        }
    };

}
