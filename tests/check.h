// Minimal test support: no framework, so the tests read as plain statements
// of fact (see doc/TESTING.md for why). A failed CHECK aborts the run.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto.h"

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,    \
                         __LINE__, #cond);                                   \
            std::exit(1);                                                    \
        }                                                                    \
    } while (0)

// The expression must throw CryptoError; anything else is a failure.
#define CHECK_THROWS(expr)                                                   \
    do {                                                                     \
        bool threw_ = false;                                                 \
        try {                                                                \
            (void)(expr);                                                    \
        } catch (const BitVault::Crypto::CryptoError &) {                    \
            threw_ = true;                                                   \
        }                                                                    \
        if (!threw_) {                                                       \
            std::fprintf(stderr,                                             \
                         "CHECK_THROWS failed at %s:%d: %s did not throw\n", \
                         __FILE__, __LINE__, #expr);                         \
            std::exit(1);                                                    \
        }                                                                    \
    } while (0)

inline std::vector<uint8_t> fromHex(const std::string &hex)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        std::fprintf(stderr, "fromHex: bad character '%c'\n", c);
        std::exit(1);
    };
    if (hex.size() % 2 != 0) {
        std::fprintf(stderr, "fromHex: odd length\n");
        std::exit(1);
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4)
                                           | nibble(hex[i + 1])));
    }
    return out;
}

inline std::string toHex(const uint8_t *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xf]);
    }
    return out;
}
