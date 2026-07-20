#include "passwordgen.h"

#include <openssl/rand.h>

#include <algorithm>
#include <vector>

#include "crypto.h"

namespace Leyni {
namespace Crypto {

namespace {

uint32_t random32()
{
    uint8_t b[4];
    if (RAND_bytes(b, sizeof(b)) != 1) {
        throw CryptoError("passwordgen: RAND_bytes failed");
    }
    return (static_cast<uint32_t>(b[0]) << 24)
         | (static_cast<uint32_t>(b[1]) << 16)
         | (static_cast<uint32_t>(b[2]) << 8)
         | static_cast<uint32_t>(b[3]);
}

// Applies the ambiguous-character filter to a class string.
std::string filterAmbiguous(const std::string &s, bool avoid)
{
    static const std::string kAmbiguous = "Il1O0o";
    if (!avoid) {
        return s;
    }
    std::string out;
    for (char c : s) {
        if (kAmbiguous.find(c) == std::string::npos) {
            out.push_back(c);
        }
    }
    return out;
}

char pick(const std::string &set)
{
    return set[randomIndex(static_cast<uint32_t>(set.size()))];
}

} // namespace

uint32_t randomIndex(uint32_t bound)
{
    if (bound == 0) {
        throw CryptoError("randomIndex: zero bound");
    }
    // 2^32 mod bound, computed without overflowing uint32.
    const uint32_t rem =
        ((static_cast<uint32_t>(UINT32_MAX % bound)) + 1u) % bound;
    if (rem == 0) {
        // bound divides 2^32 exactly (a power of two) — no bias to reject.
        return random32() % bound;
    }
    // Accept only [0, 2^32 - rem): a whole number of `bound`-sized buckets.
    const uint32_t maxAccept = 0u - rem; // 2^32 - rem (mod 2^32)
    for (;;) {
        const uint32_t r = random32();
        if (r < maxAccept) {
            return r % bound;
        }
    }
}

std::string generatePassword(const PasswordOptions &opts)
{
    if (opts.length < 1 || opts.length > 256) {
        throw CryptoError("generatePassword: length out of range");
    }

    const std::string lower = opts.lowercase
        ? filterAmbiguous("abcdefghijklmnopqrstuvwxyz", opts.avoidAmbiguous)
        : std::string();
    const std::string upper = opts.uppercase
        ? filterAmbiguous("ABCDEFGHIJKLMNOPQRSTUVWXYZ", opts.avoidAmbiguous)
        : std::string();
    const std::string digit = opts.digits
        ? filterAmbiguous("0123456789", opts.avoidAmbiguous)
        : std::string();
    // Deliberately excludes quotes, backslash and space to avoid shell/paste
    // surprises — a common, safe symbol set.
    const std::string symbol = opts.symbols
        ? std::string("!@#$%^&*()-_=+[]{};:,.?")
        : std::string();

    const std::string pool = lower + upper + digit + symbol;
    if (pool.empty()) {
        throw CryptoError("generatePassword: no character class enabled");
    }

    // At least one of every enabled class; digits/symbols honor their minima.
    const int reqLower = lower.empty() ? 0 : 1;
    const int reqUpper = upper.empty() ? 0 : 1;
    const int reqDigit = digit.empty() ? 0 : std::max(1, opts.minDigits);
    const int reqSymbol = symbol.empty() ? 0 : std::max(1, opts.minSymbols);
    const int required = reqLower + reqUpper + reqDigit + reqSymbol;
    if (opts.length < required) {
        throw CryptoError(
            "generatePassword: length too short for the selected options");
    }

    std::vector<char> chars;
    chars.reserve(static_cast<size_t>(opts.length));
    for (int i = 0; i < reqLower; ++i) chars.push_back(pick(lower));
    for (int i = 0; i < reqUpper; ++i) chars.push_back(pick(upper));
    for (int i = 0; i < reqDigit; ++i) chars.push_back(pick(digit));
    for (int i = 0; i < reqSymbol; ++i) chars.push_back(pick(symbol));
    while (static_cast<int>(chars.size()) < opts.length) {
        chars.push_back(pick(pool));
    }

    // Fisher–Yates shuffle so the guaranteed characters are not positional.
    for (size_t i = chars.size() - 1; i > 0; --i) {
        const uint32_t j = randomIndex(static_cast<uint32_t>(i + 1));
        std::swap(chars[i], chars[j]);
    }

    return std::string(chars.begin(), chars.end());
}

} // namespace Crypto
} // namespace Leyni
