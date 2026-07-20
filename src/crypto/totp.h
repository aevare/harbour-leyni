// HOTP (RFC 4226) and TOTP (RFC 6238) code generation, plus the strict
// base32 decoder for authenticator secrets. Pure functions; the vault layer
// owns secret-string parsing (otpauth:// URIs) and countdown timing.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "securebytes.h"

namespace Leyni {
namespace Crypto {

enum class TotpAlgorithm {
    Sha1, // the default for virtually all authenticator secrets
    Sha256,
    Sha512,
};

// RFC 4648 base32 (the authenticator-secret alphabet A-Z2-7).
// Case-insensitive; spaces and '=' padding are ignored (secrets are often
// displayed grouped and unpadded). Throws CryptoError on other characters.
std::vector<uint8_t> base32Decode(const std::string &text);

// RFC 4226 HOTP: HMAC over the big-endian counter, dynamic truncation,
// `digits` decimal digits (6..10), zero-padded.
std::string hotp(const SecureBytes &key, uint64_t counter, int digits,
                 TotpAlgorithm algorithm);

// RFC 6238 TOTP for the given Unix time. periodSeconds is typically 30.
std::string totp(const SecureBytes &key, uint64_t unixTime,
                 uint32_t periodSeconds, int digits, TotpAlgorithm algorithm);

} // namespace Crypto
} // namespace Leyni
