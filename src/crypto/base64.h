// Minimal strict base64 (RFC 4648, with padding). Own implementation so the
// parsing of untrusted vault data stays inside the audited core: rejects
// whitespace, missing/excess padding, and non-alphabet characters.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace BitVault {
namespace Crypto {

std::string base64Encode(const uint8_t *data, size_t len);

// Throws CryptoError on any malformed input.
std::vector<uint8_t> base64Decode(const std::string &text);

} // namespace Crypto
} // namespace BitVault
