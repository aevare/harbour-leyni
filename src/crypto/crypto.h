// The auditable crypto core (see doc/ARCHITECTURE.md).
//
// Rules for everything in src/crypto/:
//   - depends only on libcrypto (OpenSSL 1.1.1+) and the vendored argon2
//   - no I/O, no network, no globals: pure functions, bytes in, bytes out
//   - every failure throws CryptoError; nothing fails into empty/garbage output
#pragma once

#include <stdexcept>
#include <string>

namespace Leyni {
namespace Crypto {

class CryptoError : public std::runtime_error
{
public:
    explicit CryptoError(const std::string &what) : std::runtime_error(what) {}
};

const char *version();

} // namespace Crypto
} // namespace Leyni
