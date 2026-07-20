// Key stretching and unwrapping.
//
//   stretchMasterKey: 32-byte master key -> 64-byte symmetric key via
//                     HKDF-SHA256 expand with info "enc" (32 B) and "mac" (32 B).
//   rsaOaepSha1Decrypt: unwraps organization keys (EncString type 4) with the
//                     account's RSA-2048 private key (PKCS#8 DER).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "securebytes.h"

namespace Leyni {
namespace Crypto {

// A Bitwarden symmetric key: 32-byte AES key + 32-byte HMAC key.
struct SymmetricKey {
    SecureBytes encKey;
    SecureBytes macKey;
};

// HKDF-SHA256 in expand-only mode (RFC 5869 step 2; prk must already be a
// cryptographically strong key). Exposed for known-answer tests.
SecureBytes hkdfExpandSha256(const SecureBytes &prk,
                             const std::string &info, size_t outLen);

SymmetricKey stretchMasterKey(const SecureBytes &masterKey);

// Builds a SymmetricKey from 64 raw bytes (enc || mac), e.g. a decrypted
// protected key from the login response or an unwrapped organization key.
SymmetricKey symmetricKeyFromBytes(const SecureBytes &raw);

// HMAC-SHA256. The digest itself is not secret, so it is a plain vector.
std::vector<uint8_t> hmacSha256(const SecureBytes &key,
                                const uint8_t *data, size_t len);

// RSA-2048-OAEP(SHA-1) decryption with a PKCS#8 DER private key.
SecureBytes rsaOaepSha1Decrypt(const SecureBytes &privateKeyDer,
                               const uint8_t *ciphertext, size_t len);

} // namespace Crypto
} // namespace Leyni
