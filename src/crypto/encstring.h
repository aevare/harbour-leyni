// Bitwarden "EncString" handling: "<type>.<base64>|<base64>[|<base64>]".
//
// Supported types (all others are rejected with a clear error — never
// silently mis-decrypted):
//   2  AesCbc256_HmacSha256_B64  "2.<iv>|<ciphertext>|<mac>"  (all vault data)
//   4  Rsa2048_OaepSha1_B64      "4.<ciphertext>"             (org key wrapping)
//
// Type-2 decryption is encrypt-then-MAC: the HMAC-SHA256 over iv||ciphertext
// is verified in constant time BEFORE any decryption is attempted.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "keys.h"
#include "securebytes.h"

namespace Leyni {
namespace Crypto {

struct EncString {
    int type = -1;
    std::vector<uint8_t> iv;          // type 2: 16 bytes
    std::vector<uint8_t> ciphertext;  // types 2 and 4
    std::vector<uint8_t> mac;         // type 2: 32 bytes

    // Parses and validates structure (part count, iv/mac sizes, base64).
    // Throws CryptoError on malformed input or unsupported type.
    static EncString parse(const std::string &text);

    std::string serialize() const;
};

// Type 2 decrypt. Verifies the MAC first; throws CryptoError on mismatch.
SecureBytes decryptAes256CbcHmac(const EncString &enc, const SymmetricKey &key);

// Type 2 encrypt with a random IV.
EncString encryptAes256CbcHmac(const SecureBytes &plaintext,
                               const SymmetricKey &key);

// Type 2 encrypt with a caller-supplied IV — known-answer tests only.
EncString encryptAes256CbcHmacWithIv(const SecureBytes &plaintext,
                                     const SymmetricKey &key,
                                     const uint8_t iv[16]);

// Type 4 decrypt (organization key unwrap) with the account RSA private key.
SecureBytes decryptRsaOaepSha1(const EncString &enc,
                               const SecureBytes &privateKeyDer);

} // namespace Crypto
} // namespace Leyni
