// Master-key derivation, exactly as Bitwarden defines it
// (https://bitwarden.com/help/bitwarden-security-white-paper/):
//
//   PBKDF2-SHA256: masterKey = PBKDF2(password, salt = lowercase(email), iterations)
//   Argon2id:      masterKey = Argon2id(password, salt = SHA-256(lowercase(email)),
//                                       iterations, memoryMiB, parallelism)
//
// The caller is responsible for lowercasing/trimming the email; these
// functions use the salt bytes exactly as given.
#pragma once

#include <cstdint>
#include <string>

#include "securebytes.h"

namespace BitVault {
namespace Crypto {

enum class KdfType : int {
    Pbkdf2Sha256 = 0,
    Argon2id = 1,
};

struct KdfParams {
    KdfType type = KdfType::Pbkdf2Sha256;
    uint32_t iterations = 0;
    uint32_t memoryMiB = 0;    // Argon2id only
    uint32_t parallelism = 0;  // Argon2id only
};

// Sanity bounds on server-supplied KDF parameters. A malicious or broken
// server must not be able to make the client allocate gigabytes or loop
// for hours. Values outside these ranges throw CryptoError.
constexpr uint32_t kMaxPbkdf2Iterations = 10'000'000;
constexpr uint32_t kMaxArgon2Iterations = 100;
constexpr uint32_t kMaxArgon2MemoryMiB = 1024;
constexpr uint32_t kMaxArgon2Parallelism = 16;

// Raw primitives (32-byte output). Exposed for known-answer tests.
SecureBytes pbkdf2Sha256(const SecureBytes &password,
                         const uint8_t *salt, size_t saltLen,
                         uint32_t iterations, size_t outLen);
SecureBytes argon2id(const SecureBytes &password,
                     const uint8_t *salt, size_t saltLen,
                     uint32_t iterations, uint32_t memoryMiB, uint32_t parallelism,
                     size_t outLen);

// SHA-256 digest (needed for the Argon2 email salt; exposed for tests).
SecureBytes sha256(const uint8_t *data, size_t len);

// The Bitwarden master key (32 bytes) for the given normalized email.
SecureBytes deriveMasterKey(const SecureBytes &password,
                            const std::string &emailLower,
                            const KdfParams &params);

// The server authorization hash sent in the login request (32 bytes):
// PBKDF2-SHA256(password = masterKey, salt = password, 1 iteration).
SecureBytes deriveMasterPasswordHash(const SecureBytes &masterKey,
                                     const SecureBytes &password);

} // namespace Crypto
} // namespace BitVault
