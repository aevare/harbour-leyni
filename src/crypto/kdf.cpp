#include "kdf.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <argon2.h>

#include "crypto.h"

namespace BitVault {
namespace Crypto {

SecureBytes pbkdf2Sha256(const SecureBytes &password,
                         const uint8_t *salt, size_t saltLen,
                         uint32_t iterations, size_t outLen)
{
    if (iterations == 0 || iterations > kMaxPbkdf2Iterations) {
        throw CryptoError("pbkdf2Sha256: iteration count out of range");
    }
    if (outLen == 0) {
        throw CryptoError("pbkdf2Sha256: zero output length");
    }
    SecureBytes out(outLen);
    int ok = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()),
                               static_cast<int>(password.size()),
                               salt, static_cast<int>(saltLen),
                               static_cast<int>(iterations), EVP_sha256(),
                               static_cast<int>(outLen), out.data());
    if (ok != 1) {
        throw CryptoError("pbkdf2Sha256: PKCS5_PBKDF2_HMAC failed");
    }
    return out;
}

SecureBytes argon2id(const SecureBytes &password,
                     const uint8_t *salt, size_t saltLen,
                     uint32_t iterations, uint32_t memoryMiB, uint32_t parallelism,
                     size_t outLen)
{
    if (iterations == 0 || iterations > kMaxArgon2Iterations) {
        throw CryptoError("argon2id: iteration count out of range");
    }
    if (memoryMiB == 0 || memoryMiB > kMaxArgon2MemoryMiB) {
        throw CryptoError("argon2id: memory out of range");
    }
    if (parallelism == 0 || parallelism > kMaxArgon2Parallelism) {
        throw CryptoError("argon2id: parallelism out of range");
    }
    if (outLen == 0) {
        throw CryptoError("argon2id: zero output length");
    }
    SecureBytes out(outLen);
    int rc = argon2id_hash_raw(iterations, memoryMiB * 1024 /* KiB */, parallelism,
                               password.data(), password.size(),
                               salt, saltLen,
                               out.data(), out.size());
    if (rc != ARGON2_OK) {
        throw CryptoError(std::string("argon2id: ") + argon2_error_message(rc));
    }
    return out;
}

SecureBytes sha256(const uint8_t *data, size_t len)
{
    SecureBytes out(SHA256_DIGEST_LENGTH);
    unsigned int outLen = 0;
    if (EVP_Digest(data, len, out.data(), &outLen, EVP_sha256(), nullptr) != 1
            || outLen != SHA256_DIGEST_LENGTH) {
        throw CryptoError("sha256: EVP_Digest failed");
    }
    return out;
}

SecureBytes deriveMasterKey(const SecureBytes &password,
                            const std::string &emailLower,
                            const KdfParams &params)
{
    if (password.empty()) {
        throw CryptoError("deriveMasterKey: empty password");
    }
    if (emailLower.empty()) {
        throw CryptoError("deriveMasterKey: empty email");
    }
    const uint8_t *email = reinterpret_cast<const uint8_t *>(emailLower.data());

    switch (params.type) {
    case KdfType::Pbkdf2Sha256:
        return pbkdf2Sha256(password, email, emailLower.size(),
                            params.iterations, 32);
    case KdfType::Argon2id: {
        SecureBytes salt = sha256(email, emailLower.size());
        return argon2id(password, salt.data(), salt.size(),
                        params.iterations, params.memoryMiB, params.parallelism, 32);
    }
    }
    throw CryptoError("deriveMasterKey: unknown KDF type");
}

SecureBytes deriveMasterPasswordHash(const SecureBytes &masterKey,
                                     const SecureBytes &password)
{
    if (masterKey.empty() || password.empty()) {
        throw CryptoError("deriveMasterPasswordHash: empty input");
    }
    return pbkdf2Sha256(masterKey, password.data(), password.size(), 1, 32);
}

} // namespace Crypto
} // namespace BitVault
