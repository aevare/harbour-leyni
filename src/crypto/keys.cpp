#include "keys.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>

#include <memory>

#include "crypto.h"

namespace BitVault {
namespace Crypto {

namespace {

struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *ctx) const { EVP_PKEY_CTX_free(ctx); }
};
struct PkeyDeleter {
    void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); }
};

} // namespace

SecureBytes hkdfExpandSha256(const SecureBytes &prk,
                             const std::string &info, size_t outLen)
{
    if (prk.empty()) {
        throw CryptoError("hkdfExpandSha256: empty key");
    }
    if (outLen == 0) {
        throw CryptoError("hkdfExpandSha256: zero output length");
    }
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) {
        throw CryptoError("hkdfExpandSha256: context allocation failed");
    }
    SecureBytes out(outLen);
    size_t written = outLen;
    if (EVP_PKEY_derive_init(ctx.get()) != 1
            || EVP_PKEY_CTX_hkdf_mode(ctx.get(),
                                      EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1
            || EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1
            || EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), prk.data(),
                                          static_cast<int>(prk.size())) != 1
            || EVP_PKEY_CTX_add1_hkdf_info(
                   ctx.get(),
                   reinterpret_cast<const unsigned char *>(info.data()),
                   static_cast<int>(info.size())) != 1
            || EVP_PKEY_derive(ctx.get(), out.data(), &written) != 1
            || written != outLen) {
        throw CryptoError("hkdfExpandSha256: derivation failed");
    }
    return out;
}

SymmetricKey stretchMasterKey(const SecureBytes &masterKey)
{
    if (masterKey.size() != 32) {
        throw CryptoError("stretchMasterKey: master key must be 32 bytes");
    }
    SymmetricKey key;
    key.encKey = hkdfExpandSha256(masterKey, "enc", 32);
    key.macKey = hkdfExpandSha256(masterKey, "mac", 32);
    return key;
}

SymmetricKey symmetricKeyFromBytes(const SecureBytes &raw)
{
    if (raw.size() != 64) {
        throw CryptoError("symmetricKeyFromBytes: expected 64 bytes (enc||mac)");
    }
    SymmetricKey key;
    key.encKey = SecureBytes(raw.data(), 32);
    key.macKey = SecureBytes(raw.data() + 32, 32);
    return key;
}

std::vector<uint8_t> hmacSha256(const SecureBytes &key,
                                const uint8_t *data, size_t len)
{
    if (key.empty()) {
        throw CryptoError("hmacSha256: empty key");
    }
    std::vector<uint8_t> mac(32);
    unsigned int macLen = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             data, len, mac.data(), &macLen) == nullptr
            || macLen != mac.size()) {
        throw CryptoError("hmacSha256: HMAC failed");
    }
    return mac;
}

SecureBytes rsaOaepSha1Decrypt(const SecureBytes &privateKeyDer,
                               const uint8_t *ciphertext, size_t len)
{
    if (privateKeyDer.empty() || len == 0) {
        throw CryptoError("rsaOaepSha1Decrypt: empty input");
    }
    const unsigned char *der = privateKeyDer.data();
    std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey(
        d2i_AutoPrivateKey(nullptr, &der,
                           static_cast<long>(privateKeyDer.size())));
    if (!pkey) {
        throw CryptoError("rsaOaepSha1Decrypt: invalid private key DER");
    }
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr));
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) != 1
            || EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1
            || EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha1()) != 1
            || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha1()) != 1) {
        throw CryptoError("rsaOaepSha1Decrypt: context setup failed");
    }
    size_t outLen = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outLen, ciphertext, len) != 1) {
        throw CryptoError("rsaOaepSha1Decrypt: size query failed");
    }
    SecureBytes out(outLen);
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &outLen, ciphertext, len) != 1) {
        throw CryptoError("rsaOaepSha1Decrypt: decryption failed");
    }
    if (outLen != out.size()) {
        SecureBytes trimmed(out.data(), outLen);
        return trimmed;
    }
    return out;
}

} // namespace Crypto
} // namespace BitVault
