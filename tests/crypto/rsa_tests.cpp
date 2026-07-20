// RSA-OAEP(SHA-1) unwrap tests. No public Bitwarden KAT was available for
// this path, so this is a round-trip against OpenSSL's own OAEP encryption
// (independent code path from ours) with a freshly generated key. A true
// interop vector (an org key wrapped by the official client) is planned once
// the Phase 2 test account exists — see doc/TESTING.md.
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>
#include <vector>

#include "encstring.h"
#include "base64.h"
#include "keys.h"
#include "../check.h"

using namespace Leyni::Crypto;

namespace {

struct PkeyDeleter {
    void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); }
};
struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *c) const { EVP_PKEY_CTX_free(c); }
};

} // namespace

void runRsaTests()
{
    // Generate a throwaway RSA-2048 key.
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> genCtx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    CHECK(genCtx != nullptr);
    CHECK(EVP_PKEY_keygen_init(genCtx.get()) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(genCtx.get(), 2048) == 1);
    EVP_PKEY *rawKey = nullptr;
    CHECK(EVP_PKEY_keygen(genCtx.get(), &rawKey) == 1);
    std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey(rawKey);

    // DER-encode the private key the way the vault stores it.
    int derLen = i2d_PrivateKey(pkey.get(), nullptr);
    CHECK(derLen > 0);
    std::vector<uint8_t> der(static_cast<size_t>(derLen));
    uint8_t *derPtr = der.data();
    CHECK(i2d_PrivateKey(pkey.get(), &derPtr) == derLen);
    SecureBytes derKey(der.data(), der.size());

    // Encrypt a 64-byte "org key" with OpenSSL's OAEP-SHA1 directly.
    std::vector<uint8_t> orgKey(64);
    for (size_t i = 0; i < orgKey.size(); ++i) {
        orgKey[i] = static_cast<uint8_t>(i * 3 + 1);
    }
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> encCtx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr));
    CHECK(encCtx != nullptr);
    CHECK(EVP_PKEY_encrypt_init(encCtx.get()) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_padding(encCtx.get(), RSA_PKCS1_OAEP_PADDING) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_oaep_md(encCtx.get(), EVP_sha1()) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_mgf1_md(encCtx.get(), EVP_sha1()) == 1);
    size_t ctLen = 0;
    CHECK(EVP_PKEY_encrypt(encCtx.get(), nullptr, &ctLen,
                           orgKey.data(), orgKey.size()) == 1);
    std::vector<uint8_t> ciphertext(ctLen);
    CHECK(EVP_PKEY_encrypt(encCtx.get(), ciphertext.data(), &ctLen,
                           orgKey.data(), orgKey.size()) == 1);
    ciphertext.resize(ctLen);
    CHECK(ciphertext.size() == 256); // RSA-2048

    // Our unwrap must recover it, both directly and via an EncString type 4.
    {
        SecureBytes plain = rsaOaepSha1Decrypt(derKey, ciphertext.data(),
                                               ciphertext.size());
        CHECK(plain.size() == orgKey.size());
        CHECK(constantTimeEqual(plain.data(), orgKey.data(), orgKey.size()));
    }
    {
        const std::string text =
            "4." + base64Encode(ciphertext.data(), ciphertext.size());
        EncString enc = EncString::parse(text);
        CHECK(enc.type == 4);
        SecureBytes plain = decryptRsaOaepSha1(enc, derKey);
        CHECK(constantTimeEqual(plain.data(), orgKey.data(), orgKey.size()));
    }

    // Negatives: tampered ciphertext and truncated/garbage key fail closed.
    {
        std::vector<uint8_t> bad = ciphertext;
        bad[128] ^= 0x01;
        CHECK_THROWS(rsaOaepSha1Decrypt(derKey, bad.data(), bad.size()));
    }
    {
        SecureBytes junk(der.data(), der.size() / 2);
        CHECK_THROWS(rsaOaepSha1Decrypt(junk, ciphertext.data(),
                                        ciphertext.size()));
    }
}
