#include "encstring.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>

#include "base64.h"
#include "crypto.h"

namespace BitVault {
namespace Crypto {

namespace {

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

std::vector<std::string> splitParts(const std::string &data, char sep)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = data.find(sep, start);
        if (pos == std::string::npos) {
            parts.push_back(data.substr(start));
            return parts;
        }
        parts.push_back(data.substr(start, pos - start));
        start = pos + 1;
    }
}

// HMAC input is iv || ciphertext.
std::vector<uint8_t> macInput(const EncString &enc)
{
    std::vector<uint8_t> input;
    input.reserve(enc.iv.size() + enc.ciphertext.size());
    input.insert(input.end(), enc.iv.begin(), enc.iv.end());
    input.insert(input.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    return input;
}

} // namespace

EncString EncString::parse(const std::string &text)
{
    size_t dot = text.find('.');
    if (dot == std::string::npos || dot == 0) {
        throw CryptoError("EncString: missing type prefix");
    }
    const std::string typePart = text.substr(0, dot);
    for (char c : typePart) {
        if (c < '0' || c > '9') {
            throw CryptoError("EncString: non-numeric type");
        }
    }
    if (typePart.size() > 2) {
        throw CryptoError("EncString: type out of range");
    }
    const int type = std::stoi(typePart);
    const std::vector<std::string> parts = splitParts(text.substr(dot + 1), '|');

    EncString enc;
    enc.type = type;
    switch (type) {
    case 2:
        if (parts.size() != 3) {
            throw CryptoError("EncString: type 2 requires iv|ciphertext|mac");
        }
        enc.iv = base64Decode(parts[0]);
        enc.ciphertext = base64Decode(parts[1]);
        enc.mac = base64Decode(parts[2]);
        if (enc.iv.size() != 16) {
            throw CryptoError("EncString: type 2 iv must be 16 bytes");
        }
        if (enc.mac.size() != 32) {
            throw CryptoError("EncString: type 2 mac must be 32 bytes");
        }
        if (enc.ciphertext.empty() || enc.ciphertext.size() % 16 != 0) {
            throw CryptoError("EncString: type 2 ciphertext must be a"
                              " non-empty multiple of the AES block size");
        }
        return enc;
    case 4:
        if (parts.size() != 1) {
            throw CryptoError("EncString: type 4 requires a single part");
        }
        enc.ciphertext = base64Decode(parts[0]);
        if (enc.ciphertext.empty()) {
            throw CryptoError("EncString: type 4 empty ciphertext");
        }
        return enc;
    default:
        throw CryptoError("EncString: unsupported type "
                          + std::to_string(type));
    }
}

std::string EncString::serialize() const
{
    if (type != 2) {
        throw CryptoError("EncString::serialize: only type 2 is supported");
    }
    return "2." + base64Encode(iv.data(), iv.size())
         + "|" + base64Encode(ciphertext.data(), ciphertext.size())
         + "|" + base64Encode(mac.data(), mac.size());
}

SecureBytes decryptAes256CbcHmac(const EncString &enc, const SymmetricKey &key)
{
    if (enc.type != 2) {
        throw CryptoError("decryptAes256CbcHmac: not a type 2 EncString");
    }
    if (key.encKey.size() != 32 || key.macKey.size() != 32) {
        throw CryptoError("decryptAes256CbcHmac: bad key sizes");
    }

    // Encrypt-then-MAC: authenticate before touching the ciphertext.
    const std::vector<uint8_t> input = macInput(enc);
    const std::vector<uint8_t> expected =
        hmacSha256(key.macKey, input.data(), input.size());
    if (!constantTimeEqual(expected.data(), enc.mac.data(), expected.size())) {
        throw CryptoError("decryptAes256CbcHmac: MAC verification failed");
    }

    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                                   key.encKey.data(), enc.iv.data()) != 1) {
        throw CryptoError("decryptAes256CbcHmac: cipher init failed");
    }
    // Padded plaintext is at most ciphertext length.
    SecureBytes out(enc.ciphertext.size());
    int len1 = 0;
    int len2 = 0;
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &len1,
                          enc.ciphertext.data(),
                          static_cast<int>(enc.ciphertext.size())) != 1
            || EVP_DecryptFinal_ex(ctx.get(), out.data() + len1, &len2) != 1) {
        throw CryptoError("decryptAes256CbcHmac: decryption failed");
    }
    const size_t plainLen = static_cast<size_t>(len1) + static_cast<size_t>(len2);
    if (plainLen == out.size()) {
        return out;
    }
    return SecureBytes(out.data(), plainLen);
}

EncString encryptAes256CbcHmacWithIv(const SecureBytes &plaintext,
                                     const SymmetricKey &key,
                                     const uint8_t iv[16])
{
    if (key.encKey.size() != 32 || key.macKey.size() != 32) {
        throw CryptoError("encryptAes256CbcHmac: bad key sizes");
    }

    EncString enc;
    enc.type = 2;
    enc.iv.assign(iv, iv + 16);

    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                                   key.encKey.data(), enc.iv.data()) != 1) {
        throw CryptoError("encryptAes256CbcHmac: cipher init failed");
    }
    // PKCS#7 padding adds up to one full block.
    enc.ciphertext.resize(plaintext.size() + 16);
    int len1 = 0;
    int len2 = 0;
    if (EVP_EncryptUpdate(ctx.get(), enc.ciphertext.data(), &len1,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1
            || EVP_EncryptFinal_ex(ctx.get(),
                                   enc.ciphertext.data() + len1, &len2) != 1) {
        throw CryptoError("encryptAes256CbcHmac: encryption failed");
    }
    enc.ciphertext.resize(static_cast<size_t>(len1) + static_cast<size_t>(len2));

    const std::vector<uint8_t> input = macInput(enc);
    enc.mac = hmacSha256(key.macKey, input.data(), input.size());
    return enc;
}

EncString encryptAes256CbcHmac(const SecureBytes &plaintext,
                               const SymmetricKey &key)
{
    uint8_t iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        throw CryptoError("encryptAes256CbcHmac: RAND_bytes failed");
    }
    return encryptAes256CbcHmacWithIv(plaintext, key, iv);
}

SecureBytes decryptRsaOaepSha1(const EncString &enc,
                               const SecureBytes &privateKeyDer)
{
    if (enc.type != 4) {
        throw CryptoError("decryptRsaOaepSha1: not a type 4 EncString");
    }
    return rsaOaepSha1Decrypt(privateKeyDer,
                              enc.ciphertext.data(), enc.ciphertext.size());
}

} // namespace Crypto
} // namespace BitVault
