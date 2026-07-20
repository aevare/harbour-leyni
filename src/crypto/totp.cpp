#include "totp.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto.h"

namespace Leyni {
namespace Crypto {

std::vector<uint8_t> base32Decode(const std::string &text)
{
    std::vector<uint8_t> out;
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        if (c == ' ' || c == '=' ) {
            continue;
        }
        int value;
        if (c >= 'A' && c <= 'Z') {
            value = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            value = c - 'a';
        } else if (c >= '2' && c <= '7') {
            value = c - '2' + 26;
        } else {
            throw CryptoError("base32Decode: invalid character");
        }
        buffer = (buffer << 5) | static_cast<uint32_t>(value);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
    }
    return out;
}

std::string hotp(const SecureBytes &key, uint64_t counter, int digits,
                 TotpAlgorithm algorithm)
{
    if (key.empty()) {
        throw CryptoError("hotp: empty key");
    }
    if (digits < 6 || digits > 10) {
        throw CryptoError("hotp: digits out of range");
    }

    const EVP_MD *md = nullptr;
    switch (algorithm) {
    case TotpAlgorithm::Sha1:
        md = EVP_sha1();
        break;
    case TotpAlgorithm::Sha256:
        md = EVP_sha256();
        break;
    case TotpAlgorithm::Sha512:
        md = EVP_sha512();
        break;
    }
    if (md == nullptr) {
        throw CryptoError("hotp: unknown algorithm");
    }

    uint8_t counterBytes[8];
    for (int i = 7; i >= 0; --i) {
        counterBytes[i] = static_cast<uint8_t>(counter & 0xff);
        counter >>= 8;
    }

    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int macLen = 0;
    if (HMAC(md, key.data(), static_cast<int>(key.size()), counterBytes,
             sizeof(counterBytes), mac, &macLen) == nullptr
            || macLen < 20) {
        throw CryptoError("hotp: HMAC failed");
    }

    // RFC 4226 §5.3 dynamic truncation.
    const unsigned int offset = mac[macLen - 1] & 0x0f;
    const uint32_t binary = (static_cast<uint32_t>(mac[offset] & 0x7f) << 24)
                          | (static_cast<uint32_t>(mac[offset + 1]) << 16)
                          | (static_cast<uint32_t>(mac[offset + 2]) << 8)
                          | static_cast<uint32_t>(mac[offset + 3]);

    uint64_t modulus = 1;
    for (int i = 0; i < digits; ++i) {
        modulus *= 10;
    }
    const uint64_t code = binary % modulus;

    std::string result = std::to_string(code);
    while (result.size() < static_cast<size_t>(digits)) {
        result.insert(result.begin(), '0');
    }
    return result;
}

std::string totp(const SecureBytes &key, uint64_t unixTime,
                 uint32_t periodSeconds, int digits, TotpAlgorithm algorithm)
{
    if (periodSeconds == 0) {
        throw CryptoError("totp: zero period");
    }
    return hotp(key, unixTime / periodSeconds, digits, algorithm);
}

} // namespace Crypto
} // namespace Leyni
