#include "pinwrap.h"

#include <openssl/rand.h>

#include "base64.h"
#include "crypto.h"
#include "encstring.h"
#include "kdf.h"
#include "keys.h"

namespace BitVault {
namespace Crypto {

namespace {

constexpr size_t kSaltLen = 16;
constexpr char kTag[] = "BWPIN1";

// Derives the 64-byte key-encryption-key (32 enc + 32 mac) from the PIN.
SymmetricKey deriveKek(const SecureBytes &pin, const std::vector<uint8_t> &salt,
                       const PinWrapParams &params)
{
    SecureBytes raw = argon2id(pin, salt.data(), salt.size(), params.iterations,
                               params.memoryMiB, params.parallelism, 64);
    return symmetricKeyFromBytes(raw);
}

// Parses a decimal field into a bounded uint32, throwing on anything else.
uint32_t parseUint(const std::string &s)
{
    if (s.empty() || s.size() > 9) {
        throw CryptoError("PinWrappedKey::parse: bad numeric field");
    }
    uint32_t value = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            throw CryptoError("PinWrappedKey::parse: non-digit in field");
        }
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    return value;
}

} // namespace

SecureBytes randomBytes(size_t n)
{
    SecureBytes out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throw CryptoError("randomBytes: RAND_bytes failed");
    }
    return out;
}

std::string PinWrappedKey::serialize() const
{
    return std::string(kTag) + ":" + std::to_string(params.iterations) + ":"
           + std::to_string(params.memoryMiB) + ":"
           + std::to_string(params.parallelism) + ":"
           + base64Encode(salt.data(), salt.size()) + ":" + encString;
}

PinWrappedKey PinWrappedKey::parse(const std::string &text)
{
    // Split into exactly 6 fields on ':'. The encstring (field 6) contains no
    // ':' so it is taken verbatim as the remainder.
    std::vector<std::string> parts;
    size_t start = 0;
    for (int i = 0; i < 5; ++i) {
        size_t pos = text.find(':', start);
        if (pos == std::string::npos) {
            throw CryptoError("PinWrappedKey::parse: too few fields");
        }
        parts.push_back(text.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(text.substr(start));

    if (parts[0] != kTag) {
        throw CryptoError("PinWrappedKey::parse: bad tag");
    }

    PinWrappedKey out;
    out.params.iterations = parseUint(parts[1]);
    out.params.memoryMiB = parseUint(parts[2]);
    out.params.parallelism = parseUint(parts[3]);
    out.salt = base64Decode(parts[4]);
    if (out.salt.size() != kSaltLen) {
        throw CryptoError("PinWrappedKey::parse: wrong salt length");
    }
    // Validate the encstring structure now so a corrupt file fails on load,
    // not mid-unwrap. (Also rejects any non-type-2 payload.)
    EncString::parse(parts[5]);
    out.encString = parts[5];
    return out;
}

PinWrappedKey wrapWithPin(const SecureBytes &secret, const SecureBytes &pin)
{
    PinWrappedKey out;
    out.params = PinWrapParams{};
    SecureBytes saltBytes = randomBytes(kSaltLen);
    out.salt.assign(saltBytes.data(), saltBytes.data() + saltBytes.size());

    SymmetricKey kek = deriveKek(pin, out.salt, out.params);
    out.encString = encryptAes256CbcHmac(secret, kek).serialize();
    return out;
}

SecureBytes unwrapWithPin(const PinWrappedKey &wrapped, const SecureBytes &pin)
{
    SymmetricKey kek = deriveKek(pin, wrapped.salt, wrapped.params);
    // decryptAes256CbcHmac verifies the MAC in constant time before touching
    // the ciphertext: a wrong PIN throws here, cleanly.
    return decryptAes256CbcHmac(EncString::parse(wrapped.encString), kek);
}

} // namespace Crypto
} // namespace BitVault
