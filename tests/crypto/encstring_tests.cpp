#include <cstring>

#include "encstring.h"
#include "../check.h"

using namespace BitVault::Crypto;

namespace {

SymmetricKey testKey()
{
    // Fixed, arbitrary test key (NOT a real secret).
    std::vector<uint8_t> enc = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    std::vector<uint8_t> mac = fromHex(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    SymmetricKey key;
    key.encKey = SecureBytes(enc.data(), enc.size());
    key.macKey = SecureBytes(mac.data(), mac.size());
    return key;
}

SecureBytes fromText(const std::string &text)
{
    return SecureBytes(reinterpret_cast<const uint8_t *>(text.data()),
                       text.size());
}

std::string toText(const SecureBytes &bytes)
{
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       bytes.size());
}

} // namespace

void runEncStringTests()
{
    const SymmetricKey key = testKey();

    // Round-trip: encrypt → serialize → parse → decrypt.
    {
        const std::string plaintext = "the quick brown fox jumps over 16";
        EncString enc = encryptAes256CbcHmac(fromText(plaintext), key);
        CHECK(enc.type == 2);
        CHECK(enc.iv.size() == 16);
        CHECK(enc.mac.size() == 32);

        const std::string serialized = enc.serialize();
        EncString parsed = EncString::parse(serialized);
        SecureBytes decrypted = decryptAes256CbcHmac(parsed, key);
        CHECK(toText(decrypted) == plaintext);
    }

    // Deterministic encryption with a fixed IV is stable and reversible.
    {
        const uint8_t iv[16] = {0};
        EncString a = encryptAes256CbcHmacWithIv(fromText("secret"), key, iv);
        EncString b = encryptAes256CbcHmacWithIv(fromText("secret"), key, iv);
        CHECK(a.serialize() == b.serialize());
        CHECK(toText(decryptAes256CbcHmac(a, key)) == "secret");
    }

    // Empty plaintext round-trips (one full padding block).
    {
        EncString enc = encryptAes256CbcHmac(SecureBytes(), key);
        CHECK(enc.ciphertext.size() == 16);
        SecureBytes decrypted = decryptAes256CbcHmac(enc, key);
        CHECK(decrypted.empty());
    }

    // --- Negative tests: every one must fail closed. ---

    // Tampered ciphertext → MAC failure.
    {
        EncString enc = encryptAes256CbcHmac(fromText("attack at dawn"), key);
        enc.ciphertext[0] ^= 0x01;
        CHECK_THROWS(decryptAes256CbcHmac(enc, key));
    }
    // Tampered IV → MAC failure (IV is authenticated).
    {
        EncString enc = encryptAes256CbcHmac(fromText("attack at dawn"), key);
        enc.iv[3] ^= 0x80;
        CHECK_THROWS(decryptAes256CbcHmac(enc, key));
    }
    // Tampered MAC → failure.
    {
        EncString enc = encryptAes256CbcHmac(fromText("attack at dawn"), key);
        enc.mac[31] ^= 0x01;
        CHECK_THROWS(decryptAes256CbcHmac(enc, key));
    }
    // Wrong key → MAC failure (never garbage plaintext).
    {
        EncString enc = encryptAes256CbcHmac(fromText("attack at dawn"), key);
        SymmetricKey wrong = testKey();
        wrong.macKey.data()[0] ^= 0xff;
        CHECK_THROWS(decryptAes256CbcHmac(enc, wrong));
    }

    // --- Parser negatives. ---
    CHECK_THROWS(EncString::parse(""));                    // empty
    CHECK_THROWS(EncString::parse("2"));                   // no dot
    CHECK_THROWS(EncString::parse(".aa|bb|cc"));           // empty type
    CHECK_THROWS(EncString::parse("x.aa|bb|cc"));          // non-numeric type
    CHECK_THROWS(EncString::parse("2.aGVsbG8="));          // missing parts
    CHECK_THROWS(EncString::parse("2.aa|bb|cc|dd"));       // too many parts
    CHECK_THROWS(EncString::parse("0.aGVsbG8=|aGVsbG8=")); // legacy type 0
    CHECK_THROWS(EncString::parse("3.aGVsbG8="));          // unsupported RSA variant
    CHECK_THROWS(EncString::parse("6.aGVsbG8="));          // deprecated RSA+HMAC
    CHECK_THROWS(EncString::parse("99.aa|bb|cc"));         // unknown type

    // Structurally invalid type 2 (sizes checked at parse time).
    {
        // iv too short (8 bytes), valid base64.
        CHECK_THROWS(EncString::parse("2.AAAAAAAAAAA=|AAAAAAAAAAAAAAAAAAAAAA"
                                      "==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                      "AAAAAAAAA="));
    }

    // decryptRsaOaepSha1 rejects wrong type.
    {
        EncString enc = encryptAes256CbcHmac(fromText("x"), key);
        CHECK_THROWS(decryptRsaOaepSha1(enc, SecureBytes()));
    }
}
