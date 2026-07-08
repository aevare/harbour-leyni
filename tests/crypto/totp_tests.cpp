// HOTP/TOTP known-answer tests.
//   RFC 4226 Appendix D (HOTP, SHA-1, secret "12345678901234567890")
//   RFC 6238 Appendix B (TOTP; per-algorithm secrets as defined there)
//   RFC 4648 §10 base32 vectors
#include <string>

#include "totp.h"
#include "../check.h"

using namespace BitVault::Crypto;

namespace {

SecureBytes asciiKey(const std::string &text)
{
    return SecureBytes(reinterpret_cast<const uint8_t *>(text.data()),
                       text.size());
}

} // namespace

void runTotpTests()
{
    // RFC 4648 §10: BASE32("") .. BASE32("foobar").
    {
        auto decodesTo = [](const std::string &encoded,
                            const std::string &plain) {
            const std::vector<uint8_t> decoded = base32Decode(encoded);
            return std::string(decoded.begin(), decoded.end()) == plain;
        };
        CHECK(decodesTo("", ""));
        CHECK(decodesTo("MY======", "f"));
        CHECK(decodesTo("MZXQ====", "fo"));
        CHECK(decodesTo("MZXW6===", "foo"));
        CHECK(decodesTo("MZXW6YQ=", "foob"));
        CHECK(decodesTo("MZXW6YTB", "fooba"));
        CHECK(decodesTo("MZXW6YTBOI======", "foobar"));
        // Authenticator conventions: lowercase, spaces, no padding.
        CHECK(decodesTo("mzxw6ytboi", "foobar"));
        CHECK(decodesTo("MZXW 6YTB OI", "foobar"));
        CHECK_THROWS(base32Decode("MZXW1===")); // '1' not in alphabet
        CHECK_THROWS(base32Decode("MZXW-YTB"));
    }

    // RFC 4226 Appendix D: the ten reference HOTP values.
    {
        const SecureBytes key = asciiKey("12345678901234567890");
        const char *expected[] = {
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        };
        for (uint64_t counter = 0; counter < 10; ++counter) {
            CHECK(hotp(key, counter, 6, TotpAlgorithm::Sha1)
                  == expected[counter]);
        }
    }

    // RFC 6238 Appendix B: 8-digit TOTP, 30 s period. The reference secrets
    // are the ASCII seed repeated to the HMAC's natural key length:
    // 20 bytes (SHA-1), 32 bytes (SHA-256), 64 bytes (SHA-512).
    {
        const SecureBytes key20 = asciiKey("12345678901234567890");
        const SecureBytes key32 =
            asciiKey("12345678901234567890123456789012");
        const SecureBytes key64 =
            asciiKey("1234567890123456789012345678901234567890"
                     "123456789012345678901234");

        struct Row {
            uint64_t time;
            const char *sha1;
            const char *sha256;
            const char *sha512;
        };
        const Row rows[] = {
            {59ULL,          "94287082", "46119246", "90693936"},
            {1111111109ULL,  "07081804", "68084774", "25091201"},
            {1111111111ULL,  "14050471", "67062674", "99943326"},
            {1234567890ULL,  "89005924", "91819424", "93441116"},
            {2000000000ULL,  "69279037", "90698825", "38618901"},
            {20000000000ULL, "65353130", "77737706", "47863826"},
        };
        for (const Row &row : rows) {
            CHECK(totp(key20, row.time, 30, 8, TotpAlgorithm::Sha1)
                  == row.sha1);
            CHECK(totp(key32, row.time, 30, 8, TotpAlgorithm::Sha256)
                  == row.sha256);
            CHECK(totp(key64, row.time, 30, 8, TotpAlgorithm::Sha512)
                  == row.sha512);
        }
    }

    // Zero-padding: 6-digit codes keep leading zeros (RFC 6238 B row 2).
    {
        const SecureBytes key = asciiKey("12345678901234567890");
        const std::string code = totp(key, 1111111109ULL, 30, 8,
                                      TotpAlgorithm::Sha1);
        CHECK(code == "07081804");
        CHECK(code.size() == 8);
    }

    // Error paths.
    {
        const SecureBytes key = asciiKey("12345678901234567890");
        CHECK_THROWS(hotp(SecureBytes(), 0, 6, TotpAlgorithm::Sha1));
        CHECK_THROWS(hotp(key, 0, 5, TotpAlgorithm::Sha1));
        CHECK_THROWS(hotp(key, 0, 11, TotpAlgorithm::Sha1));
        CHECK_THROWS(totp(key, 59, 0, 6, TotpAlgorithm::Sha1));
    }
}
