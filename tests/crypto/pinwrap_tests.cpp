#include <cstring>
#include <string>

#include "pinwrap.h"
#include "securebytes.h"
#include "../check.h"

using namespace BitVault::Crypto;

namespace {

SecureBytes pinFrom(const std::string &digits)
{
    return SecureBytes(reinterpret_cast<const uint8_t *>(digits.data()),
                       digits.size());
}

} // namespace

void runPinWrapTests()
{
    // A fixed 32-byte "master key" to stand in for the real secret.
    uint8_t secretBytes[32];
    for (int i = 0; i < 32; ++i) {
        secretBytes[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    SecureBytes secret(secretBytes, sizeof(secretBytes));

    // Round-trip: same PIN recovers the exact secret.
    {
        PinWrappedKey wrapped = wrapWithPin(secret, pinFrom("1234"));
        CHECK(wrapped.salt.size() == 16);
        SecureBytes out = unwrapWithPin(wrapped, pinFrom("1234"));
        CHECK(out.size() == 32);
        CHECK(std::memcmp(out.data(), secretBytes, 32) == 0);
    }

    // A wrong PIN fails as a MAC mismatch — never garbage.
    {
        PinWrappedKey wrapped = wrapWithPin(secret, pinFrom("1234"));
        CHECK_THROWS(unwrapWithPin(wrapped, pinFrom("1235")));
        CHECK_THROWS(unwrapWithPin(wrapped, pinFrom("12345")));
        CHECK_THROWS(unwrapWithPin(wrapped, pinFrom("")));
    }

    // serialize -> parse round-trips and still unwraps.
    {
        PinWrappedKey wrapped = wrapWithPin(secret, pinFrom("987654"));
        std::string text = wrapped.serialize();
        CHECK(text.rfind("BWPIN1:", 0) == 0);
        PinWrappedKey reparsed = PinWrappedKey::parse(text);
        CHECK(reparsed.salt == wrapped.salt);
        CHECK(reparsed.params.iterations == wrapped.params.iterations);
        CHECK(reparsed.params.memoryMiB == wrapped.params.memoryMiB);
        CHECK(reparsed.params.parallelism == wrapped.params.parallelism);
        SecureBytes out = unwrapWithPin(reparsed, pinFrom("987654"));
        CHECK(std::memcmp(out.data(), secretBytes, 32) == 0);
    }

    // Fresh salt every call: same secret+PIN yields distinct blobs, both valid.
    {
        PinWrappedKey a = wrapWithPin(secret, pinFrom("0000"));
        PinWrappedKey b = wrapWithPin(secret, pinFrom("0000"));
        CHECK(a.salt != b.salt);
        CHECK(a.serialize() != b.serialize());
        CHECK(std::memcmp(unwrapWithPin(a, pinFrom("0000")).data(),
                          secretBytes, 32) == 0);
        CHECK(std::memcmp(unwrapWithPin(b, pinFrom("0000")).data(),
                          secretBytes, 32) == 0);
    }

    // Tampering the ciphertext or the salt breaks the MAC / KEK -> throws.
    {
        PinWrappedKey wrapped = wrapWithPin(secret, pinFrom("4242"));

        PinWrappedKey badSalt = wrapped;
        badSalt.salt[0] ^= 0x01; // different KEK -> MAC mismatch
        CHECK_THROWS(unwrapWithPin(badSalt, pinFrom("4242")));

        PinWrappedKey badBlob = PinWrappedKey::parse(wrapped.serialize());
        // Flip a byte inside the base64 ciphertext region of the encstring.
        std::string &s = badBlob.encString;
        size_t bar = s.find('|');
        CHECK(bar != std::string::npos);
        s[bar + 2] = (s[bar + 2] == 'A') ? 'B' : 'A';
        CHECK_THROWS(unwrapWithPin(badBlob, pinFrom("4242")));
    }

    // parse rejects malformed storage forms.
    {
        CHECK_THROWS(PinWrappedKey::parse("NOPE:8:64:4:AAAA:2.a|b|c"));
        CHECK_THROWS(PinWrappedKey::parse("BWPIN1:8:64:4"));          // too few
        CHECK_THROWS(PinWrappedKey::parse("BWPIN1:x:64:4:AAAA:2.a")); // bad num
        // Wrong salt length (3 bytes of base64, not 16).
        CHECK_THROWS(PinWrappedKey::parse("BWPIN1:8:64:4:AAAA:2.a|b|c"));
    }

    // randomBytes returns the requested length and is non-constant.
    {
        SecureBytes r1 = randomBytes(16);
        SecureBytes r2 = randomBytes(16);
        CHECK(r1.size() == 16);
        CHECK(r1 != r2);
        CHECK(randomBytes(0).empty());
    }
}
