#include "base64.h"
#include "../check.h"

using namespace BitVault::Crypto;

void runBase64Tests()
{
    // RFC 4648 §10 test vectors.
    struct Vector { std::string plain; std::string encoded; };
    const Vector vectors[] = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };
    for (const Vector &v : vectors) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(v.plain.data());
        CHECK(base64Encode(p, v.plain.size()) == v.encoded);
        const std::vector<uint8_t> decoded = base64Decode(v.encoded);
        CHECK(std::string(decoded.begin(), decoded.end()) == v.plain);
    }

    // Binary round-trip across all byte values.
    {
        std::vector<uint8_t> all(256);
        for (size_t i = 0; i < all.size(); ++i) {
            all[i] = static_cast<uint8_t>(i);
        }
        CHECK(base64Decode(base64Encode(all.data(), all.size())) == all);
    }

    // Malformed input must throw, not decode loosely.
    CHECK_THROWS(base64Decode("Zg="));       // bad length
    CHECK_THROWS(base64Decode("Zg==="));     // bad length
    CHECK_THROWS(base64Decode("Zm 9v"));     // whitespace
    CHECK_THROWS(base64Decode("Zm\n9v"));    // newline
    CHECK_THROWS(base64Decode("Zm9$"));      // outside alphabet
    CHECK_THROWS(base64Decode("Z=g="));      // padding in the middle
    CHECK_THROWS(base64Decode("===="));      // only padding
}
