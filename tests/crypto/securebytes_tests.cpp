#include <cstring>

#include "securebytes.h"
#include "../check.h"

using namespace BitVault::Crypto;

void runSecureBytesTests()
{
    // Construction
    {
        SecureBytes empty;
        CHECK(empty.empty());
        CHECK(empty.size() == 0);
        CHECK(empty.data() == nullptr);

        SecureBytes zeroed(16);
        CHECK(zeroed.size() == 16);
        for (size_t i = 0; i < 16; ++i) {
            CHECK(zeroed.data()[i] == 0);
        }

        const uint8_t src[] = {1, 2, 3, 4};
        SecureBytes copied(src, sizeof(src));
        CHECK(copied.size() == 4);
        CHECK(std::memcmp(copied.data(), src, 4) == 0);
    }

    // Move transfers ownership and empties the source.
    {
        const uint8_t src[] = {9, 8, 7};
        SecureBytes a(src, sizeof(src));
        const uint8_t *ptr = a.data();
        SecureBytes b(std::move(a));
        CHECK(b.data() == ptr);
        CHECK(b.size() == 3);
        CHECK(a.data() == nullptr);
        CHECK(a.empty());

        SecureBytes c;
        c = std::move(b);
        CHECK(c.data() == ptr);
        CHECK(b.data() == nullptr);
    }

    // Constant-time equality
    {
        const uint8_t x[] = {1, 2, 3};
        const uint8_t y[] = {1, 2, 4};
        SecureBytes a(x, 3);
        SecureBytes b(x, 3);
        SecureBytes c(y, 3);
        SecureBytes d(x, 2);
        CHECK(a == b);
        CHECK(a != c);
        CHECK(a != d);
        SecureBytes e1, e2;
        CHECK(e1 == e2);
    }

    // secureZero actually zeroes.
    {
        uint8_t buf[32];
        std::memset(buf, 0xAA, sizeof(buf));
        secureZero(buf, sizeof(buf));
        for (size_t i = 0; i < sizeof(buf); ++i) {
            CHECK(buf[i] == 0);
        }
    }

    // constantTimeEqual basics.
    {
        const uint8_t x[] = {0xde, 0xad};
        const uint8_t y[] = {0xde, 0xad};
        const uint8_t z[] = {0xde, 0xae};
        CHECK(constantTimeEqual(x, y, 2));
        CHECK(!constantTimeEqual(x, z, 2));
        CHECK(!constantTimeEqual(nullptr, y, 2));
    }
}
