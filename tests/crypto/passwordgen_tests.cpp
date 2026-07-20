#include <string>

#include "passwordgen.h"
#include "../check.h"

using namespace Leyni::Crypto;

namespace {

int countIn(const std::string &s, const std::string &set)
{
    int n = 0;
    for (char c : s) {
        if (set.find(c) != std::string::npos) {
            ++n;
        }
    }
    return n;
}

const std::string kLower = "abcdefghijklmnopqrstuvwxyz";
const std::string kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string kDigit = "0123456789";
const std::string kSymbol = "!@#$%^&*()-_=+[]{};:,.?";

} // namespace

void runPasswordGenTests()
{
    // randomIndex: always in range, and (for small bounds) covers everything.
    {
        for (uint32_t bound : {1u, 2u, 7u, 10u, 62u, 100u, 256u}) {
            bool seen[256] = {false};
            for (int i = 0; i < 4000; ++i) {
                uint32_t v = randomIndex(bound);
                CHECK(v < bound);
                seen[v] = true;
            }
            for (uint32_t v = 0; v < bound; ++v) {
                CHECK(seen[v]); // every value must be reachable
            }
        }
        CHECK_THROWS(randomIndex(0));
    }

    // Default options: correct length, only allowed characters, one of each
    // enabled class present. Checked over many samples.
    {
        PasswordOptions opts; // length 16, all classes, minDigits/minSymbols 1
        for (int i = 0; i < 300; ++i) {
            const std::string pw = generatePassword(opts);
            CHECK(static_cast<int>(pw.size()) == 16);
            const std::string all = kLower + kUpper + kDigit + kSymbol;
            for (char c : pw) {
                CHECK(all.find(c) != std::string::npos);
            }
            CHECK(countIn(pw, kLower) >= 1);
            CHECK(countIn(pw, kUpper) >= 1);
            CHECK(countIn(pw, kDigit) >= 1);
            CHECK(countIn(pw, kSymbol) >= 1);
        }
    }

    // Length is honored across a range.
    {
        for (int len : {4, 8, 20, 64, 128}) {
            PasswordOptions opts;
            opts.length = len;
            CHECK(static_cast<int>(generatePassword(opts).size()) == len);
        }
    }

    // Minimum digit / symbol counts are met.
    {
        PasswordOptions opts;
        opts.length = 20;
        opts.minDigits = 4;
        opts.minSymbols = 3;
        for (int i = 0; i < 200; ++i) {
            const std::string pw = generatePassword(opts);
            CHECK(countIn(pw, kDigit) >= 4);
            CHECK(countIn(pw, kSymbol) >= 3);
        }
    }

    // Avoid-ambiguous excludes I l 1 O 0 o.
    {
        PasswordOptions opts;
        opts.length = 40;
        opts.avoidAmbiguous = true;
        for (int i = 0; i < 300; ++i) {
            const std::string pw = generatePassword(opts);
            CHECK(countIn(pw, "Il1O0o") == 0);
        }
    }

    // A single enabled class yields only that class.
    {
        PasswordOptions opts;
        opts.length = 24;
        opts.lowercase = false;
        opts.uppercase = false;
        opts.symbols = false;
        opts.digits = true;
        opts.minSymbols = 0;
        for (int i = 0; i < 100; ++i) {
            const std::string pw = generatePassword(opts);
            CHECK(static_cast<int>(pw.size()) == 24);
            CHECK(countIn(pw, kDigit) == 24);
        }
    }

    // Error cases fail closed.
    {
        PasswordOptions none;
        none.lowercase = none.uppercase = none.digits = none.symbols = false;
        CHECK_THROWS(generatePassword(none));

        PasswordOptions tooShort; // 4 classes each need >=1, length 3
        tooShort.length = 3;
        CHECK_THROWS(generatePassword(tooShort));

        PasswordOptions zero;
        zero.length = 0;
        CHECK_THROWS(generatePassword(zero));

        PasswordOptions huge;
        huge.length = 257;
        CHECK_THROWS(generatePassword(huge));
    }
}
