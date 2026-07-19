// Random password generation.
//
// Security note: generation quality is what makes a generated password strong.
// Two things must hold, and both are tested:
//   - the randomness is a CSPRNG (OpenSSL RAND_bytes), never a PRNG like rand();
//   - selection is UNBIASED. A naive `RAND_byte % poolSize` skews toward the
//     low end of the pool whenever poolSize does not divide 256; randomIndex()
//     uses rejection sampling so every index is uniform.
#pragma once

#include <cstdint>
#include <string>

namespace BitVault {
namespace Crypto {

struct PasswordOptions {
    int length = 16;
    bool lowercase = true;
    bool uppercase = true;
    bool digits = true;
    bool symbols = true;
    // Exclude visually ambiguous characters: I l 1 O 0 o.
    bool avoidAmbiguous = false;
    // At least this many digits / symbols (applied only when that class is on).
    int minDigits = 1;
    int minSymbols = 1;
};

// Generates a password satisfying opts. Throws CryptoError if no character
// class is enabled, or if length cannot satisfy the required minimums plus one
// of every enabled class.
std::string generatePassword(const PasswordOptions &opts);

// Uniformly random index in [0, bound) from the CSPRNG, via rejection
// sampling. bound must be > 0. Exposed for tests.
uint32_t randomIndex(uint32_t bound);

} // namespace Crypto
} // namespace BitVault
