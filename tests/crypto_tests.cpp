// Phase 0 placeholder test. Phase 1 replaces this with known-answer vector
// tests (PBKDF2/Argon2 derivation, EncString decrypt, RSA-OAEP unwrap, etc.)
// against fixtures generated with the official Bitwarden client.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "crypto.h"

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,         \
                    __LINE__, #cond);                                        \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

int main()
{
    CHECK(std::strcmp(BitVault::Crypto::version(), "0.1.0-phase0") == 0);

    printf("crypto_tests: all checks passed\n");
    return 0;
}
