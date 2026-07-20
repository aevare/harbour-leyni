// Bounds and error-path tests for the KDFs. Known-answer vectors live in
// vector_tests.cpp.
#include "kdf.h"
#include "../check.h"

using namespace Leyni::Crypto;

void runKdfBoundsTests()
{
    const uint8_t salt[] = {'s', 'a', 'l', 't'};
    std::vector<uint8_t> pw = {'p', 'w'};
    SecureBytes password(pw.data(), pw.size());

    // PBKDF2 bounds.
    CHECK_THROWS(pbkdf2Sha256(password, salt, sizeof(salt), 0, 32));
    CHECK_THROWS(pbkdf2Sha256(password, salt, sizeof(salt),
                              kMaxPbkdf2Iterations + 1, 32));
    CHECK_THROWS(pbkdf2Sha256(password, salt, sizeof(salt), 1, 0));

    // Argon2id bounds: a hostile prelogin response must not be able to
    // demand unbounded memory or time.
    CHECK_THROWS(argon2id(password, salt, sizeof(salt), 0, 64, 4, 32));
    CHECK_THROWS(argon2id(password, salt, sizeof(salt),
                          kMaxArgon2Iterations + 1, 64, 4, 32));
    CHECK_THROWS(argon2id(password, salt, sizeof(salt), 3, 0, 4, 32));
    CHECK_THROWS(argon2id(password, salt, sizeof(salt), 3,
                          kMaxArgon2MemoryMiB + 1, 4, 32));
    CHECK_THROWS(argon2id(password, salt, sizeof(salt), 3, 64, 0, 32));
    CHECK_THROWS(argon2id(password, salt, sizeof(salt), 3, 64,
                          kMaxArgon2Parallelism + 1, 32));

    // deriveMasterKey input validation.
    KdfParams params;
    params.type = KdfType::Pbkdf2Sha256;
    params.iterations = 600000;
    CHECK_THROWS(deriveMasterKey(SecureBytes(), "user@example.com", params));
    CHECK_THROWS(deriveMasterKey(password, "", params));

    // deriveMasterPasswordHash input validation.
    CHECK_THROWS(deriveMasterPasswordHash(SecureBytes(), password));
    CHECK_THROWS(deriveMasterPasswordHash(password, SecureBytes()));

    // Different emails must give different keys (email is the salt).
    {
        KdfParams p;
        p.type = KdfType::Pbkdf2Sha256;
        p.iterations = 1000; // low for test speed only
        SecureBytes k1 = deriveMasterKey(password, "a@example.com", p);
        SecureBytes k2 = deriveMasterKey(password, "b@example.com", p);
        CHECK(k1.size() == 32 && k2.size() == 32);
        CHECK(k1 != k2);
    }

    // Argon2id smoke test: deterministic, 32 bytes, email-sensitive.
    {
        KdfParams p;
        p.type = KdfType::Argon2id;
        p.iterations = 2;
        p.memoryMiB = 16;
        p.parallelism = 2;
        SecureBytes k1 = deriveMasterKey(password, "a@example.com", p);
        SecureBytes k2 = deriveMasterKey(password, "a@example.com", p);
        SecureBytes k3 = deriveMasterKey(password, "b@example.com", p);
        CHECK(k1.size() == 32);
        CHECK(k1 == k2);
        CHECK(k1 != k3);
    }
}
