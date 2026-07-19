// PIN-wrapping of a secret (the 32-byte master key), for opt-in PIN unlock.
//
// THREAT MODEL — read before trusting this.
//   The wrapped blob is stored on disk in the app's private directory. Its
//   security rests ENTIRELY on the secrecy and entropy of the PIN: a numeric
//   PIN has only ~13 bits (4 digits) to ~20 bits (6 digits) of entropy. An
//   attacker who copies the blob off the device can brute-force it OFFLINE.
//   The aggressive Argon2id parameters below raise the per-guess cost, but do
//   not change the fundamental fact: PIN unlock protects against casual access
//   (a glance, a borrowed phone), NOT against a forensic adversary who images
//   the storage. This is documented for users in SECURITY.md.
//
// Scheme (deliberately built from the already-audited primitives):
//   salt = 16 random bytes
//   KEK  = Argon2id(PIN, salt, params) -> 64 bytes -> SymmetricKey(enc||mac)
//   blob = AES-256-CBC(secret) + HMAC-SHA256   (EncString type 2)
//   A wrong PIN fails as a MAC mismatch (CryptoError) — never as garbage.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "securebytes.h"

namespace BitVault {
namespace Crypto {

// Argon2id cost for the PIN key-encryption-key. Fixed and deliberately high:
// the wrapped key sits on disk and is offline-attackable, so every guess must
// be expensive. Within the argon2id() sanity bounds (see kdf.h). If these are
// ever raised, the params travel inside each blob so old files still unwrap.
struct PinWrapParams {
    uint32_t iterations = 8;
    uint32_t memoryMiB = 64;
    uint32_t parallelism = 4;
};

// Everything needed to unwrap except the PIN. None of it is secret on its own
// (salt/IV/MAC are public); the security is the PIN's entropy alone.
struct PinWrappedKey {
    PinWrapParams params;
    std::vector<uint8_t> salt;  // 16 bytes
    std::string encString;      // EncString type 2 of the wrapped secret

    // Compact single-line storage form:
    //   "BWPIN1:<iters>:<mem>:<par>:<base64 salt>:<encstring>"
    // The encstring is last and contains no ':', so the split is unambiguous.
    std::string serialize() const;

    // Throws CryptoError on any malformed input (wrong tag, field count,
    // out-of-range params, bad base64/salt length).
    static PinWrappedKey parse(const std::string &text);
};

// n cryptographically-secure random bytes (OpenSSL RAND_bytes). Throws on
// RNG failure — never returns weak/partial randomness.
SecureBytes randomBytes(size_t n);

// Wrap `secret` under `pin`. Generates a fresh random salt each call, so
// re-wrapping the same secret+PIN yields a different blob.
PinWrappedKey wrapWithPin(const SecureBytes &secret, const SecureBytes &pin);

// Unwrap. Throws CryptoError on a wrong PIN (MAC mismatch) or a tampered blob
// — indistinguishable by design. The caller counts failures and enforces the
// attempt limit; this function holds no state.
SecureBytes unwrapWithPin(const PinWrappedKey &wrapped, const SecureBytes &pin);

} // namespace Crypto
} // namespace BitVault
