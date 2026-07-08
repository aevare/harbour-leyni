// This directory will contain the auditable crypto core (see doc/ARCHITECTURE.md).
// It must never gain dependencies beyond libcrypto and vendored libargon2, and it
// must never do I/O. Everything here is pure functions: bytes in, bytes out.
//
// This file is a Phase 0 placeholder. The real API (SecureBytes, kdf, keys,
// EncString) lands in Phase 1.
#pragma once

namespace BitVault {
namespace Crypto {

const char *version();

} // namespace Crypto
} // namespace BitVault
