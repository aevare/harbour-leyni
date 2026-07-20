# Leyni

A fully native, open-source Bitwarden/Vaultwarden client for Sailfish OS — Qt/C++ and
Silica QML only. No Node.js, no bundled Bitwarden CLI, no background scripts wrapping
someone else's binary.

[![Crypto tests](https://github.com/aevare/harbour-leyni/actions/workflows/crypto-tests.yml/badge.svg)](https://github.com/aevare/harbour-leyni/actions/workflows/crypto-tests.yml)
[![API tests](https://github.com/aevare/harbour-leyni/actions/workflows/api-tests.yml/badge.svg)](https://github.com/aevare/harbour-leyni/actions/workflows/api-tests.yml)
[![SFOS RPM build](https://github.com/aevare/harbour-leyni/actions/workflows/sfos-build.yml/badge.svg)](https://github.com/aevare/harbour-leyni/actions/workflows/sfos-build.yml)

## Project status

**Read-only MVP, working on-device.** Phases 0–4 of [doc/PLAN.md](doc/PLAN.md) are
complete: login (including TOTP/email two-factor), sync, offline unlock, search and
folder filtering, item details with copy and reveal, TOTP code generation with
countdown, clipboard auto-clear, auto-lock, and lock-on-minimize — against Vaultwarden
and Bitwarden-compatible servers. Write support (creating/editing items) does not
exist yet. Hardening and a first packaged release are in progress (Phase 5).

## What it does today

- Sign in to bitwarden.com (US/EU) or any self-hosted/Vaultwarden server;
  two-factor via authenticator app or email code; API-key login as fallback
- Sync the encrypted vault and store it as-is (the blob on disk stays
  end-to-end encrypted); unlock and browse fully offline afterwards
- Logins, secure notes, cards, and identities; organization items included
- Search, folder filtering, favorites; reveal-on-tap or copy passwords
- TOTP codes (RFC 6238, SHA-1/256/512, otpauth:// URIs) with countdown
- Clipboard auto-clear, auto-lock timer, lock on minimize — all configurable

## Design for trust

The app is layered so the security-critical code is small and self-contained: the
crypto core in `src/crypto/` depends on nothing but libcrypto and a vendored
libargon2, does no I/O, and is unit-tested independently of the rest of the app.
Secrets are typed (`SecureBytes`: mlocked, zeroed on destruction, no conversion to
`QString`) so they cannot silently reach the UI layer, which is presentation-only
QML behind a single C++ bridge. See [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) for
the layering and secret-handling rules.

Correctness is proven, not asserted:

- **Known-answer tests** against Bitwarden's own SDK test vectors
  (`bitwarden/sdk-internal`) show byte-identical key derivation, key stretching,
  password hashing, and EncString decryption — every vector cites its source
  permalink in [tests/crypto/vector_tests.cpp](tests/crypto/vector_tests.cpp)
- Primitives are tested against RFC 5869, RFC 4231, RFC 7914, RFC 4226/6238,
  NIST SP 800-38A, and the argon2 reference test suite
- **Interop is tested live in CI**: an account registered entirely with this
  code is accepted by a real Vaultwarden, and the protected key the server
  returns at login decrypts back to the exact key that was generated
- Negative tests fail closed (tampered MAC/IV/ciphertext, wrong keys, malformed
  input); the whole suite also runs under ASan+UBSan
- The offline vault fixture in [tests/fixtures/](tests/fixtures/) is fully
  reproducible — account credentials are public test data and the TOTP secret is
  the RFC reference key, so published RFC values verify the implementation

See [doc/TESTING.md](doc/TESTING.md) for the complete strategy.

## Building

On-device / SDK build with `sfdk`:

```
sfdk build
sfdk deploy --sdk
```

To build and test the crypto core on any Linux machine, without the Sailfish SDK:

```
cmake -B build -DBUILD_APP=OFF
cmake --build build
ctest --test-dir build
```

To also build the API/vault layers and their tests (needs Qt5 Core+Network, e.g.
`qtbase5-dev`):

```
cmake -B build -DBUILD_APP=OFF -DBUILD_API=ON
cmake --build build
ctest --test-dir build -LE integration          # offline tests
ctest --test-dir build -L integration           # needs a local Vaultwarden (see dev/)
```

## Development server

The `dev/` directory contains a `docker-compose.yml` that runs a local Vaultwarden
instance for testing against, instead of hitting bitwarden.com. See
[dev/README.md](dev/README.md) for usage.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

## Known platform limitations

Sailfish OS has no system-wide autofill framework, no WebAuthn/FIDO2 support, no
biometric API for third-party apps, and no app-accessible hardware keystore, so none
of those are available in this app; see [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md)
for how these are documented rather than worked around. Names and display strings
live in regular Qt strings whose memory cannot be explicitly zeroed — keys and
passwords never do.
