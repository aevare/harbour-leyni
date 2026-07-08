# BitVault

A fully native, open-source Bitwarden/Vaultwarden client for Sailfish OS — Qt/C++ and
Silica QML only. No Node.js, no bundled Bitwarden CLI, no background scripts wrapping
someone else's binary.

## Project status

**Phase 0 — scaffold only.** This repository currently builds and packages an empty
placeholder app; none of the vault, crypto, or sync functionality exists yet. See
[doc/PLAN.md](doc/PLAN.md) for the full roadmap and current phase.

## Design for trust

The app is layered so the security-critical code is small and self-contained: the
crypto core in `src/crypto/` depends on nothing but libcrypto and a vendored
libargon2, does no I/O, and is unit-tested independently of the rest of the app.
Secrets are typed so they cannot silently reach the UI layer. See
[doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) for the full layering and secret-handling
rules.

## Building

On-device / SDK build with `sfdk`:

```
sfdk build
sfdk deploy --sdk
```

To build and test just the crypto core on any Linux machine, without the Sailfish SDK:

```
cmake -B build -DBUILD_APP=OFF
cmake --build build
ctest --test-dir build
```

## Development server

The `dev/` directory contains a `docker-compose.yml` that runs a local Vaultwarden
instance for testing against, instead of hitting bitwarden.com. See
[dev/README.md](dev/README.md) for usage.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

## Known platform limitations

Sailfish OS has no system-wide autofill framework and no WebAuthn/FIDO2 support, so
neither is available in this app; see [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) for
how these are documented rather than worked around.
