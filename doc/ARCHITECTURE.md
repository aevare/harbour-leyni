# BitVault — Architecture

The design goal is **auditability**: a reviewer must be able to answer "is my master
password handled correctly?" by reading a few hundred lines, and be able to verify that
the rest of the app *cannot* touch key material because the types don't allow it.

## Layering

Strict one-way dependencies, top to bottom:

```
qml/          Silica UI — presentation only, no logic
src/ui/       QObject view-models exposed to QML
src/vault/    decrypted vault state, lock/unlock lifecycle, item models
src/api/      HTTP client: prelogin, token, sync   (Qt Network)
src/crypto/   the auditable core                   (libcrypto + vendored libargon2 only)
```

A layer may only include headers from layers **below** it. `crypto/` includes nothing
from this project except itself. This is checked in review, and violations are treated
as bugs even when the code works.

## The crypto layer

```
src/crypto/
├── securebytes.{h,cpp}   mlock'd, zero-on-destroy, non-copyable secret buffer
├── kdf.{h,cpp}           PBKDF2-SHA256 and Argon2id master-key derivation
├── keys.{h,cpp}          HKDF stretch, master password hash, RSA-OAEP key unwrap
└── encstring.{h,cpp}     parse/decrypt/encrypt "2.<iv>|<ct>|<mac>" strings
```

`pinwrap.{h,cpp}` (opt-in PIN unlock) also lives here.

Rules:

- **Qt-free** (at most Qt Core), so it compiles and its tests run on plain Linux.
  CI runs these tests on every push without the Sailfish SDK.
- Pure functions: bytes in, bytes out. No I/O, no network, no global state.
- Thin, literal wrappers over libcrypto (`EVP_*`). No cipher-provider abstractions,
  no plugin interfaces. Short and boring is the point.
- MAC is verified (constant-time) **before** any decryption. Failures are errors,
  never silently-empty results.
- Tested against known-answer vectors generated with the official Bitwarden client,
  plus negative tests (tampered MAC, truncated input, wrong key must all fail closed).

## Secret handling

- All key material and passwords live in `SecureBytes`: `mlock`ed, explicitly zeroed
  on destruction, non-copyable (move-only), and with **no conversion to `QString`**.
  `QString` is implicitly shared and never zeroed — it must never hold a secret.
  This makes "secrets never reach the UI layer" a compile error, not a convention.
- The UI layer receives only decrypted *display* values the user asked for
  (a username, a revealed password), never keys.
- Locking the vault destroys every `SecureBytes` and all decrypted item data.

## Data at rest

The `/api/sync` response is stored **exactly as the server sent it** — it is already
end-to-end encrypted by design. Nothing decrypted is ever written to disk. The blob
lives in the Sailjail-private data directory
(`~/.local/share/<org>/harbour-bitvault/`), unreadable by other sandboxed apps.
The app requests only the `Internet` permission.

## Writes (create / edit / delete)

Write support mirrors the read path in reverse, and the direction of trust is the
same: **the plaintext→ciphertext transform is concentrated in `src/vault/`**, which
owns the keys. The user types plaintext in QML; `src/ui/` hands it to the vault as a
`QVariantMap`; the vault encrypts each field into an EncString and assembles the
request-body JSON; `src/api/` is a dumb Bearer transport that ships those bytes. The
API layer never sees plaintext, and no security decision lives in QML. After a
successful write the app re-syncs and reloads — it never patches local state, so the
on-disk blob stays byte-identical to what the server holds. See `doc/PROTOCOL.md`
"Writes".

## QML rules

- QML is presentation only: layout, bindings to view-model properties, navigation.
- No security-relevant JavaScript in QML. If a `.qml` file grows an `if` about
  crypto, locking, or secrets, that logic moves to C++.
- The cover page shows lock state and counts, never item data.

## Platform honesty (documented, not worked around)

- No system-wide autofill: Sailfish OS has no autofill framework. Copy-to-clipboard
  (with auto-clear) is the ceiling.
- No hardware keystore: default mode requires the master password on every unlock.
  Any convenience unlock (PIN) is opt-in with its weaker threat model documented
  in `SECURITY.md`.
- No WebAuthn/FIDO2 second factor: no platform support; API-key login is the
  workaround for hardware-key users.
