# tests/fixtures/sync.json

A raw `GET /api/sync` response captured from a dedicated, throwaway
Vaultwarden account. `tests/vault/vault_tests.cpp` unlocks it **offline**
(no network, no live server) and asserts on decrypted item names, fields,
folder structure, and TOTP codes. This is the Phase 3 fixture described in
`doc/TESTING.md` Layer 2.

The account holds no real data. Its credentials are public on purpose — that
is the point: anyone can regenerate this fixture themselves and confirm it
matches, or unlock it with the official Bitwarden CLI/clients to audit that
Leyni's crypto reads it correctly.

## Account

- Server: local Vaultwarden, generated with `vaultwarden/server:latest`
  (Debian trixie base, pulled 2026-07-08; re-pull `latest` to reproduce
  against whatever the image currently is — the fixture is not tied to a
  specific Vaultwarden git SHA)
- Email: `fixture@bitvault.test`
- Password: `FixtureVault123!`
- KDF: PBKDF2-SHA256, 600000 iterations

## Contents

- 1 folder: "Work"
- 4 ciphers, all personal (no organization):
  - **Example Login** — username `alice@example.com`, password
    `s3cret-Pa55`, URI `https://example.com`, and a TOTP secret (see below).
    No folder.
  - **Work Login** — username `bob@example.com`, password
    `work-Pa55w0rd`, filed under the "Work" folder. No TOTP.
  - **Fixture Note** (secure note, favorite) — body "the note body".
  - **Fixture Card** — cardholder "Alice Example", Visa, number
    `4111111111111111`, exp 12/2030, code `123`.

## TOTP secret provenance

The TOTP secret on "Example Login" is **not** randomly generated. It is the
base32 encoding of the RFC 6238 / RFC 4226 Appendix D reference key, the
ASCII string `"12345678901234567890"`:

```
base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

Using the official test key means the resulting TOTP codes are the exact
values published in RFC 4226 Appendix D / RFC 6238 Appendix B (e.g. `755224`
at Unix time 29, `287082` at Unix time 59) — a reviewer can verify Leyni's
TOTP implementation against the RFCs directly, with no trust required in how
the fixture was produced.

## Regeneration

The fixture is deterministic in content (same account, same items) but not
byte-identical between runs — the sync response embeds fresh IVs/MACs on
every EncString and a fresh RSA keypair, and Vaultwarden assigns new cipher
IDs and timestamps each time. Regenerate it like this:

1. Start a fresh local Vaultwarden (wipes any prior `fixture@bitvault.test`
   account — the fixture generator is not idempotent against a
   pre-populated instance):
   ```
   cd dev
   rm -rf vw-data       # drop any previous fixture account
   docker compose up -d
   # wait until http://127.0.0.1:8000/alive responds
   ```
2. Build the `generate_sync_fixture` tool and run it against the local
   server in one container (the binary needs the container's Qt/OpenSSL
   runtime, so build and run must share it; same image CI uses):
   ```
   cd /path/to/harbour-leyni
   docker run --rm --network host -v "$(pwd)":/work -w /work ubuntu:24.04 bash -c '
     apt-get update &&
     apt-get install -y build-essential cmake libssl-dev qtbase5-dev &&
     cmake -B build -DBUILD_APP=OFF -DBUILD_API=ON &&
     cmake --build build -- -j$(nproc) &&
     ./build/tests/generate_sync_fixture tests/fixtures/sync.json
   '
   ```
   It prints the account email/password and every folder/cipher it creates
   as it goes; it exits 1 with the HTTP status and response body on any
   failure.
3. Bring Vaultwarden back down (`cd dev && docker compose down`), review the
   diff to `sync.json`, and commit it along with this README if anything
   here changed.
4. Re-run `ctest -R vault_tests` (no server needed) to confirm the new
   fixture still unlocks and every assertion in `tests/vault/vault_tests.cpp`
   still holds.
