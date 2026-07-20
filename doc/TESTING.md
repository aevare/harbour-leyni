# Leyni — Test Strategy

Tests here do double duty: they catch regressions, and they are the public
*evidence* that the crypto is correct. A reviewer who trusts nothing else can
read the fixtures and re-derive them with the official Bitwarden client.

## What exists today (Phase 0)

- `tests/crypto_tests.cpp` — placeholder binary using a plain `CHECK` macro,
  registered with CTest, built without any framework or Qt.
- CI (`crypto-tests.yml`) builds and runs it on plain ubuntu-latest on every push.
- `dev/docker-compose.yml` — local Vaultwarden, the target for future
  integration tests.

## Framework decision: none

Tests stay plain C++ (`main()` + a small `CHECK`/`CHECK_EQ` macro set, one
binary per layer). No GoogleTest/Catch2/doctest. Rationale: the crypto tests
are part of the audit surface, and a reviewer should not need to know a
framework's fixture model to see what is being asserted. If the macro set ever
exceeds ~50 lines, that decision gets revisited here.

## Layer 1 — crypto core (Phase 1, the bulk of the effort)

Location: `tests/crypto/`, no Qt, runs everywhere. Two tiers of known-answer
tests (KAT):

**Tier 1 — primitive vectors from public standards.** Prove our libcrypto and
libargon2 wrappers are called correctly, against vectors nobody can dispute:

| Primitive | Source |
|---|---|
| PBKDF2-SHA256 | RFC 7914 §11 / published SHA-256 vectors |
| HKDF-SHA256 | RFC 5869 Appendix A |
| HMAC-SHA256 | RFC 4231 |
| Argon2id | RFC 9106 test vector |
| AES-256-CBC | NIST CAVP vectors |

**Tier 2 — composition vectors from a real Bitwarden account.** Prove the
*protocol composition* (email-salted master key → stretched key → EncString
decrypt) matches Bitwarden exactly. A dedicated throwaway test account's
values (email, password, KDF settings, protected key, a handful of EncStrings)
are hard-coded as fixtures in `tests/fixtures/`, with a README documenting how
each value was produced with the official CLI so anyone can regenerate them.
The test account exists only for this purpose and holds no real data — its
"secrets" being public is the point.

**Negative tests, same weight as positive ones.** Tampered MAC, truncated
ciphertext, wrong key, malformed base64, unknown EncString type, empty input —
every one must fail closed with an error, never return garbage plaintext.

**SecureBytes behavioral tests.** Move semantics, zero-on-destroy (best-effort
observation via a peek at the freed buffer is not portable — instead test the
zeroing function directly and that destruction calls it), mlock success path.

**Sanitizers in CI.** The crypto test job runs three times: default, ASan+UBSan,
and (periodically) Valgrind. Memory bugs in crypto code are security bugs.

## Layer 2 — vault layer (Phase 3)

Location: `tests/vault/`, needs Qt Core, still headless and offline.
A full `/api/sync` response captured from the test account lives in
`tests/fixtures/sync.json`. Tests unlock it with the test-account password and
assert on decrypted item names, fields, folder structure, and TOTP codes
(TOTP tests use fixed timestamps — no wall-clock dependence). Lock tests
assert that models are emptied and keys destroyed.

## Layer 3 — API integration (Phase 2)

Location: `tests/api/`. These need a live server, so they are **opt-in**
(`ctest -L integration`; skipped by default and in the plain unit-test job).

- Locally: against `dev/` Vaultwarden.
- In CI: a separate workflow job starts `vaultwarden/server` as a service
  container, registers a fresh account through the API, then exercises
  prelogin → login → token refresh → sync end-to-end.
- Bitwarden.com is never used in CI (rate limits, captcha, terms); a manual
  pre-release checklist item covers one real login against the cloud.

## Layer 4 — UI (Phase 4+)

Honest position: Silica QML is not meaningfully unit-testable off-device, and
we will not pretend otherwise with mocked-QML theater. Instead:

- All logic lives in C++ view-models (enforced by the architecture), which are
  testable headlessly where they contain any branching worth testing.
- `doc/RELEASE-CHECKLIST.md` (to be written in Phase 5) carries a manual
  on-device smoke script: login, sync, search, copy, clipboard auto-clear,
  TOTP countdown, lock on minimize, cover state.

## Planned hardening (Phase 5+)

- **Fuzzing** the EncString parser and sync-JSON ingestion with libFuzzer;
  parsers of attacker-influenced input are the most fuzz-worthy code we have.
- A CI badge row in README linking directly to the KAT fixtures, so "verify it
  yourself" is one click away.

## Rules

- No network in unit tests, ever. Anything needing a server is `-L integration`.
- No real credentials anywhere in the repo — fixtures come from the dedicated
  public test account only.
- A failing negative test (something decrypts that shouldn't) is a
  release-blocker, treated as a vulnerability, not a bug.
