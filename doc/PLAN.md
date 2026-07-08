# BitVault — Development Plan

A fully native, open-source Bitwarden client for Sailfish OS.

**Non-negotiable goals**

1. **Completely native** — Qt/C++ + Silica QML. No Node.js, no Bitwarden CLI wrapper, no background scripts.
2. **Auditable** — a skeptical reviewer must be able to verify the security-critical code
   without reading the whole app. Short, literal code beats clever abstraction.
3. **Honest about platform limits** — no system-wide autofill on Sailfish OS, no WebAuthn 2FA,
   no hardware keystore. We document what we cannot do instead of pretending.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the layering rules and [PROTOCOL.md](PROTOCOL.md)
for the Bitwarden protocol reference.

---

## Phase 0 — Project foundation

Goal: an empty app that builds, packages, and has CI proving it.

- [x] Choose a license: GPL-3.0-or-later (spec `License:` tag uses `GPLv3+`, the
      Fedora-style form the Sailfish rpmlint allowlist requires)
- [x] Scaffold the project: CMake template, `rpm/harbour-bitvault.spec`,
      `.desktop` with `[X-Sailjail] Permissions=Internet`, stub icons (86/108/128/172 px)
- [ ] `git init` done; **still open: publish the repository publicly on GitHub**
      (repo URL in spec/README assumes `github.com/aevare/harbour-bitvault` — fix if different)
- [x] CI workflow 1: SFOS RPM matrix build (4.5/4.6/5.0 × armv7hl + aarch64) via
      `CODeRUS/github-sfos-build` — written; proven on first push
- [x] CI workflow 2: plain-Linux build of `src/crypto/` + unit tests — verified locally
- [x] `docker-compose.yml` under `dev/` running a local Vaultwarden instance as the test server
- [x] Verify packaging: Dockerized mb2 build (SFOS 5.0.0.43 aarch64) produces
      `harbour-bitvault-0.1-1.aarch64.rpm`, rpmlint 0 errors
      (fixed: template's `$<BUILD_INTERFACE:>` include-path mangling, dir perms, changelog)
- [ ] Still open: install the RPM on a device/emulator and see the placeholder page launch

**Done when:** both CI workflows are green on every push and the empty app runs on a device
or emulator.

## Phase 1 — Crypto core (`src/crypto/`)

Goal: the entire auditable core, finished and tested before any UI exists.
Depends only on libcrypto (+ vendored libargon2). No Qt GUI, no networking, no file I/O.

- [ ] `SecureBytes` — mlock'd, zero-on-destroy, non-copyable buffer; **no** conversion
      to `QString`
- [ ] Master key derivation: PBKDF2-SHA256 (variable iterations) and Argon2id
      (vendor libargon2 into the app's bundled-lib dir per Harbour rules)
- [ ] Master password hash (server auth value): PBKDF2(masterKey, password, 1 iteration)
- [ ] Key stretching: HKDF-SHA256 expand → 64 bytes (32 enc + 32 mac)
- [ ] `EncString` parse + decrypt: `2.<iv>|<ct>|<mac>` — AES-256-CBC + HMAC-SHA256,
      **MAC verified before decrypt**, constant-time compare
- [ ] `EncString` encrypt (needed later for write support; cheap to do now while in context)
- [ ] RSA-2048-OAEP-SHA1 unwrap for organization keys
- [ ] Known-answer tests: derive expected values for a test account with the official
      client / rbw, hard-code them as fixtures; plus negative tests (bad MAC must fail closed)
- [ ] Every public function documented: inputs, outputs, what it must never do

**Done when:** crypto tests pass on plain-Linux CI and outputs are byte-identical to the
official client for the same inputs.

## Phase 2 — API client (`src/api/`)

Goal: talk to a Bitwarden/Vaultwarden server. Depends on `crypto/` and Qt Network only.

- [ ] Server configuration: bitwarden.com default, custom URL for self-hosted/Vaultwarden
- [ ] `POST /identity/accounts/prelogin` → KDF type + parameters
- [ ] `POST /identity/connect/token` — OAuth2 password grant; parse access/refresh token
      and the protected symmetric key
- [ ] 2FA: TOTP and email provider flows (WebAuthn explicitly out of scope — document it)
- [ ] Handle Bitwarden-cloud new-device verification; offer API-key login as fallback
- [ ] Token refresh; re-auth path when refresh fails
- [ ] `GET /api/sync` → store the response **as-is** (it is already end-to-end encrypted)
      in the Sailjail-private data dir
- [ ] Integration tests against the local Vaultwarden from Phase 0

**Done when:** a headless test binary can log in to local Vaultwarden and to a bitwarden.com
test account, and persists a sync blob.

## Phase 3 — Vault layer (`src/vault/`)

Goal: the in-memory decrypted vault and its lifecycle.

- [ ] Parse the sync JSON: ciphers (logins, notes, cards, identities), folders, collections
- [ ] Unlock: derive keys → verify → decrypt item names/fields into memory only
- [ ] Lock: drop and zero all decrypted material and keys; auto-lock timer;
      lock on app minimize (configurable)
- [ ] Search and folder filtering over decrypted items
- [ ] TOTP code generation (RFC 6238) for stored authenticator secrets
- [ ] `QAbstractListModel` exposing **display data only** to QML — never key material

**Done when:** a test can unlock a synced vault, find an item by search, read its password,
generate its TOTP, and lock — with memory zeroed after lock.

## Phase 4 — UI MVP (`qml/` + `src/ui/`), read-only

Goal: a daily-driver app for viewing and copying credentials.

- [ ] Login flow: server URL → email → password → 2FA pages
- [ ] Unlock page (master password; this is the default and most secure mode)
- [ ] Vault list with `SearchField`, folder sections, item-type icons
- [ ] Item detail page: reveal-on-tap password, copy buttons, TOTP with countdown
- [ ] Clipboard auto-clear N seconds after any copy (default on)
- [ ] Cover page: locked/unlocked state, item count, lock action — never item data
- [ ] Settings: auto-lock timeout, clipboard timeout, server URL
- [ ] QML rule enforced: presentation only, no security-relevant JavaScript

**Done when:** the full flow — login, sync, search, copy a password, watch the clipboard
clear, lock — works on a real device.

## Phase 5 — Hardening and first release

Goal: earn the trust the project promises, then ship.

- [ ] Write `SECURITY.md` (repo root): threat model, key lifecycle, what is stored where,
      platform limitations, how to report vulnerabilities
- [ ] Self-audit pass against the architecture rules (no secret ever crosses into `ui/`;
      grep for `QString` in crypto paths)
- [ ] Sailjail trace run: confirm the app functions with `Internet` permission only
- [ ] Harbour validation (`rpmvalidation`), fix findings
- [ ] Tag v0.1.0 → GitHub release with RPMs; submit to OBS + Chum; OpenRepos upload
- [ ] Announce beta on the Sailfish forum, explicitly inviting code review

**Done when:** v0.1.0 is installable from Chum and the forum thread links to the source
and SECURITY.md.

## Phase 6 — Post-MVP (ordered by expected demand)

1. Write support: edit/create/delete items (uses the Phase 1 encrypt path)
2. Password/passphrase generator
3. PIN unlock as a **documented weaker option** (PIN-wrapped key; threat model in SECURITY.md)
4. Organizations/collections decryption (RSA path from Phase 1)
5. Attachments (download/decrypt)
6. Bitwarden Send
7. Live sync via WebSocket notifications
8. Import/export

---

## Working agreements

- Documentation and plans live in `doc/`. `SECURITY.md` is the exception: repo root,
  because that is where auditors and GitHub look for it.
- Every phase ends with its "done when" criterion demonstrated, not assumed.
- Dependencies stay minimal: libcrypto, vendored libargon2, Qt, Silica. Anything new
  needs a written justification in this file.
- Test server is always local Vaultwarden first; bitwarden.com second.
