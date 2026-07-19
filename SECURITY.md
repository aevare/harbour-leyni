# Security

BitVault is a native Bitwarden client for Sailfish OS. This document describes
what the app protects, how, and — just as importantly — what it cannot protect.
It is written for a skeptical reviewer; nothing here is marketing.

If a statement in this file contradicts the code, the code is the bug or this
file is — either way, please report it (see below).

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/aevare/harbour-bitvault/security/advisories/new)
rather than a public issue. You should receive a response within 7 days.
Coordinated disclosure is appreciated; there is no bug bounty.

Non-sensitive hardening suggestions and audit findings are welcome as regular
issues or pull requests — public review is an explicit project goal.

## Where to look (audit entry points)

The security-critical surface is deliberately small and lives in
[`src/crypto/`](src/crypto/) (~1500 lines, libcrypto + vendored libargon2
only, no Qt GUI, no networking, no file I/O):

| File | Responsibility |
|---|---|
| `securebytes.{h,cpp}` | the only container allowed to hold secrets: `mlock`ed, zeroed on destruction, move-only, no conversion to `QString`/`std::string` |
| `kdf.{h,cpp}` | PBKDF2-SHA256 / Argon2id master-key derivation, server-parameter bounds checks |
| `keys.{h,cpp}` | HKDF stretch, master password hash, RSA-OAEP org-key unwrap |
| `encstring.{h,cpp}` | EncString parse/decrypt/encrypt; MAC-then-decrypt |
| `pinwrap.{h,cpp}` | opt-in PIN unlock: Argon2id KEK + EncString wrap of the master key (see "PIN unlock" below) |
| `passwordgen.{h,cpp}` | random password generation: CSPRNG (`RAND_bytes`) with unbiased rejection sampling |
| `totp.{h,cpp}` | RFC 6238 TOTP |

Layering is strictly one-way (`qml/` → `src/ui/` → `src/vault/` → `src/api/` →
`src/crypto/`); see [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md). The crypto
layer is tested against RFC and NIST known-answer vectors plus Bitwarden's own
SDK vectors, with negative tests that must fail closed; see
[doc/TESTING.md](doc/TESTING.md).

## Threat model

**BitVault defends against:**

- **A compromised or malicious server.** The master password never leaves the
  device; only the derived authentication hash is sent. All vault data is
  decrypted locally. Server-supplied KDF parameters are bounds-checked
  (PBKDF2 ≤ 10,000,000 iterations; Argon2id ≤ 100 iterations, ≤ 1024 MiB,
  ≤ 16 lanes) so a hostile prelogin response cannot demand unbounded
  memory or CPU. Malformed sync data is skipped and counted, never fatal.
- **Tampered ciphertext.** EncString type 2 is encrypt-then-MAC; the
  HMAC-SHA256 is verified in constant time **before** any decryption.
  Tampered MAC, IV, or ciphertext is a hard error, never empty output.
  Unsupported EncString types are rejected explicitly.
- **Network attackers.** All traffic is HTTPS through Qt's default TLS stack.
  There is no code path that disables certificate verification (no
  `ignoreSslErrors`, no peer-verify overrides) — this is grep-verifiable.
- **Theft of the device while the vault is locked.** Everything on disk is
  either end-to-end encrypted (the sync blob) or grants no access to vault
  plaintext (see "What is stored where"). Unlocking requires the master
  password; a wrong password fails cleanly on the protected key's MAC.
- **Other sandboxed apps.** All local state lives in Sailjail-private
  directories. The app requests only the `Internet` permission.

**BitVault does NOT defend against:**

- **A compromised device.** Root, or any process running as your user outside
  a sandbox, can read the app's files, read the clipboard, capture the
  screen, or read process memory. No password manager on this platform can
  defend against that.
- **Physical access to an unlocked vault.** Auto-lock (default 5 minutes),
  lock-on-minimize (default on), and clipboard auto-clear (default 30 s)
  shrink the window; they do not close it.
- **Clipboard snooping.** Copying a password puts it on the system clipboard,
  which is readable by other applications by design. The auto-clear timer
  limits exposure time, not exposure.
- **A weak master password.** Key derivation only slows down guessing; it
  cannot fix a guessable password.

## Key lifecycle

The derivation chain is the standard Bitwarden scheme:

```
master password + email ─ PBKDF2-SHA256 or Argon2id ─▶ master key (32 B)
master key + password ─ PBKDF2, 1 iteration ─▶ auth hash   → sent to server
master key ─ HKDF-SHA256 expand ─▶ stretched key (32 B enc + 32 B MAC)
stretched key ─ decrypt EncString ─▶ user key ─▶ RSA private key ─▶ org keys
user/org/per-item key ─ decrypt EncString ─▶ item fields
```

Handling rules, enforced by types rather than convention:

- Passwords and all key material live only in `Crypto::SecureBytes`:
  `mlock`ed (best-effort — failure under `RLIMIT_MEMLOCK` is tolerated),
  zeroed on destruction with an optimizer-proof `secureZero`, move-only so
  each secret has exactly one owner, and with **no conversion to `QString`**
  — copying a key into unzeroable, implicitly-shared Qt memory is a compile
  error, not a code-review catch.
- The slow KDF runs on a worker thread; the worker owns the only copy of the
  password (zeroed immediately after derivation) and hands the master key to
  the GUI thread exactly once.
- The raw master password never reaches the API layer — `src/api/` receives
  only the base64 auth hash (`apijson.h` documents this contract).
- Unlock decrypts **display fields only** (item names, usernames, primary
  URI, folder names) into memory. Passwords, TOTP secrets, notes, and
  card/identity fields are decrypted per access, on demand, and never cached.
- Lock (manual, auto-lock timer, or minimize) destroys every `SecureBytes` —
  user key, private key, org keys — and clears all decrypted display data.
  The encrypted sync blob may stay in memory; it is ciphertext.
- There is no logging of any kind in the application source — nothing can
  leak through the journal.
- **Writes** (create/edit/delete) run the same trust boundary in reverse:
  plaintext the user types is encrypted into EncStrings in `src/vault/`
  (`buildCreateBody`/`buildUpdateBody`) before it reaches the API layer, which
  only ever transmits ciphertext. Edits start from the item's original
  ciphertext and overwrite just the changed fields, so unmodeled data (password
  history, custom fields) is preserved without ever being decrypted. After a
  write the app re-syncs; the on-disk blob is only ever the server's E2E-
  encrypted response, never a locally-assembled one.

## What is stored where

All paths are Sailjail-private (inaccessible to other sandboxed apps).

| What | Where | Protection |
|---|---|---|
| Sync blob (vault ciphertext) | `~/.local/share/xyz.eggerts/harbour-bitvault/sync.json` | End-to-end encrypted by the Bitwarden scheme; stored byte-for-byte as the server sent it. Written atomically via `QSaveFile`. |
| OAuth refresh token | QSettings (`~/.config/harbour-bitvault/`) | **Plaintext.** See note below. |
| KDF parameters (type, iterations, memory, lanes) | QSettings | Plaintext; not secret (the server hands them to anyone who asks prelogin). Enables offline unlock. |
| PIN-wrapped master key (only if PIN unlock is enabled) | `~/.local/share/xyz.eggerts/harbour-bitvault/pin.dat` | The master key encrypted under a key derived from your PIN alone (Argon2id + AES-256-CBC-HMAC). **Offline-brute-forceable** — see "PIN unlock" below. Absent unless you opt in; deleted on sign-out and after too many wrong PINs. |
| Server URL, account email, device ID, UI settings | QSettings | Plaintext; not secret. |
| Access token | memory only | Discarded on exit. |
| Master password, master key, user/org keys, decrypted items | **never written to disk** | — |

**About the refresh token:** it is stored in plaintext because Sailfish OS has
no hardware-backed keystore, and encrypting it with a key stored next to it
would be obfuscation, not security. An attacker who reads it can call the API
and download your **encrypted** vault — the same ciphertext in `sync.json` —
but cannot decrypt anything without the master password. They could also
trigger server-side actions a Bitwarden session allows. "Sign out" deletes
the token locally; you can additionally revoke sessions from the Bitwarden
web vault.

**About the sync blob:** item names, usernames, URIs, notes, and all secret
fields inside it are EncStrings (ciphertext). The blob's plaintext envelope
still reveals metadata: your account email, KDF settings, item/folder counts,
item types, IDs, and revision timestamps. Treat "someone stole my sync.json"
as "someone knows how many logins I have and when they changed", not as a
vault breach.

## Cryptography

| Purpose | Algorithm | Implementation |
|---|---|---|
| Master key derivation | PBKDF2-SHA256 or Argon2id (server-selected, bounds-checked) | OpenSSL libcrypto; Argon2 reference implementation vendored at `third_party/argon2`, compiled from source |
| Key stretching | HKDF-SHA256 expand → 64 B | libcrypto |
| Vault data | EncString type 2: AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, constant-time verify before decrypt) | libcrypto |
| Org key wrapping | EncString type 4: RSA-2048-OAEP-SHA1 | libcrypto |
| TOTP | RFC 6238 / RFC 4226 (SHA-1/256/512) | libcrypto |
| PIN key-encryption-key (opt-in) | Argon2id (t=8, 64 MiB, p=4, random 16 B salt) → AES-256-CBC + HMAC-SHA256 wrap of the master key | Argon2 reference impl + libcrypto (`src/crypto/pinwrap.cpp`) |

These are Bitwarden's choices, not ours — a compatible client must implement
exactly this. All other EncString types are rejected explicitly. Wrappers are
thin and literal over `EVP_*`; there are no homegrown primitives.

## PIN unlock (opt-in, deliberately weaker)

PIN unlock is **off by default** and exists only to spare you from typing a long
master password on every auto-lock during a day of use. Enabling it is a
trade-off, stated plainly here so the choice is informed.

**What it does.** When you enable it (Settings → PIN unlock), you re-enter your
master password once. The app re-derives your 32-byte master key, verifies it
against the vault, then wraps it: a key-encryption-key is derived from your PIN
with Argon2id (t=8, 64 MiB, p=4, over a random 16-byte salt) and used to
encrypt the master key with AES-256-CBC + HMAC-SHA256. The result is written to
`pin.dat`. The PIN itself is never stored. On unlock, the PIN re-derives the
key-encryption-key, the MAC is verified in constant time, and the master key is
recovered and fed into the exact same unlock path a master-password unlock uses.

**The exposure — read this.** `pin.dat` is on disk and survives reboot. Its
security rests **entirely on the entropy of your PIN**, which is small: a 4-digit
PIN is about 13 bits, a 6-digit PIN about 20 bits. An attacker who copies
`pin.dat` off the device (physical access, a backup, forensic imaging) can try
every PIN **offline**, as fast as their hardware runs Argon2id — the 3-strikes
limit below does *not* apply offline, it only guards the running app. The
aggressive Argon2id parameters raise the per-guess cost (tens of thousands of
guesses, not billions, per second on a PC), but a short numeric PIN is still
brute-forceable in a practical amount of time.

So: **PIN unlock protects against casual access** — a glance over your shoulder,
a borrowed or briefly-unattended phone — **not against a forensic adversary who
images your storage.** If that adversary is in your threat model, do not enable
PIN unlock; use the master password.

**Limits that do apply on-device.**

- After **3 consecutive wrong PINs**, the app deletes `pin.dat` and requires a
  full master-password unlock. The counter is persisted, so it cannot be reset
  by restarting the app. (Again: this bounds *online* guessing only.)
- The wrapped key is deleted on **sign-out**, and dropped if the vault's key
  no longer matches it (e.g. you changed your master password on the server) —
  in both cases the master password is required.
- The master key is not kept in memory between unlocks; enabling PIN requires
  the master password precisely so it can be re-derived on demand rather than
  retained.

The whole scheme is one short file — `src/crypto/pinwrap.{h,cpp}` — built from
the already-audited EncString and Argon2id primitives, so a reviewer can read it
end to end.

## Platform limitations (documented, not worked around)

- **No system-wide autofill.** Sailfish OS has no autofill framework.
  Copy-to-clipboard with auto-clear is the ceiling.
- **No hardware keystore.** Unlocking always derives keys from the master
  password. Any future convenience unlock (e.g. PIN) will be opt-in with its
  weaker threat model documented here first.
- **No WebAuthn/FIDO2 second factor.** No platform authenticator UI exists.
  TOTP and email 2FA are supported; API-key login is the workaround for
  hardware-key users.
- **Qt text input is not zeroable.** The master password is typed into a
  Silica `PasswordField` and crosses the QML→C++ boundary as a `QString`; it
  is converted to `SecureBytes` immediately on entry and the fields are
  cleared on page deactivation, but the transient Qt-owned copies are freed
  unzeroed. Every Qt-based client shares this limitation. The same applies to
  secrets the user explicitly reveals or copies: once handed to the UI or
  clipboard as display text, that copy cannot be zeroed.
- **`mlock` is best-effort.** If `RLIMIT_MEMLOCK` is exhausted, key material
  could in principle be swapped; zeroing on destruction still applies.
