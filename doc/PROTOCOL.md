# BitVault — Bitwarden Protocol Notes

Working reference for the subset of the Bitwarden protocol BitVault implements.
Primary sources, in order of usefulness:

- [rbw](https://github.com/doy/rbw) — clean-room Rust client, best readable reference
- [vaultwarden](https://github.com/dani-garcia/vaultwarden) — Rust server reimplementation
  of the full API; effectively executable protocol documentation
- [bitwarden/server](https://github.com/bitwarden/server) — the official server
- [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
  — the crypto design, authoritative

Verify details against these sources during implementation; this file is a map,
not a spec.

## Endpoints

Cloud hosts split services: `identity.bitwarden.com` (auth) and
`api.bitwarden.com` (vault). Self-hosted/Vaultwarden serve both under one base URL
at `/identity/*` and `/api/*`. EU cloud uses `bitwarden.eu`.

| Step | Endpoint |
|---|---|
| KDF discovery | `POST /identity/accounts/prelogin` |
| Login / token | `POST /identity/connect/token` |
| Full vault | `GET /api/sync` |

## Key derivation

```
prelogin(email) → { kdf, iterations, memory?, parallelism? }
    kdf 0 = PBKDF2-SHA256 (default 600,000 iterations)
    kdf 1 = Argon2id (Argon2 salt = SHA-256(email))

masterKey        = KDF(password, salt = lowercase(trim(email)))          // 32 bytes
masterPasswdHash = PBKDF2-SHA256(masterKey, salt = password, 1 iter)     // sent to server
stretchedKey     = HKDF-SHA256-expand(masterKey, "enc", 32)
                 ‖ HKDF-SHA256-expand(masterKey, "mac", 32)              // 64 bytes
```

The login response contains the account's **protected symmetric key** (an EncString,
type 2) which is decrypted with the stretched key. That symmetric key (32 enc + 32 mac)
decrypts everything else. The private RSA key (also an EncString) decrypts
organization keys, which arrive RSA-2048-OAEP-SHA1-wrapped.

## Login (OAuth2 resource-owner password grant)

Form-encoded POST to `/identity/connect/token` with `grant_type=password`,
`username=<email>`, `password=<base64(masterPasswdHash)>`, `scope=api offline_access`,
a client id (e.g. `cli` or `mobile`), and device identification fields
(`deviceType`, `deviceIdentifier` — a stable UUID, `deviceName`).

- Success → `access_token` (JWT, short-lived), `refresh_token`, `Key`
  (protected symmetric key), `PrivateKey`.
- 2FA required → error response listing available providers; retry with
  `twoFactorProvider` + `twoFactorToken`. Providers BitVault supports:
  0 = authenticator TOTP, 1 = email. WebAuthn (7) is out of scope.
- Bitwarden cloud may require new-device email verification and can serve captcha
  challenges; API-key login (`grant_type=client_credentials`, then unlock locally
  with the master password) is the documented fallback. Vaultwarden has neither issue.
- Refresh: `grant_type=refresh_token`.

## EncStrings

Every encrypted field is a string `<type>.<b64 part>|<b64 part>[|<b64 part>]`:

| Type | Meaning | Parts |
|---|---|---|
| 2 | AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) | `iv \| ciphertext \| mac` |
| 4 / 6 | RSA-2048-OAEP-SHA1 (org key wrapping; 6 is legacy variant) | `ciphertext` |

Type 2 decrypt: `mac' = HMAC-SHA256(macKey, iv ‖ ciphertext)`; constant-time compare
with `mac`; **fail closed on mismatch**; only then AES-256-CBC decrypt and strip
PKCS#7 padding. Other legacy types exist (0, 1, 3, 5); reject them explicitly with
a clear error rather than mis-decrypting.

## Sync payload

`GET /api/sync` (Bearer token) returns one JSON document:

- `profile` — includes `key` (protected symmetric key), `privateKey`,
  `organizations[]` (each with an RSA-wrapped `key`)
- `ciphers[]` — vault items; `type`: 1 login, 2 secure note, 3 card, 4 identity.
  Names, usernames, passwords, URIs, notes, custom fields are all EncStrings.
  Items belonging to an organization carry `organizationId` and are encrypted
  with that org's key instead of the account key.
- `folders[]`, `collections[]`, `sends[]`, `policies[]`

BitVault stores this response verbatim on disk (it is already E2E-encrypted) and
decrypts only in memory after unlock.

## TOTP

Login items may carry a `totp` field (EncString) holding an `otpauth://` URI or a
bare Base32 secret. Codes are generated client-side per RFC 6238 (default:
SHA-1, 6 digits, 30 s; honor URI parameters when present).

## Local test server

```
cd dev && docker compose up -d     # Vaultwarden on http://localhost:8000
```

Create a test account via its web vault, then point BitVault at the base URL.
All integration tests target this before touching bitwarden.com.
