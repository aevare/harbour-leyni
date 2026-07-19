// The in-memory vault and its lock/unlock lifecycle.
//
// Security contract:
//   - The sync blob stays encrypted in memory for the whole session; unlock
//     decrypts DISPLAY fields only (item names, usernames, primary URI,
//     folder names) into DecryptedItem structs.
//   - Secret payloads (passwords, TOTP secrets, notes, card/identity data)
//     are decrypted on demand, per access, and never cached.
//   - Vault keys live in SecureBytes; lock() destroys them (zero + free) and
//     clears all decrypted display data. Display QStrings cannot be zeroed
//     (Qt owns their allocation) — that limitation is accepted for names,
//     never for keys. See doc/ARCHITECTURE.md.
//   - Wrong password surfaces as a clean failure (MAC mismatch on the
//     protected key); nothing partial is ever exposed.
#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantMap>

#include <map>
#include <vector>

#include "kdf.h"
#include "keys.h"
#include "securebytes.h"

#include "cipheritem.h"
#include "syncparser.h"

namespace BitVault {
namespace Vault {

class Vault : public QObject
{
    Q_OBJECT

public:
    explicit Vault(QObject *parent = nullptr);
    ~Vault() override;

    // Parses and holds the (still encrypted) sync data. Safe while locked.
    bool loadSync(const QByteArray &rawJson, QString *errorMessage,
                  int *skippedCiphers = nullptr);

    // Derives keys from the password, decrypts the protected user key, the
    // private key, organization keys, and display fields. The password is
    // taken by value and destroyed (zeroed) when this returns.
    bool unlock(const QString &email, Crypto::SecureBytes password,
                const Crypto::KdfParams &kdfParams, QString *errorMessage);

    // Same, but from an already-derived master key — for callers that run
    // the slow KDF on a worker thread (the vault itself must stay on its
    // owning thread because of the auto-lock QTimer). The key is destroyed
    // (zeroed) when this returns.
    bool unlockWithMasterKey(Crypto::SecureBytes masterKey,
                             QString *errorMessage);

    // Replaces the vault contents after a re-sync WITHOUT requiring the
    // password again: re-parses the blob and re-decrypts display data with
    // the keys currently in memory. If the account's protected key changed
    // (e.g. password change on the server), this locks and returns false —
    // the caller must ask for the password.
    bool reloadSync(const QByteArray &rawJson, QString *errorMessage,
                    int *skippedCiphers = nullptr);

    // True if `masterKey` decrypts the currently-loaded protected user key —
    // i.e. it is the correct master key for this account's sync blob. Read
    // only: does not change lock state or touch the vault's own keys. Used to
    // confirm a re-entered master password before wrapping it under a PIN.
    // Requires a loaded sync blob; returns false (with a message) otherwise.
    bool verifyMasterKey(const Crypto::SecureBytes &masterKey,
                         QString *errorMessage) const;

    void lock();
    bool isLocked() const { return m_locked; }

    // --- write support (see doc/PROTOCOL.md "Writes") ---
    // Build the encrypted CipherRequestModel JSON for a NEW personal-vault
    // item of the given type from plaintext `fields` (keys: name, notes,
    // folderId, favorite, and for logins username/password/uri/totp).
    // Encrypts under the user key; no per-item key. Returns the request body,
    // or an empty QByteArray with *errorMessage set. Const: encryption uses
    // the keys but changes no vault state.
    QByteArray buildCreateBody(CipherType type, const QVariantMap &fields,
                               QString *errorMessage) const;

    // Build the encrypted CipherRequestModel JSON to UPDATE an existing item:
    // starts from the item's original sync JSON (EncryptedCipher::raw),
    // overwrites only the edited fields with freshly-encrypted values, drops
    // response-only keys, and preserves everything the app does not model
    // (password history, extra URIs, custom fields). Same field keys as
    // buildCreateBody.
    QByteArray buildUpdateBody(const QString &itemId, const QVariantMap &fields,
                               QString *errorMessage) const;

    // --- display data (valid while unlocked) ---
    const std::vector<DecryptedItem> &items() const { return m_items; }
    QString folderName(const QString &folderId) const;
    // id → name, sorted by name; for folder filter UIs.
    QList<QPair<QString, QString>> folders() const;

    // --- on-demand secret access (decrypt-per-access, never cached) ---
    QString itemPassword(const QString &itemId, QString *errorMessage);
    QString itemNotes(const QString &itemId, QString *errorMessage);
    // The raw TOTP secret (otpauth:// URI or base32), for prefilling the
    // editor — distinct from totpCode(), which returns a generated code.
    QString itemTotpSecret(const QString &itemId, QString *errorMessage);
    // name/value pairs for card, identity, and custom fields.
    QList<QPair<QString, QString>> itemDetailFields(const QString &itemId,
                                                    QString *errorMessage);
    // TOTP code for the item at unixTime. Supports raw base32 secrets and
    // otpauth:// URIs (digits/period/algorithm honored; steam:// rejected).
    QString totpCode(const QString &itemId, quint64 unixTime,
                     int *secondsRemaining, QString *errorMessage);

    // --- auto-lock ---
    // 0 disables. Timer restarts on noteActivity(); fires lock().
    void setAutoLockSeconds(int seconds);
    void noteActivity();

signals:
    void lockedChanged(bool locked);

private:
    // Decrypts org keys, folder names, and item display fields from m_data
    // using the user key already in memory. Throws CryptoError upward.
    void rebuildDisplayData();

    const EncryptedCipher *findCipher(const QString &itemId) const;
    // Resolves the key protecting a cipher's fields: per-item key if
    // present, else the organization key, else the user key.
    bool cipherKey(const EncryptedCipher &cipher, Crypto::SymmetricKey *key,
                   QString *errorMessage) const;
    QString decryptToString(const std::string &encString,
                            const Crypto::SymmetricKey &key) const;

    // Encrypts UTF-8 plaintext into a serialized type-2 EncString under key.
    // Empty plaintext returns an empty string (caller stores JSON null).
    std::string encryptField(const QString &plaintext,
                             const Crypto::SymmetricKey &key) const;
    // Assembles a login sub-object: re-encrypts username/password/totp and
    // patches the primary URI while preserving any additional URIs present in
    // `existing` (empty for a fresh create).
    QJsonObject buildLoginObject(const QVariantMap &fields,
                                 const QJsonObject &existing,
                                 const Crypto::SymmetricKey &key) const;

    SyncData m_data;
    bool m_locked = true;

    Crypto::SymmetricKey m_userKey;
    Crypto::SecureBytes m_privateKeyDer;
    std::map<QString, Crypto::SymmetricKey> m_orgKeys;

    std::vector<DecryptedItem> m_items;
    QHash<QString, QString> m_folderNames;

    QTimer m_autoLockTimer;
};

} // namespace Vault
} // namespace BitVault
