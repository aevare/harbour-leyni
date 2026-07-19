// Data structures for vault contents.
//
// Two forms exist:
//   EncryptedCipher — exactly what the sync JSON contained: every sensitive
//     field is still an EncString (std::string). Held for the whole session.
//   DecryptedItem — the display fields only (name, username, uri, folder),
//     decrypted at unlock. Secret payloads (password, TOTP secret, notes,
//     card/identity fields) are NOT stored decrypted; the Vault decrypts
//     them on demand from the EncryptedCipher.
#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <string>
#include <vector>

namespace BitVault {
namespace Vault {

enum class CipherType : int {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
};

struct EncryptedLogin {
    std::string username;
    std::string password;
    std::string totp;
    std::vector<std::string> uris;
};

struct EncryptedField {
    std::string name;
    std::string value;
    int type = 0; // 0 text, 1 hidden, 2 boolean, 3 linked
};

struct EncryptedCipher {
    QString id;
    CipherType type = CipherType::Login;
    QString folderId;       // plaintext UUID or empty
    QString organizationId; // plaintext UUID or empty
    bool favorite = false;
    QDateTime revisionDate;
    std::string key;  // optional per-item key (EncString), may be empty
    std::string name; // EncString
    std::string notes;
    EncryptedLogin login;
    // Card and identity payloads stay as raw EncString field maps; they are
    // decrypted on demand as a whole.
    std::vector<EncryptedField> fields;      // custom fields
    std::vector<EncryptedField> cardFields;     // number, code, expMonth, ...
    std::vector<EncryptedField> identityFields; // firstName, address1, ...
    // The original sync JSON object for this cipher, kept verbatim so an edit
    // can re-encrypt only the changed fields and preserve everything the app
    // does not model (password history, URI match types, custom-field
    // structure). Ciphertext only — never contains decrypted data.
    QJsonObject raw;
};

struct Folder {
    QString id;
    std::string name; // EncString
};

struct Collection {
    QString id;
    QString organizationId;
    std::string name; // EncString
};

struct Organization {
    QString id;
    QString name;    // plaintext in the profile
    std::string key; // EncString type 4 (RSA-wrapped org key)
};

// Display-only decrypted view of a cipher; safe to hand to models/QML.
struct DecryptedItem {
    QString id;
    CipherType type = CipherType::Login;
    QString folderId;
    QString organizationId;
    bool favorite = false;
    QString name;
    QString username;    // logins only
    QString primaryUri;  // logins only
    bool hasTotp = false;
    bool hasPassword = false;
    // Existence flags only — whether encrypted payloads are present, never
    // their contents.
    bool hasNotes = false;
    bool hasDetails = false;
};

} // namespace Vault
} // namespace BitVault
