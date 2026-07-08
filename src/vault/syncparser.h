// Parses the raw /api/sync JSON into EncryptedCipher/Folder/Collection
// structures. Pure functions, no decryption — EncStrings pass through
// verbatim and are only validated/decrypted by the crypto layer when used.
// Accepts both camelCase and PascalCase field names (server variants).
#pragma once

#include <QByteArray>
#include <QString>

#include <vector>

#include "cipheritem.h"

namespace BitVault {
namespace Vault {

struct SyncData {
    QString profileEmail;
    std::string profileKey;        // protected user key (EncString)
    std::string profilePrivateKey; // encrypted RSA private key (EncString)
    std::vector<Organization> organizations;
    std::vector<EncryptedCipher> ciphers;
    std::vector<Folder> folders;
    std::vector<Collection> collections;
};

// Returns false and sets errorMessage on structurally invalid input.
// Individual malformed ciphers are skipped and counted in skippedCiphers
// (one bad item must not make the whole vault unreadable).
bool parseSyncJson(const QByteArray &json, SyncData *out,
                   QString *errorMessage, int *skippedCiphers = nullptr);

} // namespace Vault
} // namespace BitVault
