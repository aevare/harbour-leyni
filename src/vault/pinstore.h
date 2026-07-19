// Persists the PIN-wrapped master key. The stored blob is an EncString
// (AES-256-CBC + HMAC) whose key is derived from the PIN alone — see
// src/crypto/pinwrap.h for the threat model. Nothing decrypted is ever
// written. Lives in the Sailjail-private app data directory, next to sync.json.
#pragma once

#include <QByteArray>
#include <QString>

namespace BitVault {
namespace Vault {

class PinStore
{
public:
    // Default location: QStandardPaths::AppDataLocation/pin.dat.
    // A custom directory can be injected for tests.
    explicit PinStore(const QString &directory = QString());

    // Atomic write (QSaveFile). `serialized` is PinWrappedKey::serialize().
    bool save(const QByteArray &serialized);
    QByteArray load() const;
    bool exists() const;
    bool clear();

    QString filePath() const { return m_filePath; }

private:
    QString m_filePath;
};

} // namespace Vault
} // namespace BitVault
