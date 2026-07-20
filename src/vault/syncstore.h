// Persists the raw /api/sync response. The blob is stored exactly as the
// server sent it — every sensitive field inside is an EncString, so the
// file on disk is already end-to-end encrypted. Nothing decrypted is ever
// written. Lives in the Sailjail-private app data directory.
#pragma once

#include <QByteArray>
#include <QString>

namespace Leyni {
namespace Vault {

class SyncStore
{
public:
    // Default location: QStandardPaths::AppDataLocation/sync.json.
    // A custom directory can be injected for tests.
    explicit SyncStore(const QString &directory = QString());

    // Atomic write (QSaveFile): never leaves a torn file behind.
    bool save(const QByteArray &rawSyncJson);
    QByteArray load() const;
    bool exists() const;
    bool clear();

    QString filePath() const { return m_filePath; }

private:
    QString m_filePath;
};

} // namespace Vault
} // namespace Leyni
