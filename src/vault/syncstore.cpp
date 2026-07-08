#include "syncstore.h"

#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>

namespace BitVault {
namespace Vault {

SyncStore::SyncStore(const QString &directory)
{
    QString dir = directory;
    if (dir.isEmpty()) {
        dir = QStandardPaths::writableLocation(
            QStandardPaths::AppDataLocation);
    }
    QDir().mkpath(dir);
    m_filePath = dir + QStringLiteral("/sync.json");
}

bool SyncStore::save(const QByteArray &rawSyncJson)
{
    QSaveFile file(m_filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    if (file.write(rawSyncJson) != rawSyncJson.size()) {
        file.cancelWriting();
        return false;
    }
    return file.commit();
}

QByteArray SyncStore::load() const
{
    QFile file(m_filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    return file.readAll();
}

bool SyncStore::exists() const
{
    return QFile::exists(m_filePath);
}

bool SyncStore::clear()
{
    if (!exists()) {
        return true;
    }
    return QFile::remove(m_filePath);
}

} // namespace Vault
} // namespace BitVault
