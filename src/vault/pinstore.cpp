#include "pinstore.h"

#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>

namespace BitVault {
namespace Vault {

PinStore::PinStore(const QString &directory)
{
    QString dir = directory;
    if (dir.isEmpty()) {
        dir = QStandardPaths::writableLocation(
            QStandardPaths::AppDataLocation);
    }
    QDir().mkpath(dir);
    m_filePath = dir + QStringLiteral("/pin.dat");
}

bool PinStore::save(const QByteArray &serialized)
{
    QSaveFile file(m_filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    if (file.write(serialized) != serialized.size()) {
        file.cancelWriting();
        return false;
    }
    if (!file.commit()) {
        return false;
    }
    // Owner-only: the blob is offline-brute-forceable, so at least keep other
    // apps/users on the device from reading it directly.
    QFile::setPermissions(m_filePath,
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

QByteArray PinStore::load() const
{
    QFile file(m_filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    return file.readAll();
}

bool PinStore::exists() const
{
    return QFile::exists(m_filePath);
}

bool PinStore::clear()
{
    if (!exists()) {
        return true;
    }
    return QFile::remove(m_filePath);
}

} // namespace Vault
} // namespace BitVault
