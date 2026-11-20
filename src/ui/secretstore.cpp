#include "secretstore.h"

#include <QDebug>
#include <QFile>

#include <Secrets/createcollectionrequest.h>
#include <Secrets/deletesecretrequest.h>
#include <Secrets/result.h>
#include <Secrets/secret.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/storesecretrequest.h>

using namespace Sailfish::Secrets;

namespace Leyni {

namespace {

// Collection names are per storage plugin, so keep them app-specific.
const QString kCollectionName = QStringLiteral("harbourleyni");

Secret::Identifier identifier(const QString &name)
{
    return Secret::Identifier(name, kCollectionName,
                              SecretManager::DefaultEncryptedStoragePluginName);
}

bool isNotFound(const Result &result)
{
    return result.errorCode() == Result::InvalidSecretError
        || result.errorCode() == Result::InvalidCollectionError;
}

void logFailure(const char *what, const QString &name, const Result &result)
{
    qWarning() << "Sailfish Secrets:" << what << name << "failed:"
               << result.errorCode() << result.errorMessage();
}

} // namespace

bool SecretStore::ensureCollection()
{
    if (m_collectionReady) {
        return true;
    }
    CreateCollectionRequest req;
    req.setManager(&m_manager);
    req.setCollectionName(kCollectionName);
    req.setCollectionLockType(CreateCollectionRequest::DeviceLock);
    req.setDeviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked);
    req.setAccessControlMode(SecretManager::OwnerOnlyMode);
    req.setUserInteractionMode(SecretManager::SystemInteraction);
    req.setStoragePluginName(SecretManager::DefaultEncryptedStoragePluginName);
    req.setEncryptionPluginName(
        SecretManager::DefaultEncryptedStoragePluginName);
    req.setAuthenticationPluginName(
        SecretManager::DefaultAuthenticationPluginName);
    req.startRequest();
    req.waitForFinished();

    const Result result = req.result();
    if (result.code() == Result::Succeeded
            || result.errorCode() == Result::CollectionAlreadyExistsError) {
        m_collectionReady = true;
        return true;
    }
    logFailure("create collection", kCollectionName, result);
    return false;
}

bool SecretStore::remove(const QString &name)
{
    DeleteSecretRequest req;
    req.setManager(&m_manager);
    req.setIdentifier(identifier(name));
    req.setUserInteractionMode(SecretManager::SystemInteraction);
    req.startRequest();
    req.waitForFinished();

    const Result result = req.result();
    if (result.code() == Result::Succeeded || isNotFound(result)) {
        return true; // gone either way
    }
    logFailure("delete", name, result);
    return false;
}

bool SecretStore::store(const QString &name, const QByteArray &data)
{
    if (!ensureCollection()) {
        return false;
    }
    // Store does not overwrite an existing secret; replace explicitly.
    if (!remove(name)) {
        return false;
    }

    Secret secret(identifier(name));
    secret.setType(Secret::TypeBlob);
    secret.setData(data);

    StoreSecretRequest req;
    req.setManager(&m_manager);
    req.setSecretStorageType(StoreSecretRequest::CollectionSecret);
    req.setUserInteractionMode(SecretManager::SystemInteraction);
    req.setSecret(secret);
    req.startRequest();
    req.waitForFinished();

    const Result result = req.result();
    if (result.code() != Result::Succeeded) {
        logFailure("store", name, result);
        return false;
    }
    return true;
}

SecretStore::LoadStatus SecretStore::load(const QString &name,
                                          QByteArray *out)
{
    out->clear();
    StoredSecretRequest req;
    req.setManager(&m_manager);
    req.setIdentifier(identifier(name));
    req.setUserInteractionMode(SecretManager::SystemInteraction);
    req.startRequest();
    req.waitForFinished();

    const Result result = req.result();
    if (result.code() != Result::Succeeded) {
        if (isNotFound(result)) {
            return LoadStatus::Missing;
        }
        logFailure("read", name, result);
        return LoadStatus::Unavailable;
    }
    *out = req.secret().data();
    return out->isEmpty() ? LoadStatus::Missing : LoadStatus::Found;
}

void SecretStore::migrateFile(const QString &filePath, const QString &name)
{
    QFile file(filePath);
    if (!file.exists()) {
        return;
    }
    QByteArray existing;
    if (load(name, &existing) == LoadStatus::Found) {
        // Already migrated (e.g. a previous removal failed); file is stale.
        file.remove();
        return;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    const QByteArray data = file.readAll();
    file.close();
    if (data.isEmpty() || store(name, data)) {
        file.remove();
    }
}

} // namespace Leyni
