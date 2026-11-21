// Thin synchronous wrapper over Sailfish Secrets for the app's few persistent
// secrets: the PIN-wrapped master key, its wrong-attempt counter, and the
// OAuth refresh token.
//
// Everything lives in one owner-only, device-lock-protected collection inside
// the secrets daemon's encrypted (SQLCipher) storage, so none of it is a plain
// file that a backup or a copy of the home directory picks up. Values are
// stored as-is; callers decide what goes in (the PIN key is still the
// Argon2id-wrapped blob from src/crypto/pinwrap.h — nothing decrypted).
//
// Requires the "Secrets" Sailjail permission. Calls are short D-Bus
// round-trips to sailfishsecretsd and block until done.
#pragma once

#include <QByteArray>
#include <QString>

#include <Secrets/secretmanager.h>

namespace Leyni {

class SecretStore
{
public:
    enum class LoadStatus {
        Found,
        Missing,     // definitely not stored
        Unavailable, // daemon unreachable, collection locked, ...
    };

    bool store(const QString &name, const QByteArray &data);

    // `out` is cleared unless the status is Found.
    LoadStatus load(const QString &name, QByteArray *out);

    // True if the secret is gone afterwards (including "was never there").
    bool remove(const QString &name);

    // One-time move of a legacy plain-file value into Secrets. The file is
    // removed only once the value is safely stored (or already present).
    void migrateFile(const QString &filePath, const QString &name);

private:
    bool ensureCollection();

    Sailfish::Secrets::SecretManager m_manager;
    bool m_collectionReady = false;
};

} // namespace Leyni
