// Qt list model exposing the unlocked Vault's decrypted items to QML.
//
// Display-only contract: every role below carries only fields already
// present on DecryptedItem (see cipheritem.h) — item id, name, username,
// primary URI, cipher type, favorite flag, folder id, and whether a TOTP
// secret / password exist. NOTHING here ever carries a password, a TOTP
// secret, a note body, card/identity fields, or any key material. There is
// no method on this class that returns a secret, and there never should be
// — secrets stay behind Vault::itemPassword/itemNotes/itemDetailFields/
// totpCode, which the UI calls per-access, on demand. If a future role or
// method would expose more than DecryptedItem already holds, it belongs on
// Vault, not here.
#pragma once

#include <QAbstractListModel>
#include <QHash>
#include <QList>
#include <QString>

#include <vector>

#include "cipheritem.h"

namespace BitVault {
namespace Vault {

class Vault;

class VaultListModel : public QAbstractListModel
{
    Q_OBJECT

public:
    enum Role {
        ItemIdRole = Qt::UserRole + 1,
        NameRole,
        UsernameRole,
        UriRole,
        CipherTypeRole,
        FavoriteRole,
        FolderIdRole,
        HasTotpRole,
        HasPasswordRole,
    };

    explicit VaultListModel(Vault *vault, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

public slots:
    // Re-reads vault->items() and re-applies the current filter: a full
    // model reset. Call after unlock(); also connected to
    // Vault::lockedChanged so locking clears the model automatically.
    void refresh();

    // Case-insensitive substring match over name/username/uri. Re-filters
    // immediately.
    void setSearchQuery(const QString &query);

    // Empty = all items; the literal string "none" = items with no folder.
    // Re-filters immediately.
    void setFolderFilter(const QString &folderId);

private:
    void applyFilter();

    Vault *m_vault;
    std::vector<DecryptedItem> m_source; // full set from vault->items()
    QList<DecryptedItem> m_filtered;     // source after search/folder filter
    QString m_searchQuery;
    QString m_folderFilter;
};

} // namespace Vault
} // namespace BitVault
