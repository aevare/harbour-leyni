#include "vaultmodel.h"

#include "vault.h"

namespace BitVault {
namespace Vault {

VaultListModel::VaultListModel(Vault *vault, QObject *parent)
    : QAbstractListModel(parent)
    , m_vault(vault)
{
    connect(m_vault, &Vault::lockedChanged, this, &VaultListModel::refresh);
}

int VaultListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return m_filtered.size();
}

QVariant VaultListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_filtered.size()) {
        return QVariant();
    }
    const DecryptedItem &item = m_filtered.at(index.row());
    switch (role) {
    case ItemIdRole:
        return item.id;
    case NameRole:
        return item.name;
    case UsernameRole:
        return item.username;
    case UriRole:
        return item.primaryUri;
    case CipherTypeRole:
        return static_cast<int>(item.type);
    case FavoriteRole:
        return item.favorite;
    case FolderIdRole:
        return item.folderId;
    case HasTotpRole:
        return item.hasTotp;
    case HasPasswordRole:
        return item.hasPassword;
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> VaultListModel::roleNames() const
{
    return {
        {ItemIdRole, QByteArrayLiteral("itemId")},
        {NameRole, QByteArrayLiteral("name")},
        {UsernameRole, QByteArrayLiteral("username")},
        {UriRole, QByteArrayLiteral("uri")},
        {CipherTypeRole, QByteArrayLiteral("cipherType")},
        {FavoriteRole, QByteArrayLiteral("favorite")},
        {FolderIdRole, QByteArrayLiteral("folderId")},
        {HasTotpRole, QByteArrayLiteral("hasTotp")},
        {HasPasswordRole, QByteArrayLiteral("hasPassword")},
    };
}

void VaultListModel::refresh()
{
    const std::vector<DecryptedItem> &items = m_vault->items();
    m_source.assign(items.begin(), items.end());
    applyFilter();
}

void VaultListModel::setSearchQuery(const QString &query)
{
    if (m_searchQuery == query) {
        return;
    }
    m_searchQuery = query;
    applyFilter();
}

void VaultListModel::setFolderFilter(const QString &folderId)
{
    if (m_folderFilter == folderId) {
        return;
    }
    m_folderFilter = folderId;
    applyFilter();
}

void VaultListModel::applyFilter()
{
    beginResetModel();
    m_filtered.clear();
    for (const DecryptedItem &item : m_source) {
        if (!m_folderFilter.isEmpty()) {
            if (m_folderFilter == QLatin1String("none")) {
                if (!item.folderId.isEmpty()) {
                    continue;
                }
            } else if (item.folderId != m_folderFilter) {
                continue;
            }
        }
        if (!m_searchQuery.isEmpty()) {
            const Qt::CaseSensitivity cs = Qt::CaseInsensitive;
            const bool matches = item.name.contains(m_searchQuery, cs)
                || item.username.contains(m_searchQuery, cs)
                || item.primaryUri.contains(m_searchQuery, cs);
            if (!matches) {
                continue;
            }
        }
        m_filtered.append(item);
    }
    endResetModel();
}

} // namespace Vault
} // namespace BitVault
