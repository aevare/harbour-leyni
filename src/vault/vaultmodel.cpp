#include "vaultmodel.h"

#include <QSet>

#include <algorithm>

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
    case HasNotesRole:
        return item.hasNotes;
    case HasDetailsRole:
        return item.hasDetails;
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
        {HasNotesRole, QByteArrayLiteral("hasNotes")},
        {HasDetailsRole, QByteArrayLiteral("hasDetails")},
    };
}

void VaultListModel::refresh()
{
    const std::vector<DecryptedItem> &items = m_vault->items();
    beginResetModel();
    m_source.assign(items.begin(), items.end());
    m_filtered = filteredItems();
    endResetModel();
    updateHasFavorites();
}

void VaultListModel::setSearchQuery(const QString &query)
{
    if (m_searchQuery == query) {
        return;
    }
    m_searchQuery = query;
    applyFilterDiff();
}

void VaultListModel::setFolderFilter(const QString &folderId)
{
    if (m_folderFilter == folderId) {
        return;
    }
    m_folderFilter = folderId;
    applyFilterDiff();
}

QList<DecryptedItem> VaultListModel::filteredItems() const
{
    QList<DecryptedItem> result;
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
        result.append(item);
    }
    // Favourites first, then by name — same collation as Vault::folders().
    // The stable sort keeps vault order for equal names, which also makes
    // every filtered list a subsequence of the same master order — the
    // precondition for the merge walk in applyFilterDiff().
    std::stable_sort(result.begin(), result.end(),
                     [](const DecryptedItem &a, const DecryptedItem &b) {
                         if (a.favorite != b.favorite) {
                             return a.favorite;
                         }
                         return a.name.localeAwareCompare(b.name) < 0;
                     });
    return result;
}

// Row-level inserts/removes instead of a model reset. A reset per keystroke
// makes the ListView rebuild everything: the view jolts, the scroll position
// jumps, and the keyboard is dismissed while typing in the header search
// field. Filter changes never reorder surviving rows (see filteredItems()),
// so a single merge walk emits the minimal row operations.
void VaultListModel::applyFilterDiff()
{
    const QList<DecryptedItem> fresh = filteredItems();

    QSet<QString> freshIds;
    for (const DecryptedItem &item : fresh) {
        freshIds.insert(item.id);
    }

    int row = 0;
    for (const DecryptedItem &item : fresh) {
        // Drop current rows that fell out of the filter.
        while (row < m_filtered.size() && m_filtered.at(row).id != item.id
               && !freshIds.contains(m_filtered.at(row).id)) {
            beginRemoveRows(QModelIndex(), row, row);
            m_filtered.removeAt(row);
            endRemoveRows();
        }
        if (row < m_filtered.size() && m_filtered.at(row).id == item.id) {
            ++row; // unchanged row
        } else {
            beginInsertRows(QModelIndex(), row, row);
            m_filtered.insert(row, item);
            endInsertRows();
            ++row;
        }
    }
    while (m_filtered.size() > row) {
        beginRemoveRows(QModelIndex(), row, row);
        m_filtered.removeAt(row);
        endRemoveRows();
    }

    updateHasFavorites();
}

void VaultListModel::updateHasFavorites()
{
    const bool hasFav = !m_filtered.isEmpty() && m_filtered.first().favorite;
    if (hasFav != m_hasFavorites) {
        m_hasFavorites = hasFav;
        emit hasFavoritesChanged();
    }
}

} // namespace Vault
} // namespace BitVault
