// Offline vault-layer tests (Phase 3, doc/TESTING.md Layer 2). No network:
// everything here unlocks the committed tests/fixtures/sync.json fixture
// (see tests/fixtures/README.md for what it is and how it was produced).
// Needs QCoreApplication because Vault uses QTimer for auto-lock.
#include <cstdio>
#include <cstring>

#include <QByteArray>
#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QSet>
#include <QString>
#include <QTimer>

#include "cipheritem.h"
#include "kdf.h"
#include "securebytes.h"
#include "syncparser.h"
#include "vault.h"
#include "vaultmodel.h"

#include "../check.h"

using namespace BitVault::Crypto;
using namespace BitVault::Vault;

namespace {

QByteArray readFixture(const char *name)
{
    QFile file(QString::fromUtf8(BITVAULT_FIXTURE_DIR) + QStringLiteral("/")
              + QString::fromUtf8(name));
    if (!file.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open fixture: %s\n", qPrintable(file.fileName()));
        std::exit(1);
    }
    return file.readAll();
}

SecureBytes toSecureBytes(const char *text)
{
    return SecureBytes(reinterpret_cast<const uint8_t *>(text), std::strlen(text));
}

const DecryptedItem *findByName(const std::vector<DecryptedItem> &items,
                                const QString &name)
{
    for (const DecryptedItem &item : items) {
        if (item.name == name) {
            return &item;
        }
    }
    return nullptr;
}

KdfParams fixtureKdf()
{
    KdfParams kdf;
    kdf.type = KdfType::Pbkdf2Sha256;
    kdf.iterations = 600000;
    return kdf;
}

void testParseSyncJson(const QByteArray &fixtureJson)
{
    SyncData data;
    QString error;
    int skipped = -1;
    const bool ok = parseSyncJson(fixtureJson, &data, &error, &skipped);
    CHECK(ok);
    CHECK(data.ciphers.size() >= 4);
    CHECK(data.folders.size() == 1);
    CHECK(!data.profileKey.empty());
    CHECK(skipped == 0);
    std::printf("parseSyncJson: OK (%zu ciphers, %zu folders, %d skipped)\n",
                data.ciphers.size(), data.folders.size(), skipped);
}

void testSyncparserNegatives()
{
    // Garbage bytes: not JSON at all.
    {
        SyncData data;
        QString error;
        CHECK(!parseSyncJson(QByteArray("not json {{{"), &data, &error));
        CHECK(!error.isEmpty());
    }

    // Structurally valid JSON, but no profile at all.
    {
        SyncData data;
        QString error;
        CHECK(!parseSyncJson(QByteArray("{}"), &data, &error));
        CHECK(!error.isEmpty());
    }

    // A cipher entry with no id/name must be skipped and counted, without
    // failing the whole parse (one bad item must not brick the vault).
    {
        QJsonObject profile;
        profile.insert(QStringLiteral("email"), QStringLiteral("nobody@example.com"));
        profile.insert(QStringLiteral("key"), QStringLiteral("2.iv|ct|mac"));

        QJsonObject badCipher;
        badCipher.insert(QStringLiteral("type"), 1); // no id, no name

        QJsonArray ciphers;
        ciphers.append(badCipher);

        QJsonObject root;
        root.insert(QStringLiteral("profile"), profile);
        root.insert(QStringLiteral("ciphers"), ciphers);

        const QByteArray json = QJsonDocument(root).toJson(QJsonDocument::Compact);

        SyncData data;
        QString error;
        int skipped = -1;
        const bool ok = parseSyncJson(json, &data, &error, &skipped);
        CHECK(ok);
        CHECK(data.ciphers.empty());
        CHECK(skipped == 1);
    }

    std::printf("syncparser negatives: OK\n");
}

void testUnlockAndLookups(const QByteArray &fixtureJson)
{
    Vault vault;
    QString error;
    int skipped = -1;
    CHECK(vault.loadSync(fixtureJson, &error, &skipped));
    CHECK(skipped == 0);

    CHECK(vault.unlock(QStringLiteral("fixture@bitvault.test"),
                       toSecureBytes("FixtureVault123!"), fixtureKdf(), &error));
    CHECK(!vault.isLocked());
    std::printf("unlock: OK\n");

    const std::vector<DecryptedItem> &items = vault.items();

    const DecryptedItem *login1 = findByName(items, QStringLiteral("Example Login"));
    CHECK(login1 != nullptr);
    CHECK(login1->username == QStringLiteral("alice@example.com"));
    CHECK(login1->primaryUri == QStringLiteral("https://example.com"));
    CHECK(login1->hasTotp);
    CHECK(login1->hasPassword);
    CHECK(!login1->hasNotes);   // fixture: notes null, fields empty
    CHECK(!login1->hasDetails);

    const DecryptedItem *login2 = findByName(items, QStringLiteral("Work Login"));
    CHECK(login2 != nullptr);
    CHECK(!login2->folderId.isEmpty());
    CHECK(vault.folderName(login2->folderId) == QStringLiteral("Work"));

    const DecryptedItem *note = findByName(items, QStringLiteral("Fixture Note"));
    CHECK(note != nullptr);
    CHECK(note->favorite);
    CHECK(note->type == CipherType::SecureNote);
    CHECK(note->hasNotes);

    const DecryptedItem *card = findByName(items, QStringLiteral("Fixture Card"));
    CHECK(card != nullptr);
    CHECK(card->type == CipherType::Card);
    CHECK(card->hasDetails);
    std::printf("items(): OK (found Example Login, Work Login, Fixture Note, "
                "Fixture Card)\n");

    // --- on-demand secret access ---
    {
        QString err;
        const QString pw = vault.itemPassword(login1->id, &err);
        CHECK(pw == QStringLiteral("s3cret-Pa55"));
    }
    {
        QString err;
        const QString notes = vault.itemNotes(note->id, &err);
        CHECK(notes == QStringLiteral("the note body"));
    }
    {
        QString err;
        const QList<QPair<QString, QString>> fields =
            vault.itemDetailFields(card->id, &err);
        bool foundNumber = false;
        bool foundCode = false;
        for (const auto &field : fields) {
            if (field.first == QStringLiteral("number")
                && field.second == QStringLiteral("4111111111111111")) {
                foundNumber = true;
            }
            if (field.first == QStringLiteral("code")
                && field.second == QStringLiteral("123")) {
                foundCode = true;
            }
        }
        CHECK(foundNumber);
        CHECK(foundCode);
    }
    std::printf("itemPassword/itemNotes/itemDetailFields: OK\n");

    // --- TOTP: only the RFC 4226 Appendix D table values, per doc/TESTING.md
    // (t=29 -> counter 0 -> "755224"; t=59 -> counter 1 -> "287082"). ---
    {
        int secondsRemaining = -1;
        QString err;
        const QString code = vault.totpCode(login1->id, 29, &secondsRemaining, &err);
        CHECK(code == QStringLiteral("755224"));
        CHECK(secondsRemaining == 1);
    }
    {
        int secondsRemaining = -1;
        QString err;
        const QString code = vault.totpCode(login1->id, 59, &secondsRemaining, &err);
        CHECK(code == QStringLiteral("287082"));
        CHECK(secondsRemaining == 1);
    }
    std::printf("totpCode: OK (RFC 4226 Appendix D values)\n");

    // --- VaultListModel ---
    {
        VaultListModel model(&vault);
        model.refresh();
        CHECK(static_cast<size_t>(model.rowCount()) == items.size());

        // Favourites sort first ("Fixture Note" is the fixture's only
        // favourite), and hasFavorites tracks the filtered view.
        CHECK(model.data(model.index(0, 0), VaultListModel::NameRole).toString()
              == QStringLiteral("Fixture Note"));
        CHECK(model.data(model.index(0, 0), VaultListModel::FavoriteRole).toBool());
        CHECK(model.hasFavorites());

        // Filtering must emit row-level updates only — a model reset per
        // keystroke makes the vault page's ListView rebuild, which dismisses
        // the keyboard while typing in the header search field.
        int resetCount = 0;
        QObject::connect(&model, &QAbstractItemModel::modelReset,
                         [&resetCount]() { ++resetCount; });

        model.setSearchQuery(QStringLiteral("work"));
        CHECK(model.rowCount() == 1);
        CHECK(model.data(model.index(0, 0), VaultListModel::NameRole).toString()
              == QStringLiteral("Work Login"));
        CHECK(!model.hasFavorites()); // no favourite matches "work"

        model.setSearchQuery(QStringLiteral("alice"));
        CHECK(model.rowCount() == 1); // matches by username

        model.setSearchQuery(QString());
        CHECK(static_cast<size_t>(model.rowCount()) == items.size());
        CHECK(model.data(model.index(0, 0), VaultListModel::NameRole).toString()
              == QStringLiteral("Fixture Note")); // sort intact after diffs
        CHECK(resetCount == 0);

        model.setFolderFilter(login2->folderId);
        CHECK(model.rowCount() == 1);

        model.setFolderFilter(QStringLiteral("none"));
        CHECK(model.rowCount() == static_cast<int>(items.size()) - 1);

        model.setFolderFilter(QString());
        CHECK(static_cast<size_t>(model.rowCount()) == items.size());
        CHECK(resetCount == 0); // folder switches diff too

        // Display-only contract: exactly the roles in the spec, nothing
        // that could carry a secret.
        const QHash<int, QByteArray> roles = model.roleNames();
        QSet<QByteArray> roleNames;
        for (auto it = roles.constBegin(); it != roles.constEnd(); ++it) {
            roleNames.insert(it.value());
        }
        const QSet<QByteArray> expected = {
            QByteArrayLiteral("itemId"),   QByteArrayLiteral("name"),
            QByteArrayLiteral("username"), QByteArrayLiteral("uri"),
            QByteArrayLiteral("cipherType"), QByteArrayLiteral("favorite"),
            QByteArrayLiteral("folderId"), QByteArrayLiteral("hasTotp"),
            QByteArrayLiteral("hasPassword"), QByteArrayLiteral("hasNotes"),
            QByteArrayLiteral("hasDetails"),
        };
        CHECK(roleNames == expected);

        // Locking the vault must clear the model without an explicit
        // refresh() call -- this is what the lockedChanged connection in
        // the constructor is for.
        vault.lock();
        CHECK(model.rowCount() == 0);
    }
    std::printf("VaultListModel: OK\n");
}

void testWrongPassword(const QByteArray &fixtureJson)
{
    Vault vault;
    QString error;
    CHECK(vault.loadSync(fixtureJson, &error));

    const bool ok = vault.unlock(QStringLiteral("fixture@bitvault.test"),
                                 toSecureBytes("WrongPassword123!"), fixtureKdf(),
                                 &error);
    CHECK(!ok);
    CHECK(error.contains(QStringLiteral("wrong master password")));
    CHECK(vault.isLocked());
    std::printf("wrong password: OK (rejected, vault stays locked)\n");
}

void testLockClearsStateAndSignals(const QByteArray &fixtureJson)
{
    Vault vault;
    QString error;
    CHECK(vault.loadSync(fixtureJson, &error));
    CHECK(vault.unlock(QStringLiteral("fixture@bitvault.test"),
                       toSecureBytes("FixtureVault123!"), fixtureKdf(), &error));
    CHECK(!vault.items().empty());

    int lockedSignalCount = 0;
    QObject::connect(&vault, &Vault::lockedChanged,
                     [&lockedSignalCount](bool) { ++lockedSignalCount; });

    vault.lock();
    CHECK(vault.isLocked());
    CHECK(vault.items().empty());
    CHECK(lockedSignalCount == 1);

    QString pwError;
    const QString pw = vault.itemPassword(QStringLiteral("does-not-matter"), &pwError);
    CHECK(pw.isEmpty());
    CHECK(pwError.contains(QStringLiteral("vault is locked")));

    std::printf("lock(): OK (items cleared, itemPassword fails closed, "
                "lockedChanged observed)\n");
}

void testAutoLock(const QByteArray &fixtureJson)
{
    Vault vault;
    QString error;
    CHECK(vault.loadSync(fixtureJson, &error));
    CHECK(vault.unlock(QStringLiteral("fixture@bitvault.test"),
                       toSecureBytes("FixtureVault123!"), fixtureKdf(), &error));

    vault.setAutoLockSeconds(1);
    vault.noteActivity();

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(1600);
    loop.exec();

    CHECK(vault.isLocked());
    std::printf("auto-lock: OK (locked after timeout)\n");
}

// reloadSync: a re-sync while unlocked keeps the vault usable without the
// password; a changed protected key fails closed into the locked state.
void testReloadSync(const QByteArray &fixtureJson)
{
    Vault vault;
    QString error;
    CHECK(vault.loadSync(fixtureJson, &error));
    CHECK(vault.unlock(QStringLiteral("fixture@bitvault.test"),
                       toSecureBytes("FixtureVault123!"), fixtureKdf(),
                       &error));

    // Same blob again (unchanged protected key): stays unlocked, items intact.
    const size_t itemCount = vault.items().size();
    CHECK(vault.reloadSync(fixtureJson, &error));
    CHECK(!vault.isLocked());
    CHECK(vault.items().size() == itemCount);
    QString pwError;
    const DecryptedItem *login =
        findByName(vault.items(), QStringLiteral("Example Login"));
    CHECK(login != nullptr);
    CHECK(vault.itemPassword(login->id, &pwError)
          == QStringLiteral("s3cret-Pa55"));

    // Tampered profile key (simulates a server-side password change):
    // must lock and fail with a re-auth message.
    QJsonObject root = QJsonDocument::fromJson(fixtureJson).object();
    QJsonObject profile = root.value(QStringLiteral("profile")).toObject();
    QString key = profile.value(QStringLiteral("key")).toString();
    key[3] = key[3] == QLatin1Char('A') ? QLatin1Char('B') : QLatin1Char('A');
    profile.insert(QStringLiteral("key"), key);
    root.insert(QStringLiteral("profile"), profile);
    const QByteArray changed = QJsonDocument(root).toJson();

    CHECK(!vault.reloadSync(changed, &error));
    CHECK(vault.isLocked());
    CHECK(vault.items().empty());

    // While locked, reloadSync must refuse outright.
    CHECK(!vault.reloadSync(fixtureJson, &error));
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const QByteArray fixtureJson = readFixture("sync.json");

    testParseSyncJson(fixtureJson);
    testSyncparserNegatives();
    testWrongPassword(fixtureJson);
    testUnlockAndLookups(fixtureJson);
    testLockClearsStateAndSignals(fixtureJson);
    testAutoLock(fixtureJson);
    testReloadSync(fixtureJson);

    std::printf("vault_tests: all checks passed\n");
    return 0;
}
