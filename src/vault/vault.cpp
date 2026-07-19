#include "vault.h"

#include <algorithm>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>

#include "base64.h"
#include "crypto.h"
#include "encstring.h"
#include "totp.h"

namespace BitVault {
namespace Vault {

namespace {

using Crypto::CryptoError;
using Crypto::EncString;
using Crypto::SecureBytes;
using Crypto::SymmetricKey;

// Accept camelCase (current servers) and PascalCase (older ones), mirroring
// syncparser's reader — the raw cipher object we patch came from there.
QJsonValue rawValueOf(const QJsonObject &obj, const QString &camelCase)
{
    if (obj.contains(camelCase)) {
        return obj.value(camelCase);
    }
    QString pascal = camelCase;
    pascal[0] = pascal[0].toUpper();
    return obj.value(pascal);
}

QString fromSecure(const SecureBytes &bytes)
{
    return QString::fromUtf8(reinterpret_cast<const char *>(bytes.data()),
                             static_cast<int>(bytes.size()));
}

// TOTP secret parameters extracted from either a raw base32 secret or an
// otpauth:// URI.
struct TotpSpec {
    std::string base32Secret;
    uint32_t period = 30;
    int digits = 6;
    Crypto::TotpAlgorithm algorithm = Crypto::TotpAlgorithm::Sha1;
};

// Minimal otpauth:// query parsing on std::string — deliberately not QUrl,
// to keep the number of copies of the secret low and under our control.
bool parseTotpSecret(const std::string &raw, TotpSpec *spec, QString *error)
{
    if (raw.compare(0, 8, "steam://") == 0) {
        *error = QStringLiteral("Steam TOTP is not supported");
        return false;
    }
    if (raw.compare(0, 10, "otpauth://") != 0) {
        spec->base32Secret = raw; // plain base32 secret
        return true;
    }
    const size_t queryStart = raw.find('?');
    if (queryStart == std::string::npos) {
        *error = QStringLiteral("otpauth URI has no parameters");
        return false;
    }
    size_t pos = queryStart + 1;
    while (pos < raw.size()) {
        size_t end = raw.find('&', pos);
        if (end == std::string::npos) {
            end = raw.size();
        }
        const size_t eq = raw.find('=', pos);
        if (eq != std::string::npos && eq < end) {
            const std::string key = raw.substr(pos, eq - pos);
            const std::string value = raw.substr(eq + 1, end - eq - 1);
            if (key == "secret") {
                spec->base32Secret = value;
            } else if (key == "period") {
                spec->period = static_cast<uint32_t>(std::atoi(value.c_str()));
            } else if (key == "digits") {
                spec->digits = std::atoi(value.c_str());
            } else if (key == "algorithm") {
                if (value == "SHA1" || value == "sha1") {
                    spec->algorithm = Crypto::TotpAlgorithm::Sha1;
                } else if (value == "SHA256" || value == "sha256") {
                    spec->algorithm = Crypto::TotpAlgorithm::Sha256;
                } else if (value == "SHA512" || value == "sha512") {
                    spec->algorithm = Crypto::TotpAlgorithm::Sha512;
                } else {
                    *error = QStringLiteral("unsupported TOTP algorithm");
                    return false;
                }
            }
        }
        pos = end + 1;
    }
    if (spec->base32Secret.empty()) {
        *error = QStringLiteral("otpauth URI has no secret");
        return false;
    }
    if (spec->period == 0 || spec->digits < 6 || spec->digits > 10) {
        *error = QStringLiteral("otpauth URI has invalid parameters");
        return false;
    }
    return true;
}

} // namespace

Vault::Vault(QObject *parent)
    : QObject(parent)
{
    m_autoLockTimer.setSingleShot(true);
    connect(&m_autoLockTimer, &QTimer::timeout, this, &Vault::lock);
}

Vault::~Vault()
{
    lock();
}

bool Vault::loadSync(const QByteArray &rawJson, QString *errorMessage,
                     int *skippedCiphers)
{
    SyncData data;
    if (!parseSyncJson(rawJson, &data, errorMessage, skippedCiphers)) {
        return false;
    }
    // New data invalidates any decrypted state derived from the old data.
    lock();
    m_data = std::move(data);
    return true;
}

bool Vault::unlock(const QString &email, Crypto::SecureBytes password,
                   const Crypto::KdfParams &kdfParams, QString *errorMessage)
{
    try {
        const std::string emailLower =
            email.trimmed().toLower().toStdString();
        SecureBytes masterKey =
            Crypto::deriveMasterKey(password, emailLower, kdfParams);
        return unlockWithMasterKey(std::move(masterKey), errorMessage);
    } catch (const CryptoError &e) {
        *errorMessage = QStringLiteral("unlock failed: %1")
                            .arg(QString::fromUtf8(e.what()));
        return false;
    }
}

bool Vault::unlockWithMasterKey(Crypto::SecureBytes masterKey,
                                QString *errorMessage)
{
    if (m_data.profileKey.empty()) {
        *errorMessage = QStringLiteral("no vault data loaded");
        return false;
    }
    lock();

    try {
        SymmetricKey stretched = Crypto::stretchMasterKey(masterKey);

        SecureBytes userKeyRaw;
        try {
            userKeyRaw = Crypto::decryptAes256CbcHmac(
                EncString::parse(m_data.profileKey), stretched);
        } catch (const CryptoError &) {
            // MAC mismatch on the protected key ⇒ wrong password (or a
            // corrupted blob — indistinguishable by design).
            *errorMessage = QStringLiteral("wrong master password");
            return false;
        }
        m_userKey = Crypto::symmetricKeyFromBytes(userKeyRaw);

        rebuildDisplayData();
    } catch (const CryptoError &e) {
        lock();
        *errorMessage = QStringLiteral("unlock failed: %1")
                            .arg(QString::fromUtf8(e.what()));
        return false;
    }

    m_locked = false;
    if (m_autoLockTimer.interval() > 0) {
        m_autoLockTimer.start();
    }
    emit lockedChanged(false);
    return true;
}

bool Vault::verifyMasterKey(const Crypto::SecureBytes &masterKey,
                            QString *errorMessage) const
{
    if (m_data.profileKey.empty()) {
        *errorMessage = QStringLiteral("no vault data loaded");
        return false;
    }
    try {
        SymmetricKey stretched = Crypto::stretchMasterKey(masterKey);
        // Throws on MAC mismatch ⇒ wrong master key. The decrypted bytes are
        // dropped immediately (SecureBytes destructor zeroes them).
        Crypto::decryptAes256CbcHmac(EncString::parse(m_data.profileKey),
                                     stretched);
        return true;
    } catch (const CryptoError &) {
        *errorMessage = QStringLiteral("wrong master password");
        return false;
    }
}

bool Vault::reloadSync(const QByteArray &rawJson, QString *errorMessage,
                       int *skippedCiphers)
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return false;
    }
    SyncData data;
    if (!parseSyncJson(rawJson, &data, errorMessage, skippedCiphers)) {
        return false;
    }
    // The user key in memory is only known to fit if the account's protected
    // key is unchanged. If it changed (password change/rotation on the
    // server), fail closed: lock and demand the password.
    if (data.profileKey != m_data.profileKey) {
        lock();
        *errorMessage =
            QStringLiteral("account keys changed — please unlock again");
        return false;
    }

    m_data = std::move(data);
    m_orgKeys.clear();
    m_items.clear();
    m_folderNames.clear();
    try {
        rebuildDisplayData();
    } catch (const CryptoError &e) {
        lock();
        *errorMessage = QStringLiteral("re-sync failed: %1")
                            .arg(QString::fromUtf8(e.what()));
        return false;
    }
    return true;
}

void Vault::rebuildDisplayData()
{
    if (!m_data.profilePrivateKey.empty()) {
        m_privateKeyDer = Crypto::decryptAes256CbcHmac(
            EncString::parse(m_data.profilePrivateKey), m_userKey);
    }

    // Organization keys are RSA-wrapped with the account key. A broken
    // org key must not brick the personal vault: skip it, its ciphers
    // will report an error on access.
    for (const Organization &org : m_data.organizations) {
        if (m_privateKeyDer.empty()) {
            break;
        }
        try {
            SecureBytes orgKeyRaw = Crypto::decryptRsaOaepSha1(
                EncString::parse(org.key), m_privateKeyDer);
            m_orgKeys.emplace(org.id,
                              Crypto::symmetricKeyFromBytes(orgKeyRaw));
        } catch (const CryptoError &) {
            continue;
        }
    }

    for (const Folder &folder : m_data.folders) {
        m_folderNames.insert(folder.id,
                             decryptToString(folder.name, m_userKey));
    }

    m_items.reserve(m_data.ciphers.size());
    for (const EncryptedCipher &cipher : m_data.ciphers) {
        SymmetricKey key;
        QString keyError;
        if (!cipherKey(cipher, &key, &keyError)) {
            continue; // org key unavailable; skip from display
        }
        DecryptedItem item;
        item.id = cipher.id;
        item.type = cipher.type;
        item.folderId = cipher.folderId;
        item.organizationId = cipher.organizationId;
        item.favorite = cipher.favorite;
        item.name = decryptToString(cipher.name, key);
        item.hasNotes = !cipher.notes.empty();
        item.hasDetails = !cipher.fields.empty() || !cipher.cardFields.empty()
            || !cipher.identityFields.empty();
        if (cipher.type == CipherType::Login) {
            if (!cipher.login.username.empty()) {
                item.username =
                    decryptToString(cipher.login.username, key);
            }
            if (!cipher.login.uris.empty()) {
                item.primaryUri =
                    decryptToString(cipher.login.uris.front(), key);
            }
            item.hasTotp = !cipher.login.totp.empty();
            item.hasPassword = !cipher.login.password.empty();
        }
        m_items.push_back(item);
    }
}

void Vault::lock()
{
    const bool wasLocked = m_locked;
    m_autoLockTimer.stop();

    // SecureBytes destructors zero the key material.
    m_userKey = Crypto::SymmetricKey();
    m_privateKeyDer = Crypto::SecureBytes();
    m_orgKeys.clear();

    m_items.clear();
    m_items.shrink_to_fit();
    m_folderNames.clear();

    m_locked = true;
    if (!wasLocked) {
        emit lockedChanged(true);
    }
}

QString Vault::folderName(const QString &folderId) const
{
    return m_folderNames.value(folderId);
}

QList<QPair<QString, QString>> Vault::folders() const
{
    QList<QPair<QString, QString>> result;
    for (auto it = m_folderNames.constBegin(); it != m_folderNames.constEnd();
         ++it) {
        result.append(qMakePair(it.key(), it.value()));
    }
    std::sort(result.begin(), result.end(),
              [](const QPair<QString, QString> &a,
                 const QPair<QString, QString> &b) {
                  return a.second.localeAwareCompare(b.second) < 0;
              });
    return result;
}

const EncryptedCipher *Vault::findCipher(const QString &itemId) const
{
    for (const EncryptedCipher &cipher : m_data.ciphers) {
        if (cipher.id == itemId) {
            return &cipher;
        }
    }
    return nullptr;
}

bool Vault::cipherKey(const EncryptedCipher &cipher, SymmetricKey *key,
                      QString *errorMessage) const
{
    const SymmetricKey *owner = &m_userKey;
    if (!cipher.organizationId.isEmpty()) {
        const auto it = m_orgKeys.find(cipher.organizationId);
        if (it == m_orgKeys.end()) {
            *errorMessage =
                QStringLiteral("organization key unavailable for this item");
            return false;
        }
        owner = &it->second;
    }
    if (cipher.key.empty()) {
        // SymmetricKey holds SecureBytes (move-only); make explicit copies.
        key->encKey = SecureBytes(owner->encKey.data(), owner->encKey.size());
        key->macKey = SecureBytes(owner->macKey.data(), owner->macKey.size());
        return true;
    }
    try {
        SecureBytes itemKeyRaw = Crypto::decryptAes256CbcHmac(
            EncString::parse(cipher.key), *owner);
        *key = Crypto::symmetricKeyFromBytes(itemKeyRaw);
        return true;
    } catch (const CryptoError &e) {
        *errorMessage = QStringLiteral("item key unwrap failed: %1")
                            .arg(QString::fromUtf8(e.what()));
        return false;
    }
}

QString Vault::decryptToString(const std::string &encString,
                               const SymmetricKey &key) const
{
    const SecureBytes plain =
        Crypto::decryptAes256CbcHmac(EncString::parse(encString), key);
    return fromSecure(plain);
}

QString Vault::itemPassword(const QString &itemId, QString *errorMessage)
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return QString();
    }
    const EncryptedCipher *cipher = findCipher(itemId);
    if (cipher == nullptr || cipher->login.password.empty()) {
        *errorMessage = QStringLiteral("no password on this item");
        return QString();
    }
    SymmetricKey key;
    if (!cipherKey(*cipher, &key, errorMessage)) {
        return QString();
    }
    try {
        return decryptToString(cipher->login.password, key);
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        return QString();
    }
}

QString Vault::itemNotes(const QString &itemId, QString *errorMessage)
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return QString();
    }
    const EncryptedCipher *cipher = findCipher(itemId);
    if (cipher == nullptr || cipher->notes.empty()) {
        return QString();
    }
    SymmetricKey key;
    if (!cipherKey(*cipher, &key, errorMessage)) {
        return QString();
    }
    try {
        return decryptToString(cipher->notes, key);
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        return QString();
    }
}

QString Vault::itemTotpSecret(const QString &itemId, QString *errorMessage)
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return QString();
    }
    const EncryptedCipher *cipher = findCipher(itemId);
    if (cipher == nullptr || cipher->login.totp.empty()) {
        return QString();
    }
    SymmetricKey key;
    if (!cipherKey(*cipher, &key, errorMessage)) {
        return QString();
    }
    try {
        return decryptToString(cipher->login.totp, key);
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        return QString();
    }
}

QList<QPair<QString, QString>> Vault::itemDetailFields(const QString &itemId,
                                                       QString *errorMessage)
{
    QList<QPair<QString, QString>> result;
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return result;
    }
    const EncryptedCipher *cipher = findCipher(itemId);
    if (cipher == nullptr) {
        *errorMessage = QStringLiteral("unknown item");
        return result;
    }
    SymmetricKey key;
    if (!cipherKey(*cipher, &key, errorMessage)) {
        return result;
    }
    try {
        for (const EncryptedField &field : cipher->cardFields) {
            result.append(qMakePair(QString::fromStdString(field.name),
                                    decryptToString(field.value, key)));
        }
        for (const EncryptedField &field : cipher->identityFields) {
            result.append(qMakePair(QString::fromStdString(field.name),
                                    decryptToString(field.value, key)));
        }
        for (const EncryptedField &field : cipher->fields) {
            const QString name = field.name.empty()
                ? QString()
                : decryptToString(field.name, key);
            const QString value = field.value.empty()
                ? QString()
                : decryptToString(field.value, key);
            result.append(qMakePair(name, value));
        }
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        result.clear();
    }
    return result;
}

QString Vault::totpCode(const QString &itemId, quint64 unixTime,
                        int *secondsRemaining, QString *errorMessage)
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return QString();
    }
    const EncryptedCipher *cipher = findCipher(itemId);
    if (cipher == nullptr || cipher->login.totp.empty()) {
        *errorMessage = QStringLiteral("no TOTP secret on this item");
        return QString();
    }
    SymmetricKey key;
    if (!cipherKey(*cipher, &key, errorMessage)) {
        return QString();
    }
    try {
        SecureBytes rawSecret = Crypto::decryptAes256CbcHmac(
            EncString::parse(cipher->login.totp), key);
        std::string secretText(
            reinterpret_cast<const char *>(rawSecret.data()),
            rawSecret.size());

        TotpSpec spec;
        const bool parsed = parseTotpSecret(secretText, &spec, errorMessage);
        Crypto::secureZero(&secretText[0], secretText.size());
        if (!parsed) {
            return QString();
        }

        const std::vector<uint8_t> keyBytes =
            Crypto::base32Decode(spec.base32Secret);
        Crypto::secureZero(&spec.base32Secret[0], spec.base32Secret.size());
        SecureBytes totpKey(keyBytes.data(), keyBytes.size());
        Crypto::secureZero(
            const_cast<uint8_t *>(keyBytes.data()), keyBytes.size());

        const std::string code = Crypto::totp(
            totpKey, unixTime, spec.period, spec.digits, spec.algorithm);
        if (secondsRemaining != nullptr) {
            *secondsRemaining =
                static_cast<int>(spec.period - (unixTime % spec.period));
        }
        return QString::fromStdString(code);
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        return QString();
    }
}

void Vault::setAutoLockSeconds(int seconds)
{
    if (seconds <= 0) {
        m_autoLockTimer.stop();
        m_autoLockTimer.setInterval(0);
        return;
    }
    m_autoLockTimer.setInterval(seconds * 1000);
    if (!m_locked) {
        m_autoLockTimer.start();
    }
}

void Vault::noteActivity()
{
    if (!m_locked && m_autoLockTimer.interval() > 0) {
        m_autoLockTimer.start();
    }
}

std::string Vault::encryptField(const QString &plaintext,
                                const SymmetricKey &key) const
{
    if (plaintext.isEmpty()) {
        return std::string();
    }
    const QByteArray utf8 = plaintext.toUtf8();
    SecureBytes pt(reinterpret_cast<const uint8_t *>(utf8.constData()),
                   static_cast<size_t>(utf8.size()));
    return Crypto::encryptAes256CbcHmac(pt, key).serialize();
    // The QByteArray copy of the plaintext is freed unzeroed — the same Qt
    // limitation accepted elsewhere for user-entered strings (see toSecure).
}

QJsonObject Vault::buildLoginObject(const QVariantMap &fields,
                                    const QJsonObject &existing,
                                    const SymmetricKey &key) const
{
    auto encOrNull = [&](const QString &plaintext) -> QJsonValue {
        const std::string enc = encryptField(plaintext, key);
        return enc.empty() ? QJsonValue(QJsonValue::Null)
                           : QJsonValue(QString::fromStdString(enc));
    };

    QJsonObject login = existing;
    login.insert(QStringLiteral("username"),
                 encOrNull(fields.value(QStringLiteral("username")).toString()));
    login.insert(QStringLiteral("password"),
                 encOrNull(fields.value(QStringLiteral("password")).toString()));
    login.insert(QStringLiteral("totp"),
                 encOrNull(fields.value(QStringLiteral("totp")).toString()));

    // The editor exposes one (primary) URI. Patch uris[0] and keep any extra
    // URIs the item already had; only clear when there is at most one.
    const QString uri = fields.value(QStringLiteral("uri")).toString();
    QJsonArray uris = rawValueOf(existing, QStringLiteral("uris")).toArray();
    if (!uri.isEmpty()) {
        QJsonObject first =
            uris.isEmpty() ? QJsonObject() : uris.at(0).toObject();
        first.insert(QStringLiteral("uri"),
                     QJsonValue(QString::fromStdString(encryptField(uri, key))));
        if (!first.contains(QStringLiteral("match"))) {
            first.insert(QStringLiteral("match"), QJsonValue(QJsonValue::Null));
        }
        if (uris.isEmpty()) {
            uris.append(first);
        } else {
            uris.replace(0, first);
        }
        login.insert(QStringLiteral("uris"), uris);
    } else if (uris.size() <= 1) {
        login.insert(QStringLiteral("uris"), QJsonValue(QJsonValue::Null));
    }
    return login;
}

QByteArray Vault::buildCreateBody(CipherType type, const QVariantMap &fields,
                                  QString *errorMessage) const
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return QByteArray();
    }
    const QString name = fields.value(QStringLiteral("name")).toString();
    if (name.isEmpty()) {
        *errorMessage = QStringLiteral("name is required");
        return QByteArray();
    }
    // New personal items are encrypted directly under the user key (no
    // per-item key — Bitwarden's default for freshly created ciphers).
    const SymmetricKey &key = m_userKey;

    try {
        auto encOrNull = [&](const QString &plaintext) -> QJsonValue {
            const std::string enc = encryptField(plaintext, key);
            return enc.empty() ? QJsonValue(QJsonValue::Null)
                               : QJsonValue(QString::fromStdString(enc));
        };
        const QString folderId =
            fields.value(QStringLiteral("folderId")).toString();

        QJsonObject body;
        body.insert(QStringLiteral("type"), static_cast<int>(type));
        body.insert(QStringLiteral("name"),
                    QString::fromStdString(encryptField(name, key)));
        body.insert(QStringLiteral("notes"),
                    encOrNull(fields.value(QStringLiteral("notes")).toString()));
        body.insert(QStringLiteral("favorite"),
                    fields.value(QStringLiteral("favorite")).toBool());
        body.insert(QStringLiteral("folderId"),
                    folderId.isEmpty() ? QJsonValue(QJsonValue::Null)
                                       : QJsonValue(folderId));
        body.insert(QStringLiteral("organizationId"),
                    QJsonValue(QJsonValue::Null));

        if (type == CipherType::Login) {
            body.insert(QStringLiteral("login"),
                        buildLoginObject(fields, QJsonObject(), key));
        } else if (type == CipherType::SecureNote) {
            QJsonObject note;
            note.insert(QStringLiteral("type"), 0);
            body.insert(QStringLiteral("secureNote"), note);
        } else {
            *errorMessage = QStringLiteral("unsupported item type");
            return QByteArray();
        }
        return QJsonDocument(body).toJson(QJsonDocument::Compact);
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        return QByteArray();
    }
}

QByteArray Vault::buildUpdateBody(const QString &itemId,
                                  const QVariantMap &fields,
                                  QString *errorMessage) const
{
    if (m_locked) {
        *errorMessage = QStringLiteral("vault is locked");
        return QByteArray();
    }
    const EncryptedCipher *cipher = findCipher(itemId);
    if (cipher == nullptr) {
        *errorMessage = QStringLiteral("item not found");
        return QByteArray();
    }
    const QString name = fields.value(QStringLiteral("name")).toString();
    if (name.isEmpty()) {
        *errorMessage = QStringLiteral("name is required");
        return QByteArray();
    }
    SymmetricKey key;
    if (!cipherKey(*cipher, &key, errorMessage)) {
        return QByteArray();
    }

    try {
        auto encOrNull = [&](const QString &plaintext) -> QJsonValue {
            const std::string enc = encryptField(plaintext, key);
            return enc.empty() ? QJsonValue(QJsonValue::Null)
                               : QJsonValue(QString::fromStdString(enc));
        };

        // Start from the original object so unmodeled fields (password
        // history, custom fields, extra URIs, reprompt) survive verbatim.
        QJsonObject body = cipher->raw;
        const QString revision =
            rawValueOf(body, QStringLiteral("revisionDate")).toString();

        // Remove response-only keys the update endpoint does not accept.
        static const char *const responseOnly[] = {
            "object", "id", "revisionDate", "creationDate", "deletedDate",
            "edit", "viewPassword", "permissions", "collectionIds",
            "organizationUseTotp"};
        for (const char *k : responseOnly) {
            QString camel = QLatin1String(k);
            body.remove(camel);
            QString pascal = camel;
            pascal[0] = pascal[0].toUpper();
            body.remove(pascal);
        }

        const QString folderId =
            fields.value(QStringLiteral("folderId")).toString();
        body.insert(QStringLiteral("name"),
                    QString::fromStdString(encryptField(name, key)));
        body.insert(QStringLiteral("notes"),
                    encOrNull(fields.value(QStringLiteral("notes")).toString()));
        body.insert(QStringLiteral("favorite"),
                    fields.value(QStringLiteral("favorite")).toBool());
        body.insert(QStringLiteral("folderId"),
                    folderId.isEmpty() ? QJsonValue(QJsonValue::Null)
                                       : QJsonValue(folderId));

        if (cipher->type == CipherType::Login) {
            const QJsonObject existing =
                rawValueOf(body, QStringLiteral("login")).toObject();
            body.remove(QStringLiteral("Login"));
            body.insert(QStringLiteral("login"),
                        buildLoginObject(fields, existing, key));
        }

        // Optimistic-concurrency hint: the server rejects the edit if the item
        // changed elsewhere since this revision.
        if (!revision.isEmpty()) {
            body.insert(QStringLiteral("lastKnownRevisionDate"), revision);
        }
        return QJsonDocument(body).toJson(QJsonDocument::Compact);
    } catch (const CryptoError &e) {
        *errorMessage = QString::fromUtf8(e.what());
        return QByteArray();
    }
}

} // namespace Vault
} // namespace BitVault
