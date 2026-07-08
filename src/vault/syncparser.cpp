#include "syncparser.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace BitVault {
namespace Vault {

namespace {

// Accept camelCase (current servers) and PascalCase (older ones).
QJsonValue valueOf(const QJsonObject &obj, const QString &camelCase)
{
    if (obj.contains(camelCase)) {
        return obj.value(camelCase);
    }
    QString pascal = camelCase;
    pascal[0] = pascal[0].toUpper();
    return obj.value(pascal);
}

std::string encStringOf(const QJsonObject &obj, const QString &key)
{
    const QJsonValue value = valueOf(obj, key);
    return value.isString() ? value.toString().toStdString() : std::string();
}

void appendField(std::vector<EncryptedField> *fields, const QString &name,
                 const std::string &value)
{
    if (!value.empty()) {
        EncryptedField field;
        field.name = name.toStdString(); // literal field label, not encrypted
        field.value = value;
        fields->push_back(field);
    }
}

bool parseCipher(const QJsonObject &obj, EncryptedCipher *out)
{
    const QString id = valueOf(obj, QStringLiteral("id")).toString();
    const int type = valueOf(obj, QStringLiteral("type")).toInt(0);
    if (id.isEmpty() || type < 1 || type > 4) {
        return false;
    }
    out->id = id;
    out->type = static_cast<CipherType>(type);
    out->folderId = valueOf(obj, QStringLiteral("folderId")).toString();
    out->organizationId =
        valueOf(obj, QStringLiteral("organizationId")).toString();
    out->favorite = valueOf(obj, QStringLiteral("favorite")).toBool(false);
    out->revisionDate = QDateTime::fromString(
        valueOf(obj, QStringLiteral("revisionDate")).toString(), Qt::ISODate);
    out->key = encStringOf(obj, QStringLiteral("key"));
    out->name = encStringOf(obj, QStringLiteral("name"));
    if (out->name.empty()) {
        return false; // every cipher has an encrypted name
    }
    out->notes = encStringOf(obj, QStringLiteral("notes"));

    const QJsonValue loginValue = valueOf(obj, QStringLiteral("login"));
    if (out->type == CipherType::Login && loginValue.isObject()) {
        const QJsonObject login = loginValue.toObject();
        out->login.username = encStringOf(login, QStringLiteral("username"));
        out->login.password = encStringOf(login, QStringLiteral("password"));
        out->login.totp = encStringOf(login, QStringLiteral("totp"));
        const QJsonValue uris = valueOf(login, QStringLiteral("uris"));
        if (uris.isArray()) {
            const QJsonArray uriArray = uris.toArray();
            for (const QJsonValue &entry : uriArray) {
                const std::string uri =
                    encStringOf(entry.toObject(), QStringLiteral("uri"));
                if (!uri.empty()) {
                    out->login.uris.push_back(uri);
                }
            }
        }
    }

    const QJsonValue cardValue = valueOf(obj, QStringLiteral("card"));
    if (out->type == CipherType::Card && cardValue.isObject()) {
        const QJsonObject card = cardValue.toObject();
        const char *keys[] = {"cardholderName", "brand", "number",
                              "expMonth", "expYear", "code"};
        for (const char *key : keys) {
            appendField(&out->cardFields, QLatin1String(key),
                        encStringOf(card, QLatin1String(key)));
        }
    }

    const QJsonValue identityValue = valueOf(obj, QStringLiteral("identity"));
    if (out->type == CipherType::Identity && identityValue.isObject()) {
        const QJsonObject identity = identityValue.toObject();
        const char *keys[] = {"title", "firstName", "middleName", "lastName",
                              "address1", "address2", "address3", "city",
                              "state", "postalCode", "country", "company",
                              "email", "phone", "ssn", "username",
                              "passportNumber", "licenseNumber"};
        for (const char *key : keys) {
            appendField(&out->identityFields, QLatin1String(key),
                        encStringOf(identity, QLatin1String(key)));
        }
    }

    const QJsonValue fieldsValue = valueOf(obj, QStringLiteral("fields"));
    if (fieldsValue.isArray()) {
        const QJsonArray fieldArray = fieldsValue.toArray();
        for (const QJsonValue &entry : fieldArray) {
            const QJsonObject fieldObj = entry.toObject();
            EncryptedField field;
            field.name = encStringOf(fieldObj, QStringLiteral("name"));
            field.value = encStringOf(fieldObj, QStringLiteral("value"));
            field.type = valueOf(fieldObj, QStringLiteral("type")).toInt(0);
            if (!field.name.empty() || !field.value.empty()) {
                out->fields.push_back(field);
            }
        }
    }
    return true;
}

} // namespace

bool parseSyncJson(const QByteArray &json, SyncData *out,
                   QString *errorMessage, int *skippedCiphers)
{
    if (skippedCiphers != nullptr) {
        *skippedCiphers = 0;
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        *errorMessage = QStringLiteral("sync: invalid JSON");
        return false;
    }
    const QJsonObject root = doc.object();

    const QJsonValue profileValue = valueOf(root, QStringLiteral("profile"));
    if (!profileValue.isObject()) {
        *errorMessage = QStringLiteral("sync: missing profile");
        return false;
    }
    const QJsonObject profile = profileValue.toObject();
    out->profileEmail = valueOf(profile, QStringLiteral("email")).toString();
    out->profileKey = encStringOf(profile, QStringLiteral("key"));
    out->profilePrivateKey =
        encStringOf(profile, QStringLiteral("privateKey"));
    if (out->profileKey.empty()) {
        *errorMessage = QStringLiteral("sync: profile has no protected key");
        return false;
    }

    const QJsonValue orgsValue =
        valueOf(profile, QStringLiteral("organizations"));
    if (orgsValue.isArray()) {
        const QJsonArray orgs = orgsValue.toArray();
        for (const QJsonValue &entry : orgs) {
            const QJsonObject orgObj = entry.toObject();
            Organization org;
            org.id = valueOf(orgObj, QStringLiteral("id")).toString();
            org.name = valueOf(orgObj, QStringLiteral("name")).toString();
            org.key = encStringOf(orgObj, QStringLiteral("key"));
            if (!org.id.isEmpty() && !org.key.empty()) {
                out->organizations.push_back(org);
            }
        }
    }

    const QJsonValue ciphersValue = valueOf(root, QStringLiteral("ciphers"));
    if (ciphersValue.isArray()) {
        const QJsonArray ciphers = ciphersValue.toArray();
        for (const QJsonValue &entry : ciphers) {
            EncryptedCipher cipher;
            if (entry.isObject() && parseCipher(entry.toObject(), &cipher)) {
                out->ciphers.push_back(cipher);
            } else if (skippedCiphers != nullptr) {
                ++*skippedCiphers;
            }
        }
    }

    const QJsonValue foldersValue = valueOf(root, QStringLiteral("folders"));
    if (foldersValue.isArray()) {
        const QJsonArray folders = foldersValue.toArray();
        for (const QJsonValue &entry : folders) {
            const QJsonObject folderObj = entry.toObject();
            Folder folder;
            folder.id = valueOf(folderObj, QStringLiteral("id")).toString();
            folder.name = encStringOf(folderObj, QStringLiteral("name"));
            if (!folder.id.isEmpty() && !folder.name.empty()) {
                out->folders.push_back(folder);
            }
        }
    }

    const QJsonValue collectionsValue =
        valueOf(root, QStringLiteral("collections"));
    if (collectionsValue.isArray()) {
        const QJsonArray collections = collectionsValue.toArray();
        for (const QJsonValue &entry : collections) {
            const QJsonObject collectionObj = entry.toObject();
            Collection collection;
            collection.id =
                valueOf(collectionObj, QStringLiteral("id")).toString();
            collection.organizationId =
                valueOf(collectionObj, QStringLiteral("organizationId"))
                    .toString();
            collection.name =
                encStringOf(collectionObj, QStringLiteral("name"));
            if (!collection.id.isEmpty() && !collection.name.empty()) {
                out->collections.push_back(collection);
            }
        }
    }

    return true;
}

} // namespace Vault
} // namespace BitVault
