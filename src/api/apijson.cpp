#include "apijson.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QUrlQuery>

namespace BitVault {
namespace Api {

namespace {

void addFormField(QUrlQuery *query, const QString &key, const QString &value)
{
    // QUrlQuery::addQueryItem does not escape '+' etc. the way form
    // encoding requires; percent-encode explicitly.
    query->addQueryItem(QString::fromLatin1(QUrl::toPercentEncoding(key)),
                        QString::fromLatin1(QUrl::toPercentEncoding(value)));
}

void addDeviceFields(QUrlQuery *query, const DeviceInfo &device)
{
    addFormField(query, QStringLiteral("deviceType"),
                 QString::number(device.type));
    addFormField(query, QStringLiteral("deviceIdentifier"), device.identifier);
    addFormField(query, QStringLiteral("deviceName"), device.name);
}

// Bitwarden's JSON uses camelCase, but some deployments (and older server
// versions) emit PascalCase. Accept either.
QJsonValue valueOf(const QJsonObject &obj, const QString &camelCase)
{
    if (obj.contains(camelCase)) {
        return obj.value(camelCase);
    }
    QString pascal = camelCase;
    pascal[0] = pascal[0].toUpper();
    return obj.value(pascal);
}

} // namespace

QByteArray buildPreloginBody(const QString &email)
{
    QJsonObject obj;
    obj.insert(QStringLiteral("email"), email.trimmed().toLower());
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QByteArray buildPasswordTokenBody(const QString &email,
                                  const QByteArray &masterPasswordHashB64,
                                  const DeviceInfo &device,
                                  const TwoFactorRequest &twoFactor,
                                  const QString &newDeviceOtp)
{
    QUrlQuery query;
    addFormField(&query, QStringLiteral("grant_type"),
                 QStringLiteral("password"));
    addFormField(&query, QStringLiteral("username"),
                 email.trimmed().toLower());
    addFormField(&query, QStringLiteral("password"),
                 QString::fromLatin1(masterPasswordHashB64));
    addFormField(&query, QStringLiteral("scope"),
                 QStringLiteral("api offline_access"));
    addFormField(&query, QStringLiteral("client_id"), QStringLiteral("cli"));
    addDeviceFields(&query, device);
    if (twoFactor.provider >= 0) {
        addFormField(&query, QStringLiteral("twoFactorProvider"),
                     QString::number(twoFactor.provider));
        addFormField(&query, QStringLiteral("twoFactorToken"), twoFactor.token);
        addFormField(&query, QStringLiteral("twoFactorRemember"),
                     twoFactor.remember ? QStringLiteral("1")
                                        : QStringLiteral("0"));
    }
    if (!newDeviceOtp.isEmpty()) {
        addFormField(&query, QStringLiteral("newDeviceOtp"), newDeviceOtp);
    }
    return query.query(QUrl::FullyEncoded).toLatin1();
}

QByteArray buildApiKeyTokenBody(const QString &clientId,
                                const QByteArray &clientSecret,
                                const DeviceInfo &device)
{
    QUrlQuery query;
    addFormField(&query, QStringLiteral("grant_type"),
                 QStringLiteral("client_credentials"));
    addFormField(&query, QStringLiteral("client_id"), clientId);
    addFormField(&query, QStringLiteral("client_secret"),
                 QString::fromLatin1(clientSecret));
    addFormField(&query, QStringLiteral("scope"), QStringLiteral("api"));
    addDeviceFields(&query, device);
    return query.query(QUrl::FullyEncoded).toLatin1();
}

QByteArray buildRefreshTokenBody(const QByteArray &refreshToken)
{
    QUrlQuery query;
    addFormField(&query, QStringLiteral("grant_type"),
                 QStringLiteral("refresh_token"));
    addFormField(&query, QStringLiteral("client_id"), QStringLiteral("cli"));
    addFormField(&query, QStringLiteral("refresh_token"),
                 QString::fromLatin1(refreshToken));
    return query.query(QUrl::FullyEncoded).toLatin1();
}

QByteArray buildSendEmailLoginBody(const QString &email,
                                   const QByteArray &masterPasswordHashB64,
                                   const QString &deviceIdentifier)
{
    QJsonObject obj;
    obj.insert(QStringLiteral("email"), email.trimmed().toLower());
    obj.insert(QStringLiteral("masterPasswordHash"),
               QString::fromLatin1(masterPasswordHashB64));
    obj.insert(QStringLiteral("deviceIdentifier"), deviceIdentifier);
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QByteArray authEmailHeaderValue(const QString &email)
{
    return email.trimmed().toLower().toUtf8().toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

bool parsePreloginResponse(const QByteArray &body, PreloginResponse *out,
                           QString *errorMessage)
{
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        *errorMessage = QStringLiteral("prelogin: invalid JSON");
        return false;
    }
    const QJsonObject obj = doc.object();

    const int kdfType = valueOf(obj, QStringLiteral("kdf")).toInt(-1);
    Crypto::KdfParams params;
    switch (kdfType) {
    case 0:
        params.type = Crypto::KdfType::Pbkdf2Sha256;
        break;
    case 1:
        params.type = Crypto::KdfType::Argon2id;
        break;
    default:
        *errorMessage = QStringLiteral("prelogin: unknown KDF type %1")
                            .arg(kdfType);
        return false;
    }
    params.iterations = static_cast<uint32_t>(
        valueOf(obj, QStringLiteral("kdfIterations")).toInt(0));
    params.memoryMiB = static_cast<uint32_t>(
        valueOf(obj, QStringLiteral("kdfMemory")).toInt(0));
    params.parallelism = static_cast<uint32_t>(
        valueOf(obj, QStringLiteral("kdfParallelism")).toInt(0));
    // Range validation happens in the crypto layer when the values are used.
    out->kdf = params;
    return true;
}

bool parseTokenResponse(const QByteArray &body, TokenResponse *out,
                        QString *errorMessage)
{
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        *errorMessage = QStringLiteral("token: invalid JSON");
        return false;
    }
    const QJsonObject obj = doc.object();
    const QString accessToken =
        obj.value(QStringLiteral("access_token")).toString();
    if (accessToken.isEmpty()) {
        *errorMessage = QStringLiteral("token: missing access_token");
        return false;
    }
    out->accessToken = accessToken.toUtf8();
    out->refreshToken =
        obj.value(QStringLiteral("refresh_token")).toString().toUtf8();
    out->expiresInSeconds = obj.value(QStringLiteral("expires_in")).toInt(0);
    out->key = valueOf(obj, QStringLiteral("key")).toString();
    out->privateKey = valueOf(obj, QStringLiteral("privateKey")).toString();
    out->twoFactorRememberToken =
        valueOf(obj, QStringLiteral("twoFactorToken")).toString();
    return true;
}

ApiError parseTokenError(int httpStatus, const QByteArray &body)
{
    ApiError error;
    error.httpStatus = httpStatus;

    const QJsonDocument doc = QJsonDocument::fromJson(body);
    if (!doc.isObject()) {
        error.message = QStringLiteral("HTTP %1").arg(httpStatus);
        return error;
    }
    const QJsonObject obj = doc.object();

    // Two-factor challenge: the error body lists available providers.
    const QJsonValue providers =
        valueOf(obj, QStringLiteral("twoFactorProviders"));
    if (providers.isArray()) {
        error.twoFactorRequired = true;
        const QJsonArray arr = providers.toArray();
        for (const QJsonValue &v : arr) {
            // Servers emit these as numbers or as strings; accept both.
            bool ok = false;
            const int id = v.isString() ? v.toString().toInt(&ok)
                                        : v.toInt(-1);
            if (v.isString() ? ok : id >= 0) {
                error.twoFactorProviders.append(
                    v.isString() ? v.toString().toInt() : id);
            }
        }
    }

    if (obj.contains(QStringLiteral("HCaptcha_SiteKey"))
            || obj.contains(QStringLiteral("hCaptcha_SiteKey"))) {
        error.captchaRequired = true;
    }

    QString description =
        obj.value(QStringLiteral("error_description")).toString();
    // Newer servers put the human-readable message in an ErrorModel.
    const QJsonValue model = valueOf(obj, QStringLiteral("errorModel"));
    if (model.isObject()) {
        const QString modelMessage =
            valueOf(model.toObject(), QStringLiteral("message")).toString();
        if (!modelMessage.isEmpty()) {
            description = modelMessage;
        }
    }
    if (description.isEmpty()) {
        description = obj.value(QStringLiteral("error")).toString();
    }
    error.message = description.isEmpty()
        ? QStringLiteral("HTTP %1").arg(httpStatus)
        : description;

    if (error.message.contains(QStringLiteral("new device"),
                               Qt::CaseInsensitive)
            || error.message.contains(QStringLiteral("device verification"),
                                      Qt::CaseInsensitive)) {
        error.newDeviceVerificationRequired = true;
    }
    return error;
}

} // namespace Api
} // namespace BitVault
