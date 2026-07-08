#include "apiclient.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace BitVault {
namespace Api {

namespace {

int httpStatusOf(QNetworkReply *reply)
{
    return reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
}

ApiError transportError(QNetworkReply *reply)
{
    ApiError error;
    error.networkError = true;
    error.message = reply->errorString();
    return error;
}

} // namespace

ApiClient::ApiClient(const ServerConfig &config, QObject *parent)
    : QObject(parent)
    , m_config(config)
    , m_network(new QNetworkAccessManager(this))
{
}

void ApiClient::setServerConfig(const ServerConfig &config)
{
    m_config = config;
}

QNetworkReply *ApiClient::post(const QString &url, const QByteArray &body,
                               const char *contentType,
                               const QByteArray &authEmail)
{
    QNetworkRequest request{QUrl(url)};
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QByteArray(contentType));
    request.setRawHeader("Accept", "application/json");
    if (!authEmail.isEmpty()) {
        request.setRawHeader("Auth-Email", authEmail);
    }
    return m_network->post(request, body);
}

void ApiClient::prelogin(const QString &email,
                         std::function<void(Result<PreloginResponse>)> callback)
{
    QNetworkReply *reply = post(m_config.preloginUrl(),
                                buildPreloginBody(email),
                                "application/json", QByteArray());
    connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        Result<PreloginResponse> result;
        const QByteArray body = reply->readAll();
        const int status = httpStatusOf(reply);
        if (reply->error() != QNetworkReply::NoError && status == 0) {
            result.error = transportError(reply);
        } else if (status != 200) {
            result.error.httpStatus = status;
            result.error.message =
                QStringLiteral("prelogin failed (HTTP %1)").arg(status);
        } else {
            QString message;
            if (!parsePreloginResponse(body, &result.value, &message)) {
                result.error.httpStatus = status;
                result.error.message = message;
            }
        }
        callback(result);
    });
}

void ApiClient::postToken(const QByteArray &body, const QString &authEmail,
                          std::function<void(Result<TokenResponse>)> callback)
{
    QNetworkReply *reply =
        post(m_config.tokenUrl(), body, "application/x-www-form-urlencoded",
             authEmail.isEmpty() ? QByteArray()
                                 : authEmailHeaderValue(authEmail));
    connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        Result<TokenResponse> result;
        const QByteArray responseBody = reply->readAll();
        const int status = httpStatusOf(reply);
        if (reply->error() != QNetworkReply::NoError && status == 0) {
            result.error = transportError(reply);
        } else if (status != 200) {
            result.error = parseTokenError(status, responseBody);
        } else {
            QString message;
            if (!parseTokenResponse(responseBody, &result.value, &message)) {
                result.error.httpStatus = status;
                result.error.message = message;
            }
        }
        callback(result);
    });
}

void ApiClient::loginPassword(
    const QString &email, const QByteArray &masterPasswordHashB64,
    const DeviceInfo &device, const TwoFactorRequest &twoFactor,
    const QString &newDeviceOtp,
    std::function<void(Result<TokenResponse>)> callback)
{
    postToken(buildPasswordTokenBody(email, masterPasswordHashB64, device,
                                     twoFactor, newDeviceOtp),
              email, callback);
}

void ApiClient::loginApiKey(const QString &clientId,
                            const QByteArray &clientSecret,
                            const DeviceInfo &device,
                            std::function<void(Result<TokenResponse>)> callback)
{
    postToken(buildApiKeyTokenBody(clientId, clientSecret, device),
              QString(), callback);
}

void ApiClient::refreshToken(
    const QByteArray &refreshToken,
    std::function<void(Result<TokenResponse>)> callback)
{
    postToken(buildRefreshTokenBody(refreshToken), QString(), callback);
}

void ApiClient::sendEmailLoginCode(
    const QString &email, const QByteArray &masterPasswordHashB64,
    const QString &deviceIdentifier,
    std::function<void(Result<QByteArray>)> callback)
{
    QNetworkReply *reply = post(
        m_config.sendEmailLoginUrl(),
        buildSendEmailLoginBody(email, masterPasswordHashB64, deviceIdentifier),
        "application/json", authEmailHeaderValue(email));
    connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        Result<QByteArray> result;
        const int status = httpStatusOf(reply);
        if (reply->error() != QNetworkReply::NoError && status == 0) {
            result.error = transportError(reply);
        } else if (status < 200 || status >= 300) {
            result.error.httpStatus = status;
            result.error.message =
                QStringLiteral("send-email-login failed (HTTP %1)").arg(status);
        } else {
            result.value = reply->readAll();
        }
        callback(result);
    });
}

void ApiClient::sync(const QByteArray &accessToken,
                     std::function<void(Result<QByteArray>)> callback)
{
    QNetworkRequest request{QUrl(m_config.syncUrl())};
    request.setRawHeader("Accept", "application/json");
    request.setRawHeader("Authorization", "Bearer " + accessToken);
    QNetworkReply *reply = m_network->get(request);
    connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        Result<QByteArray> result;
        const int status = httpStatusOf(reply);
        if (reply->error() != QNetworkReply::NoError && status == 0) {
            result.error = transportError(reply);
        } else if (status != 200) {
            result.error.httpStatus = status;
            result.error.message =
                QStringLiteral("sync failed (HTTP %1)").arg(status);
        } else {
            result.value = reply->readAll();
        }
        callback(result);
    });
}

} // namespace Api
} // namespace BitVault
