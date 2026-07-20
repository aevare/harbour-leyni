// Thin async HTTP transport over QNetworkAccessManager. All protocol
// knowledge (bodies, parsing, error classification) lives in apijson.cpp;
// this class only moves bytes. One callback per call, invoked exactly once.
#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>

#include <functional>

#include "apijson.h"
#include "serverconfig.h"

class QNetworkAccessManager;
class QNetworkReply;

namespace Leyni {
namespace Api {

// Exactly one of value/error is meaningful: check error.isEmpty() first.
template <typename T>
struct Result {
    T value;
    ApiError error;
    bool ok() const { return error.isEmpty(); }
};

class ApiClient : public QObject
{
    Q_OBJECT

public:
    explicit ApiClient(const ServerConfig &config, QObject *parent = nullptr);

    void setServerConfig(const ServerConfig &config);
    ServerConfig serverConfig() const { return m_config; }

    void prelogin(const QString &email,
                  std::function<void(Result<PreloginResponse>)> callback);

    void loginPassword(const QString &email,
                       const QByteArray &masterPasswordHashB64,
                       const DeviceInfo &device,
                       const TwoFactorRequest &twoFactor,
                       const QString &newDeviceOtp,
                       std::function<void(Result<TokenResponse>)> callback);

    void loginApiKey(const QString &clientId, const QByteArray &clientSecret,
                     const DeviceInfo &device,
                     std::function<void(Result<TokenResponse>)> callback);

    void refreshToken(const QByteArray &refreshToken,
                      std::function<void(Result<TokenResponse>)> callback);

    // Returns the raw response body untouched — it is stored on disk as-is
    // (already end-to-end encrypted) and only ever decrypted in memory.
    void sync(const QByteArray &accessToken,
              std::function<void(Result<QByteArray>)> callback);

    // Triggers the email-2FA code mail after a login attempt reported
    // twoFactorRequired with provider 1. Value is unused on success.
    void sendEmailLoginCode(const QString &email,
                            const QByteArray &masterPasswordHashB64,
                            const QString &deviceIdentifier,
                            std::function<void(Result<QByteArray>)> callback);

    // Cipher writes (Bearer-authenticated, same host as sync). The body is
    // the already-encrypted CipherRequestModel JSON built by the vault layer;
    // this class never sees plaintext. The raw response body is returned but
    // the caller normally discards it and re-syncs. See doc/PROTOCOL.md.
    void createCipher(const QByteArray &accessToken, const QByteArray &body,
                      std::function<void(Result<QByteArray>)> callback);
    void updateCipher(const QByteArray &accessToken, const QString &id,
                      const QByteArray &body,
                      std::function<void(Result<QByteArray>)> callback);
    // Soft delete: moves the item to Trash (recoverable from the web vault).
    // It is a PUT to /ciphers/{id}/delete with no body, not an HTTP DELETE.
    void softDeleteCipher(const QByteArray &accessToken, const QString &id,
                          std::function<void(Result<QByteArray>)> callback);

private:
    void postToken(const QByteArray &body, const QString &authEmail,
                   std::function<void(Result<TokenResponse>)> callback);
    QNetworkReply *post(const QString &url, const QByteArray &body,
                        const char *contentType, const QByteArray &authEmail);
    // Sends a Bearer-authenticated request (verb "POST" or "PUT") and delivers
    // the raw response body, accepting any 2xx status. A JSON Content-Type is
    // set when the body is non-empty.
    void sendAuthed(const QString &url, const QByteArray &verb,
                    const QByteArray &accessToken, const QByteArray &body,
                    const QString &opName,
                    std::function<void(Result<QByteArray>)> callback);

    ServerConfig m_config;
    QNetworkAccessManager *m_network;
};

} // namespace Api
} // namespace Leyni
