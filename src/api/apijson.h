// Pure request-building and response-parsing for the Bitwarden protocol.
// No networking here — everything takes bytes and returns structs, so the
// whole protocol surface is unit-testable offline (see tests/api/).
//
// Field names and error shapes follow bitwarden/server and are verified
// against Vaultwarden in the integration tests; see doc/PROTOCOL.md.
#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

#include "kdf.h"

namespace BitVault {
namespace Api {

// Bitwarden DeviceType enum: 8 = LinuxDesktop. There is no Sailfish value;
// LinuxDesktop is the closest truthful category.
struct DeviceInfo {
    QString identifier; // stable UUID, generated once per install
    QString name;       // e.g. "Sailfish OS device"
    int type = 8;
};

// Two-factor provider ids we support (see doc/PLAN.md for what is out of
// scope and why).
enum class TwoFactorProvider : int {
    Authenticator = 0, // TOTP
    Email = 1,
};

struct TwoFactorRequest {
    int provider = -1; // -1 = none
    QString token;
    bool remember = false;
};

struct PreloginResponse {
    Crypto::KdfParams kdf;
};

struct TokenResponse {
    QByteArray accessToken;
    QByteArray refreshToken;
    int expiresInSeconds = 0;
    QString key;        // protected symmetric key (EncString), may be empty
    QString privateKey; // encrypted RSA private key (EncString), may be empty
    QString twoFactorRememberToken; // set when remember was requested
};

struct ApiError {
    int httpStatus = 0;
    QString message;
    bool networkError = false;           // transport-level failure
    bool twoFactorRequired = false;
    QList<int> twoFactorProviders;
    bool captchaRequired = false;
    bool newDeviceVerificationRequired = false;

    bool isEmpty() const { return httpStatus == 0 && !networkError; }
};

// --- request bodies ---

QByteArray buildPreloginBody(const QString &email);

// grant_type=password. The master password hash arrives pre-encoded
// (base64) from the crypto layer; the raw password never reaches this layer.
QByteArray buildPasswordTokenBody(const QString &email,
                                  const QByteArray &masterPasswordHashB64,
                                  const DeviceInfo &device,
                                  const TwoFactorRequest &twoFactor,
                                  const QString &newDeviceOtp);

QByteArray buildApiKeyTokenBody(const QString &clientId,
                                const QByteArray &clientSecret,
                                const DeviceInfo &device);

QByteArray buildRefreshTokenBody(const QByteArray &refreshToken);

// Asks the server to email a login OTP (2FA provider 1). JSON body.
QByteArray buildSendEmailLoginBody(const QString &email,
                                   const QByteArray &masterPasswordHashB64,
                                   const QString &deviceIdentifier);

// The Auth-Email header value: base64url(email), unpadded.
QByteArray authEmailHeaderValue(const QString &email);

// --- response parsing (each returns false and fills error on failure) ---

bool parsePreloginResponse(const QByteArray &body, PreloginResponse *out,
                           QString *errorMessage);

bool parseTokenResponse(const QByteArray &body, TokenResponse *out,
                        QString *errorMessage);

// Classifies a token-endpoint error body (2FA required / captcha /
// new-device verification / plain failure).
ApiError parseTokenError(int httpStatus, const QByteArray &body);

} // namespace Api
} // namespace BitVault
