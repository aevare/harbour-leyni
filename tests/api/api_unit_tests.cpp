// Offline, no-network tests for src/api/: request building, response
// parsing, server-config URL assembly, and SyncStore persistence. Everything
// here is a pure function or plain file I/O, so no QCoreApplication/event
// loop is needed (see tests/api/api_integration_tests.cpp for the live
// end-to-end tests, which do need one).
#include <cstdio>

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QString>
#include <QTemporaryDir>
#include <QUrl>
#include <QUrlQuery>

#include "apijson.h"
#include "serverconfig.h"
#include "syncstore.h"

#include "../check.h"

using namespace BitVault::Api;
using namespace BitVault::Crypto;

namespace {

// Decodes a single application/x-www-form-urlencoded field from a body
// produced by the request builders, so assertions are independent of
// whether spaces were encoded as "%20" or "+".
QString formValue(const QByteArray &body, const QString &key)
{
    QUrlQuery query(QString::fromLatin1(body));
    return query.queryItemValue(key, QUrl::FullyDecoded);
}

void testServerConfig()
{
    const ServerConfig us = ServerConfig::cloudUs();
    CHECK(us.identityBase == QStringLiteral("https://identity.bitwarden.com"));
    CHECK(us.apiBase == QStringLiteral("https://api.bitwarden.com"));
    CHECK(us.preloginUrl()
          == QStringLiteral("https://identity.bitwarden.com/accounts/prelogin"));
    CHECK(us.tokenUrl()
          == QStringLiteral("https://identity.bitwarden.com/connect/token"));
    CHECK(us.syncUrl() == QStringLiteral("https://api.bitwarden.com/sync"));

    const ServerConfig eu = ServerConfig::cloudEu();
    CHECK(eu.identityBase == QStringLiteral("https://identity.bitwarden.eu"));
    CHECK(eu.apiBase == QStringLiteral("https://api.bitwarden.eu"));

    const ServerConfig self = ServerConfig::selfHosted(
        QStringLiteral("http://localhost:8000/"));
    CHECK(self.identityBase == QStringLiteral("http://localhost:8000/identity"));
    CHECK(self.apiBase == QStringLiteral("http://localhost:8000/api"));
    CHECK(self.tokenUrl()
          == QStringLiteral("http://localhost:8000/identity/connect/token"));
    CHECK(self.syncUrl() == QStringLiteral("http://localhost:8000/api/sync"));

    // Trailing-slash trimming: more than one trailing slash, and a bare
    // (no-trailing-slash) URL both normalize the same way.
    const ServerConfig manySlashes = ServerConfig::selfHosted(
        QStringLiteral("http://localhost:8000///"));
    CHECK(manySlashes.identityBase
          == QStringLiteral("http://localhost:8000/identity"));

    const ServerConfig noSlash = ServerConfig::selfHosted(
        QStringLiteral("http://localhost:8000"));
    CHECK(noSlash.identityBase
          == QStringLiteral("http://localhost:8000/identity"));
}

void testAuthEmailHeaderValue()
{
    const QByteArray header =
        authEmailHeaderValue(QStringLiteral("Test@Example.COM "));
    CHECK(header == QByteArray("dGVzdEBleGFtcGxlLmNvbQ"));
    // No padding, no '/' or '+' would appear for this input, but confirm the
    // "unpadded" contract explicitly.
    CHECK(!header.contains('='));
}

void testBuildPreloginBody()
{
    const QByteArray body =
        buildPreloginBody(QStringLiteral(" Test@Example.COM "));
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
    CHECK(parseError.error == QJsonParseError::NoError);
    CHECK(doc.isObject());
    CHECK(doc.object().value(QStringLiteral("email")).toString()
          == QStringLiteral("test@example.com"));
}

void testBuildPasswordTokenBody()
{
    {
        const DeviceInfo device{QStringLiteral("device-uuid-1"),
                                QStringLiteral("Sailfish OS device"), 8};
        const TwoFactorRequest noTwoFactor;
        const QByteArray body = buildPasswordTokenBody(
            QStringLiteral(" Test@Example.COM "), QByteArray("aGFzaA=="),
            device, noTwoFactor, QString());

        CHECK(formValue(body, QStringLiteral("grant_type"))
              == QStringLiteral("password"));
        CHECK(formValue(body, QStringLiteral("username"))
              == QStringLiteral("test@example.com"));
        CHECK(formValue(body, QStringLiteral("scope"))
              == QStringLiteral("api offline_access"));
        // Explicitly accept either encoding of the space Bitwarden's own
        // clients and Vaultwarden both understand.
        CHECK(body.contains("scope=api%20offline_access")
              || body.contains("scope=api+offline_access"));
        CHECK(formValue(body, QStringLiteral("client_id"))
              == QStringLiteral("cli"));
        CHECK(body.contains("deviceType="));
        CHECK(body.contains("deviceIdentifier=device-uuid-1"));
        CHECK(body.contains("deviceName="));
        // No 2FA fields when none requested.
        CHECK(!body.contains("twoFactorProvider"));
    }
    {
        const DeviceInfo device{QStringLiteral("device-uuid-2"),
                                QStringLiteral("Sailfish OS device"), 8};
        const TwoFactorRequest twoFactor{0, QStringLiteral("123456"), false};
        const QByteArray body = buildPasswordTokenBody(
            QStringLiteral("test@example.com"), QByteArray("aGFzaA=="),
            device, twoFactor, QString());
        CHECK(body.contains("twoFactorProvider=0"));
        CHECK(formValue(body, QStringLiteral("twoFactorToken"))
              == QStringLiteral("123456"));
    }
    {
        // The master password hash arrives base64-encoded and can contain
        // '+', '/', and '='. Those are reserved in form encoding ('+' means
        // space); they must be percent-encoded, never passed through raw.
        const DeviceInfo device{QStringLiteral("device-uuid-3"),
                                QStringLiteral("Sailfish OS device"), 8};
        const TwoFactorRequest noTwoFactor;
        const QByteArray hash("ab+/cd==");
        const QByteArray body = buildPasswordTokenBody(
            QStringLiteral("test@example.com"), hash, device, noTwoFactor,
            QString());
        // The raw '+' must not appear un-encoded in the password field
        // (a literal '+' there would decode back to a space downstream).
        CHECK(body.contains("%2B") || body.contains("%2b"));
        CHECK(formValue(body, QStringLiteral("password"))
              == QStringLiteral("ab+/cd=="));
    }
}

void testParsePreloginResponse()
{
    {
        PreloginResponse resp;
        QString error;
        CHECK(parsePreloginResponse(
            "{\"kdf\":0,\"kdfIterations\":600000}", &resp, &error));
        CHECK(resp.kdf.type == KdfType::Pbkdf2Sha256);
        CHECK(resp.kdf.iterations == 600000u);
    }
    {
        PreloginResponse resp;
        QString error;
        CHECK(parsePreloginResponse(
            "{\"kdf\":1,\"kdfIterations\":3,\"kdfMemory\":64,"
            "\"kdfParallelism\":4}",
            &resp, &error));
        CHECK(resp.kdf.type == KdfType::Argon2id);
        CHECK(resp.kdf.iterations == 3u);
        CHECK(resp.kdf.memoryMiB == 64u);
        CHECK(resp.kdf.parallelism == 4u);
    }
    {
        // PascalCase variant, seen from some server versions.
        PreloginResponse resp;
        QString error;
        CHECK(parsePreloginResponse(
            "{\"Kdf\":0,\"KdfIterations\":100000}", &resp, &error));
        CHECK(resp.kdf.type == KdfType::Pbkdf2Sha256);
        CHECK(resp.kdf.iterations == 100000u);
    }
    {
        PreloginResponse resp;
        QString error;
        CHECK(!parsePreloginResponse("{\"kdf\":9}", &resp, &error));
        CHECK(!error.isEmpty());
    }
    {
        PreloginResponse resp;
        QString error;
        CHECK(!parsePreloginResponse("not json at all", &resp, &error));
        CHECK(!error.isEmpty());
    }
}

void testParseTokenResponse()
{
    {
        TokenResponse resp;
        QString error;
        const QByteArray body =
            "{\"access_token\":\"AT\",\"expires_in\":3600,"
            "\"token_type\":\"Bearer\",\"refresh_token\":\"RT\","
            "\"Key\":\"2.abc|def|ghi\",\"PrivateKey\":\"2.xxx|yyy|zzz\"}";
        CHECK(parseTokenResponse(body, &resp, &error));
        CHECK(resp.accessToken == QByteArray("AT"));
        CHECK(resp.refreshToken == QByteArray("RT"));
        CHECK(resp.expiresInSeconds == 3600);
        CHECK(resp.key == QStringLiteral("2.abc|def|ghi"));
        CHECK(resp.privateKey == QStringLiteral("2.xxx|yyy|zzz"));
    }
    {
        // camelCase "key" variant.
        TokenResponse resp;
        QString error;
        const QByteArray body =
            "{\"access_token\":\"AT2\",\"key\":\"2.aaa|bbb|ccc\"}";
        CHECK(parseTokenResponse(body, &resp, &error));
        CHECK(resp.accessToken == QByteArray("AT2"));
        CHECK(resp.key == QStringLiteral("2.aaa|bbb|ccc"));
    }
    {
        TokenResponse resp;
        QString error;
        CHECK(!parseTokenResponse("{\"expires_in\":10}", &resp, &error));
        CHECK(!error.isEmpty());
    }
}

void testParseTokenError()
{
    {
        // 2FA challenge body.
        const QByteArray body =
            "{\"error\":\"invalid_grant\",\"error_description\":"
            "\"Two factor required.\",\"TwoFactorProviders\":[\"0\",\"1\"],"
            "\"TwoFactorProviders2\":{\"0\":null,\"1\":{\"Email\":"
            "\"t***@example.com\"}}}";
        const ApiError error = parseTokenError(400, body);
        CHECK(error.twoFactorRequired);
        CHECK(error.twoFactorProviders.contains(0));
        CHECK(error.twoFactorProviders.contains(1));
    }
    {
        // Plain wrong-password failure.
        const QByteArray body =
            "{\"error\":\"invalid_grant\",\"error_description\":"
            "\"Username or password is incorrect. Try again\"}";
        const ApiError error = parseTokenError(400, body);
        CHECK(!error.message.isEmpty());
        CHECK(!error.twoFactorRequired);
    }
    {
        // Captcha challenge.
        const QByteArray body =
            "{\"error\":\"invalid_grant\",\"HCaptcha_SiteKey\":\"abc123\"}";
        const ApiError error = parseTokenError(400, body);
        CHECK(error.captchaRequired);
    }
    {
        // Non-JSON body: fall back to a bare HTTP-status message.
        const ApiError error = parseTokenError(400, "not json");
        CHECK(error.message == QStringLiteral("HTTP 400"));
    }
}

void testSyncStore()
{
    QTemporaryDir dir;
    CHECK(dir.isValid());

    BitVault::Vault::SyncStore store(dir.path());
    CHECK(!store.exists());
    CHECK(store.load().isEmpty());

    const QByteArray payload = "{\"profile\":{},\"ciphers\":[]}";
    CHECK(store.save(payload));
    CHECK(store.exists());
    CHECK(store.load() == payload);

    CHECK(store.clear());
    CHECK(!store.exists());
    CHECK(store.load().isEmpty());
}

} // namespace

int main()
{
    testServerConfig();
    std::printf("serverconfig: OK\n");
    testAuthEmailHeaderValue();
    std::printf("authEmailHeaderValue: OK\n");
    testBuildPreloginBody();
    std::printf("buildPreloginBody: OK\n");
    testBuildPasswordTokenBody();
    std::printf("buildPasswordTokenBody: OK\n");
    testParsePreloginResponse();
    std::printf("parsePreloginResponse: OK\n");
    testParseTokenResponse();
    std::printf("parseTokenResponse: OK\n");
    testParseTokenError();
    std::printf("parseTokenError: OK\n");
    testSyncStore();
    std::printf("SyncStore: OK\n");

    std::printf("api_unit_tests: all checks passed\n");
    return 0;
}
