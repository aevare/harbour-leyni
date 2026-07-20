// End-to-end tests against a live Bitwarden-compatible server (Vaultwarden
// by default). This is opt-in (`ctest -L integration`; see doc/TESTING.md)
// because it needs a live server and does real network I/O.
//
// This suite is also the project's crypto-interop proof: it registers a
// fresh throwaway account using OUR crypto library end-to-end (master key
// derivation, key stretching, AES-256-CBC+HMAC encryption, RSA-2048 keypair
// generation), logs in through the real ApiClient, and checks that the
// symmetric key the server hands back in the login response decrypts back
// to exactly the key WE generated during registration. If that check
// passes, our derivation/encryption path is provably interoperable with a
// real Bitwarden-protocol server, independent of the KAT fixtures in
// tests/crypto/.
#include <cstdio>
#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QString>
#include <QTemporaryDir>
#include <QTimer>
#include <QUrl>
#include <QUuid>
#include <QVariantMap>

#include "apiclient.h"
#include "apijson.h"
#include "cipheritem.h"
#include "serverconfig.h"
#include "syncstore.h"
#include "vault.h"

#include "base64.h"
#include "crypto.h"
#include "encstring.h"
#include "kdf.h"
#include "keys.h"
#include "securebytes.h"

#include "../check.h"

using namespace Leyni::Api;
using namespace Leyni::Crypto;

namespace {

constexpr int kTimeoutMs = 20000;

// Runs an async ApiClient-style call (last argument is a
// std::function<void(Result<T>)> callback) inside its own event loop with a
// timeout, so a hung/unresponsive server fails the test instead of hanging
// the whole suite.
template <typename T, typename Starter>
Result<T> waitFor(Starter starter, bool *timedOut)
{
    QEventLoop loop;
    Result<T> result;
    bool done = false;

    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(kTimeoutMs);

    starter(std::function<void(Result<T>)>([&](Result<T> r) {
        result = r;
        done = true;
        loop.quit();
    }));

    loop.exec();
    *timedOut = !done;
    return result;
}

struct HttpResponse {
    int status = 0;
    QByteArray body;
    bool timedOut = false;
};

// Plain QNetworkAccessManager POST with a timeout — used only for account
// registration, which is not part of the app's runtime API surface (users
// register through the web vault or another client; Leyni only ever
// logs in). Kept local to this test rather than added to src/api/.
HttpResponse postJson(QNetworkAccessManager *net, const QString &url,
                      const QByteArray &json)
{
    QNetworkRequest request{QUrl(url)};
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QByteArray("application/json"));
    request.setRawHeader("Accept", "application/json");
    QNetworkReply *reply = net->post(request, json);

    QEventLoop loop;
    bool done = false;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(kTimeoutMs);
    QObject::connect(reply, &QNetworkReply::finished, &loop, [&]() {
        done = true;
        loop.quit();
    });
    loop.exec();

    HttpResponse response;
    response.timedOut = !done;
    if (done) {
        response.status =
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        response.body = reply->readAll();
    }
    reply->deleteLater();
    return response;
}

// QUuid::toString(QUuid::WithoutBraces) is Qt 5.11+; strip manually to stay
// Qt 5.6-compatible. Returns "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
QString newUuidString()
{
    QString uuid = QUuid::createUuid().toString(); // "{8-4-4-4-12}"
    uuid.remove(QLatin1Char('{'));
    uuid.remove(QLatin1Char('}'));
    return uuid.toLower();
}

// Plain hex (no dashes) from a freshly generated UUID, for the throwaway
// account email.
QString randomHex()
{
    QString hex = newUuidString();
    hex.remove(QLatin1Char('-'));
    return hex;
}

SecureBytes toSecureBytes(const QByteArray &bytes)
{
    return SecureBytes(reinterpret_cast<const uint8_t *>(bytes.constData()),
                       static_cast<size_t>(bytes.size()));
}

QByteArray toQByteArray(const std::string &s)
{
    return QByteArray(s.data(), static_cast<int>(s.size()));
}

struct PkeyDeleter {
    void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); }
};
struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *c) const { EVP_PKEY_CTX_free(c); }
};

// Generates a throwaway RSA-2048 keypair, returning the SPKI DER public key
// and the traditional-format DER private key (same encoding used by
// tests/crypto/rsa_tests.cpp, and the format our rsaOaepSha1Decrypt/
// d2i_AutoPrivateKey path accepts).
struct RsaKeyPair {
    std::vector<uint8_t> publicKeyDer;
    std::vector<uint8_t> privateKeyDer;
};

RsaKeyPair generateRsaKeyPair()
{
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> genCtx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    CHECK(genCtx != nullptr);
    CHECK(EVP_PKEY_keygen_init(genCtx.get()) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(genCtx.get(), 2048) == 1);
    EVP_PKEY *rawKey = nullptr;
    CHECK(EVP_PKEY_keygen(genCtx.get(), &rawKey) == 1);
    std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey(rawKey);

    RsaKeyPair pair;

    int pubLen = i2d_PUBKEY(pkey.get(), nullptr);
    CHECK(pubLen > 0);
    pair.publicKeyDer.resize(static_cast<size_t>(pubLen));
    {
        uint8_t *p = pair.publicKeyDer.data();
        CHECK(i2d_PUBKEY(pkey.get(), &p) == pubLen);
    }

    int privLen = i2d_PrivateKey(pkey.get(), nullptr);
    CHECK(privLen > 0);
    pair.privateKeyDer.resize(static_cast<size_t>(privLen));
    {
        uint8_t *p = pair.privateKeyDer.data();
        CHECK(i2d_PrivateKey(pkey.get(), &p) == privLen);
    }
    return pair;
}

QString testServerUrl()
{
    const QByteArray env = qgetenv("BITVAULT_TEST_SERVER");
    return env.isEmpty() ? QStringLiteral("http://127.0.0.1:8000")
                         : QString::fromUtf8(env);
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const QString baseUrl = testServerUrl();
    const ServerConfig config = ServerConfig::selfHosted(baseUrl);

    // --- a. random throwaway account ---
    const QString email = QStringLiteral("it-%1@example.test").arg(randomHex());
    const QByteArray passwordUtf8 = QByteArray("IntegrationTest123!");
    const std::string emailLower = email.trimmed().toLower().toStdString();

    KdfParams kdfParams;
    kdfParams.type = KdfType::Pbkdf2Sha256;
    kdfParams.iterations = 600000;

    SecureBytes password = toSecureBytes(passwordUtf8);

    // --- b. derive keys with OUR crypto lib ---
    SecureBytes masterKey = deriveMasterKey(password, emailLower, kdfParams);
    SecureBytes masterHash = deriveMasterPasswordHash(masterKey, password);
    const QByteArray serverHashB64 =
        toQByteArray(base64Encode(masterHash.data(), masterHash.size()));

    SymmetricKey stretched = stretchMasterKey(masterKey);

    std::vector<uint8_t> userKeyBytes(64);
    CHECK(RAND_bytes(userKeyBytes.data(), static_cast<int>(userKeyBytes.size()))
          == 1);
    SecureBytes userKey(userKeyBytes.data(), userKeyBytes.size());

    const std::string protectedKey =
        encryptAes256CbcHmac(userKey, stretched).serialize();

    RsaKeyPair rsaKeys = generateRsaKeyPair();
    const std::string publicKeyB64 =
        base64Encode(rsaKeys.publicKeyDer.data(), rsaKeys.publicKeyDer.size());

    SecureBytes privateKeyDer(rsaKeys.privateKeyDer.data(),
                              rsaKeys.privateKeyDer.size());
    const std::string encryptedPrivateKey =
        encryptAes256CbcHmac(privateKeyDer, symmetricKeyFromBytes(userKey))
            .serialize();

    std::printf("crypto setup: OK (email=%s)\n", qPrintable(email));

    // --- c. register ---
    QNetworkAccessManager registerNet;
    QJsonObject keys;
    keys.insert(QStringLiteral("publicKey"), QString::fromStdString(publicKeyB64));
    keys.insert(QStringLiteral("encryptedPrivateKey"),
               QString::fromStdString(encryptedPrivateKey));

    QJsonObject registerBody;
    registerBody.insert(QStringLiteral("email"), email);
    registerBody.insert(QStringLiteral("name"), QStringLiteral("Leyni IT"));
    registerBody.insert(QStringLiteral("masterPasswordHash"),
                        QString::fromUtf8(serverHashB64));
    registerBody.insert(QStringLiteral("key"),
                        QString::fromStdString(protectedKey));
    registerBody.insert(QStringLiteral("kdf"), 0);
    registerBody.insert(QStringLiteral("kdfIterations"), 600000);
    registerBody.insert(QStringLiteral("keys"), keys);
    const QByteArray registerJson =
        QJsonDocument(registerBody).toJson(QJsonDocument::Compact);

    HttpResponse registerResponse =
        postJson(&registerNet, config.registerUrl(), registerJson);
    CHECK(!registerResponse.timedOut);
    if (registerResponse.status == 404) {
        // Vaultwarden version differences: some serve /identity/accounts/
        // register, others only /api/accounts/register.
        const QString altUrl = config.apiBase + QStringLiteral("/accounts/register");
        registerResponse = postJson(&registerNet, altUrl, registerJson);
        CHECK(!registerResponse.timedOut);
    }
    CHECK(registerResponse.status == 200 || registerResponse.status == 201);
    std::printf("register: OK (HTTP %d)\n", registerResponse.status);

    ApiClient client(config);

    // --- d. prelogin ---
    {
        bool timedOut = false;
        Result<PreloginResponse> result = waitFor<PreloginResponse>(
            [&](std::function<void(Result<PreloginResponse>)> cb) {
                client.prelogin(email, cb);
            },
            &timedOut);
        CHECK(!timedOut);
        CHECK(result.ok());
        CHECK(result.value.kdf.type == KdfType::Pbkdf2Sha256);
        CHECK(result.value.kdf.iterations == 600000u);
        std::printf("prelogin: OK\n");
    }

    const DeviceInfo device{newUuidString(),
                            QStringLiteral("leyni-integration-test"), 8};
    const TwoFactorRequest noTwoFactor;

    // --- e. login with wrong hash ---
    {
        SecureBytes wrongPassword = toSecureBytes(QByteArray("WrongPassword123!"));
        SecureBytes wrongHash = deriveMasterPasswordHash(masterKey, wrongPassword);
        const QByteArray wrongHashB64 =
            toQByteArray(base64Encode(wrongHash.data(), wrongHash.size()));

        bool timedOut = false;
        Result<TokenResponse> result = waitFor<TokenResponse>(
            [&](std::function<void(Result<TokenResponse>)> cb) {
                client.loginPassword(email, wrongHashB64, device, noTwoFactor,
                                    QString(), cb);
            },
            &timedOut);
        CHECK(!timedOut);
        CHECK(!result.ok());
        CHECK(!result.error.message.isEmpty());
        CHECK(!result.error.twoFactorRequired);
        std::printf("login (wrong hash): OK (rejected as expected)\n");
    }

    // --- f. login with correct hash ---
    QByteArray accessToken;
    QByteArray refreshToken;
    QString loginKey;
    {
        bool timedOut = false;
        Result<TokenResponse> result = waitFor<TokenResponse>(
            [&](std::function<void(Result<TokenResponse>)> cb) {
                client.loginPassword(email, serverHashB64, device, noTwoFactor,
                                    QString(), cb);
            },
            &timedOut);
        CHECK(!timedOut);
        CHECK(result.ok());
        CHECK(!result.value.accessToken.isEmpty());
        CHECK(!result.value.refreshToken.isEmpty());
        CHECK(result.value.key.startsWith(QStringLiteral("2.")));
        accessToken = result.value.accessToken;
        refreshToken = result.value.refreshToken;
        loginKey = result.value.key;
        std::printf("login (correct hash): OK\n");
    }

    // --- g. interop check: server's protected key decrypts to OUR userKey ---
    {
        EncString parsed = EncString::parse(loginKey.toStdString());
        SecureBytes decrypted = decryptAes256CbcHmac(parsed, stretched);
        CHECK(decrypted.size() == userKey.size());
        CHECK(constantTimeEqual(decrypted.data(), userKey.data(), userKey.size()));
        std::printf("interop check: OK (server key decrypts to our userKey)\n");
    }

    // --- h. sync ---
    QTemporaryDir syncDir;
    CHECK(syncDir.isValid());
    {
        bool timedOut = false;
        Result<QByteArray> result = waitFor<QByteArray>(
            [&](std::function<void(Result<QByteArray>)> cb) {
                client.sync(accessToken, cb);
            },
            &timedOut);
        CHECK(!timedOut);
        CHECK(result.ok());

        QJsonParseError parseError;
        const QJsonDocument doc =
            QJsonDocument::fromJson(result.value, &parseError);
        CHECK(parseError.error == QJsonParseError::NoError);
        CHECK(doc.isObject());
        const QJsonObject obj = doc.object();
        CHECK(obj.contains(QStringLiteral("profile"))
              || obj.contains(QStringLiteral("Profile")));
        const QJsonObject profile =
            (obj.contains(QStringLiteral("profile"))
                 ? obj.value(QStringLiteral("profile"))
                 : obj.value(QStringLiteral("Profile")))
                .toObject();
        const QString profileKey =
            profile.contains(QStringLiteral("key"))
                ? profile.value(QStringLiteral("key")).toString()
                : profile.value(QStringLiteral("Key")).toString();
        CHECK(profileKey == loginKey);

        Leyni::Vault::SyncStore store(syncDir.path());
        CHECK(store.save(result.value));
        CHECK(store.exists());
        CHECK(store.load() == result.value);
        std::printf("sync: OK (profile key matches login key, round-trips"
                    " through SyncStore)\n");
    }

    // --- i. refresh token ---
    {
        bool timedOut = false;
        Result<TokenResponse> result = waitFor<TokenResponse>(
            [&](std::function<void(Result<TokenResponse>)> cb) {
                client.refreshToken(refreshToken, cb);
            },
            &timedOut);
        CHECK(!timedOut);
        CHECK(result.ok());
        CHECK(!result.value.accessToken.isEmpty());
        const QByteArray newAccessToken = result.value.accessToken;
        std::printf("refresh token: OK\n");

        bool syncTimedOut = false;
        Result<QByteArray> syncResult = waitFor<QByteArray>(
            [&](std::function<void(Result<QByteArray>)> cb) {
                client.sync(newAccessToken, cb);
            },
            &syncTimedOut);
        CHECK(!syncTimedOut);
        CHECK(syncResult.ok());
        std::printf("sync with refreshed token: OK\n");
    }

    // --- j. write round-trip: create → edit → soft-delete, via the real
    // Vault build methods and ApiClient cipher calls. Proves the write path
    // interoperates with the server and stays decryptable. ---
    {
        auto findItem = [](const Leyni::Vault::Vault &v, const QString &name)
            -> const Leyni::Vault::DecryptedItem * {
            for (const Leyni::Vault::DecryptedItem &it : v.items()) {
                if (it.name == name) {
                    return &it;
                }
            }
            return nullptr;
        };
        auto resync = [&](Leyni::Vault::Vault *v) {
            bool to = false;
            Result<QByteArray> s = waitFor<QByteArray>(
                [&](std::function<void(Result<QByteArray>)> cb) {
                    client.sync(accessToken, cb);
                },
                &to);
            CHECK(!to);
            CHECK(s.ok());
            QString err;
            CHECK(v->reloadSync(s.value, &err));
        };

        // A vault unlocked from the account's own master key.
        Leyni::Vault::Vault vault;
        {
            bool to = false;
            Result<QByteArray> s = waitFor<QByteArray>(
                [&](std::function<void(Result<QByteArray>)> cb) {
                    client.sync(accessToken, cb);
                },
                &to);
            CHECK(!to);
            CHECK(s.ok());
            QString err;
            CHECK(vault.loadSync(s.value, &err));
            CHECK(vault.unlockWithMasterKey(
                SecureBytes(masterKey.data(), masterKey.size()), &err));
        }

        // create
        QVariantMap fields;
        fields.insert(QStringLiteral("name"), QStringLiteral("IT Login"));
        fields.insert(QStringLiteral("username"), QStringLiteral("it@x.test"));
        fields.insert(QStringLiteral("password"), QStringLiteral("itpw-1"));
        fields.insert(QStringLiteral("uri"), QStringLiteral("https://it.test"));
        fields.insert(QStringLiteral("totp"), QString());
        fields.insert(QStringLiteral("notes"), QStringLiteral("it note"));
        fields.insert(QStringLiteral("favorite"), false);
        fields.insert(QStringLiteral("folderId"), QString());

        QString buildErr;
        const QByteArray createBody = vault.buildCreateBody(
            Leyni::Vault::CipherType::Login, fields, &buildErr);
        CHECK(!createBody.isEmpty());
        {
            bool to = false;
            Result<QByteArray> r = waitFor<QByteArray>(
                [&](std::function<void(Result<QByteArray>)> cb) {
                    client.createCipher(accessToken, createBody, cb);
                },
                &to);
            CHECK(!to);
            CHECK(r.ok());
        }
        resync(&vault);
        const Leyni::Vault::DecryptedItem *created =
            findItem(vault, QStringLiteral("IT Login"));
        CHECK(created != nullptr);
        CHECK(created->username == QStringLiteral("it@x.test"));
        const QString cipherId = created->id;
        {
            QString err;
            CHECK(vault.itemPassword(cipherId, &err) == QStringLiteral("itpw-1"));
        }
        std::printf("create cipher: OK\n");

        // edit
        fields.insert(QStringLiteral("name"), QStringLiteral("IT Login v2"));
        fields.insert(QStringLiteral("password"), QStringLiteral("itpw-2"));
        const QByteArray updateBody =
            vault.buildUpdateBody(cipherId, fields, &buildErr);
        CHECK(!updateBody.isEmpty());
        {
            bool to = false;
            Result<QByteArray> r = waitFor<QByteArray>(
                [&](std::function<void(Result<QByteArray>)> cb) {
                    client.updateCipher(accessToken, cipherId, updateBody, cb);
                },
                &to);
            CHECK(!to);
            CHECK(r.ok());
        }
        resync(&vault);
        CHECK(findItem(vault, QStringLiteral("IT Login")) == nullptr);
        const Leyni::Vault::DecryptedItem *edited =
            findItem(vault, QStringLiteral("IT Login v2"));
        CHECK(edited != nullptr);
        {
            QString err;
            CHECK(vault.itemPassword(edited->id, &err)
                  == QStringLiteral("itpw-2"));
        }
        std::printf("update cipher: OK\n");

        // soft delete
        {
            bool to = false;
            Result<QByteArray> r = waitFor<QByteArray>(
                [&](std::function<void(Result<QByteArray>)> cb) {
                    client.softDeleteCipher(accessToken, cipherId, cb);
                },
                &to);
            CHECK(!to);
            CHECK(r.ok());
        }
        resync(&vault);
        CHECK(findItem(vault, QStringLiteral("IT Login v2")) == nullptr);
        std::printf("soft-delete cipher: OK (hidden from vault)\n");
    }

    std::printf("api_integration_tests: all checks passed\n");
    return 0;
}
