// One-off tool (NOT a test): registers a fixture account on a local
// Vaultwarden, populates it with a folder and a handful of ciphers via
// authenticated POSTs, then fetches and saves the raw /api/sync response.
// The committed output (tests/fixtures/sync.json) is what tests/vault/
// vault_tests.cpp unlocks offline. See tests/fixtures/README.md for
// regeneration instructions and the account's public test credentials.
//
// The crypto-setup and account-registration steps below are copied from
// tests/api/api_integration_tests.cpp (same account-creation pattern, fixed
// email/password/KDF instead of a random throwaway account).
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QUuid>

#include "apiclient.h"
#include "apijson.h"
#include "serverconfig.h"

#include "base64.h"
#include "crypto.h"
#include "encstring.h"
#include "kdf.h"
#include "keys.h"
#include "securebytes.h"

using namespace Leyni::Api;
using namespace Leyni::Crypto;

namespace {

constexpr int kTimeoutMs = 20000;

// The fixture account. Values are intentionally public: this account holds
// no real data, only the fixtures below.
const QString kEmail = QStringLiteral("fixture@bitvault.test");
const QByteArray kPasswordUtf8 = QByteArray("FixtureVault123!");
constexpr uint32_t kPbkdf2Iterations = 600000;

// RFC 6238 Appendix B / RFC 4226 Appendix D reference key, ASCII
// "12345678901234567890", base32-encoded. Chosen so the TOTP codes in
// tests/vault/vault_tests.cpp are the well-known RFC test vectors
// ("755224" at t=29, "287082" at t=59) — nobody has to trust us on this,
// they can recompute it from the RFCs.
const std::string kTotpSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

void must(bool ok, const char *what)
{
    if (!ok) {
        std::fprintf(stderr, "FAILED: %s\n", what);
        std::exit(1);
    }
}

void failHttp(const QString &what, int httpStatus, const QByteArray &body)
{
    std::fprintf(stderr, "FAILED: %s (HTTP %d)\n%s\n", qPrintable(what),
                 httpStatus, body.constData());
    std::exit(1);
}

// Runs an async ApiClient-style call (last argument is a
// std::function<void(Result<T>)> callback) inside its own event loop with a
// timeout. Copied from tests/api/api_integration_tests.cpp.
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

// Plain QNetworkAccessManager POST with a timeout and an optional bearer
// token. Copied/extended from api_integration_tests.cpp's postJson; account
// registration and the authenticated folder/cipher creation calls here are
// not part of the app's runtime API surface (BitVault only ever logs in),
// so they live in test/tool code rather than src/api/.
HttpResponse postJson(QNetworkAccessManager *net, const QString &url,
                      const QByteArray &json,
                      const QByteArray &bearerToken = QByteArray())
{
    QNetworkRequest request{QUrl(url)};
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QByteArray("application/json"));
    request.setRawHeader("Accept", "application/json");
    if (!bearerToken.isEmpty()) {
        request.setRawHeader("Authorization", "Bearer " + bearerToken);
    }
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

QString newUuidString()
{
    QString uuid = QUuid::createUuid().toString(); // "{8-4-4-4-12}"
    uuid.remove(QLatin1Char('{'));
    uuid.remove(QLatin1Char('}'));
    return uuid.toLower();
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

struct RsaKeyPair {
    std::vector<uint8_t> publicKeyDer;
    std::vector<uint8_t> privateKeyDer;
};

// Copied verbatim from api_integration_tests.cpp.
RsaKeyPair generateRsaKeyPair()
{
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> genCtx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    must(genCtx != nullptr, "RSA keygen: context alloc failed");
    must(EVP_PKEY_keygen_init(genCtx.get()) == 1, "RSA keygen: init failed");
    must(EVP_PKEY_CTX_set_rsa_keygen_bits(genCtx.get(), 2048) == 1,
         "RSA keygen: set bits failed");
    EVP_PKEY *rawKey = nullptr;
    must(EVP_PKEY_keygen(genCtx.get(), &rawKey) == 1, "RSA keygen failed");
    std::unique_ptr<EVP_PKEY, PkeyDeleter> pkey(rawKey);

    RsaKeyPair pair;

    int pubLen = i2d_PUBKEY(pkey.get(), nullptr);
    must(pubLen > 0, "RSA keygen: public key encode failed");
    pair.publicKeyDer.resize(static_cast<size_t>(pubLen));
    {
        uint8_t *p = pair.publicKeyDer.data();
        must(i2d_PUBKEY(pkey.get(), &p) == pubLen,
             "RSA keygen: public key encode mismatch");
    }

    int privLen = i2d_PrivateKey(pkey.get(), nullptr);
    must(privLen > 0, "RSA keygen: private key encode failed");
    pair.privateKeyDer.resize(static_cast<size_t>(privLen));
    {
        uint8_t *p = pair.privateKeyDer.data();
        must(i2d_PrivateKey(pkey.get(), &p) == privLen,
             "RSA keygen: private key encode mismatch");
    }
    return pair;
}

QString testServerUrl()
{
    const QByteArray env = qgetenv("BITVAULT_TEST_SERVER");
    return env.isEmpty() ? QStringLiteral("http://127.0.0.1:8000")
                         : QString::fromUtf8(env);
}

// Accepts both camelCase and PascalCase id fields (server variants).
QString jsonId(const QJsonObject &obj)
{
    if (obj.contains(QStringLiteral("id"))) {
        return obj.value(QStringLiteral("id")).toString();
    }
    return obj.value(QStringLiteral("Id")).toString();
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const QString outputPath =
        argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("sync.json");

    const QString baseUrl = testServerUrl();
    const ServerConfig config = ServerConfig::selfHosted(baseUrl);

    std::printf("=== BitVault sync fixture generator ===\n");
    std::printf("server:  %s\n", qPrintable(baseUrl));
    std::printf("output:  %s\n", qPrintable(outputPath));
    std::printf("account email:    %s\n", qPrintable(kEmail));
    std::printf("account password: %s\n", kPasswordUtf8.constData());
    std::printf("kdf: PBKDF2-SHA256, iterations=%u\n", kPbkdf2Iterations);
    std::printf(
        "TOTP secret is the RFC 6238/4226 reference key \"12345678901234567890\" "
        "(base32: %s) -- codes are predictable, not secret\n",
        kTotpSecretBase32.c_str());

    const std::string emailLower = kEmail.trimmed().toLower().toStdString();

    KdfParams kdfParams;
    kdfParams.type = KdfType::Pbkdf2Sha256;
    kdfParams.iterations = kPbkdf2Iterations;

    SecureBytes password = toSecureBytes(kPasswordUtf8);

    // --- derive keys with OUR crypto lib ---
    SecureBytes masterKey = deriveMasterKey(password, emailLower, kdfParams);
    SecureBytes masterHash = deriveMasterPasswordHash(masterKey, password);
    const QByteArray serverHashB64 =
        toQByteArray(base64Encode(masterHash.data(), masterHash.size()));

    SymmetricKey stretched = stretchMasterKey(masterKey);

    std::vector<uint8_t> userKeyBytes(64);
    must(RAND_bytes(userKeyBytes.data(), static_cast<int>(userKeyBytes.size()))
             == 1,
         "RAND_bytes failed generating the user key");
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

    std::printf("crypto setup: OK\n");

    // --- register ---
    QNetworkAccessManager net;
    QJsonObject keys;
    keys.insert(QStringLiteral("publicKey"), QString::fromStdString(publicKeyB64));
    keys.insert(QStringLiteral("encryptedPrivateKey"),
               QString::fromStdString(encryptedPrivateKey));

    QJsonObject registerBody;
    registerBody.insert(QStringLiteral("email"), kEmail);
    registerBody.insert(QStringLiteral("name"), QStringLiteral("BitVault Fixture"));
    registerBody.insert(QStringLiteral("masterPasswordHash"),
                        QString::fromUtf8(serverHashB64));
    registerBody.insert(QStringLiteral("key"),
                        QString::fromStdString(protectedKey));
    registerBody.insert(QStringLiteral("kdf"), 0);
    registerBody.insert(QStringLiteral("kdfIterations"),
                        static_cast<int>(kPbkdf2Iterations));
    registerBody.insert(QStringLiteral("keys"), keys);
    const QByteArray registerJson =
        QJsonDocument(registerBody).toJson(QJsonDocument::Compact);

    HttpResponse registerResponse =
        postJson(&net, config.registerUrl(), registerJson);
    if (registerResponse.timedOut) {
        failHttp(QStringLiteral("register timed out"), 0, QByteArray());
    }
    if (registerResponse.status == 404) {
        // Vaultwarden version differences: some serve /identity/accounts/
        // register, others only /api/accounts/register.
        const QString altUrl = config.apiBase + QStringLiteral("/accounts/register");
        registerResponse = postJson(&net, altUrl, registerJson);
        if (registerResponse.timedOut) {
            failHttp(QStringLiteral("register (alt URL) timed out"), 0,
                     QByteArray());
        }
    }
    if (registerResponse.status != 200 && registerResponse.status != 201) {
        failHttp(QStringLiteral("register account"), registerResponse.status,
                 registerResponse.body);
    }
    std::printf("register: OK (HTTP %d)\n", registerResponse.status);

    // --- login ---
    ApiClient client(config);
    const DeviceInfo device{newUuidString(),
                            QStringLiteral("bitvault-fixture-generator"), 8};
    const TwoFactorRequest noTwoFactor;

    QByteArray accessToken;
    {
        bool timedOut = false;
        Result<TokenResponse> result = waitFor<TokenResponse>(
            [&](std::function<void(Result<TokenResponse>)> cb) {
                client.loginPassword(kEmail, serverHashB64, device, noTwoFactor,
                                    QString(), cb);
            },
            &timedOut);
        if (timedOut) {
            failHttp(QStringLiteral("login timed out"), 0, QByteArray());
        }
        if (!result.ok()) {
            failHttp(QStringLiteral("login"), result.error.httpStatus,
                     result.error.message.toUtf8());
        }
        accessToken = result.value.accessToken;
        std::printf("login: OK\n");
    }

    SymmetricKey userSymKey = symmetricKeyFromBytes(userKey);

    // enc(plaintext) — the EncString the vault layer expects, encrypted
    // with the fixture account's user key.
    auto enc = [&](const std::string &plaintext) -> QString {
        SecureBytes bytes(reinterpret_cast<const uint8_t *>(plaintext.data()),
                          plaintext.size());
        return QString::fromStdString(
            encryptAes256CbcHmac(bytes, userSymKey).serialize());
    };

    // --- folder: "Work" ---
    QString folderId;
    {
        QJsonObject body;
        body.insert(QStringLiteral("name"), enc("Work"));
        const QByteArray json = QJsonDocument(body).toJson(QJsonDocument::Compact);
        HttpResponse response =
            postJson(&net, config.apiBase + QStringLiteral("/folders"), json,
                    accessToken);
        if (response.timedOut) {
            failHttp(QStringLiteral("create folder \"Work\" timed out"), 0,
                     QByteArray());
        }
        if (response.status != 200 && response.status != 201) {
            failHttp(QStringLiteral("create folder \"Work\""), response.status,
                     response.body);
        }
        QJsonParseError parseError;
        const QJsonDocument doc =
            QJsonDocument::fromJson(response.body, &parseError);
        folderId = jsonId(doc.object());
        if (folderId.isEmpty()) {
            failHttp(QStringLiteral("create folder \"Work\": no id in response"),
                     response.status, response.body);
        }
        std::printf("folder \"Work\": OK (id=%s)\n", qPrintable(folderId));
    }

    // --- login item: "Example Login" ---
    {
        QJsonObject login;
        login.insert(QStringLiteral("username"), enc("alice@example.com"));
        login.insert(QStringLiteral("password"), enc("s3cret-Pa55"));
        login.insert(QStringLiteral("totp"), enc(kTotpSecretBase32));
        QJsonArray uris;
        QJsonObject uri;
        uri.insert(QStringLiteral("uri"), enc("https://example.com"));
        uri.insert(QStringLiteral("match"), QJsonValue());
        uris.append(uri);
        login.insert(QStringLiteral("uris"), uris);

        QJsonObject body;
        body.insert(QStringLiteral("type"), 1);
        body.insert(QStringLiteral("name"), enc("Example Login"));
        body.insert(QStringLiteral("notes"), QJsonValue());
        body.insert(QStringLiteral("favorite"), false);
        body.insert(QStringLiteral("login"), login);
        body.insert(QStringLiteral("fields"), QJsonArray());

        const QByteArray json = QJsonDocument(body).toJson(QJsonDocument::Compact);
        HttpResponse response = postJson(
            &net, config.apiBase + QStringLiteral("/ciphers"), json, accessToken);
        if (response.timedOut) {
            failHttp(QStringLiteral("create cipher \"Example Login\" timed out"),
                     0, QByteArray());
        }
        if (response.status != 200 && response.status != 201) {
            failHttp(QStringLiteral("create cipher \"Example Login\""),
                     response.status, response.body);
        }
        std::printf("cipher \"Example Login\": OK\n");
    }

    // --- login item: "Work Login" (in the Work folder, no TOTP) ---
    {
        QJsonObject login;
        login.insert(QStringLiteral("username"), enc("bob@example.com"));
        login.insert(QStringLiteral("password"), enc("work-Pa55w0rd"));

        QJsonObject body;
        body.insert(QStringLiteral("type"), 1);
        body.insert(QStringLiteral("folderId"), folderId);
        body.insert(QStringLiteral("name"), enc("Work Login"));
        body.insert(QStringLiteral("notes"), QJsonValue());
        body.insert(QStringLiteral("favorite"), false);
        body.insert(QStringLiteral("login"), login);
        body.insert(QStringLiteral("fields"), QJsonArray());

        const QByteArray json = QJsonDocument(body).toJson(QJsonDocument::Compact);
        HttpResponse response = postJson(
            &net, config.apiBase + QStringLiteral("/ciphers"), json, accessToken);
        if (response.timedOut) {
            failHttp(QStringLiteral("create cipher \"Work Login\" timed out"), 0,
                     QByteArray());
        }
        if (response.status != 200 && response.status != 201) {
            failHttp(QStringLiteral("create cipher \"Work Login\""),
                     response.status, response.body);
        }
        std::printf("cipher \"Work Login\": OK (folderId=%s)\n",
                    qPrintable(folderId));
    }

    // --- secure note: "Fixture Note" ---
    {
        QJsonObject secureNote;
        secureNote.insert(QStringLiteral("type"), 0);

        QJsonObject body;
        body.insert(QStringLiteral("type"), 2);
        body.insert(QStringLiteral("name"), enc("Fixture Note"));
        body.insert(QStringLiteral("notes"), enc("the note body"));
        body.insert(QStringLiteral("secureNote"), secureNote);
        body.insert(QStringLiteral("favorite"), true);

        const QByteArray json = QJsonDocument(body).toJson(QJsonDocument::Compact);
        HttpResponse response = postJson(
            &net, config.apiBase + QStringLiteral("/ciphers"), json, accessToken);
        if (response.timedOut) {
            failHttp(QStringLiteral("create cipher \"Fixture Note\" timed out"),
                     0, QByteArray());
        }
        if (response.status != 200 && response.status != 201) {
            failHttp(QStringLiteral("create cipher \"Fixture Note\""),
                     response.status, response.body);
        }
        std::printf("cipher \"Fixture Note\": OK\n");
    }

    // --- card: "Fixture Card" ---
    {
        QJsonObject card;
        card.insert(QStringLiteral("cardholderName"), enc("Alice Example"));
        card.insert(QStringLiteral("brand"), enc("Visa"));
        card.insert(QStringLiteral("number"), enc("4111111111111111"));
        card.insert(QStringLiteral("expMonth"), enc("12"));
        card.insert(QStringLiteral("expYear"), enc("2030"));
        card.insert(QStringLiteral("code"), enc("123"));

        QJsonObject body;
        body.insert(QStringLiteral("type"), 3);
        body.insert(QStringLiteral("name"), enc("Fixture Card"));
        body.insert(QStringLiteral("card"), card);

        const QByteArray json = QJsonDocument(body).toJson(QJsonDocument::Compact);
        HttpResponse response = postJson(
            &net, config.apiBase + QStringLiteral("/ciphers"), json, accessToken);
        if (response.timedOut) {
            failHttp(QStringLiteral("create cipher \"Fixture Card\" timed out"),
                     0, QByteArray());
        }
        if (response.status != 200 && response.status != 201) {
            failHttp(QStringLiteral("create cipher \"Fixture Card\""),
                     response.status, response.body);
        }
        std::printf("cipher \"Fixture Card\": OK\n");
    }

    // --- sync ---
    {
        bool timedOut = false;
        Result<QByteArray> result = waitFor<QByteArray>(
            [&](std::function<void(Result<QByteArray>)> cb) {
                client.sync(accessToken, cb);
            },
            &timedOut);
        if (timedOut) {
            failHttp(QStringLiteral("sync timed out"), 0, QByteArray());
        }
        if (!result.ok()) {
            failHttp(QStringLiteral("sync"), result.error.httpStatus,
                     result.error.message.toUtf8());
        }

        QFile file(outputPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            std::fprintf(stderr, "FAILED: cannot open %s for writing\n",
                        qPrintable(outputPath));
            return 1;
        }
        file.write(result.value);
        file.close();
        std::printf("sync: OK, wrote %lld bytes to %s\n",
                    static_cast<long long>(result.value.size()),
                    qPrintable(outputPath));
    }

    std::printf("\ndone.\n");
    std::printf("account email:    %s\n", qPrintable(kEmail));
    std::printf("account password: %s\n", kPasswordUtf8.constData());
    std::printf("(public test-only credentials -- this account holds no real"
                " data)\n");
    return 0;
}
