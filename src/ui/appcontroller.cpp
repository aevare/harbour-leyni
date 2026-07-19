#include "appcontroller.h"

#include <QClipboard>
#include <QDateTime>
#include <QGuiApplication>
#include <QUuid>
#include <QtConcurrent/QtConcurrentRun>

#include "base64.h"
#include "crypto.h"
#include "kdf.h"
#include "pinwrap.h"

namespace BitVault {
namespace Ui {

namespace {

const char kSettingServer[] = "account/serverUrl";
const char kSettingEmail[] = "account/email";
const char kSettingDeviceId[] = "account/deviceId";
const char kSettingRefreshToken[] = "session/refreshToken";
const char kSettingKdfType[] = "kdf/type";
const char kSettingKdfIterations[] = "kdf/iterations";
const char kSettingKdfMemory[] = "kdf/memoryMiB";
const char kSettingKdfParallelism[] = "kdf/parallelism";
const char kSettingAutoLockMinutes[] = "security/autoLockMinutes";
const char kSettingClipboardSeconds[] = "security/clipboardClearSeconds";
const char kSettingLockOnMinimize[] = "security/lockOnMinimize";
const char kSettingPinFailures[] = "security/pinFailures";

// Consecutive wrong-PIN attempts before the wrapped key is wiped and a full
// master-password unlock is forced. Chosen by the user (2026-07-19).
const int kMaxPinFailures = 3;
// Shortest PIN we will wrap. Enforced in QML too; this is the backstop.
const int kMinPinLength = 4;

Crypto::SecureBytes toSecure(const QString &text)
{
    const QByteArray utf8 = text.toUtf8();
    return Crypto::SecureBytes(
        reinterpret_cast<const uint8_t *>(utf8.constData()),
        static_cast<size_t>(utf8.size()));
    // The QByteArray/QString copies are freed unzeroed — a platform
    // limitation shared by every Qt client; see doc/ARCHITECTURE.md.
}

} // namespace

AppController::AppController(QObject *parent)
    : QObject(parent)
    , m_settings(QStringLiteral("harbour-bitvault"),
                 QStringLiteral("harbour-bitvault"))
    , m_api(Api::ServerConfig::cloudUs(), this)
    , m_vault(this)
    , m_model(&m_vault, this)
{
    m_api.setServerConfig(currentServerConfig());

    m_refreshToken =
        m_settings.value(QLatin1String(kSettingRefreshToken)).toByteArray();

    m_vault.setAutoLockSeconds(autoLockMinutes() * 60);
    connect(&m_vault, &Vault::Vault::lockedChanged, this, [this](bool locked) {
        if (locked && m_state == QLatin1String("unlocked")) {
            setState(QStringLiteral("locked"));
        }
        emit vaultChanged();
    });

    m_clipboardTimer.setSingleShot(true);
    connect(&m_clipboardTimer, &QTimer::timeout, this,
            &AppController::clearClipboardIfOurs);

    connect(qGuiApp, &QGuiApplication::applicationStateChanged, this,
            &AppController::handleAppStateChanged);

    // Initial state: an existing local blob means we can work offline.
    if (email().isEmpty()) {
        m_state = QStringLiteral("setup");
    } else if (m_syncStore.exists()) {
        QString error;
        if (m_vault.loadSync(m_syncStore.load(), &error)) {
            m_state = QStringLiteral("locked");
        } else {
            m_state = QStringLiteral("login");
        }
    } else {
        m_state = QStringLiteral("login");
    }
}

QString AppController::serverUrl() const
{
    return m_settings.value(QLatin1String(kSettingServer)).toString();
}

QString AppController::email() const
{
    return m_settings.value(QLatin1String(kSettingEmail)).toString();
}

int AppController::autoLockMinutes() const
{
    return m_settings.value(QLatin1String(kSettingAutoLockMinutes), 5).toInt();
}

void AppController::setAutoLockMinutes(int minutes)
{
    m_settings.setValue(QLatin1String(kSettingAutoLockMinutes), minutes);
    m_vault.setAutoLockSeconds(minutes * 60);
    emit settingsChanged();
}

int AppController::clipboardClearSeconds() const
{
    return m_settings.value(QLatin1String(kSettingClipboardSeconds), 30)
        .toInt();
}

void AppController::setClipboardClearSeconds(int seconds)
{
    m_settings.setValue(QLatin1String(kSettingClipboardSeconds), seconds);
    emit settingsChanged();
}

bool AppController::lockOnMinimize() const
{
    return m_settings.value(QLatin1String(kSettingLockOnMinimize), true)
        .toBool();
}

void AppController::setLockOnMinimize(bool on)
{
    m_settings.setValue(QLatin1String(kSettingLockOnMinimize), on);
    emit settingsChanged();
}

void AppController::setState(const QString &state)
{
    if (m_state != state) {
        m_state = state;
        emit stateChanged();
    }
}

void AppController::setBusy(bool busy)
{
    if (m_busy != busy) {
        m_busy = busy;
        emit busyChanged();
    }
}

void AppController::setError(const QString &message)
{
    m_lastError = message;
    emit lastErrorChanged();
}

Api::ServerConfig AppController::currentServerConfig() const
{
    const QString url = serverUrl();
    if (url.isEmpty() || url == QLatin1String("bitwarden.com")
            || url == QLatin1String("https://bitwarden.com")) {
        return Api::ServerConfig::cloudUs();
    }
    if (url == QLatin1String("bitwarden.eu")
            || url == QLatin1String("https://bitwarden.eu")) {
        return Api::ServerConfig::cloudEu();
    }
    return Api::ServerConfig::selfHosted(url);
}

Api::DeviceInfo AppController::deviceInfo()
{
    QString id = m_settings.value(QLatin1String(kSettingDeviceId)).toString();
    if (id.isEmpty()) {
        id = QUuid::createUuid().toString();
        id.remove(QLatin1Char('{'));
        id.remove(QLatin1Char('}'));
        m_settings.setValue(QLatin1String(kSettingDeviceId), id);
    }
    Api::DeviceInfo device;
    device.identifier = id;
    device.name = QStringLiteral("Sailfish OS (BitVault)");
    device.type = 8; // LinuxDesktop; see apijson.h
    return device;
}

Crypto::KdfParams AppController::storedKdfParams() const
{
    Crypto::KdfParams params;
    params.type = static_cast<Crypto::KdfType>(
        m_settings.value(QLatin1String(kSettingKdfType), 0).toInt());
    params.iterations = m_settings.value(QLatin1String(kSettingKdfIterations),
                                         0).toUInt();
    params.memoryMiB =
        m_settings.value(QLatin1String(kSettingKdfMemory), 0).toUInt();
    params.parallelism =
        m_settings.value(QLatin1String(kSettingKdfParallelism), 0).toUInt();
    return params;
}

void AppController::storeKdfParams(const Crypto::KdfParams &params)
{
    m_settings.setValue(QLatin1String(kSettingKdfType),
                        static_cast<int>(params.type));
    m_settings.setValue(QLatin1String(kSettingKdfIterations),
                        params.iterations);
    m_settings.setValue(QLatin1String(kSettingKdfMemory), params.memoryMiB);
    m_settings.setValue(QLatin1String(kSettingKdfParallelism),
                        params.parallelism);
}

void AppController::configureAccount(const QString &serverUrl,
                                     const QString &email)
{
    m_settings.setValue(QLatin1String(kSettingServer), serverUrl.trimmed());
    m_settings.setValue(QLatin1String(kSettingEmail),
                        email.trimmed().toLower());
    m_api.setServerConfig(currentServerConfig());
    emit accountChanged();
    setState(QStringLiteral("login"));
}

void AppController::deriveAsync(
    const QString &password, const Crypto::KdfParams &params,
    std::function<void(std::shared_ptr<DerivedSecrets>)> next)
{
    if (m_deriveWatcher.isRunning()) {
        setError(QStringLiteral("another operation is in progress"));
        return;
    }
    const QString accountEmail = email();
    // The SecureBytes password is moved into the shared context; the worker
    // owns the only copy of the derived key until `next` takes it.
    auto passwordPtr =
        std::make_shared<Crypto::SecureBytes>(toSecure(password));

    // QFutureWatcher: one connection per run, single-shot semantics.
    disconnect(&m_deriveWatcher, nullptr, nullptr, nullptr);
    connect(&m_deriveWatcher,
            &QFutureWatcher<std::shared_ptr<DerivedSecrets>>::finished, this,
            [this, next]() { next(m_deriveWatcher.result()); });

    m_deriveWatcher.setFuture(QtConcurrent::run(
        [passwordPtr, accountEmail, params]() -> std::shared_ptr<DerivedSecrets> {
            auto out = std::make_shared<DerivedSecrets>();
            try {
                out->masterKey = Crypto::deriveMasterKey(
                    *passwordPtr, accountEmail.toLower().toStdString(),
                    params);
                const Crypto::SecureBytes hash =
                    Crypto::deriveMasterPasswordHash(out->masterKey,
                                                     *passwordPtr);
                out->passwordHashB64 = QByteArray::fromStdString(
                    Crypto::base64Encode(hash.data(), hash.size()));
            } catch (const Crypto::CryptoError &e) {
                out->error = QString::fromUtf8(e.what());
            }
            *passwordPtr = Crypto::SecureBytes(); // zero the password now
            return out;
        }));
}

void AppController::runPinWorker(
    std::function<std::shared_ptr<PinResult>()> work,
    std::function<void(std::shared_ptr<PinResult>)> next)
{
    if (m_pinWatcher.isRunning()) {
        setError(QStringLiteral("another operation is in progress"));
        return;
    }
    disconnect(&m_pinWatcher, nullptr, nullptr, nullptr);
    connect(&m_pinWatcher,
            &QFutureWatcher<std::shared_ptr<PinResult>>::finished, this,
            [this, next]() { next(m_pinWatcher.result()); });
    m_pinWatcher.setFuture(QtConcurrent::run(work));
}

void AppController::startLogin(const QString &password)
{
    if (email().isEmpty()) {
        setError(QStringLiteral("no account configured"));
        return;
    }
    setError(QString());
    setBusy(true);

    m_api.prelogin(email(), [this, password](
                                Api::Result<Api::PreloginResponse> result) {
        if (!result.ok()) {
            setBusy(false);
            setError(result.error.message);
            return;
        }
        storeKdfParams(result.value.kdf);
        deriveAsync(password, result.value.kdf,
                    [this](std::shared_ptr<DerivedSecrets> secrets) {
            if (!secrets->error.isEmpty()) {
                setBusy(false);
                setError(secrets->error);
                return;
            }
            m_pendingSecrets = secrets;
            m_api.loginPassword(
                email(), secrets->passwordHashB64, deviceInfo(),
                Api::TwoFactorRequest(), QString(),
                [this](Api::Result<Api::TokenResponse> loginResult) {
                    if (loginResult.ok()) {
                        finishLogin(loginResult.value);
                        return;
                    }
                    if (loginResult.error.twoFactorRequired) {
                        m_pendingHash = m_pendingSecrets->passwordHashB64;
                        m_twoFactorProviders.clear();
                        for (int provider :
                             loginResult.error.twoFactorProviders) {
                            m_twoFactorProviders.append(provider);
                        }
                        setBusy(false);
                        setState(QStringLiteral("twofactor"));
                        return;
                    }
                    m_pendingSecrets.reset();
                    setBusy(false);
                    setError(loginResult.error.message);
                });
        });
    });
}

void AppController::submitTwoFactor(int provider, const QString &code,
                                    bool remember)
{
    if (!m_pendingSecrets || m_pendingHash.isEmpty()) {
        setError(QStringLiteral("no login in progress"));
        return;
    }
    setError(QString());
    setBusy(true);
    Api::TwoFactorRequest twoFactor;
    twoFactor.provider = provider;
    twoFactor.token = code.trimmed();
    twoFactor.remember = remember;
    m_api.loginPassword(email(), m_pendingHash, deviceInfo(), twoFactor,
                        QString(),
                        [this](Api::Result<Api::TokenResponse> result) {
        if (result.ok()) {
            finishLogin(result.value);
        } else {
            setBusy(false);
            setError(result.error.message);
        }
    });
}

void AppController::requestEmailCode()
{
    if (m_pendingHash.isEmpty()) {
        setError(QStringLiteral("no login in progress"));
        return;
    }
    m_api.sendEmailLoginCode(email(), m_pendingHash,
                             deviceInfo().identifier,
                             [this](Api::Result<QByteArray> result) {
        if (result.ok()) {
            emit notify(QStringLiteral("Code sent — check your email"));
        } else {
            setError(result.error.message);
        }
    });
}

void AppController::cancelLogin()
{
    m_pendingSecrets.reset();
    m_pendingHash.clear();
    m_twoFactorProviders.clear();
    setBusy(false);
    setState(QStringLiteral("login"));
}

void AppController::finishLogin(const Api::TokenResponse &token)
{
    m_accessToken = token.accessToken;
    m_refreshToken = token.refreshToken;
    m_settings.setValue(QLatin1String(kSettingRefreshToken), m_refreshToken);
    m_pendingHash.clear();
    m_twoFactorProviders.clear();

    m_api.sync(m_accessToken, [this](Api::Result<QByteArray> result) {
        if (!result.ok()) {
            m_pendingSecrets.reset();
            setBusy(false);
            setError(QStringLiteral("sync failed: %1")
                         .arg(result.error.message));
            setState(QStringLiteral("login"));
            return;
        }
        applySyncBlob(result.value, true);
    });
}

void AppController::applySyncBlob(const QByteArray &blob, bool freshLogin)
{
    if (!m_syncStore.save(blob)) {
        // Non-fatal: the in-memory vault still works this session.
        emit notify(QStringLiteral("Warning: could not store vault locally"));
    }

    QString error;
    if (!m_vault.isLocked()) {
        if (m_vault.reloadSync(blob, &error)) {
            emit vaultChanged();
            emit notify(QStringLiteral("Vault synced"));
            m_model.refresh();
        } else {
            setState(QStringLiteral("locked"));
            setError(error);
        }
        setBusy(false);
        return;
    }

    if (!m_vault.loadSync(blob, &error)) {
        setBusy(false);
        setError(error);
        return;
    }

    if (freshLogin && m_pendingSecrets) {
        // Unlock right away with the key derived during login.
        std::shared_ptr<DerivedSecrets> secrets = m_pendingSecrets;
        m_pendingSecrets.reset();
        if (m_vault.unlockWithMasterKey(std::move(secrets->masterKey),
                                        &error)) {
            m_model.refresh();
            emit vaultChanged();
            setState(QStringLiteral("unlocked"));
        } else {
            setError(error);
            setState(QStringLiteral("locked"));
        }
    } else {
        setState(QStringLiteral("locked"));
    }
    setBusy(false);
}

void AppController::unlock(const QString &password)
{
    if (m_vault.isLocked() && !m_syncStore.exists()) {
        setError(QStringLiteral("no local vault — sign in first"));
        return;
    }
    Crypto::KdfParams params = storedKdfParams();
    if (params.iterations == 0) {
        setError(QStringLiteral("missing KDF parameters — sign in again"));
        setState(QStringLiteral("login"));
        return;
    }
    setError(QString());
    setBusy(true);
    deriveAsync(password, params,
                [this](std::shared_ptr<DerivedSecrets> secrets) {
        setBusy(false);
        if (!secrets->error.isEmpty()) {
            setError(secrets->error);
            return;
        }
        QString error;
        if (m_vault.unlockWithMasterKey(std::move(secrets->masterKey),
                                        &error)) {
            m_model.refresh();
            emit vaultChanged();
            setState(QStringLiteral("unlocked"));
        } else {
            setError(error);
        }
    });
}

bool AppController::pinEnabled() const
{
    return m_pinStore.exists();
}

int AppController::pinFailures() const
{
    return m_settings.value(QLatin1String(kSettingPinFailures), 0).toInt();
}

void AppController::setPinFailures(int count)
{
    m_settings.setValue(QLatin1String(kSettingPinFailures), count);
}

void AppController::forgetPin()
{
    m_pinStore.clear();
    m_settings.remove(QLatin1String(kSettingPinFailures));
    emit pinChanged();
}

void AppController::enablePin(const QString &masterPassword, const QString &pin)
{
    // enablePin runs from Settings, whose page does not display App.lastError.
    // Feedback (success and failure) is therefore surfaced via notify(), the
    // global banner — mirroring the "PIN unlock enabled" success toast.
    if (pin.size() < kMinPinLength) {
        emit notify(QStringLiteral("PIN must be at least %1 digits")
                        .arg(kMinPinLength));
        return;
    }
    if (!m_syncStore.exists()) {
        emit notify(QStringLiteral("No vault — sign in first"));
        return;
    }
    Crypto::KdfParams params = storedKdfParams();
    if (params.iterations == 0) {
        emit notify(QStringLiteral("Missing KDF parameters — sign in again"));
        return;
    }
    setError(QString());
    setBusy(true);

    // Stage 1: re-derive the master key from the master password (account KDF,
    // off-thread). Stage 2: verify it, then wrap it under the PIN (Argon2id,
    // also off-thread). The master key exists only inside these callbacks.
    deriveAsync(masterPassword, params,
                [this, pin](std::shared_ptr<DerivedSecrets> secrets) {
        if (!secrets->error.isEmpty()) {
            setBusy(false);
            emit notify(secrets->error);
            return;
        }
        QString error;
        if (!m_vault.verifyMasterKey(secrets->masterKey, &error)) {
            setBusy(false);
            emit notify(QStringLiteral("Wrong master password — PIN not "
                                       "enabled"));
            return;
        }
        // Move the verified master key and the PIN into the wrap worker.
        auto keyPtr = std::make_shared<Crypto::SecureBytes>(
            std::move(secrets->masterKey));
        auto pinPtr =
            std::make_shared<Crypto::SecureBytes>(toSecure(pin));
        runPinWorker(
            [keyPtr, pinPtr]() -> std::shared_ptr<PinResult> {
                auto out = std::make_shared<PinResult>();
                try {
                    out->blob = QByteArray::fromStdString(
                        Crypto::wrapWithPin(*keyPtr, *pinPtr).serialize());
                } catch (const Crypto::CryptoError &e) {
                    out->error = QString::fromUtf8(e.what());
                }
                *keyPtr = Crypto::SecureBytes();
                *pinPtr = Crypto::SecureBytes();
                return out;
            },
            [this](std::shared_ptr<PinResult> result) {
                setBusy(false);
                if (!result->error.isEmpty()) {
                    emit notify(result->error);
                    return;
                }
                if (!m_pinStore.save(result->blob)) {
                    emit notify(QStringLiteral("Could not store PIN"));
                    return;
                }
                setPinFailures(0);
                emit pinChanged();
                emit notify(QStringLiteral("PIN unlock enabled"));
            });
    });
}

void AppController::disablePin()
{
    forgetPin();
    emit notify(QStringLiteral("PIN unlock disabled"));
}

void AppController::unlockWithPin(const QString &pin)
{
    if (!m_pinStore.exists()) {
        setError(QStringLiteral("PIN not set up"));
        return;
    }
    if (!m_syncStore.exists()) {
        setError(QStringLiteral("no local vault — sign in first"));
        return;
    }

    Crypto::PinWrappedKey wrapped;
    try {
        wrapped = Crypto::PinWrappedKey::parse(
            m_pinStore.load().toStdString());
    } catch (const Crypto::CryptoError &) {
        // A corrupt PIN file is unusable — drop it and fall back.
        forgetPin();
        setError(QStringLiteral("PIN data unreadable — use your master "
                                "password"));
        return;
    }

    setError(QString());
    setBusy(true);
    auto pinPtr = std::make_shared<Crypto::SecureBytes>(toSecure(pin));
    auto wrappedPtr =
        std::make_shared<Crypto::PinWrappedKey>(std::move(wrapped));
    runPinWorker(
        [pinPtr, wrappedPtr]() -> std::shared_ptr<PinResult> {
            auto out = std::make_shared<PinResult>();
            try {
                out->masterKey =
                    Crypto::unwrapWithPin(*wrappedPtr, *pinPtr);
            } catch (const Crypto::CryptoError &e) {
                out->error = QString::fromUtf8(e.what());
            }
            *pinPtr = Crypto::SecureBytes();
            return out;
        },
        [this](std::shared_ptr<PinResult> result) {
            setBusy(false);
            if (!result->error.isEmpty()) {
                // Wrong PIN (MAC mismatch). Count it; wipe at the limit.
                const int failures = pinFailures() + 1;
                if (failures >= kMaxPinFailures) {
                    forgetPin();
                    setError(QStringLiteral(
                        "Too many wrong PINs — unlock with your master "
                        "password"));
                } else {
                    setPinFailures(failures);
                    setError(QStringLiteral("Wrong PIN (%1 of %2)")
                                 .arg(failures)
                                 .arg(kMaxPinFailures));
                }
                return;
            }
            QString error;
            if (m_vault.unlockWithMasterKey(std::move(result->masterKey),
                                            &error)) {
                setPinFailures(0);
                m_model.refresh();
                emit vaultChanged();
                setState(QStringLiteral("unlocked"));
            } else {
                // Correct PIN but the key no longer fits the vault (e.g. the
                // master password was changed on the server). Not a wrong-PIN
                // event: drop the stale PIN and ask for the master password.
                forgetPin();
                setError(QStringLiteral("Vault key changed — unlock with your "
                                        "master password"));
            }
        });
}

void AppController::lock()
{
    m_vault.lock();
    setState(m_syncStore.exists() || !m_vault.isLocked()
                 ? QStringLiteral("locked")
                 : QStringLiteral("login"));
}

void AppController::syncNow()
{
    if (m_refreshToken.isEmpty()) {
        setError(QStringLiteral("not signed in"));
        return;
    }
    setError(QString());
    setBusy(true);
    refreshAndSync(false);
}

void AppController::refreshAndSync(bool freshLogin)
{
    m_api.refreshToken(m_refreshToken,
                       [this, freshLogin](Api::Result<Api::TokenResponse> r) {
        if (!r.ok()) {
            setBusy(false);
            setError(QStringLiteral("session expired — sign in again"));
            m_settings.remove(QLatin1String(kSettingRefreshToken));
            m_refreshToken.clear();
            if (m_vault.isLocked()) {
                setState(QStringLiteral("login"));
            }
            return;
        }
        m_accessToken = r.value.accessToken;
        if (!r.value.refreshToken.isEmpty()) {
            m_refreshToken = r.value.refreshToken;
            m_settings.setValue(QLatin1String(kSettingRefreshToken),
                                m_refreshToken);
        }
        m_api.sync(m_accessToken,
                   [this, freshLogin](Api::Result<QByteArray> result) {
            if (!result.ok()) {
                setBusy(false);
                setError(QStringLiteral("sync failed: %1")
                             .arg(result.error.message));
                return;
            }
            applySyncBlob(result.value, freshLogin);
        });
    });
}

void AppController::signOut()
{
    m_vault.lock();
    m_accessToken.clear();
    m_refreshToken.clear();
    m_settings.remove(QLatin1String(kSettingRefreshToken));
    m_syncStore.clear();
    forgetPin(); // the wrapped master key belongs to this account
    setState(QStringLiteral("login"));
    emit vaultChanged();
}

QString AppController::itemPassword(const QString &itemId)
{
    QString error;
    noteActivity();
    const QString password = m_vault.itemPassword(itemId, &error);
    if (!error.isEmpty()) {
        setError(error);
    }
    return password;
}

QString AppController::itemNotes(const QString &itemId)
{
    QString error;
    noteActivity();
    return m_vault.itemNotes(itemId, &error);
}

QVariantList AppController::itemDetailFields(const QString &itemId)
{
    QString error;
    noteActivity();
    QVariantList list;
    const auto fields = m_vault.itemDetailFields(itemId, &error);
    for (const auto &field : fields) {
        QVariantMap map;
        map.insert(QStringLiteral("name"), field.first);
        map.insert(QStringLiteral("value"), field.second);
        list.append(map);
    }
    return list;
}

QVariantMap AppController::totpFor(const QString &itemId)
{
    QString error;
    int secondsRemaining = 0;
    noteActivity();
    // currentMSecsSinceEpoch: Qt 5.8's currentSecsSinceEpoch is unavailable
    // on the SFOS target (Qt 5.6).
    const QString code = m_vault.totpCode(
        itemId,
        static_cast<quint64>(QDateTime::currentMSecsSinceEpoch() / 1000),
        &secondsRemaining, &error);
    QVariantMap map;
    map.insert(QStringLiteral("code"), code);
    map.insert(QStringLiteral("seconds"), secondsRemaining);
    map.insert(QStringLiteral("error"), error);
    return map;
}

QString AppController::folderName(const QString &folderId)
{
    return m_vault.folderName(folderId);
}

QVariantList AppController::folders()
{
    QVariantList list;
    const auto folders = m_vault.folders();
    for (const auto &folder : folders) {
        QVariantMap map;
        map.insert(QStringLiteral("id"), folder.first);
        map.insert(QStringLiteral("name"), folder.second);
        list.append(map);
    }
    return list;
}

void AppController::copyToClipboard(const QString &text)
{
    QGuiApplication::clipboard()->setText(text);
    m_clipboardExpected = text;
    const int seconds = clipboardClearSeconds();
    if (seconds > 0) {
        m_clipboardTimer.start(seconds * 1000);
        emit notify(QStringLiteral("Copied — clears in %1 s").arg(seconds));
    } else {
        emit notify(QStringLiteral("Copied"));
    }
    noteActivity();
}

void AppController::clearClipboardIfOurs()
{
    // Only clear if the clipboard still holds what we put there — never
    // stomp on something the user copied elsewhere in the meantime.
    if (QGuiApplication::clipboard()->text() == m_clipboardExpected) {
        QGuiApplication::clipboard()->clear();
    }
    m_clipboardExpected.clear();
}

void AppController::noteActivity()
{
    m_vault.noteActivity();
}

void AppController::handleAppStateChanged(Qt::ApplicationState state)
{
    if (state != Qt::ApplicationActive && lockOnMinimize()
            && !m_vault.isLocked()) {
        lock();
    }
}

} // namespace Ui
} // namespace BitVault
