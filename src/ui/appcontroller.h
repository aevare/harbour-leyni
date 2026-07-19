// The single QML-facing controller. Owns the ApiClient, the Vault, the
// list model, persisted settings, and all security policy:
//   - the master password is converted to SecureBytes immediately on entry
//     from QML and never retained beyond the operation that needs it
//   - key derivation runs on a worker thread (QtConcurrent); the Vault is
//     only ever touched from the GUI thread
//   - clipboard copies auto-clear after a configurable timeout
//   - the vault locks on app minimize (configurable) and on auto-lock
//   - QML gets display data and one-shot secret fetches only; no key
//     material, no security decisions in JavaScript (doc/ARCHITECTURE.md)
//
// States: "setup" (no account), "login" (account, no session), "twofactor"
// (login pending a code), "locked" (sync blob present), "unlocked".
#pragma once

#include <QFutureWatcher>
#include <QObject>
#include <QSettings>
#include <QTimer>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

#include <memory>

#include "apiclient.h"
#include "pinstore.h"
#include "securebytes.h"
#include "syncstore.h"
#include "vault.h"
#include "vaultmodel.h"

namespace BitVault {
namespace Ui {

// Result of the worker-thread KDF run (shared_ptr because QFuture requires
// a copyable payload; the pointee is moved out exactly once on the GUI
// thread and zeroed by SecureBytes semantics).
struct DerivedSecrets {
    Crypto::SecureBytes masterKey;
    QByteArray passwordHashB64;
    QString error;
};

// Result of an off-thread PIN operation (Argon2id is slow, so wrap/unwrap
// never run on the GUI thread). Exactly one of masterKey/blob is populated on
// success; error is set on failure.
struct PinResult {
    Crypto::SecureBytes masterKey;  // set by unwrap (the recovered master key)
    QByteArray blob;                // set by wrap (serialized PinWrappedKey)
    QString error;
};

class AppController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)
    Q_PROPERTY(QObject *vaultModel READ vaultModel CONSTANT)
    Q_PROPERTY(QString serverUrl READ serverUrl NOTIFY accountChanged)
    Q_PROPERTY(QString email READ email NOTIFY accountChanged)
    Q_PROPERTY(int itemCount READ itemCount NOTIFY vaultChanged)
    Q_PROPERTY(QVariantList twoFactorProviders READ twoFactorProviders
                   NOTIFY stateChanged)
    Q_PROPERTY(int autoLockMinutes READ autoLockMinutes
                   WRITE setAutoLockMinutes NOTIFY settingsChanged)
    Q_PROPERTY(int clipboardClearSeconds READ clipboardClearSeconds
                   WRITE setClipboardClearSeconds NOTIFY settingsChanged)
    Q_PROPERTY(bool lockOnMinimize READ lockOnMinimize
                   WRITE setLockOnMinimize NOTIFY settingsChanged)
    // True when a PIN-wrapped master key exists on disk: the unlock screen
    // offers PIN entry, and Settings shows the feature as enabled.
    Q_PROPERTY(bool pinEnabled READ pinEnabled NOTIFY pinChanged)

public:
    explicit AppController(QObject *parent = nullptr);

    QString state() const { return m_state; }
    bool busy() const { return m_busy; }
    QString lastError() const { return m_lastError; }
    QObject *vaultModel() { return &m_model; }
    QString serverUrl() const;
    QString email() const;
    int itemCount() const { return static_cast<int>(m_vault.items().size()); }
    QVariantList twoFactorProviders() const { return m_twoFactorProviders; }

    int autoLockMinutes() const;
    void setAutoLockMinutes(int minutes);
    int clipboardClearSeconds() const;
    void setClipboardClearSeconds(int seconds);
    bool lockOnMinimize() const;
    void setLockOnMinimize(bool on);
    bool pinEnabled() const;

    // Enable PIN unlock: re-derives the master key from the given master
    // password (verified against the loaded vault), wraps it under `pin`, and
    // stores the blob. The master password is required so this is an
    // explicitly authorized action and the master key need not be kept in
    // memory between unlocks.
    Q_INVOKABLE void enablePin(const QString &masterPassword,
                               const QString &pin);
    // Forget the PIN-wrapped key; next unlock needs the master password.
    Q_INVOKABLE void disablePin();

    // --- account/session ---
    Q_INVOKABLE void configureAccount(const QString &serverUrl,
                                      const QString &email);
    Q_INVOKABLE void startLogin(const QString &password);
    Q_INVOKABLE void submitTwoFactor(int provider, const QString &code,
                                     bool remember);
    Q_INVOKABLE void requestEmailCode();
    Q_INVOKABLE void cancelLogin();
    Q_INVOKABLE void unlock(const QString &password);
    // Unlock with the PIN: unwraps the stored master key (Argon2id off-thread)
    // and reuses the normal master-key unlock path. A wrong PIN counts toward
    // the attempt limit; the limit's worth of failures wipes the wrapped key
    // and forces a full master-password unlock.
    Q_INVOKABLE void unlockWithPin(const QString &pin);
    Q_INVOKABLE void lock();
    Q_INVOKABLE void syncNow();
    // Forgets tokens and the local blob; back to "login" (keeps account).
    Q_INVOKABLE void signOut();

    // --- write support (create/edit/soft-delete) ---
    // `fields` is a QVariantMap of plaintext entered in QML (keys: name,
    // notes, folderId, favorite, and for logins username/password/uri/totp).
    // The vault encrypts it; plaintext never leaves this process unencrypted.
    // Each: build body → refresh token → cipher call → re-sync → notify.
    Q_INVOKABLE void createItem(int type, const QVariantMap &fields);
    Q_INVOKABLE void saveItem(const QString &itemId, const QVariantMap &fields);
    Q_INVOKABLE void deleteItem(const QString &itemId);

    // --- password generator ---
    // Generates a password from `options` (keys: length, lowercase, uppercase,
    // digits, symbols, avoidAmbiguous). Returns empty + sets lastError on an
    // impossible combination (the UI also guards against those).
    Q_INVOKABLE QString generatePassword(const QVariantMap &options);
    // Last-used generator options (persisted), so the dialog restores them.
    Q_INVOKABLE QVariantMap generatorOptions() const;
    Q_INVOKABLE void setGeneratorOptions(const QVariantMap &options);

    // --- item access (thin proxies over Vault; see vault.h) ---
    Q_INVOKABLE QString itemPassword(const QString &itemId);
    Q_INVOKABLE QString itemNotes(const QString &itemId);
    // Raw TOTP secret for prefilling the editor (not a generated code).
    Q_INVOKABLE QString itemTotpSecret(const QString &itemId);
    Q_INVOKABLE QVariantList itemDetailFields(const QString &itemId);
    Q_INVOKABLE QVariantMap totpFor(const QString &itemId);
    Q_INVOKABLE QString folderName(const QString &folderId);
    Q_INVOKABLE QVariantList folders();

    // --- clipboard with auto-clear ---
    Q_INVOKABLE void copyToClipboard(const QString &text);

    Q_INVOKABLE void noteActivity();

signals:
    void stateChanged();
    void busyChanged();
    void lastErrorChanged();
    void accountChanged();
    void vaultChanged();
    void settingsChanged();
    void pinChanged();
    // One-shot toast requests for QML (e.g. "Copied — clears in 30 s").
    void notify(const QString &message);

private:
    void setState(const QString &state);
    void setBusy(bool busy);
    void setError(const QString &message);
    Api::ServerConfig currentServerConfig() const;
    Api::DeviceInfo deviceInfo();
    Crypto::KdfParams storedKdfParams() const;
    void storeKdfParams(const Crypto::KdfParams &params);

    // Runs deriveMasterKey(+ password hash) off-thread, then `next` on the
    // GUI thread with the result.
    void deriveAsync(const QString &password, const Crypto::KdfParams &params,
                     std::function<void(std::shared_ptr<DerivedSecrets>)> next);

    // Runs a PIN wrap/unwrap (both Argon2id-bound) off-thread, then `next` on
    // the GUI thread with the result. `work` must be self-contained (capture
    // only shared_ptrs); it runs on a worker thread.
    void runPinWorker(std::function<std::shared_ptr<PinResult>()> work,
                      std::function<void(std::shared_ptr<PinResult>)> next);

    // Persisted count of consecutive failed PIN attempts; wiping the wrapped
    // key at the limit survives an app restart (an attacker cannot reset it by
    // relaunching). kMaxPinFailures lives in the .cpp.
    int pinFailures() const;
    void setPinFailures(int count);
    // Delete the wrapped key + reset the counter, then notify QML.
    void forgetPin();

    void finishLogin(const Api::TokenResponse &token);
    void applySyncBlob(const QByteArray &blob, bool freshLogin);
    void refreshAndSync(bool freshLogin);

    // A cipher write: given a valid access token, invoke the ApiClient call
    // and deliver its result.
    using CipherWriteCall = std::function<void(
        const QByteArray &token, std::function<void(Api::Result<QByteArray>)>)>;

    // Shared write pipeline. Uses the live access token when present (a
    // just-logged-in session may have no refresh token at all); refreshes only
    // when there is no access token (offline unlock) or the server rejects it
    // (401/403). On success re-syncs and reloads from the server's response.
    void writeAndResync(const CipherWriteCall &doWrite,
                        const QString &successMessage);
    // Refresh the access token, then run the write. Used as the fallback path.
    void refreshThenWrite(const CipherWriteCall &doWrite,
                          const QString &successMessage);
    // Handle a write result: on success re-sync + reload; else notify.
    void finishWrite(const Api::Result<QByteArray> &writeResult,
                     const QString &successMessage);
    // Post-write reload (vault is unlocked): persist blob, reloadSync, refresh
    // the model, notify. Locks + reports if the account key changed.
    void applyWriteSync(const QByteArray &blob, const QString &successMessage);
    void handleAppStateChanged(Qt::ApplicationState state);
    void clearClipboardIfOurs();

    QSettings m_settings;
    Api::ApiClient m_api;
    Vault::Vault m_vault;
    Vault::VaultListModel m_model;
    Vault::SyncStore m_syncStore;
    Vault::PinStore m_pinStore;

    QString m_state;
    bool m_busy = false;
    QString m_lastError;
    QVariantList m_twoFactorProviders;

    // Session (memory only).
    QByteArray m_accessToken;
    QByteArray m_refreshToken;

    // Pending login context while a 2FA code is required.
    QByteArray m_pendingHash;
    std::shared_ptr<DerivedSecrets> m_pendingSecrets;

    QString m_clipboardExpected;
    QTimer m_clipboardTimer;

    QFutureWatcher<std::shared_ptr<DerivedSecrets>> m_deriveWatcher;
    QFutureWatcher<std::shared_ptr<PinResult>> m_pinWatcher;
};

} // namespace Ui
} // namespace BitVault
