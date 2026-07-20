// Server endpoint configuration. Bitwarden cloud splits auth and vault
// across two hosts; self-hosted servers (including Vaultwarden) serve both
// under one base URL at /identity and /api.
#pragma once

#include <QString>

namespace Leyni {
namespace Api {

struct ServerConfig {
    QString identityBase; // ".../identity" or https://identity.bitwarden.com
    QString apiBase;      // ".../api"      or https://api.bitwarden.com

    static ServerConfig cloudUs();
    static ServerConfig cloudEu();
    // Any self-hosted base URL, e.g. "https://vault.example.com".
    static ServerConfig selfHosted(const QString &baseUrl);

    QString preloginUrl() const { return identityBase + "/accounts/prelogin"; }
    QString tokenUrl() const { return identityBase + "/connect/token"; }
    QString registerUrl() const { return identityBase + "/accounts/register"; }
    QString syncUrl() const { return apiBase + "/sync"; }
    QString sendEmailLoginUrl() const
    {
        return apiBase + "/two-factor/send-email-login";
    }
    QString ciphersUrl() const { return apiBase + "/ciphers"; }
    QString cipherUrl(const QString &id) const
    {
        return apiBase + "/ciphers/" + id;
    }
};

} // namespace Api
} // namespace Leyni
