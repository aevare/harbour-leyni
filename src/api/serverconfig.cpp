#include "serverconfig.h"

namespace Leyni {
namespace Api {

ServerConfig ServerConfig::cloudUs()
{
    ServerConfig config;
    config.identityBase = QStringLiteral("https://identity.bitwarden.com");
    config.apiBase = QStringLiteral("https://api.bitwarden.com");
    return config;
}

ServerConfig ServerConfig::cloudEu()
{
    ServerConfig config;
    config.identityBase = QStringLiteral("https://identity.bitwarden.eu");
    config.apiBase = QStringLiteral("https://api.bitwarden.eu");
    return config;
}

ServerConfig ServerConfig::selfHosted(const QString &baseUrl)
{
    QString base = baseUrl.trimmed();
    while (base.endsWith(QLatin1Char('/'))) {
        base.chop(1);
    }
    ServerConfig config;
    config.identityBase = base + QStringLiteral("/identity");
    config.apiBase = base + QStringLiteral("/api");
    return config;
}

} // namespace Api
} // namespace Leyni
