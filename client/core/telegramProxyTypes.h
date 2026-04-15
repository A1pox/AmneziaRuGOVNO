#ifndef TELEGRAMPROXYTYPES_H
#define TELEGRAMPROXYTYPES_H

#include <QString>

struct TelegramProxyRuntimeConfig
{
    QString listenHost = QStringLiteral("127.0.0.1");
    quint16 port = 1443;
    QString secret;
    QString fakeTlsDomain;
    QString cfProxyDomain;
    bool cfProxyEnabled = true;
    bool cfProxyPriorityEnabled = true;
};

Q_DECLARE_METATYPE(TelegramProxyRuntimeConfig)

#endif // TELEGRAMPROXYTYPES_H
